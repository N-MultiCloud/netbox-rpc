"""Contract coverage for the typed Proxmox Backup Server procedure family."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

MIGRATION = "netbox_rpc.migrations.0111_seed_pbs_procedures"
ROOT = Path(__file__).resolve().parents[1]
DISK_IDENTITY = "0123456789abcdef" * 4


def _load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


constants = _load_file("pbs_constants", ROOT / "netbox_rpc/constants.py")


def _load_migration(monkeypatch):
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")

    class RunPython:
        def __init__(self, code, reverse_code=None):
            self.code = code
            self.reverse_code = reverse_code

    django_db.migrations = SimpleNamespace(Migration=object, RunPython=RunPython)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    return _load_file(
        "pbs_migration",
        ROOT / "netbox_rpc/migrations/0111_seed_pbs_procedures.py",
    )


@dataclass
class _Row:
    name: str = ""
    enabled: bool = False
    values: dict = field(default_factory=dict)

    def __getattr__(self, key):
        if key in self.values:
            return self.values[key]
        raise AttributeError(key)


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, _Row] = {}

    def update_or_create(self, *, name, defaults):
        row = self.rows.setdefault(name, _Row(name=name))
        row.values.update(defaults)
        row.enabled = defaults["enabled"]
        return row, True

    def filter(self, *, name__in):
        rows = [self.rows[name] for name in name__in if name in self.rows]
        return SimpleNamespace(
            update=lambda **values: [
                setattr(row, key, value)
                for row in rows
                for key, value in values.items()
            ]
        )


class _CommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict] = {}

    def update_or_create(self, *, procedure, sequence, defaults):
        self.rows[(procedure.name, sequence)] = defaults
        return defaults, True


def _apps():
    procedures = SimpleNamespace(objects=_ProcedureManager())
    commands = SimpleNamespace(objects=_CommandManager())

    def get_model(app, model):
        assert app == "netbox_rpc"
        return {"RPCProcedure": procedures, "RPCProcedureCommand": commands}[model]

    return SimpleNamespace(get_model=get_model), procedures.objects, commands.objects


def test_migration_apply_reverse_and_contracts(monkeypatch) -> None:
    migration = _load_migration(monkeypatch)
    apps, procedures, commands = _apps()
    migration.seed_pbs_procedures(apps, None)
    assert set(procedures.rows) == constants.PBS_1_PROCEDURE_NAMES
    assert len(commands.rows) == 4
    for name, row in procedures.rows.items():
        assert row.enabled is False
        assert row.values["handler_id"] == name
        assert row.values["target_models"] == [
            "dcim.device",
            "virtualization.virtualmachine",
        ]
        assert row.values["params_schema"]["additionalProperties"] is False
        jsonschema.Draft202012Validator.check_schema(row.values["params_schema"])
        jsonschema.Draft202012Validator.check_schema(row.values["result_schema"])
        jsonschema.validate(
            {"procedure": name, "failure": {"code": "RPC_PBS_COMMAND_FAILED"}},
            row.values["result_schema"],
        )
        assert commands.rows[(name, 1)]["argv"][0] == "backend-orchestrated"
        is_datastore_create = name == constants.PBS_1_DATASTORE_FROM_DISK
        assert row.values["transport_driver"] == "asyncssh"
        assert row.values["transport_pinned"] is is_datastore_create
        assert row.values["transport_driver_chain"] == []
    procedures.rows[constants.PBS_1_STATUS].enabled = True
    migration.disable_pbs_procedures(apps, None)
    assert not any(row.enabled for row in procedures.rows.values())


def test_datastore_schema_accepts_valid_and_rejects_injection(monkeypatch) -> None:
    migration = _load_migration(monkeypatch)
    row = next(
        row
        for row in migration._PROCEDURES
        if row[0] == constants.PBS_1_DATASTORE_FROM_DISK
    )
    schema = row[4]
    jsonschema.validate(
        {
            "name": "backup01",
            "disk": "nvme10n12",
            "filesystem": "xfs",
            "disk_identity": DISK_IDENTITY,
        },
        schema,
    )
    for invalid in (
        {
            "name": "x; rm -rf /",
            "disk": "sdb",
            "filesystem": "ext4",
            "disk_identity": DISK_IDENTITY,
        },
        {
            "name": "ok1",
            "disk": "sdb;id",
            "filesystem": "ext4",
            "disk_identity": DISK_IDENTITY,
        },
        {
            "name": "ok1",
            "disk": "sdb",
            "filesystem": "btrfs",
            "disk_identity": DISK_IDENTITY,
        },
        {
            "name": "ok1",
            "disk": "sdb",
            "filesystem": "ext4",
            "disk_identity": DISK_IDENTITY,
            "extra": True,
        },
        {
            "name": "ok1",
            "disk": "sdb",
            "filesystem": "ext4",
            "disk_identity": "A" * 64,
        },
    ):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)


def test_disk_list_result_requires_closed_identity(monkeypatch) -> None:
    migration = _load_migration(monkeypatch)
    schema = next(
        row[5] for row in migration._PROCEDURES if row[0] == constants.PBS_1_DISK_LIST
    )
    result = {
        "procedure": constants.PBS_1_DISK_LIST,
        "disks": [
            {
                "name": "sdb",
                "size_bytes": 1000,
                "used": "unused",
                "gpt": True,
                "model": "Disk",
                "identity": DISK_IDENTITY,
                "identity_stable": True,
            }
        ],
    }
    jsonschema.validate(result, schema)
    for required_field in ("identity", "identity_stable"):
        invalid = json.loads(json.dumps(result))
        invalid["disks"][0].pop(required_field)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)


def test_failure_result_branches_are_closed(monkeypatch) -> None:
    migration = _load_migration(monkeypatch)
    for (
        name,
        _effect,
        _timeout,
        _approval,
        _params,
        schema,
        *_rest,
    ) in migration._PROCEDURES:
        for code in (
            "RPC_PBS_DISK_NOT_FOUND",
            "RPC_PBS_CONNECTION_FAILED",
            "RPC_PBS_OUTCOME_UNKNOWN",
            "RPC_PBS_BUSY",
            "RPC_PBS_CREDENTIAL_UNAVAILABLE",
            "RPC_HANDLER_FAILED",
            "RPC_FUTURE_ROUTER_REFUSAL",
        ):
            jsonschema.validate({"procedure": name, "failure": {"code": code}}, schema)
        valid = {"procedure": name, "failure": {"code": "RPC_PBS_OUTCOME_UNKNOWN"}}
        for invalid in (
            {**valid, "extra": True},
            {"procedure": name, "failure": {"code": "OTHER_FAILURE"}},
            {"procedure": name, "failure": {"code": "RPC_PBS_bad"}},
            {"procedure": name, "failure": {"code": "RPC_PBS_" + "A" * 65}},
            {"procedure": name, "failure": {"code": "RPC_PBS_COMMAND_FAILED", "x": 1}},
        ):
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(invalid, schema)


def _execution(name: str, params: dict) -> SimpleNamespace:
    target = SimpleNamespace(pk=56, name="pbs01")
    return SimpleNamespace(
        procedure=SimpleNamespace(name=name, handler_id=name),
        target_model_label="virtualization.virtualmachine",
        assigned_object=target,
        assigned_object_id=56,
        params=params,
    )


def test_normalizer_output_and_code_gate(monkeypatch) -> None:
    import test_influxdb3_debian13_procedures as influx_test

    influx_test._install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    importlib.import_module("netbox_rpc.jobs")
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    assert normalization.code_gate_unavailable_reason(constants.PBS_1_STATUS)
    assert (
        normalization.code_gate_unavailable_reason("service.unknown.1.status") is None
    )
    monkeypatch.setattr(normalization, "_PBS_1_AVAILABLE", True)
    normalized = normalization._normalize_pbs_execution(
        _execution(
            constants.PBS_1_DATASTORE_FROM_DISK,
            {
                "name": "backup01",
                "disk": "sdb",
                "filesystem": "ext4",
                "disk_identity": DISK_IDENTITY,
            },
        ),
        "pbs01",
    )
    assert normalized["target_object"] == {
        "content_type": "virtualization.virtualmachine",
        "object_id": 56,
    }
    assert normalized["command_fingerprint"]["disk"] == "sdb"
    assert normalized["command_fingerprint"]["disk_identity"] == DISK_IDENTITY


def test_capability_and_approval_policy(monkeypatch) -> None:
    assert (
        constants.PBS_1_PROCEDURE_NAMES
        <= constants.EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES
    )
    assert (
        not constants.PBS_1_PROCEDURE_NAMES
        & constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    )
    migration = _load_migration(monkeypatch)
    destructive = next(
        row
        for row in migration._PROCEDURES
        if row[0] == constants.PBS_1_DATASTORE_FROM_DISK
    )
    assert destructive[1:4] == ("destructive", 600, True)


def test_command_contract_exemptions_exist() -> None:
    command_contract = _load_file(
        "pbs_command_contract", ROOT / "netbox_rpc/command_contract.py"
    )

    assert (
        constants.PBS_1_PROCEDURE_NAMES
        <= command_contract.EXEMPT_HANDLER_RATIONALE.keys()
    )


def test_seeded_command_hashes_match_backend_contracts(monkeypatch) -> None:
    migration = _load_migration(monkeypatch)
    apps, procedures, commands = _apps()
    migration.seed_pbs_procedures(apps, None)
    expected = {
        "service.pbs.1.status": "85f3e0737a9a497ede990fff66941b1d4b0d51d56a695591599d63546ae5eae7",
        "service.pbs.1.cert_fingerprint": "c4e5af0e704bd772a72cde0799f75be7103bfa609b549706aa673f9c4246ee5e",
        "service.pbs.1.disk_list": "60858ed64bff5110400f0f0d1190ea3c40b525aebd172902a4154c91948df01e",
        "service.pbs.1.datastore_from_disk": "0828526e80bfe8ab7a6cbb5ff5e63ba3b2c0876b5d7735fc7455940e884925c2",
    }
    for name, row in procedures.rows.items():
        command = commands.rows[(name, 1)]
        payload = {
            "handler_id": row.values["handler_id"],
            "version": row.values["version"],
            "effect": row.values["effect"],
            "commands": [
                {
                    "sequence": 1,
                    "step_type": command["step_type"],
                    "device_cli_mode": command["device_cli_mode"],
                    "argv": command["argv"],
                    "render_mode": command["render_mode"],
                    "produces_var": command["produces_var"],
                    "capture_kind": command["capture_kind"],
                    "capture_expression": command["capture_expression"],
                    "condition_param": command["condition_param"],
                    "condition_negate": command["condition_negate"],
                    "for_each_param": command["for_each_param"],
                    "continue_on_error": command["continue_on_error"],
                }
            ],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        assert hashlib.sha256(canonical.encode()).hexdigest() == expected[name]
