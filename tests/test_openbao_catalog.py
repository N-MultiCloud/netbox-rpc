"""Independent contract oracles for the OpenBao issue-252 catalog."""

from __future__ import annotations

import importlib
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_MIGRATION = (
    "netbox_rpc.migrations.0077_seed_openbao_service_allowlist"
)
PROCEDURE_MIGRATION = "netbox_rpc.migrations.0078_seed_openbao_procedures"

READS = {
    "service.openbao.1.inspect",
    "service.openbao.1.seal_status",
    "service.openbao.1.health",
    "service.openbao.1.policies_list",
    "service.openbao.1.auth_list",
    "service.openbao.1.secrets_list",
    "service.openbao.1.audit_list",
    "service.openbao.1.raft_list_peers",
    "service.openbao.1.raft_autopilot_state",
    "service.openbao.1.snapshots_list",
}
WRITES = {
    "service.openbao.1.policy_write",
    "service.openbao.1.auth_enable",
    "service.openbao.1.secrets_enable",
    "service.openbao.1.audit_enable",
    "service.openbao.1.snapshot_create",
    "service.openbao.1.service_action",
}
DESTRUCTIVE = {
    "service.openbao.1.seal",
    "service.openbao.1.step_down",
    "service.openbao.1.raft_remove_peer",
    "service.openbao.1.policy_delete",
    "service.openbao.1.auth_disable",
    "service.openbao.1.secrets_disable",
    "service.openbao.1.audit_disable",
}
WITHHELD = {
    "service.openbao.1.config_deploy",
    "service.openbao.1.rekey",
    "service.openbao.1.config_read",
    "service.openbao.1.policy_read",
    "service.openbao.1.initialize",
    "service.openbao.1.unseal",
    "service.openbao.1.snapshot_restore",
}
EXPECTED_NAMES = READS | WRITES | DESTRUCTIVE
FORBIDDEN_SSH_OVERRIDES = {
    "rpc_ssh_credential_pk",
    "rpc_ssh_host",
    "rpc_ssh_port",
    "rpc_ssh_known_hosts_entry",
    "rpc_ssh_strict_host_key_checking",
}


def _handler_id(name: str) -> str:
    operation = name.removeprefix("service.openbao.1.")
    return f"service.openbao_1.{operation}"


def test_seed_is_exact_and_all_withheld_procedures_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, procedures, commands = _run_procedure_seed(monkeypatch)

    assert set(procedures.rows) == EXPECTED_NAMES
    for withheld_name in WITHHELD:
        assert withheld_name not in procedures.rows
    all_migration_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "netbox_rpc/migrations").glob("0*.py"))
    )
    for withheld_name in WITHHELD:
        assert withheld_name not in all_migration_source
    assert set(commands.rows) == {(name, 1) for name in EXPECTED_NAMES}


def test_handler_ids_effects_and_approval_match_the_fixed_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, procedures, commands = _run_procedure_seed(monkeypatch)

    for name in READS:
        expected = ("read", False)
        assert (
            procedures.rows[name]["effect"],
            procedures.rows[name]["approval_required"],
        ) == expected
    for name in WRITES:
        expected = ("write", False)
        assert (
            procedures.rows[name]["effect"],
            procedures.rows[name]["approval_required"],
        ) == expected
    for name in DESTRUCTIVE:
        expected = ("destructive", True)
        assert (
            procedures.rows[name]["effect"],
            procedures.rows[name]["approval_required"],
        ) == expected

    for name in EXPECTED_NAMES:
        row = procedures.rows[name]
        assert row["handler_id"] == _handler_id(name)
        assert row["version"] == 1
        assert row["enabled"] is True
        assert row["target_models"] == [
            "dcim.device",
            "virtualization.virtualmachine",
        ]
        command = commands.rows[(name, 1)]
        assert command["argv"] == [
            "backend-orchestrated",
            "openbao-" + name.rsplit(".", 1)[1].replace("_", "-"),
        ]


def test_every_params_schema_is_closed_and_declares_no_ssh_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, procedures, _ = _run_procedure_seed(monkeypatch)

    valid_params = {
        **{name: {} for name in READS},
        "service.openbao.1.policy_write": {
            "policy_name": "ops-read",
            "policy_content": 'path "kv/data/*" { capabilities = ["read"] }',
        },
        "service.openbao.1.auth_enable": {
            "auth_type": "approle",
            "mount_path": "machine-auth",
        },
        "service.openbao.1.secrets_enable": {
            "engine_type": "kv",
            "mount_path": "application-secrets",
            "kv_version": 2,
        },
        "service.openbao.1.audit_enable": {
            "audit_type": "file",
            "mount_path": "file-audit",
        },
        "service.openbao.1.snapshot_create": {"snapshot_name": "before-maintenance"},
        "service.openbao.1.service_action": {"action": "restart"},
        "service.openbao.1.seal": {},
        "service.openbao.1.step_down": {},
        "service.openbao.1.raft_remove_peer": {"peer_id": "bao-peer-03"},
        "service.openbao.1.policy_delete": {"policy_name": "retired-policy"},
        "service.openbao.1.auth_disable": {"mount_path": "retired-auth"},
        "service.openbao.1.secrets_disable": {"mount_path": "retired-kv"},
        "service.openbao.1.audit_disable": {"mount_path": "retired-audit"},
    }

    assert set(valid_params) == EXPECTED_NAMES
    for name, params in valid_params.items():
        schema = procedures.rows[name]["params_schema"]
        assert schema["additionalProperties"] is False
        assert not (set(schema["properties"]) & FORBIDDEN_SSH_OVERRIDES)
        assert not any(key.startswith("rpc_ssh_") for key in schema["properties"])
        assert "rpc_ssh_" not in json.dumps(schema, sort_keys=True)
        validate(params, schema)

    # Mirrors OpenBao's Pydantic cross-field contract: kv_version is meaningful
    # only for the kv engine, while public HSM token labels are metadata rather
    # than persisted token material.
    validate(
        {
            "policy_name": "hsm-policy",
            "policy_content": 'token_label = "OpenBao"',
        },
        procedures.rows["service.openbao.1.policy_write"]["params_schema"],
    )
    with pytest.raises(ValidationError):
        validate(
            {"engine_type": "database", "kv_version": 2},
            procedures.rows["service.openbao.1.secrets_enable"]["params_schema"],
        )


def test_result_schemas_accept_the_actual_handler_envelopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, procedures, _ = _run_procedure_seed(monkeypatch)
    service = {
        "unit": "openbao.service",
        "load_state": "loaded",
        "active_state": "active",
        "sub_state": "running",
        "unit_file_state": "enabled",
    }
    extras = {
        "inspect": {
            "installation": {
                "installed": True,
                "version": "OpenBao v2.6.2",
                "binary": "/usr/bin/bao",
                "unit": "openbao.service",
                "config_path": "/etc/openbao/openbao.hcl",
                "snapshot_root": "/var/lib/openbao/snapshots",
            }
        },
        "seal_status": {
            "sealed": False,
            "initialized": True,
            "version": "2.6.2",
            "storage_type": "raft",
            "ha_enabled": True,
            "progress": 0,
            "threshold": 3,
            "error": "",
        },
        "health": {
            "service": service,
            "sealed": False,
            "initialized": True,
            "error": "",
        },
        "policies_list": {"policies": ["default", "ops-read"], "error": ""},
        "auth_list": {"auth_methods": {"approle/": {"type": "approle"}}, "error": ""},
        "secrets_list": {"secret_engines": {"kv/": {"type": "kv"}}, "error": ""},
        "audit_list": {"audit_devices": {"file/": {"type": "file"}}, "error": ""},
        "raft_list_peers": {"peers": {"data": {"config": {}}}, "error": ""},
        "raft_autopilot_state": {"autopilot": {"healthy": True}, "error": ""},
        "snapshots_list": {
            "snapshot_root": "/var/lib/openbao/snapshots",
            "snapshots": [
                {
                    "name": "raft.20260825T010203000000Z.snap",
                    "size": 4096,
                    "mtime": "2026-08-25T01:02:03+00:00",
                }
            ],
            "error": "",
        },
        "policy_write": {"policy_name": "ops-read", "error": ""},
        "auth_enable": {"auth_type": "approle", "mount_path": "approle", "error": ""},
        "secrets_enable": {
            "engine_type": "kv",
            "mount_path": "kv",
            "kv_version": None,
            "error": "",
        },
        "audit_enable": {"audit_type": "file", "mount_path": "file", "error": ""},
        "snapshot_create": {
            "snapshot_name": "before-maintenance",
            "path": "/var/lib/openbao/snapshots/before-maintenance.snap",
            "error": "",
        },
        "service_action": {"action": "restart", "service": service, "error": ""},
        "seal": {"sealed": True, "error": ""},
        "step_down": {"error": ""},
        "raft_remove_peer": {"peer_id": "bao-peer-03", "error": ""},
        "policy_delete": {"policy_name": "retired-policy", "error": ""},
        "auth_disable": {"mount_path": "retired-auth", "error": ""},
        "secrets_disable": {"mount_path": "retired-kv", "error": ""},
        "audit_disable": {"mount_path": "retired-audit", "error": ""},
    }

    assert {f"service.openbao.1.{operation}" for operation in extras} == EXPECTED_NAMES
    for operation, extra in extras.items():
        name = f"service.openbao.1.{operation}"
        result = {
            "ok": True,
            "procedure": f"service.openbao_1.{operation}",
            "target": "bao01",
            **extra,
        }
        validate(result, procedures.rows[name]["result_schema"])


def test_allowlist_seed_is_enabled_and_reverse_is_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration, allowlist = _run_allowlist_seed(monkeypatch)

    assert allowlist.rows["openbao"] == {
        "systemd_unit": "openbao.service",
        "enabled": True,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "description": "OpenBao server service",
    }
    allowlist.rows["unrelated"] = {"systemd_unit": "unrelated.service"}
    migration._remove(_apps_for_allowlist(allowlist), None)
    assert allowlist.rows == {
        "unrelated": {"systemd_unit": "unrelated.service"}
    }


def test_procedure_reverse_deletes_exactly_the_seeded_rows_and_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration, procedures, commands = _run_procedure_seed(monkeypatch)
    procedures.rows["service.unrelated.1.inspect"] = {
        "handler_id": "service.unrelated_1.inspect"
    }
    commands.rows[("service.unrelated.1.inspect", 9)] = {
        "argv": ["unrelated", "command"]
    }

    migration._remove(_apps_for_procedures(procedures, commands), None)

    assert procedures.rows == {
        "service.unrelated.1.inspect": {
            "handler_id": "service.unrelated_1.inspect"
        }
    }
    assert commands.rows == {
        ("service.unrelated.1.inspect", 9): {"argv": ["unrelated", "command"]}
    }


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)


def test_openbao_normalizer_emits_no_ssh_override(jobs_module) -> None:
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name="service.openbao.1.secrets_enable",
            handler_id="service.openbao_1.secrets_enable",
        ),
        params={
            "engine_type": "kv",
            "mount_path": "applications/kv",
            "kv_version": 2,
            "_timeout_seconds_snapshot": 60,
        },
        target_display="bao01",
        target_model_label="dcim.device",
        assigned_object_id=871,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 871,
    }
    assert normalized["engine_type"] == "kv"
    assert normalized["mount_path"] == "applications/kv"
    assert normalized["kv_version"] == 2
    assert "_timeout_seconds_snapshot" not in normalized
    serialized = json.dumps(normalized, sort_keys=True)
    assert "rpc_ssh_" not in serialized


@pytest.mark.parametrize("override", sorted(FORBIDDEN_SSH_OVERRIDES))
def test_openbao_normalizer_rejects_every_ssh_override(
    jobs_module,
    override: str,
) -> None:
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name="service.openbao.1.inspect",
            handler_id="service.openbao_1.inspect",
        ),
        params={override: 22},
        target_display="bao01",
        target_model_label="dcim.device",
        assigned_object_id=871,
    )

    with pytest.raises(jobs_module.RPCExecutionError) as caught:
        jobs_module.normalize_execution_params(execution)
    assert caught.value.code == "RPC_PARAM_INVALID"


class _FakeProcedure:
    def __init__(self, manager: "_ProcedureManager", name: str) -> None:
        self.manager = manager
        self.name = name

    @property
    def handler_id(self) -> str:
        return str(self.manager.rows[self.name]["handler_id"])


class _ProcedureQuery:
    def __init__(self, manager: "_ProcedureManager", names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def delete(self) -> None:
        for name in set(self.manager.rows) & self.names:
            self.manager.rows.pop(name)
            if self.manager.commands is not None:
                for key in [key for key in self.manager.commands.rows if key[0] == name]:
                    self.manager.commands.rows.pop(key)


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.commands: _CommandManager | None = None

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.rows[name] = dict(defaults)
        return _FakeProcedure(self, name), True

    def filter(self, *, name__in):
        return _ProcedureQuery(self, set(name__in))


class _CommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def update_or_create(
        self,
        *,
        procedure: _FakeProcedure,
        sequence: int,
        defaults: dict[str, object],
    ):
        self.rows[(procedure.name, sequence)] = dict(defaults)
        return SimpleNamespace(sequence=sequence, **defaults), True


class _AllowlistQuery:
    def __init__(self, manager: "_AllowlistManager", slug: str) -> None:
        self.manager = manager
        self.slug = slug

    def delete(self) -> None:
        self.manager.rows.pop(self.slug, None)


class _AllowlistManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def update_or_create(self, *, slug: str, defaults: dict[str, object]):
        self.rows[slug] = dict(defaults)
        return SimpleNamespace(slug=slug, **defaults), True

    def filter(self, *, slug: str):
        return _AllowlistQuery(self, slug)


def _apps_for_procedures(
    procedures: _ProcedureManager,
    commands: _CommandManager,
):
    def get_model(app_label: str, model_name: str):
        assert app_label == "netbox_rpc"
        if model_name == "RPCProcedure":
            return SimpleNamespace(objects=procedures)
        if model_name == "RPCProcedureCommand":
            return SimpleNamespace(objects=commands)
        raise AssertionError(model_name)

    return SimpleNamespace(get_model=get_model)


def _apps_for_allowlist(allowlist: _AllowlistManager):
    def get_model(app_label: str, model_name: str):
        assert (app_label, model_name) == (
            "netbox_rpc",
            "RPCLinuxServiceAllowlist",
        )
        return SimpleNamespace(objects=allowlist)

    return SimpleNamespace(get_model=get_model)


def _run_procedure_seed(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(PROCEDURE_MIGRATION, None)
    migration = importlib.import_module(PROCEDURE_MIGRATION)
    procedures = _ProcedureManager()
    commands = _CommandManager()
    procedures.commands = commands
    migration._seed(_apps_for_procedures(procedures, commands), None)
    return migration, procedures, commands


def _run_allowlist_seed(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(ALLOWLIST_MIGRATION, None)
    migration = importlib.import_module(ALLOWLIST_MIGRATION)
    allowlist = _AllowlistManager()
    migration._seed(_apps_for_allowlist(allowlist), None)
    return migration, allowlist


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    django.db = django_db
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"
    netbox_jobs = types.ModuleType("netbox.jobs")
    netbox_jobs.JobRunner = type(
        "JobRunner",
        (),
        {"enqueue": classmethod(lambda cls, *args, **kwargs: None)},
    )
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone
    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCExecution = type("RPCExecution", (), {})
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})
    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")
    requests_exceptions.RequestException = type("RequestException", (Exception,), {})
    requests_exceptions.ConnectionError = type("ConnectionError", (Exception,), {})
    requests_mod.exceptions = requests_exceptions
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
