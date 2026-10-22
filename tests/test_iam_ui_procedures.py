"""Catalog policy and fixed-target normalization for IAM UI control."""

from __future__ import annotations

import importlib
import runpy
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
import test_netbox_rq_worker_procedures as rq_tests
from test_netbox_rq_worker_procedures import (
    _execution,
    _install_runtime_import_stubs,
    _Manager,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = runpy.run_path(str(ROOT / "netbox_rpc/iam_ui_contract.py"))
MIGRATION = ROOT / "netbox_rpc/migrations/0112_seed_iam_ui_control.py"
NAMES = CONTRACT["HANDLER_IDS"]


@pytest.fixture()
def normalization_jobs(monkeypatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_seed_is_frozen_idempotent_and_preserves_history(monkeypatch):
    monkeypatch.setattr(rq_tests, "MIGRATION_PATH", MIGRATION)
    migration = vars(rq_tests._load_migration())
    monkeypatch.setattr(migration["transaction"], "atomic", nullcontext)
    procedures = _Manager("procedure")
    commands = _Manager("command")
    managers = {"RPCProcedure": procedures, "RPCProcedureCommand": commands}
    apps = SimpleNamespace(
        get_model=lambda _app, model: SimpleNamespace(objects=managers[model])
    )
    assert migration["PROCEDURE_POLICIES"] == CONTRACT["PROCEDURE_POLICIES"]
    migration["seed"](apps, None)
    migration["seed"](apps, None)
    assert len(procedures.rows) == 4
    assert len(commands.rows) == 4
    for row in procedures.rows:
        name = row.name
        expected = CONTRACT["PROCEDURE_POLICIES"][name]
        for key, value in expected.items():
            assert getattr(row, key) == value
    migration["reverse"](apps, None)
    assert all(row.enabled is False for row in procedures.rows)
    assert len(commands.rows) == 4
    migration["seed"](apps, None)
    assert all(row.enabled is False for row in procedures.rows)
    procedures.rows[0].approval_required = not procedures.rows[0].approval_required
    with pytest.raises(RuntimeError):
        migration["seed"](apps, None)


@pytest.mark.parametrize("name", NAMES)
def test_exact_fixed_target_and_fingerprint(normalization_jobs, name):
    row = _execution(name, {})
    normalized = normalization_jobs.normalize_execution_params(row)
    jsonschema.validate(normalized, CONTRACT["NORMALIZED_PARAMS_SCHEMAS"][name])
    assert normalized["target"] == "nmc-prod-207"
    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 44,
    }
    mode = name.removeprefix(CONTRACT["PREFIX"])
    assert normalized["command_fingerprint"]["argv_sha256"] == CONTRACT[
        "canonical_sha256"
    ](
        [
            "sudo",
            "-n",
            CONTRACT["HELPER"],
            mode,
        ]
    )
    row.params = {"_timeout_seconds_snapshot": 60}
    assert normalization_jobs.normalize_execution_params(row) == normalized


@pytest.mark.parametrize(
    "field,value",
    [
        ("assigned_object_id", 45),
        ("assigned_object", SimpleNamespace(pk=44, name="other")),
        ("target_display", "other"),
        ("target_model_label", "virtualization.virtualmachine"),
    ],
)
def test_wrong_target_is_refused(normalization_jobs, field, value):
    row = _execution("service.keycloak.iam_ui.inspect", {})
    setattr(row, field, value)
    with pytest.raises(normalization_jobs.RPCExecutionError) as error:
        normalization_jobs.normalize_execution_params(row)
    assert error.value.code == "RPC_TARGET_INVALID"


@pytest.mark.parametrize(
    "params",
    [
        {"rpc_ssh_host": "evil.invalid"},
        {"timeout_seconds": 999},
        {"operation": "configure"},
        {"command": "unsafe"},
        [],
    ],
)
def test_caller_parameters_are_refused(normalization_jobs, params):
    row = _execution("service.keycloak.iam_ui.configure", params)
    with pytest.raises(normalization_jobs.RPCExecutionError):
        normalization_jobs.normalize_execution_params(row)


def test_policy_is_capability_gated_and_all_writes_are_protected():
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))
    assert NAMES <= constants["EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES"]
    assert (
        CONTRACT["WRITE_HANDLER_IDS"] <= constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    )
    for name, policy in CONTRACT["PROCEDURE_POLICIES"].items():
        assert policy["approval_required"] is (name in CONTRACT["WRITE_HANDLER_IDS"])
        assert policy["effect"] == ("write" if policy["approval_required"] else "read")
        assert policy["transport_pinned"] is True
        assert policy["transport_driver"] == "asyncssh"
        assert policy["transport_driver_chain"] == []
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"arbitrary": "value"}, policy["params_schema"])
