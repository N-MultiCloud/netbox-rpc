from __future__ import annotations

import importlib
import runpy
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = "netbox_rpc.migrations.0080_seed_gitea_runner_register"
PROCEDURE_ID = "service.gitea.runner.register"
EXPECTED_SEMANTIC_SHA256 = (
    "ba3a8bcbe551d92996107799d1b2ce30e8413a33be919499da3f71636ea8b240"
)


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    migrations = types.ModuleType("django.db.migrations")
    migrations.Migration = type("Migration", (), {})
    migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    exceptions = types.ModuleType("django.db.migrations.exceptions")
    exceptions.IrreversibleError = type("IrreversibleError", (RuntimeError,), {})
    django_db.migrations = migrations
    for name, module in {
        "netbox": netbox,
        "netbox.plugins": netbox_plugins,
        "django": django,
        "django.db": django_db,
        "django.db.migrations": migrations,
        "django.db.migrations.exceptions": exceptions,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


class _Filter:
    def __init__(self, exists: bool) -> None:
        self._exists = exists

    def exists(self) -> bool:
        return self._exists


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def filter(self, *, name: str) -> _Filter:
        return _Filter(name in self.rows)

    def create(self, *, name: str, **values: object) -> SimpleNamespace:
        self.rows[name] = dict(values)
        return SimpleNamespace(name=name, **values)


class _CommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def create(
        self,
        *,
        procedure: SimpleNamespace,
        sequence: int,
        **values: object,
    ) -> SimpleNamespace:
        self.rows[(procedure.name, sequence)] = dict(values)
        return SimpleNamespace()


def _apps(
    procedures: _ProcedureManager,
    commands: _CommandManager,
) -> SimpleNamespace:
    models = {
        "RPCProcedure": SimpleNamespace(objects=procedures),
        "RPCProcedureCommand": SimpleNamespace(objects=commands),
    }
    return SimpleNamespace(
        get_model=lambda app_label, model_name: (
            models[model_name] if app_label == "netbox_rpc" else None
        )
    )


def test_seed_is_disabled_closed_inline_and_irreversible(migration) -> None:
    runtime = runpy.run_path(str(ROOT / "netbox_rpc/gitea_runner_contract.py"))
    defaults = migration._PROCEDURE_DEFAULTS

    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0079_rpcexecution_source_intent")
    ]
    assert defaults == {
        **{
            key: runtime["PROCEDURE_POLICY"][key]
            for key in (
                "handler_id",
                "version",
                "target_models",
                "effect",
                "timeout_seconds",
                "approval_required",
                "transport_driver",
                "transport_driver_chain",
                "output_parser",
                "output_schema",
            )
        },
        "enabled": False,
        "params_schema": runtime["PARAMS_SCHEMA"],
        "result_schema": runtime["RESULT_SCHEMA"],
        "description": defaults["description"],
    }
    assert runtime["COMMAND_CONTRACT"] == [
        {"sequence": 1, **migration._REPRESENTATIVE_COMMAND}
    ]
    source = (
        ROOT / "netbox_rpc/migrations/0080_seed_gitea_runner_register.py"
    ).read_text(encoding="utf-8")
    assert "from netbox_rpc" not in source

    procedures = _ProcedureManager()
    commands = _CommandManager()
    apps = _apps(procedures, commands)
    migration.seed_gitea_runner_register(apps, None)
    assert procedures.rows == {PROCEDURE_ID: defaults}
    assert commands.rows == {(PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND}
    with pytest.raises(RuntimeError, match="cannot adopt an existing"):
        migration.seed_gitea_runner_register(apps, None)
    with pytest.raises(migration.IrreversibleError, match="intentionally irreversible"):
        migration.unseed_gitea_runner_register(apps, None)


def test_contract_closes_caller_result_normalized_and_fingerprint_shapes() -> None:
    runtime = runpy.run_path(str(ROOT / "netbox_rpc/gitea_runner_contract.py"))

    for schema_name in (
        "PARAMS_SCHEMA",
        "RESULT_SCHEMA",
        "NORMALIZED_PARAMS_SCHEMA",
        "COMMAND_FINGERPRINT_SCHEMA",
    ):
        schema = runtime[schema_name]
        Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])

    for operation in runtime["OPERATIONS"]:
        for scope in runtime["SCOPES"]:
            validate(
                {"operation": operation, "scope": scope},
                runtime["PARAMS_SCHEMA"],
            )
    for hostile in (
        {},
        {"scope": "nmulticloud-org"},
        {"operation": "rotate", "scope": "nmulticloud-org"},
        {"operation": "register", "scope": "N-MultiCloud"},
        {"operation": "register", "scope": "nmulticloud-org", "token": "secret"},
        {
            "operation": "register",
            "scope": "nmulticloud-org",
            "ssh_host": "10.0.30.96",
        },
    ):
        with pytest.raises(ValidationError):
            validate(hostile, runtime["PARAMS_SCHEMA"])

    normalized_properties = runtime["NORMALIZED_PARAMS_SCHEMA"]["properties"]
    fingerprint_properties = runtime["COMMAND_FINGERPRINT_SCHEMA"]["properties"]
    assert "token" not in normalized_properties
    assert "token" not in fingerprint_properties
    assert (
        fingerprint_properties["target_object_sha256"]["const"]
        == runtime["RUNNER_TARGET_OBJECT_SHA256"]
    )
    assert (
        fingerprint_properties["runner_target_object_sha256"]["const"]
        == runtime["RUNNER_TARGET_OBJECT_SHA256"]
    )
    assert (
        fingerprint_properties["gitea_target_object_sha256"]["const"]
        == runtime["GITEA_TARGET_OBJECT_SHA256"]
    )
    assert normalized_properties["runner_ssh_policy_ref"]["const"] == (
        "target-owned-ssh:virtualization.virtualmachine:399"
    )
    assert normalized_properties["gitea_ssh_policy_ref"]["const"] == (
        "target-owned-ssh:virtualization.virtualmachine:170"
    )


def test_semantic_capability_digest_is_the_cross_repository_anchor() -> None:
    runtime = runpy.run_path(str(ROOT / "netbox_rpc/gitea_runner_contract.py"))

    assert runtime["SEMANTIC_CAPABILITY_SHA256"] == EXPECTED_SEMANTIC_SHA256
    assert runtime["PROCEDURE_POLICY"]["semantic_contract_sha256"] == (
        EXPECTED_SEMANTIC_SHA256
    )
    assert runtime["SEMANTIC_CAPABILITY_EXTENSION"]["runtime"] == {
        "route_budget_seconds": 300,
        "handler_budget_seconds": 270,
        "preflight_timeout_seconds": 30,
        "token_timeout_seconds": 30,
        "register_timeout_seconds": 150,
        "reset_timeout_seconds": 30,
        "capture_max_bytes": 512,
        "backend_response_max_bytes": 4096,
        "reconciliation_quiescence_seconds": 360,
    }


def test_static_code_gate_and_protected_policy_paths_are_present() -> None:
    normalization = (ROOT / "netbox_rpc/domain/normalization.py").read_text(
        encoding="utf-8"
    )
    handlers = (ROOT / "netbox_rpc/application/command_handlers.py").read_text(
        encoding="utf-8"
    )
    views = (ROOT / "netbox_rpc/api/views.py").read_text(encoding="utf-8")

    assert "_GITEA_RUNNER_REGISTER_AVAILABLE = False" in normalization
    assert "procedure_name == GITEA_RUNNER_REGISTER" in normalization
    assert "code_gate_unavailable_reason(procedure.name)" in handlers
    assert "code_gate_unavailable_reason(procedure.name)" in views
    assert "_require_gitea_runner_assigned_object(" in handlers
    assert "_require_current_protected_approval(" in handlers
    assert "_issue_dispatch_lease(" in handlers


def test_scope_fence_migration_is_seeded_closed_and_database_constrained() -> None:
    migration = (
        ROOT / "netbox_rpc/migrations/0081_gitea_runner_scope_fence.py"
    ).read_text(encoding="utf-8")
    models = (ROOT / "netbox_rpc/models.py").read_text(encoding="utf-8")

    for canonical_scope in (
        "N-MultiCloud",
        "emersonfelipesp/netbox-proxbox",
        "emersonfelipesp/proxbox-api",
    ):
        assert canonical_scope in migration
    assert "cannot adopt existing Gitea runner scope fences" in migration
    assert "intentionally irreversible" in migration
    for constraint in (
        "netbox_rpc_gitea_scope_fence_state_consistent",
        "netbox_rpc_gitea_scope_fence_reconcile_consistent",
    ):
        assert constraint in migration
        assert constraint in models
