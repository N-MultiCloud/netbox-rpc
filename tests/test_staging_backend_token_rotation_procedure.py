from __future__ import annotations

import importlib
import importlib.util
import runpy
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = "netbox_rpc.migrations.0068_seed_staging_backend_token_rotation"
PROCEDURE_ID = "service.netbox.staging.rotate_backend_token"
PARAM_KEYS: set[str] = set()
RESULT_KEYS = {"ok", "procedure", "target", "rotated", "stage"}


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_staging_rotation_policy_and_schema_contract(migration) -> None:
    defaults = migration._PROCEDURE_DEFAULTS

    assert migration._PROCEDURE_NAME == PROCEDURE_ID
    assert migration._HANDLER_ID == PROCEDURE_ID
    assert defaults["handler_id"] == PROCEDURE_ID
    assert defaults["version"] == 1
    assert defaults["enabled"] is True
    assert defaults["target_models"] == ["dcim.device"]
    assert defaults["effect"] == "destructive"
    assert defaults["approval_required"] is True
    assert defaults["timeout_seconds"] == 1800
    assert defaults["transport_driver"] == "asyncssh"
    assert defaults["transport_driver_chain"] == []
    assert defaults["output_parser"] == "none"
    assert defaults["output_schema"] == {}

    params_schema = defaults["params_schema"]
    result_schema = defaults["result_schema"]
    Draft202012Validator.check_schema(params_schema)
    Draft202012Validator.check_schema(result_schema)

    assert params_schema["additionalProperties"] is False
    assert set(params_schema["properties"]) == PARAM_KEYS
    assert result_schema["additionalProperties"] is False
    assert set(result_schema["required"]) == RESULT_KEYS
    assert set(result_schema["properties"]) == RESULT_KEYS
    assert result_schema["properties"]["procedure"] == {"const": PROCEDURE_ID}
    assert result_schema["properties"]["target"] == {"const": "nms-front-door"}
    assert result_schema["properties"]["rotated"] == {"type": ["boolean", "null"]}
    assert result_schema["properties"]["stage"]["enum"] == [
        "execute",
        "complete",
        "indeterminate",
    ]

    runtime_contract = runpy.run_path(
        str(ROOT / "netbox_rpc/staging_rotation_contract.py")
    )
    assert runtime_contract["PROCEDURE_POLICY"] == {
        "name": PROCEDURE_ID,
        **{
            key: defaults[key]
            for key in (
                "handler_id",
                "version",
                "enabled",
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
        "command_contract_sha256": runtime_contract["COMMAND_CONTRACT_SHA256"],
    }
    assert runtime_contract["COMMAND_CONTRACT"] == [
        {"sequence": 1, **migration._REPRESENTATIVE_COMMAND}
    ]
    assert runtime_contract["PARAMS_SCHEMA"] == params_schema
    assert runtime_contract["RESULT_SCHEMA"] == result_schema
    assert len(runtime_contract["PROCEDURE_POLICY_SHA256"]) == 64
    assert len(runtime_contract["PARAMS_SCHEMA_SHA256"]) == 64
    assert len(runtime_contract["RESULT_SCHEMA_SHA256"]) == 64


def test_staging_rotation_accepts_no_caller_routing_params(migration) -> None:
    schema = migration._PARAMS_SCHEMA
    validate({}, schema)

    for invalid in (
        {"rpc_ssh_credential_pk": 20},
        {"rpc_ssh_host": "10.0.30.207"},
        {"rpc_ssh_port": 2222},
        {"rpc_ssh_known_hosts_entry": "host ssh-ed25519 key"},
        {"rpc_ssh_strict_host_key_checking": True},
        {"token": "must-not-enter-rpc"},
        {"token_value": "must-not-enter-rpc"},
        {"secret": "must-not-enter-rpc"},
        {"command": "rotate --token must-not-enter-rpc"},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, schema)


def test_staging_rotation_result_is_closed_and_secret_silent(migration) -> None:
    schema = migration._RESULT_SCHEMA
    valid = {
        "ok": True,
        "procedure": PROCEDURE_ID,
        "target": "nms-front-door",
        "rotated": True,
        "stage": "complete",
    }
    validate(valid, schema)
    validate({**valid, "ok": False, "rotated": False, "stage": "execute"}, schema)
    validate({**valid, "ok": False, "rotated": True, "stage": "complete"}, schema)
    validate(
        {**valid, "ok": False, "rotated": None, "stage": "indeterminate"},
        schema,
    )

    for field in (
        "token",
        "token_value",
        "secret",
        "value",
        "stdout",
        "stderr",
        "output",
        "command",
        "path",
    ):
        with pytest.raises(ValidationError):
            validate({**valid, field: "must-not-be-recorded"}, schema)
    for invalid in (
        {**valid, "procedure": "different.handler"},
        {**valid, "target": "different-target"},
        {**valid, "stage": "failed"},
        {**valid, "rotated": False},
        {**valid, "stage": "execute"},
        {**valid, "ok": False, "rotated": False},
        {**valid, "ok": False, "rotated": True, "stage": "execute"},
        {**valid, "ok": False, "rotated": None, "stage": "execute"},
        {**valid, "ok": False, "rotated": None, "stage": "complete"},
        {**valid, "ok": True, "rotated": None, "stage": "indeterminate"},
        {key: value for key, value in valid.items() if key != "rotated"},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, schema)


def test_staging_rotation_seed_is_idempotent(
    migration,
) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    apps = _fake_apps()

    migration.seed_staging_backend_token_rotation(apps, None)
    migration.seed_staging_backend_token_rotation(apps, None)

    assert procedures.rows == {PROCEDURE_ID: migration._PROCEDURE_DEFAULTS}
    assert commands.rows == {
        (PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND,
    }
    assert procedures.update_calls == 2
    assert commands.update_calls == 2


def test_staging_rotation_migration_is_ordered_inline_and_command_is_safe(
    migration,
) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0067_merge_huawei_bgp_and_upgrade_result_limits")
    ]
    run_python_args, run_python_kwargs = migration.Migration.operations[0]
    assert run_python_args == (migration.seed_staging_backend_token_rotation,)
    assert run_python_kwargs == {
        "reverse_code": migration.unseed_staging_backend_token_rotation
    }
    source = (
        ROOT / "netbox_rpc/migrations/0068_seed_staging_backend_token_rotation.py"
    ).read_text(encoding="utf-8")
    assert "from netbox_rpc" not in source

    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))
    assert constants["NETBOX_STAGING_ROTATE_BACKEND_TOKEN"] == PROCEDURE_ID
    assert constants["NETBOX_STAGING_ROTATE_BACKEND_TOKEN_HANDLER"] == PROCEDURE_ID

    spec = importlib.util.spec_from_file_location(
        "staging_rotation_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    assert PROCEDURE_ID in command_contract.EXEMPT_HANDLER_RATIONALE
    assert PROCEDURE_ID in command_contract.EXEMPT_HANDLER_IDS
    assert migration._REPRESENTATIVE_COMMAND["argv"][0] == "backend-orchestrated"
    assert all(
        command_contract.token_is_safe(token)
        for token in migration._REPRESENTATIVE_COMMAND["argv"]
    )


def test_staging_rotation_reverse_deletes_unreferenced_seed(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    apps = _fake_apps()
    migration.seed_staging_backend_token_rotation(apps, None)

    migration.unseed_staging_backend_token_rotation(apps, None)

    assert procedures.rows == {}
    assert commands.rows == {}


def test_staging_rotation_reverse_disables_protected_history(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.commands = commands
    procedures.protected_error = migration.ProtectedError
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    apps = _fake_apps()
    migration.seed_staging_backend_token_rotation(apps, None)

    migration.unseed_staging_backend_token_rotation(apps, None)

    assert procedures.rows[PROCEDURE_ID]["enabled"] is False
    assert commands.rows == {
        (PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND,
    }


def test_approver_identity_migration_follows_the_new_seed() -> None:
    source = (
        ROOT / "netbox_rpc/migrations/0069_rpcexecution_approved_by.py"
    ).read_text(encoding="utf-8")

    assert '("netbox_rpc", "0068_seed_staging_backend_token_rotation")' in source
    assert 'model_name="rpcexecution"' in source
    assert 'name="approved_by"' in source


def test_approval_policy_hash_migration_follows_approver_identity() -> None:
    source = (
        ROOT / "netbox_rpc/migrations/0070_rpcapprovalrequest_policy_hashes.py"
    ).read_text(encoding="utf-8")

    assert '("netbox_rpc", "0069_rpcexecution_approved_by")' in source
    assert source.count('model_name="rpcapprovalrequest"') == 4
    for name in (
        "backend_target_sha256",
        "procedure_policy_sha256",
        "params_schema_sha256",
        "result_schema_sha256",
    ):
        assert f'name="{name}"' in source


class _FakeProcedureQuerySet:
    def __init__(self, manager: _FakeProcedureManager, name: str) -> None:
        self.manager = manager
        self.name = name

    def first(self):
        if self.name not in self.manager.rows:
            return None
        return _FakeProcedureRow(self.manager, self.name)


class _FakeProcedureRow:
    def __init__(self, manager: _FakeProcedureManager, name: str) -> None:
        self.manager = manager
        self.name = name
        self.enabled = bool(manager.rows[name]["enabled"])

    def delete(self) -> None:
        if self.manager.protected_error is not None:
            raise self.manager.protected_error("protected", [])
        self.manager.rows.pop(self.name, None)
        if self.manager.commands is not None:
            for key in list(self.manager.commands.rows):
                if key[0] == self.name:
                    self.manager.commands.rows.pop(key)

    def save(self, *, update_fields: list[str]) -> None:
        assert update_fields == ["enabled"]
        self.manager.rows[self.name]["enabled"] = self.enabled


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.update_calls = 0
        self.commands: _FakeCommandManager | None = None
        self.protected_error: type[Exception] | None = None

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.update_calls += 1
        created = name not in self.rows
        self.rows[name] = dict(defaults)
        return SimpleNamespace(name=name, **defaults), created

    def filter(self, *, name: str) -> _FakeProcedureQuerySet:
        return _FakeProcedureQuerySet(self, name)


class _FakeRPCProcedure:
    objects: _FakeProcedureManager


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}
        self.update_calls = 0

    def update_or_create(self, *, procedure, sequence: int, defaults):
        self.update_calls += 1
        key = (procedure.name, sequence)
        created = key not in self.rows
        self.rows[key] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence), created


class _FakeRPCProcedureCommand:
    objects: _FakeCommandManager


def _fake_apps():
    models = {
        ("netbox_rpc", "RPCProcedure"): _FakeRPCProcedure,
        ("netbox_rpc", "RPCProcedureCommand"): _FakeRPCProcedureCommand,
    }
    return SimpleNamespace(
        get_model=lambda app_label, model_name: models[(app_label, model_name)]
    )


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db_models = types.ModuleType("django.db.models")
    django_db_models_deletion = types.ModuleType("django.db.models.deletion")
    django_db_models_deletion.ProtectedError = type(
        "ProtectedError", (Exception,), {}
    )
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    django_db.models = django_db_models
    django.db = django_db

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.models", django_db_models)
    monkeypatch.setitem(
        sys.modules,
        "django.db.models.deletion",
        django_db_models_deletion,
    )
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)
