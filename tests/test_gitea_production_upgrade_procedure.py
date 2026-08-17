from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import runpy
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = "netbox_rpc.migrations.0071_seed_gitea_production_upgrade_1271"
PROCEDURE_ID = "service.gitea.production.upgrade_1_27_1"
OFFICIAL_SHA256 = "86a7ac26e7f9c9cca0f56c4fac07fff205d5fc3bca0e54af23a204f07b833bc9"
RESULT_KEYS = {"ok", "procedure", "target", "changed", "healthy", "stage"}


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_gitea_upgrade_seed_policy_and_runtime_activation_contract(migration) -> None:
    defaults = migration._PROCEDURE_DEFAULTS
    runtime = runpy.run_path(str(ROOT / "netbox_rpc/gitea_upgrade_contract.py"))

    assert migration._PROCEDURE_NAME == PROCEDURE_ID
    assert defaults["handler_id"] == PROCEDURE_ID
    assert defaults["version"] == 1
    assert defaults["enabled"] is False
    assert defaults["target_models"] == ["virtualization.virtualmachine"]
    assert defaults["effect"] == "destructive"
    assert defaults["approval_required"] is True
    assert defaults["timeout_seconds"] == 1800
    assert defaults["transport_driver"] == "asyncssh"
    assert defaults["transport_driver_chain"] == []
    assert defaults["output_parser"] == "none"
    assert defaults["output_schema"] == {}
    assert migration._ARTIFACT_SHA256 == OFFICIAL_SHA256

    # The seed is off by default; the immutable policy is the exact state that
    # must hold after ordered, operator-authorized activation.
    assert runtime["PROCEDURE_POLICY"]["enabled"] is True
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
    ):
        assert runtime["PROCEDURE_POLICY"][key] == defaults[key]
    assert runtime["PARAMS_SCHEMA"] == defaults["params_schema"]
    assert runtime["RESULT_SCHEMA"] == defaults["result_schema"]
    assert runtime["COMMAND_CONTRACT"] == [
        {"sequence": 1, **migration._REPRESENTATIVE_COMMAND}
    ]


def test_gitea_upgrade_schemas_are_closed_and_match_all_backend_states(migration) -> None:
    params_schema = migration._PARAMS_SCHEMA
    result_schema = migration._RESULT_SCHEMA
    Draft202012Validator.check_schema(params_schema)
    Draft202012Validator.check_schema(result_schema)

    validate({}, params_schema)
    for invalid in (
        {"target": "Gitea"},
        {"rpc_ssh_host": "10.0.30.96"},
        {"credential_policy": "caller-controlled"},
        {"artifact_sha256": OFFICIAL_SHA256},
        {"token": "must-not-enter-rpc"},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, params_schema)

    base = {"procedure": PROCEDURE_ID, "target": "Gitea"}
    valid_states = (
        {"ok": True, "changed": True, "healthy": True, "stage": "complete"},
        {"ok": True, "changed": False, "healthy": True, "stage": "complete"},
        {"ok": False, "changed": False, "healthy": False, "stage": "execute"},
        {"ok": False, "changed": False, "healthy": True, "stage": "rolled_back"},
        {"ok": False, "changed": True, "healthy": False, "stage": "complete"},
        {"ok": False, "changed": None, "healthy": None, "stage": "indeterminate"},
    )
    for state in valid_states:
        validate({**base, **state}, result_schema)

    assert result_schema["additionalProperties"] is False
    assert set(result_schema["required"]) == RESULT_KEYS
    assert set(result_schema["properties"]) == RESULT_KEYS
    for invalid in (
        {**base, **valid_states[0], "stdout": "secret-prone output"},
        {**base, **valid_states[0], "target": "other"},
        {**base, **valid_states[0], "healthy": False},
        {**base, **valid_states[2], "healthy": True},
        {**base, **valid_states[5], "changed": False},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, result_schema)


def test_gitea_upgrade_migration_is_inline_ordered_idempotent_and_reversible(
    migration,
) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0070_rpcapprovalrequest_policy_hashes")
    ]
    source = (
        ROOT / "netbox_rpc/migrations/0071_seed_gitea_production_upgrade_1271.py"
    ).read_text(encoding="utf-8")
    assert "from netbox_rpc" not in source
    assert OFFICIAL_SHA256 in source

    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    apps = _fake_apps()
    migration.seed_gitea_production_upgrade(apps, None)
    migration.seed_gitea_production_upgrade(apps, None)
    assert procedures.rows == {PROCEDURE_ID: migration._PROCEDURE_DEFAULTS}
    assert commands.rows == {(PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND}

    procedures.protected_error = migration.ProtectedError
    with pytest.raises(migration.IrreversibleError, match="referenced"):
        migration.unseed_gitea_production_upgrade(apps, None)
    assert procedures.rows[PROCEDURE_ID]["enabled"] is False
    assert commands.rows == {(PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND}


def test_gitea_upgrade_static_command_and_documentation_contract(migration) -> None:
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))
    assert constants["GITEA_PRODUCTION_UPGRADE_1_27_1"] == PROCEDURE_ID
    assert PROCEDURE_ID in constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]

    spec = importlib.util.spec_from_file_location(
        "gitea_upgrade_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)
    assert PROCEDURE_ID in command_contract.EXEMPT_HANDLER_RATIONALE
    assert migration._REPRESENTATIVE_COMMAND["argv"] == [
        "backend-orchestrated",
        "gitea-production-upgrade-1-27-1",
    ]
    assert all(
        command_contract.token_is_safe(token)
        for token in migration._REPRESENTATIVE_COMMAND["argv"]
    )

    for path in (
        ROOT / "README.md",
        ROOT / "AGENTS.md",
        ROOT / "CLAUDE.md",
        ROOT / "docs/gitea-production-upgrade-1.27.1.md",
    ):
        assert PROCEDURE_ID in path.read_text(encoding="utf-8")


def test_gitea_semantic_capability_fixture_is_canonical_and_hashes_exactly(
    migration,
) -> None:
    runtime = runpy.run_path(str(ROOT / "netbox_rpc/gitea_upgrade_contract.py"))
    fixture = json.loads(
        (
            ROOT / "tests/fixtures/gitea_upgrade/capability_contract.json"
        ).read_text(encoding="utf-8")
    )
    assert fixture == {
        "canonical_json": runtime["CAPABILITY_CONTRACT_CANONICAL_JSON"],
        "sha256": runtime["CAPABILITY_CONTRACT_SHA256"],
    }
    assert json.loads(fixture["canonical_json"]) == runtime[
        "CAPABILITY_CONTRACT_PAYLOAD"
    ]

    capabilities = importlib.import_module("netbox_rpc.capabilities")
    procedure = SimpleNamespace(
        handler_id=PROCEDURE_ID,
        version=1,
        effect="destructive",
        commands=SimpleNamespace(
            all=lambda: [
                SimpleNamespace(
                    sequence=1,
                    **migration._REPRESENTATIVE_COMMAND,
                )
            ]
        ),
    )
    assert (
        capabilities.derive_command_contract_hash(procedure)
        == fixture["sha256"]
    )
    Draft202012Validator.check_schema(runtime["NORMALIZED_PARAMS_SCHEMA"])
    Draft202012Validator.check_schema(runtime["COMMAND_FINGERPRINT_SCHEMA"])
    assert runtime["SSH_HOST_KEY_ALGORITHM"] == "ssh-ed25519"
    assert runtime["SSH_HOST_KEY_ENCODED_MAX_LENGTH"] == 256
    assert runtime["SSH_HOST_KEY_BYTES"] == 32
    assert runtime["HANDLER_BUDGET_SECONDS"] == 1725
    assert runtime["PROCESS_TIMEOUT_SECONDS"] == 1690

    legacy_handler_id = "service.example.legacy"
    procedure.handler_id = legacy_handler_id
    legacy_payload = {
        "handler_id": legacy_handler_id,
        "version": 1,
        "effect": "destructive",
        "commands": runtime["CAPABILITY_COMMAND_CONTRACT"],
    }
    expected_legacy_hash = hashlib.sha256(
        json.dumps(
            legacy_payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    assert capabilities.derive_command_contract_hash(procedure) == expected_legacy_hash

    capabilities_source = (ROOT / "netbox_rpc/capabilities.py").read_text(
        encoding="utf-8"
    )
    assert "allow_redirects=False" in capabilities_source


class _FakeProcedureQuerySet:
    def __init__(self, manager, name):
        self.manager = manager
        self.name = name

    def first(self):
        if self.name not in self.manager.rows:
            return None
        return _FakeProcedureRow(self.manager, self.name)


class _FakeProcedureRow:
    def __init__(self, manager, name):
        self.manager = manager
        self.name = name
        self.enabled = bool(manager.rows[name]["enabled"])

    def delete(self):
        if self.manager.protected_error is not None:
            raise self.manager.protected_error("protected", [])
        self.manager.rows.pop(self.name, None)

    def save(self, *, update_fields):
        assert update_fields == ["enabled"]
        self.manager.rows[self.name]["enabled"] = self.enabled


class _FakeProcedureManager:
    def __init__(self):
        self.rows = {}
        self.commands = None
        self.protected_error = None

    def update_or_create(self, *, name, defaults):
        created = name not in self.rows
        self.rows[name] = dict(defaults)
        return SimpleNamespace(name=name, **defaults), created

    def filter(self, *, name):
        return _FakeProcedureQuerySet(self, name)


class _FakeCommandManager:
    def __init__(self):
        self.rows = {}

    def update_or_create(self, *, procedure, sequence, defaults):
        key = (procedure.name, sequence)
        created = key not in self.rows
        self.rows[key] = dict(defaults)
        return SimpleNamespace(), created


class _FakeRPCProcedure:
    objects = None


class _FakeRPCProcedureCommand:
    objects = None


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
    deletion = types.ModuleType("django.db.models.deletion")
    deletion.ProtectedError = type("ProtectedError", (Exception,), {})
    migrations = types.ModuleType("django.db.migrations")
    migration_exceptions = types.ModuleType("django.db.migrations.exceptions")
    migration_exceptions.IrreversibleError = type(
        "IrreversibleError", (Exception,), {}
    )
    migrations.Migration = type("Migration", (), {})
    migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = migrations
    django_db.models = django_db_models
    django.db = django_db
    for name, module in {
        "netbox": netbox,
        "netbox.plugins": netbox_plugins,
        "django": django,
        "django.db": django_db,
        "django.db.models": django_db_models,
        "django.db.models.deletion": deletion,
        "django.db.migrations": migrations,
        "django.db.migrations.exceptions": migration_exceptions,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
