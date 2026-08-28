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
MIGRATION_MODULE = "netbox_rpc.migrations.0073_seed_gitea_production_upgrade_1271"
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


def test_gitea_upgrade_migration_is_inline_owned_and_explicitly_irreversible(
    migration,
) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0072_seed_influxdb3_debian13_install_procedures")
    ]
    source = (
        ROOT / "netbox_rpc/migrations/0073_seed_gitea_production_upgrade_1271.py"
    ).read_text(encoding="utf-8")
    assert "from netbox_rpc" not in source
    assert OFFICIAL_SHA256 in source

    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    execution_references = _FakeReferenceManager()
    intent_references = _FakeReferenceManager()
    approval_references = _FakeReferenceManager()
    generic_references = [_FakeGenericReferenceManager() for _ in range(4)]
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    _FakeRPCExecution.objects = execution_references
    _FakeRPCIntentProcedure.objects = intent_references
    _FakeRPCApprovalRequest.objects = approval_references
    (
        _FakeTaggedItem.objects,
        _FakeBookmark.objects,
        _FakeSubscription.objects,
        _FakeJournalEntry.objects,
    ) = generic_references
    apps = _fake_apps()
    migration.seed_gitea_production_upgrade(apps, None)
    assert procedures.rows == {PROCEDURE_ID: migration._PROCEDURE_DEFAULTS}
    assert commands.rows == {(PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND}
    with pytest.raises(RuntimeError, match="canonical name already exists"):
        migration.seed_gitea_production_upgrade(apps, None)
    assert procedures.rows == {PROCEDURE_ID: migration._PROCEDURE_DEFAULTS}
    assert commands.rows == {(PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND}

    execution_references.referenced_procedure_ids.add(170)
    with pytest.raises(migration.IrreversibleError, match="intentionally irreversible"):
        migration.unseed_gitea_production_upgrade(apps, _FakeSchemaEditor(procedures, commands))
    assert procedures.rows[PROCEDURE_ID]["enabled"] is False
    assert commands.rows == {(PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND}

    execution_references.referenced_procedure_ids.clear()
    _FakeTaggedItem.objects.referenced_pairs.add((700, 170))
    with pytest.raises(migration.IrreversibleError, match="intentionally irreversible"):
        migration.unseed_gitea_production_upgrade(
            apps,
            _FakeSchemaEditor(procedures, commands),
        )
    _FakeTaggedItem.objects.referenced_pairs.clear()

    schema_editor = _FakeSchemaEditor(procedures, commands)
    with pytest.raises(migration.IrreversibleError, match="intentionally irreversible"):
        migration.unseed_gitea_production_upgrade(apps, schema_editor)
    assert procedures.rows == {PROCEDURE_ID: migration._PROCEDURE_DEFAULTS}
    assert commands.rows == {(PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND}
    assert schema_editor.queries == []


def test_gitea_upgrade_seed_never_adopts_operator_owned_rows(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.rows[PROCEDURE_ID] = {
        "enabled": True,
        "handler_id": "operator-owned-handler",
        "description": "Preserve operator data.",
    }
    commands.rows[(PROCEDURE_ID, 7)] = {
        "argv": ["operator-owned", "command"],
    }
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands

    before_procedures = {
        name: dict(row) for name, row in procedures.rows.items()
    }
    before_commands = {key: dict(row) for key, row in commands.rows.items()}
    with pytest.raises(RuntimeError, match="canonical name already exists"):
        migration.seed_gitea_production_upgrade(_fake_apps(), None)

    assert procedures.rows == before_procedures
    assert commands.rows == before_commands


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
    assert runtime["SEMANTIC_CAPABILITY_EXTENSION"]["backend"] == {
        "backend_id": 1,
        "base_url": "http://127.0.0.1:16005",
        "verify_ssl": False,
    }
    assert runtime["SEMANTIC_CAPABILITY_SHA256"] == runtime[
        "canonical_sha256"
    ](runtime["SEMANTIC_CAPABILITY_EXTENSION"])
    assert runtime["PROCEDURE_POLICY"]["semantic_contract_sha256"] == runtime[
        "SEMANTIC_CAPABILITY_SHA256"
    ]
    assert runtime["SEMANTIC_CAPABILITY_EXTENSION"]["executable"] == {
        "version": 1,
        "canonicalization": "json-sort-keys-compact-utf8",
        "script_length_bytes": 68_394,
        "script_sha256": (
            "7e6fdacd945f038e06eb0c4f12752b72c702bfde984ff47a89cce2d68fffad41"
        ),
        "argv_length_bytes": 72_240,
        "argv_sha256": (
            "cc41baaa641673a191a4163595cacecb9df5d2233edbdb385cfec741b6ffb2d0"
        ),
    }
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

    def exists(self):
        return self.name in self.manager.rows


class _FakeProcedureRow:
    def __init__(self, manager, name):
        self.manager = manager
        self.name = name
        self.pk = 170
        self.enabled = bool(manager.rows[name]["enabled"])

    def save(self, *, update_fields):
        assert update_fields == ["enabled"]
        self.manager.rows[self.name]["enabled"] = self.enabled


class _FakeProcedureManager:
    def __init__(self):
        self.rows = {}
        self.commands = None

    def create(self, *, name, **values):
        assert name not in self.rows
        self.rows[name] = dict(values)
        return SimpleNamespace(pk=170, name=name, **values)

    def filter(self, *, name):
        return _FakeProcedureQuerySet(self, name)


class _FakeCommandManager:
    def __init__(self):
        self.rows = {}

    def create(self, *, procedure, sequence, **values):
        key = (procedure.name, sequence)
        assert key not in self.rows
        self.rows[key] = dict(values)
        return SimpleNamespace()

    def filter(self, *, procedure_id):
        values = [171] if procedure_id == 170 and self.rows else []
        return _FakeValuesQuerySet(values)


class _FakeRPCProcedure:
    objects = None
    _meta = SimpleNamespace(
        db_table="netbox_rpc_rpcprocedure",
        pk=SimpleNamespace(column="id"),
    )


class _FakeRPCProcedureCommand:
    objects = None
    _meta = SimpleNamespace(
        db_table="netbox_rpc_rpcprocedurecommand",
        get_field=lambda name: SimpleNamespace(column=f"{name}_id"),
    )


class _FakeReferenceQuerySet:
    def __init__(self, exists):
        self._exists = exists

    def exists(self):
        return self._exists


class _FakeReferenceManager:
    def __init__(self):
        self.referenced_procedure_ids = set()

    def filter(self, *, procedure_id):
        return _FakeReferenceQuerySet(
            procedure_id in self.referenced_procedure_ids
        )


class _FakeValuesQuerySet:
    def __init__(self, values):
        self.values = values

    def values_list(self, field, *, flat):
        assert field == "pk"
        assert flat is True
        return self

    def first(self):
        return self.values[0] if self.values else None

    def __iter__(self):
        return iter(self.values)


class _FakeContentTypeManager:
    ids = {
        "rpcprocedure": 700,
        "rpcprocedurecommand": 701,
    }

    def filter(self, *, app_label, model):
        assert app_label == "netbox_rpc"
        value = self.ids.get(model)
        return _FakeValuesQuerySet([] if value is None else [value])


class _FakeGenericReferenceManager:
    def __init__(self):
        self.referenced_pairs = set()

    def filter(self, **criteria):
        content_type_id = next(
            value
            for key, value in criteria.items()
            if key.endswith("type_id")
        )
        object_ids = next(
            value
            for key, value in criteria.items()
            if key.endswith("object_id__in")
        )
        return _FakeReferenceQuerySet(
            any(
                (content_type_id, object_id) in self.referenced_pairs
                for object_id in object_ids
            )
        )


class _FakeRPCExecution:
    objects = None


class _FakeRPCIntentProcedure:
    objects = None


class _FakeRPCApprovalRequest:
    objects = None


class _FakeContentType:
    objects = _FakeContentTypeManager()


class _FakeTaggedItem:
    objects = None


class _FakeBookmark:
    objects = None


class _FakeSubscription:
    objects = None


class _FakeJournalEntry:
    objects = None


class _FakeCursor:
    def __init__(self, schema_editor):
        self.schema_editor = schema_editor
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, query, params):
        params = list(params)
        self.schema_editor.queries.append((query, params))
        if "rpcprocedurecommand" in query:
            procedure_names = {
                name
                for name, row in self.schema_editor.procedures.rows.items()
                if params == [170] and row is not None
            }
            for key in tuple(self.schema_editor.commands.rows):
                if key[0] in procedure_names:
                    self.schema_editor.commands.rows.pop(key)
            self.rowcount = len(procedure_names)
            return
        deleted = int(PROCEDURE_ID in self.schema_editor.procedures.rows)
        self.schema_editor.procedures.rows.pop(PROCEDURE_ID, None)
        self.rowcount = deleted


class _FakeSchemaEditor:
    def __init__(self, procedures, commands):
        self.procedures = procedures
        self.commands = commands
        self.queries = []
        self.connection = SimpleNamespace(cursor=lambda: _FakeCursor(self))

    @staticmethod
    def quote_name(name):
        return f'"{name}"'


def _fake_apps():
    models = {
        ("netbox_rpc", "RPCProcedure"): _FakeRPCProcedure,
        ("netbox_rpc", "RPCProcedureCommand"): _FakeRPCProcedureCommand,
        ("netbox_rpc", "RPCExecution"): _FakeRPCExecution,
        ("netbox_rpc", "RPCIntentProcedure"): _FakeRPCIntentProcedure,
        ("netbox_rpc", "RPCApprovalRequest"): _FakeRPCApprovalRequest,
        ("contenttypes", "ContentType"): _FakeContentType,
        ("extras", "TaggedItem"): _FakeTaggedItem,
        ("extras", "Bookmark"): _FakeBookmark,
        ("extras", "Subscription"): _FakeSubscription,
        ("extras", "JournalEntry"): _FakeJournalEntry,
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
