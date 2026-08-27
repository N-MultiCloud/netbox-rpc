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
DNS_MIGRATION_MODULE = "netbox_rpc.migrations.0082_seed_dns_staging_deploy"
DNS_PROCEDURE_ID = "service.netbox.staging.deploy_dns_pair"
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


@pytest.fixture()
def dns_migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(DNS_MIGRATION_MODULE, None)
    module = importlib.import_module(DNS_MIGRATION_MODULE)
    yield module
    sys.modules.pop(DNS_MIGRATION_MODULE, None)


def test_dns_staging_deploy_policy_migration_matches_runtime_contract(
    dns_migration,
) -> None:
    defaults = dns_migration._PROCEDURE_DEFAULTS
    runtime = runpy.run_path(str(ROOT / "netbox_rpc/dns_staging_deploy_contract.py"))

    assert defaults == {
        "handler_id": DNS_PROCEDURE_ID,
        "version": 1,
        "enabled": True,
        "target_models": ["dcim.device"],
        "effect": "destructive",
        "timeout_seconds": 2700,
        "approval_required": True,
        "params_schema": runtime["PARAMS_SCHEMA"],
        "result_schema": runtime["RESULT_SCHEMA"],
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "transport_pinned": True,
        "output_parser": "none",
        "output_schema": {},
        "description": defaults["description"],
    }
    assert runtime["COMMAND_CONTRACT"] == [
        {"sequence": 1, **dns_migration._REPRESENTATIVE_COMMAND}
    ]
    assert (
        runtime["PROCEDURE_POLICY"]["semantic_contract_sha256"]
        == runtime["SEMANTIC_CAPABILITY_SHA256"]
    )
    assert (
        runtime["SEMANTIC_CAPABILITY_SHA256"]
        == "ec137f258aab79cf992ea95b98dbcf93054e9431a57755cad5fd67529a6e013c"
    )
    assert (
        runtime["COMMAND_CONTRACT_SHA256"]
        == "d3a41e414f0e839cc8ae52e5a5064fd2c1816fb4da1f26916ef134e21f042836"
    )
    assert (
        runtime["PROCESS_TIMEOUT_SECONDS"]
        < runtime["HANDLER_BUDGET_SECONDS"]
        < runtime["ROUTE_BUDGET_SECONDS"]
        < defaults["timeout_seconds"]
    )


def test_dns_staging_deploy_accepts_only_one_exact_lowercase_commit(
    dns_migration,
) -> None:
    schema = dns_migration._PARAMS_SCHEMA
    validate({"commit_sha": "a" * 40}, schema)

    for invalid in (
        {},
        {"commit_sha": "a" * 39},
        {"commit_sha": "A" * 40},
        {"commit_sha": "a" * 40 + "\n"},
        {"commit_sha": "a" * 40, "rpc_ssh_host": "attacker.invalid"},
        {"commit_sha": "a" * 40, "provider": "godaddy"},
        {"commit_sha": "a" * 40, "token": "must-not-enter-rpc"},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, schema)


def test_dns_staging_deploy_result_has_only_three_closed_states(
    dns_migration,
) -> None:
    schema = dns_migration._RESULT_SCHEMA
    base = {
        "procedure": DNS_PROCEDURE_ID,
        "target": "nms-front-door",
        "commit_sha": "a" * 40,
    }
    for state in (
        {**base, "ok": True, "deployed": True, "stage": "complete"},
        {**base, "ok": False, "deployed": False, "stage": "execute"},
        {**base, "ok": False, "deployed": None, "stage": "indeterminate"},
    ):
        validate(state, schema)
    for invalid in (
        {**base, "ok": False, "deployed": False, "stage": "complete"},
        {**base, "ok": False, "deployed": True, "stage": "complete"},
        {**base, "ok": False, "deployed": None, "stage": "execute"},
        {**base, "ok": True, "deployed": True, "stage": "complete", "output": "x"},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, schema)


def test_dns_staging_deploy_seed_refuses_adoption_and_is_irreversible(
    dns_migration,
) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    apps = _fake_apps()

    dns_migration.seed_dns_staging_deploy(apps, None)
    with pytest.raises(RuntimeError):
        dns_migration.seed_dns_staging_deploy(apps, None)
    with pytest.raises(
        dns_migration.IrreversibleError,
        match="intentionally irreversible",
    ):
        dns_migration.unseed_dns_staging_deploy(apps, None)

    assert procedures.rows[DNS_PROCEDURE_ID]["transport_pinned"] is True
    assert commands.rows[(DNS_PROCEDURE_ID, 1)]["argv"] == [
        "backend-orchestrated",
        "netbox-staging-deploy-dns-pair",
    ]


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


def test_staging_rotation_reverse_disables_instead_of_deleting(migration) -> None:
    """The reverse must never invoke Django's deletion collector.

    ``RPCProcedure`` has inbound FKs, so ``Model.delete()`` walks related models
    and can raise ``ValueError`` when a related app has no migrations — aborting
    the downgrade. ``queryset.update()`` touches one table and cannot.
    """

    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    apps = _fake_apps()
    migration.seed_staging_backend_token_rotation(apps, None)

    migration.unseed_staging_backend_token_rotation(apps, None)

    # The audited row survives, disabled — history is never destroyed.
    assert procedures.rows[PROCEDURE_ID]["enabled"] is False
    # A table-level UPDATE ran...
    assert procedures.update_queryset_calls == 1
    # ...and the deletion collector was never entered. Reverting the fix to
    # ``procedure.delete()`` makes this assertion fail.
    assert procedures.delete_calls == 0
    # Nothing cascaded away.
    assert commands.rows == {
        (PROCEDURE_ID, 1): migration._REPRESENTATIVE_COMMAND,
    }


def test_staging_rotation_reverse_is_safe_when_the_seed_is_absent(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    procedures.commands = commands
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    apps = _fake_apps()

    migration.unseed_staging_backend_token_rotation(apps, None)

    assert procedures.rows == {}
    assert procedures.delete_calls == 0


def test_staging_rotation_reverse_source_uses_no_deletion_path(migration) -> None:
    """Static guard: the reverse body must not reach for delete/ProtectedError.

    The fake-manager assertions above prove behaviour; this proves intent, and
    catches a reintroduced ``except ProtectedError`` guard that would silently
    re-open the ``ValueError`` hole it cannot catch.
    """

    source = (
        ROOT / "netbox_rpc/migrations/0068_seed_staging_backend_token_rotation.py"
    ).read_text(encoding="utf-8")
    body = source.split("def unseed_staging_backend_token_rotation", 1)[1].split(
        "class Migration", 1
    )[0]
    code = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith(("#", ">"))
    )
    # Strip the explanatory docstring, which names both terms deliberately.
    code = code.split('"""')[0] + code.split('"""')[-1]

    assert ".delete(" not in code
    assert "ProtectedError" not in code
    assert ".update(" in code
    assert "from django.db.models.deletion import ProtectedError" not in source


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

    def exists(self) -> bool:
        return self.name in self.manager.rows

    def update(self, **fields: object) -> int:
        """Table-level update: never walks relations, never touches commands."""

        self.manager.update_queryset_calls += 1
        if self.name not in self.manager.rows:
            return 0
        self.manager.rows[self.name].update(fields)
        return 1


class _FakeProcedureRow:
    def __init__(self, manager: _FakeProcedureManager, name: str) -> None:
        self.manager = manager
        self.name = name
        self.enabled = bool(manager.rows[name]["enabled"])

    def delete(self) -> None:
        # Records the deletion-collector path so a regression back to
        # ``Model.delete()`` in the reverse is detectable, not silent.
        self.manager.delete_calls += 1
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
        self.update_queryset_calls = 0
        self.delete_calls = 0
        self.commands: _FakeCommandManager | None = None
        self.protected_error: type[Exception] | None = None

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.update_calls += 1
        created = name not in self.rows
        self.rows[name] = dict(defaults)
        return SimpleNamespace(name=name, **defaults), created

    def create(self, *, name: str, **defaults: object):
        if name in self.rows:
            raise AssertionError("duplicate fake procedure")
        self.rows[name] = dict(defaults)
        return SimpleNamespace(name=name, **defaults)

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

    def create(self, *, procedure, sequence: int, **defaults: object):
        key = (procedure.name, sequence)
        if key in self.rows:
            raise AssertionError("duplicate fake command")
        self.rows[key] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence, **defaults)


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
    django_db_models_deletion.ProtectedError = type("ProtectedError", (Exception,), {})
    django_migrations = types.ModuleType("django.db.migrations")
    django_migration_exceptions = types.ModuleType("django.db.migrations.exceptions")
    django_migration_exceptions.IrreversibleError = type(
        "IrreversibleError", (RuntimeError,), {}
    )
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
    monkeypatch.setitem(
        sys.modules,
        "django.db.migrations.exceptions",
        django_migration_exceptions,
    )
