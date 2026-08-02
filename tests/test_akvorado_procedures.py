from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = "netbox_rpc.migrations.0057_seed_akvorado_procedures"
PROCEDURE_NAMES = {
    "service.akvorado.1.config_read",
    "service.akvorado.1.config_deploy",
    "service.akvorado.1.deploy_stack",
    "service.akvorado.1.status_stack",
    "service.akvorado.1.restart_stack",
}
TARGET = "akvorado-01.example.net"
ENV_CONTENT_REF = "nms-secret:123e4567-e89b-42d3-a456-426614174000"


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_seed_creates_five_standalone_procedures_and_safe_command_rows(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    executions = _FakeExecutionManager()
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    _FakeRPCExecution.objects = executions
    apps = SimpleNamespace(get_model=_model_lookup)

    migration.seed_akvorado_procedures(apps, None)

    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0056_seed_influxdb_onboarding_procedures")
    ]
    assert set(procedures.rows) == PROCEDURE_NAMES
    assert len(commands.rows) == 5
    for name, procedure in procedures.rows.items():
        assert procedure["handler_id"] == name
        assert procedure["version"] == 1
        assert procedure["enabled"] is True
        assert procedure["target_models"] == [
            "dcim.device",
            "virtualization.virtualmachine",
        ]
        assert procedure["transport_driver"] == "asyncssh"
        assert procedure["transport_driver_chain"] == []
        assert procedure["output_parser"] == "none"
        assert procedure["output_schema"] == {}

        command = commands.rows[(name, 1)]
        assert command["argv"][0] == "backend-orchestrated"
        assert all("content" not in token for token in command["argv"])
        assert all("{" not in token and "}" not in token for token in command["argv"])

    assert procedures.rows["service.akvorado.1.config_read"]["effect"] == "read"
    assert (
        procedures.rows["service.akvorado.1.config_read"]["approval_required"]
        is False
    )
    assert procedures.rows["service.akvorado.1.config_deploy"]["effect"] == "write"
    assert (
        procedures.rows["service.akvorado.1.config_deploy"]["approval_required"]
        is True
    )
    assert procedures.rows["service.akvorado.1.deploy_stack"]["effect"] == "write"
    assert (
        procedures.rows["service.akvorado.1.deploy_stack"]["approval_required"]
        is True
    )
    assert procedures.rows["service.akvorado.1.status_stack"]["effect"] == "read"
    assert (
        procedures.rows["service.akvorado.1.status_stack"]["approval_required"]
        is False
    )
    assert procedures.rows["service.akvorado.1.restart_stack"]["effect"] == "write"
    assert (
        procedures.rows["service.akvorado.1.restart_stack"]["approval_required"]
        is True
    )
    assert {
        name: procedure["timeout_seconds"]
        for name, procedure in procedures.rows.items()
    } == {
        "service.akvorado.1.config_read": 30,
        "service.akvorado.1.config_deploy": 120,
        "service.akvorado.1.deploy_stack": 300,
        "service.akvorado.1.status_stack": 60,
        "service.akvorado.1.restart_stack": 120,
    }

    migration.unseed_akvorado_procedures(apps, None)
    assert procedures.rows == {}


def test_unseed_disables_referenced_procedure_and_deletes_unreferenced(
    migration,
) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    executions = _FakeExecutionManager()
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands
    _FakeRPCExecution.objects = executions
    apps = SimpleNamespace(get_model=_model_lookup)
    migration.seed_akvorado_procedures(apps, None)
    referenced_name = "service.akvorado.1.config_read"
    executions.procedure_ids.add(procedures.pks[referenced_name])

    migration.unseed_akvorado_procedures(apps, None)

    assert set(procedures.rows) == {referenced_name}
    assert procedures.rows[referenced_name]["enabled"] is False


def test_all_akvorado_params_and_result_schemas_accept_valid_documents(
    migration,
) -> None:
    by_name = {row["name"]: row for row in migration.AKVORADO_PROCEDURES}
    valid_params = {
        "service.akvorado.1.config_read": {},
        "service.akvorado.1.config_deploy": {
            "config_content": "inlet:\n  kafka:\n    topic: flows\n",
        },
        "service.akvorado.1.deploy_stack": {
            "compose_content": "services:\n  akvorado:\n    image: akvorado:latest\n",
            "env_content": ENV_CONTENT_REF,
        },
        "service.akvorado.1.status_stack": {},
        "service.akvorado.1.restart_stack": {},
    }
    valid_results = {
        "service.akvorado.1.config_read": {
            "ok": True,
            "procedure": "service.akvorado.1.config_read",
            "target": TARGET,
            "content": "inlet: {}\n",
        },
        "service.akvorado.1.config_deploy": {
            "ok": True,
            "procedure": "service.akvorado.1.config_deploy",
            "target": TARGET,
            "deploy_status": "deployed",
            "validation_output": "configuration is valid",
        },
        "service.akvorado.1.deploy_stack": {
            "ok": True,
            "procedure": "service.akvorado.1.deploy_stack",
            "target": TARGET,
            "deploy_status": "deployed",
            "validation_output": "compose configuration is valid",
        },
        "service.akvorado.1.status_stack": {
            "ok": True,
            "procedure": "service.akvorado.1.status_stack",
            "target": TARGET,
            "status": "running",
            "output": "akvorado running",
        },
        "service.akvorado.1.restart_stack": {
            "ok": True,
            "procedure": "service.akvorado.1.restart_stack",
            "target": TARGET,
            "status": "running",
            "output": "akvorado restarted",
        },
    }

    for name, row in by_name.items():
        Draft202012Validator.check_schema(row["params_schema"])
        Draft202012Validator.check_schema(row["result_schema"])
        validate(valid_params[name], row["params_schema"])
        validate(valid_results[name], row["result_schema"])


@pytest.mark.parametrize(
    ("procedure_name", "params"),
    [
        ("service.akvorado.1.config_read", {"target": TARGET}),
        (
            "service.akvorado.1.config_deploy",
            {"config_content": ""},
        ),
        (
            "service.akvorado.1.config_deploy",
            {"config_content": "valid: true\n", "command": "id"},
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": "services: {}\n",
                "env_content": "PASSWORD=plaintext",
            },
        ),
        ("service.akvorado.1.status_stack", {"target": "host;id"}),
        (
            "service.akvorado.1.restart_stack",
            {"shell": "docker compose restart"},
        ),
    ],
)
def test_akvorado_params_schemas_reject_missing_unsafe_or_extra_input(
    migration,
    procedure_name: str,
    params: dict[str, object],
) -> None:
    by_name = {row["name"]: row for row in migration.AKVORADO_PROCEDURES}

    with pytest.raises(ValidationError):
        validate(params, by_name[procedure_name]["params_schema"])


@pytest.mark.parametrize("procedure_name", sorted(PROCEDURE_NAMES))
def test_akvorado_result_schemas_reject_incomplete_results(
    migration,
    procedure_name: str,
) -> None:
    by_name = {row["name"]: row for row in migration.AKVORADO_PROCEDURES}

    with pytest.raises(ValidationError):
        validate(
            {"ok": True, "procedure": procedure_name, "target": TARGET},
            by_name[procedure_name]["result_schema"],
        )


def test_content_contract_uses_input_data_and_safe_representative_argv(migration) -> None:
    spec = importlib.util.spec_from_file_location(
        "command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    by_name = {row["name"]: row for row in migration.AKVORADO_PROCEDURES}
    for handler_id in PROCEDURE_NAMES:
        assert handler_id in command_contract.EXEMPT_HANDLER_IDS
        command = migration._command(
            handler_id.rsplit(".", 1)[-1].replace("_", "-"), "representative"
        )
        assert all(command_contract.token_is_safe(token) for token in command["argv"])

    deploy = by_name["service.akvorado.1.config_deploy"]["params_schema"]
    stack = by_name["service.akvorado.1.deploy_stack"]["params_schema"]
    assert "input_data" in deploy["properties"]["config_content"]["description"]
    assert "input_data" in stack["properties"]["compose_content"]["description"]
    assert "input_data" in stack["properties"]["env_content"]["description"]
    assert stack["properties"]["env_content"]["pattern"].startswith("^nms-secret:")
    for row in by_name.values():
        assert "target" not in row["params_schema"]["properties"]
        assert "target" not in row["params_schema"]["required"]


@pytest.mark.parametrize(
    ("procedure_name", "field_name", "content"),
    [
        ("service.akvorado.1.config_deploy", "config_content", "valid:\x00false\n"),
        ("service.akvorado.1.config_deploy", "config_content", "password: plaintext\n"),
        (
            "service.akvorado.1.config_deploy",
            "config_content",
            "endpoint: https://user:pass@example.net\n",
        ),
        (
            "service.akvorado.1.deploy_stack",
            "compose_content",
            "services:\n  akvorado:\x00\n",
        ),
        (
            "service.akvorado.1.deploy_stack",
            "compose_content",
            "services:\n  akvorado:\n    api_token: plaintext\n",
        ),
        (
            "service.akvorado.1.deploy_stack",
            "compose_content",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        ),
    ],
)
def test_content_schemas_reject_nul_and_plaintext_secrets(
    migration,
    procedure_name: str,
    field_name: str,
    content: str,
) -> None:
    by_name = {row["name"]: row for row in migration.AKVORADO_PROCEDURES}
    params = {field_name: content}
    if procedure_name.endswith("deploy_stack"):
        params["env_content"] = ENV_CONTENT_REF

    with pytest.raises(ValidationError):
        validate(params, by_name[procedure_name]["params_schema"])


def _model_lookup(app_label: str, model_name: str):
    models = {
        ("netbox_rpc", "RPCProcedure"): _FakeRPCProcedure,
        ("netbox_rpc", "RPCProcedureCommand"): _FakeRPCProcedureCommand,
        ("netbox_rpc", "RPCExecution"): _FakeRPCExecution,
    }
    return models[(app_label, model_name)]


class _FakeQuerySet:
    def __init__(self, manager: _FakeProcedureManager, names: list[str]) -> None:
        self.manager = manager
        self.names = names

    def delete(self) -> None:
        for name in self.names:
            self.manager.rows.pop(name, None)

    def __iter__(self):
        for name in self.names:
            if name in self.manager.rows:
                yield _FakeProcedureRow(
                    manager=self.manager,
                    name=name,
                    pk=self.manager.pks[name],
                )


class _FakeProcedureRow:
    def __init__(self, *, manager: _FakeProcedureManager, name: str, pk: int) -> None:
        self.manager = manager
        self.name = name
        self.pk = pk
        self.enabled = bool(manager.rows[name]["enabled"])

    def save(self, *, update_fields: list[str]) -> None:
        assert update_fields == ["enabled"]
        self.manager.rows[self.name]["enabled"] = self.enabled

    def delete(self) -> None:
        self.manager.rows.pop(self.name, None)


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.pks: dict[str, int] = {}

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.rows[name] = dict(defaults)
        self.pks.setdefault(name, len(self.pks) + 1)
        return SimpleNamespace(name=name, pk=self.pks[name], **defaults), True

    def filter(self, *, name__in: list[str]) -> _FakeQuerySet:
        return _FakeQuerySet(self, name__in)


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def update_or_create(
        self,
        *,
        procedure: SimpleNamespace,
        sequence: int,
        defaults: dict[str, object],
    ):
        self.rows[(procedure.name, sequence)] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence, **defaults), True


class _FakeExecutionQuerySet:
    def __init__(self, exists: bool) -> None:
        self._exists = exists

    def exists(self) -> bool:
        return self._exists


class _FakeExecutionManager:
    def __init__(self) -> None:
        self.procedure_ids: set[int] = set()

    def filter(self, *, procedure_id: int) -> _FakeExecutionQuerySet:
        return _FakeExecutionQuerySet(procedure_id in self.procedure_ids)


class _FakeRPCProcedure:
    objects: _FakeProcedureManager


class _FakeRPCProcedureCommand:
    objects: _FakeCommandManager


class _FakeRPCExecution:
    objects: _FakeExecutionManager


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")

    class RunPython:
        noop = staticmethod(lambda apps, schema_editor: None)

        def __init__(self, code, reverse_code=None) -> None:
            self.code = code
            self.reverse_code = reverse_code

    django_db.migrations = SimpleNamespace(
        Migration=object,
        RunPython=RunPython,
    )
    django.db = django_db

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
