"""Contract tests for the typed InfluxDB OSS 2 / Core 3 RPC catalog."""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MIGRATION_MODULE = "netbox_rpc.migrations.0055_seed_influxdb_management_procedures"
PROCEDURE_NAMES = (
    "service.influxdb.1.inspect",
    "service.influxdb.1.config_read",
    "service.influxdb.1.files_list",
    "service.influxdb.1.file_read",
    "service.influxdb.1.service_status",
    "service.influxdb.1.health",
    "service.influxdb.1.journal",
    "service.influxdb.1.config_deploy",
    "service.influxdb.1.config_rollback",
    "service.influxdb.1.file_write",
    "service.influxdb.1.file_delete",
    "service.influxdb.1.service_control",
)
MUTATION_NAMES = frozenset(PROCEDURE_NAMES[7:])


def test_seed_creates_typed_approval_gated_influxdb_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    migration = importlib.import_module(MIGRATION_MODULE)
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()

    def get_model(app_label: str, model_name: str):
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure"):
            return SimpleNamespace(objects=procedures)
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedureCommand"):
            return SimpleNamespace(objects=commands)
        raise AssertionError((app_label, model_name))

    apps = SimpleNamespace(get_model=get_model)
    migration._seed(apps, None)

    assert set(procedures.rows) == set(PROCEDURE_NAMES)
    assert len(commands.rows) == len(PROCEDURE_NAMES)
    for name in PROCEDURE_NAMES:
        row = procedures.rows[name]
        assert row["version"] == 1
        assert row["enabled"] is True
        assert row["target_models"] == [
            "virtualization.virtualmachine",
            "dcim.device",
        ]
        assert row["params_schema"]["additionalProperties"] is False
        assert row["approval_required"] is (name in MUTATION_NAMES)
        expected_effect = (
            "destructive"
            if name.endswith(("config_rollback", "file_delete"))
            else "write"
            if name in MUTATION_NAMES
            else "read"
        )
        assert row["effect"] == expected_effect
        command = commands.rows[(row["handler_id"], 1)]
        assert command["argv"][0] == "backend-orchestrated"
        assert "_" not in command["argv"][1]

    deploy_schema = procedures.rows["service.influxdb.1.config_deploy"]["params_schema"]
    assert deploy_schema["properties"]["config_content"]["maxLength"] == 1024 * 1024
    assert "token" in str(
        procedures.rows["service.influxdb.1.file_write"]["params_schema"]
    )

    migration._remove(apps, None)
    assert procedures.rows == {}


def test_handlers_are_documented_command_contract_exemptions() -> None:
    spec = importlib.util.spec_from_file_location(
        "command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    for name in PROCEDURE_NAMES:
        handler_id = name.replace("service.influxdb.1.", "service.influxdb_1.")
        assert handler_id in command_contract.EXEMPT_HANDLER_IDS


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_file_write_normalizes_content_by_digest_not_plaintext(jobs_module) -> None:
    content = "# NMS managed\nquery-file-directory = '/srv/influxdb/queries'\n"
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.influxdb.1.file_write",
            {
                "family": "core3",
                "scope": "plugins",
                "relative_path": "processing/normalize.py",
                "content": content,
                "mode": "0644",
                **_ssh_params(),
            },
        )
    )

    assert normalized["content"] == content
    assert normalized["family"] == "core3"
    assert normalized["scope"] == "plugins"
    assert normalized["relative_path"] == "processing/normalize.py"
    assert normalized["mode"] == "0644"
    assert normalized["rpc_ssh_host"] == "influx01.example.net"
    fingerprint = normalized["command_fingerprint"]
    assert content not in str(fingerprint)
    assert fingerprint["content_bytes"] == len(content.encode("utf-8"))
    assert len(fingerprint["content_sha256"]) == 64


def test_inspect_and_journal_have_safe_defaults(jobs_module) -> None:
    inspect = jobs_module.normalize_execution_params(
        _execution("service.influxdb.1.inspect", {})
    )
    journal = jobs_module.normalize_execution_params(
        _execution("service.influxdb.1.journal", {"family": "oss2"})
    )

    assert "family" not in inspect
    assert journal["lines"] == 100
    assert journal["command_fingerprint"]["lines"] == 100


@pytest.mark.parametrize(
    "procedure_name,params,error_code",
    [
        (
            "service.influxdb.1.file_read",
            {"family": "oss2", "scope": "plugins", "relative_path": "task.py"},
            "RPC_PARAM_INVALID",
        ),
        (
            "service.influxdb.1.file_read",
            {"family": "core3", "scope": "managed", "relative_path": "../etc/a.toml"},
            "RPC_PARAM_INVALID",
        ),
        (
            "service.influxdb.1.file_read",
            {"family": "core3", "scope": "managed", "relative_path": "api-token.toml"},
            "RPC_PARAM_INVALID",
        ),
        (
            "service.influxdb.1.config_deploy",
            {"family": "oss2", "config_content": 'operator-token = "short"'},
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.influxdb.1.config_deploy",
            {"family": "core3", "config_content": "-----BEGIN PRIVATE KEY-----"},
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.influxdb.1.config_rollback",
            {"family": "core3", "snapshot_id": "../../etc/passwd"},
            "RPC_PARAM_INVALID",
        ),
        (
            "service.influxdb.1.service_control",
            {"family": "core3", "action": "daemon-reload"},
            "RPC_PARAM_INVALID",
        ),
    ],
)
def test_normalization_rejects_unsafe_inputs(
    jobs_module,
    procedure_name: str,
    params: dict[str, object],
    error_code: str,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution(procedure_name, params))

    assert exc_info.value.code == error_code


def _execution(procedure_name: str, params: dict[str, object]):
    handler_id = procedure_name.replace("service.influxdb.1.", "service.influxdb_1.")
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=handler_id),
        params=params,
        target_display="influx01",
        target_model_label="virtualization.virtualmachine",
    )


def _ssh_params() -> dict[str, object]:
    return {
        "rpc_ssh_host": "influx01.example.net",
        "rpc_ssh_credential_pk": 17,
        "rpc_ssh_port": 22,
        "rpc_ssh_known_hosts_entry": "influx01.example.net ssh-ed25519 AAAA",
        "rpc_ssh_strict_host_key_checking": True,
    }


class _FakeProcedure:
    def __init__(self, name: str, data: dict[str, object]) -> None:
        self.name = name
        self.handler_id = str(data["handler_id"])


class _ProcedureQuery:
    def __init__(self, manager: "_FakeProcedureManager", names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def __iter__(self):
        for name, row in self.manager.rows.items():
            if name in self.names:
                yield _FakeProcedure(name, row)

    def delete(self) -> None:
        for procedure in list(self):
            self.manager.rows.pop(procedure.name, None)


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.rows[name] = dict(defaults)
        return _FakeProcedure(name, self.rows[name]), True

    def filter(self, *, name__in):
        return _ProcedureQuery(self, set(name__in))


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def update_or_create(
        self, *, procedure: _FakeProcedure, sequence: int, defaults: dict
    ):
        self.rows[(procedure.handler_id, sequence)] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence, **defaults), True


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})

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
