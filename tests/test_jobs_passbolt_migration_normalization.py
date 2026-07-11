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

MIGRATION_MODULE = "netbox_rpc.migrations.0048_seed_passbolt_migration_procedures"
PROCEDURE_IDS = (
    "services.passbolt.export_secrets",
    "services.passbolt.transfer_secrets",
    "services.passbolt.import_secrets",
    "services.passbolt.cleanup",
)


def test_passbolt_seed_migration_creates_destructive_approval_gated_procedures(
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

    migration._seed_passbolt_procedures(apps, None)
    migration._seed_passbolt_commands(apps, None)

    assert set(procedures.rows) == set(PROCEDURE_IDS)
    for procedure_id in PROCEDURE_IDS:
        row = procedures.rows[procedure_id]
        assert row["handler_id"] == procedure_id
        assert row["effect"] == "destructive"
        assert row["approval_required"] is True
        assert row["params_schema"]["additionalProperties"] is False
        assert "rpc_ssh_host" in row["params_schema"]["required"]
        assert "rpc_ssh_credential_pk" in row["params_schema"]["required"]
        assert row["target_models"] == []
        assert commands.rows[(procedure_id, 1)]["argv"][0] == "backend-orchestrated"

    export_schema = procedures.rows["services.passbolt.export_secrets"]["params_schema"]
    assert export_schema["properties"]["gpg_dir"]["default"] == "/etc/passbolt/gpg"
    assert export_schema["properties"]["jwt_dir"]["default"] == "/etc/passbolt/jwt"
    assert "db_password" not in export_schema["properties"]
    assert "db_password_env" in export_schema["properties"]

    import_schema = procedures.rows["services.passbolt.import_secrets"]["params_schema"]
    assert import_schema["properties"]["cake_bin_path"]["default"].endswith("/bin/cake")

    migration._remove_passbolt_commands(apps, None)
    migration._remove_passbolt_procedures(apps, None)

    assert procedures.rows == {}
    assert commands.rows == {}


def test_passbolt_handlers_are_documented_command_contract_exemptions() -> None:
    spec = importlib.util.spec_from_file_location(
        "command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    for procedure_id in PROCEDURE_IDS:
        assert procedure_id in command_contract.EXEMPT_HANDLER_IDS

    migration = (
        ROOT / "netbox_rpc/migrations/0048_seed_passbolt_migration_procedures.py"
    ).read_text(encoding="utf-8")
    assert "RPCProcedureCommand" in migration
    for procedure_id in PROCEDURE_IDS:
        assert procedure_id in migration


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_passbolt_export_normalization_uses_runtime_params_and_no_secret_value(
    jobs_module,
) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "services.passbolt.export_secrets",
            {
                **_ssh_params(),
                "app_container_name": "passbolt-app-1",
                "db_container_name": "passbolt-db-1",
                "db_name": "passbolt",
                "db_host": "mariadb",
                "db_port": 3306,
                "db_user_env": "MYSQL_USER",
                "db_password_env": "MYSQL_PASSWORD",
                "staging_dir": "/var/tmp/passbolt-migration-156",
            },
        )
    )

    assert normalized["target"] == "passbolt-source"
    assert normalized["rpc_ssh_host"] == "source.example.net"
    assert normalized["app_container_name"] == "passbolt-app-1"
    assert normalized["db_container_name"] == "passbolt-db-1"
    assert normalized["gpg_dir"] == "/etc/passbolt/gpg"
    assert normalized["jwt_dir"] == "/etc/passbolt/jwt"
    assert "super-secret" not in str(normalized)
    assert normalized["command_fingerprint"]["db_password_env"] == "MYSQL_PASSWORD"


def test_passbolt_transfer_normalization_for_host_to_host_rsync(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "services.passbolt.transfer_secrets",
            {
                **_ssh_params(),
                "source_staging_dir": "/var/tmp/passbolt-source",
                "target_host": "10.0.30.121",
                "target_ssh_user": "root",
                "target_ssh_port": 22,
                "target_staging_dir": "/var/tmp/passbolt-target",
            },
        )
    )

    assert normalized["source_staging_dir"] == "/var/tmp/passbolt-source"
    assert normalized["target_host"] == "10.0.30.121"
    assert normalized["target_ssh_user"] == "root"
    assert normalized["target_ssh_port"] == 22


def test_passbolt_import_normalization_defaults_safe_path_fields(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "services.passbolt.import_secrets",
            {
                **_ssh_params(host="10.0.30.121"),
                "staging_dir": "/var/tmp/passbolt-target",
                "db_name": "passbolt",
            },
        )
    )

    assert normalized["gpg_dest_dir"] == "/etc/passbolt/gpg"
    assert normalized["jwt_dest_dir"] == "/etc/passbolt/jwt"
    assert normalized["cake_bin_path"] == "/usr/share/php/passbolt/bin/cake"


def test_passbolt_cleanup_normalization_requires_both_hosts(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "services.passbolt.cleanup",
            {
                **_ssh_params(),
                "source_staging_dir": "/var/tmp/passbolt-source",
                "target_host": "passbolt-target.example.net",
                "target_ssh_user": "ubuntu",
                "target_ssh_port": 2222,
                "target_staging_dir": "/var/tmp/passbolt-target",
            },
        )
    )

    assert normalized["target_host"] == "passbolt-target.example.net"
    assert normalized["target_staging_dir"] == "/var/tmp/passbolt-target"


@pytest.mark.parametrize(
    "procedure_id,params",
    [
        (
            "services.passbolt.export_secrets",
            {
                "app_container_name": "passbolt;rm",
                "db_container_name": "db",
                "db_name": "passbolt",
                "db_host": "mariadb",
                "db_port": 3306,
                "db_user_env": "MYSQL_USER",
                "db_password_env": "MYSQL_PASSWORD",
                "staging_dir": "/var/tmp/passbolt",
            },
        ),
        (
            "services.passbolt.export_secrets",
            {
                "app_container_name": "passbolt",
                "db_container_name": "db",
                "db_name": "passbolt;drop",
                "db_host": "mariadb",
                "db_port": 3306,
                "db_user_env": "MYSQL_USER",
                "db_password_env": "MYSQL_PASSWORD",
                "staging_dir": "/var/tmp/passbolt",
            },
        ),
        (
            "services.passbolt.transfer_secrets",
            {
                "source_staging_dir": "/var/tmp/../secret",
                "target_host": "10.0.30.121",
                "target_ssh_user": "root",
                "target_ssh_port": 22,
                "target_staging_dir": "/var/tmp/passbolt-target",
            },
        ),
        (
            "services.passbolt.import_secrets",
            {
                "staging_dir": "/var/tmp/passbolt",
                "db_name": "passbolt",
                "cake_bin_path": "/usr/share/php/passbolt/bin/cake;id",
            },
        ),
        (
            "services.passbolt.cleanup",
            {
                "source_staging_dir": "/",
                "target_host": "target.example.net",
                "target_ssh_user": "root",
                "target_ssh_port": 22,
                "target_staging_dir": "/var/tmp/passbolt-target",
            },
        ),
        # Regression: a leading `/../` segment must be rejected (it previously
        # bypassed the traversal lookahead and the broad-directory blocklist).
        (
            "services.passbolt.export_secrets",
            {
                "app_container_name": "passbolt",
                "db_container_name": "db",
                "db_name": "passbolt",
                "db_host": "mariadb",
                "db_port": 3306,
                "db_user_env": "MYSQL_USER",
                "db_password_env": "MYSQL_PASSWORD",
                "staging_dir": "/../etc",
            },
        ),
        (
            "services.passbolt.import_secrets",
            {
                "staging_dir": "/var/tmp/passbolt",
                "db_name": "passbolt",
                "gpg_dest_dir": "/../etc/passwd",
            },
        ),
        (
            "services.passbolt.cleanup",
            {
                "source_staging_dir": "/../root/.ssh",
                "target_host": "target.example.net",
                "target_ssh_user": "root",
                "target_ssh_port": 22,
                "target_staging_dir": "/var/tmp/passbolt-target",
            },
        ),
    ],
)
def test_passbolt_normalization_rejects_injection_or_unsafe_paths(
    jobs_module,
    procedure_id: str,
    params: dict[str, object],
) -> None:
    execution = _execution(procedure_id, {**_ssh_params(), **params})

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def _execution(procedure_id: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_id, handler_id=procedure_id),
        params=params,
        target_display="passbolt-source",
        target_model_label="dcim.device",
    )


def _ssh_params(host: str = "source.example.net") -> dict[str, object]:
    return {
        "rpc_ssh_host": host,
        "rpc_ssh_credential_pk": 7,
        "rpc_ssh_port": 22,
        "rpc_ssh_known_hosts_entry": f"{host} ssh-ed25519 AAAA",
        "rpc_ssh_strict_host_key_checking": True,
    }


class _FakeProcedure:
    def __init__(self, name: str, data: dict[str, object]) -> None:
        self.name = name
        self.handler_id = str(data["handler_id"])


class _ProcedureQuery:
    def __init__(
        self, manager: "_FakeProcedureManager", *, names=None, handler_ids=None
    ) -> None:
        self.manager = manager
        self.names = set(names or [])
        self.handler_ids = set(handler_ids or [])

    def __iter__(self):
        for name, row in self.manager.rows.items():
            if self.names and name not in self.names:
                continue
            if self.handler_ids and row["handler_id"] not in self.handler_ids:
                continue
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

    def filter(self, **kwargs):
        if "name" in kwargs:
            return _ProcedureQuery(self, names=[kwargs["name"]])
        if "handler_id" in kwargs:
            return _ProcedureQuery(self, handler_ids=[kwargs["handler_id"]])
        if "handler_id__in" in kwargs:
            return _ProcedureQuery(self, handler_ids=kwargs["handler_id__in"])
        raise AssertionError(kwargs)


class _FakeCommandQuery:
    def __init__(
        self, manager: "_FakeCommandManager", procedures: list[_FakeProcedure]
    ) -> None:
        self.manager = manager
        self.procedures = procedures

    def delete(self) -> None:
        allowed = {procedure.handler_id for procedure in self.procedures}
        for key in list(self.manager.rows):
            if key[0] in allowed:
                self.manager.rows.pop(key, None)


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def update_or_create(
        self, *, procedure: _FakeProcedure, sequence: int, defaults: dict
    ):
        self.rows[(procedure.handler_id, sequence)] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence, **defaults), True

    def filter(self, *, procedure__in):
        return _FakeCommandQuery(self, list(procedure__in))


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_migrations = types.ModuleType("django.db.migrations")

    class Migration:
        pass

    django_migrations.Migration = Migration
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

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig

    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"

    netbox_jobs = types.ModuleType("netbox.jobs")

    class JobRunner:
        @classmethod
        def enqueue(cls, *args, **kwargs):
            return None

    netbox_jobs.JobRunner = JobRunner

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")

    class _RequestException(Exception):
        pass

    class _ConnectionError(_RequestException):
        pass

    requests_exceptions.RequestException = _RequestException
    requests_exceptions.ConnectionError = _ConnectionError
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
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
