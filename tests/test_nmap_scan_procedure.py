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

MIGRATION_MODULE = "netbox_rpc.migrations.0045_seed_nmap_scan_procedure"
PROCEDURE_NAME = "nmap-scan"
HANDLER_ID = "os.linux.nmap.scan"


def test_nmap_scan_seed_migration_creates_and_removes_procedure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    migration = importlib.import_module(MIGRATION_MODULE)
    manager = _FakeProcedureManager()
    apps = SimpleNamespace(
        get_model=lambda app_label, model_name: _FakeRPCProcedure
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure")
        else None
    )
    _FakeRPCProcedure.objects = manager

    migration._seed_nmap_scan_procedure(apps, None)

    procedure = manager.rows[PROCEDURE_NAME]
    assert procedure["handler_id"] == HANDLER_ID
    assert procedure["effect"] == "read"
    assert procedure["approval_required"] is False
    assert procedure["timeout_seconds"] == 120
    assert procedure["target_models"] == [
        "ipam.ipaddress",
        "dcim.device",
        "virtualization.virtualmachine",
    ]
    assert procedure["params_schema"]["required"] == ["target"]
    assert procedure["params_schema"]["additionalProperties"] is False
    assert procedure["params_schema"]["properties"]["scan_type"]["enum"] == [
        "connect",
        "syn",
        "os-detect",
    ]
    assert "oneOf" in procedure["params_schema"]["properties"]["ports"]
    assert procedure["result_schema"] == {
        "type": "object",
        "additionalProperties": False,
        "required": ["status", "findings", "details"],
        "properties": {
            "status": {
                "type": "string",
                "enum": ["ok", "warning", "error", "unknown"],
            },
            "findings": {
                "type": "array",
                "items": {"type": "string"},
            },
            "details": {
                "type": "object",
                "additionalProperties": False,
                "required": ["host_state", "os_guess", "open_ports"],
                "properties": {
                    "host_state": {"type": "string"},
                    "os_guess": {"type": "string"},
                    "open_ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["port", "protocol", "service", "state"],
                            "properties": {
                                "port": {"type": "integer"},
                                "protocol": {"type": "string"},
                                "service": {"type": "string"},
                                "state": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
    }

    migration._remove_nmap_scan_procedure(apps, None)

    assert PROCEDURE_NAME not in manager.rows


def test_nmap_scan_uses_fixed_argv_without_command_contract_exemption() -> None:
    spec = importlib.util.spec_from_file_location(
        "command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    assert HANDLER_ID not in command_contract.EXEMPT_HANDLER_IDS
    for token in ("nmap", "-oX", "-", "-sT", "-sS", "-O", "-p", "{target}"):
        assert command_contract.token_is_safe(token)
        assert command_contract.token_has_balanced_placeholders(token)


@pytest.mark.parametrize("target", ["198.51.100.10", "198.51.100.0/24"])
def test_nmap_scan_normalizes_valid_ip_and_cidr(
    jobs_module,
    target: str,
) -> None:
    execution = _execution(
        {
            "target": target,
            "ports": [22, 443],
            "scan_type": "syn",
            "rpc_ssh_host": "scanner.example.net",
            "rpc_ssh_credential_pk": 7,
        }
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == target
    assert normalized["ports"] == "22,443"
    assert normalized["scan_type"] == "syn"
    assert normalized["rpc_ssh_host"] == "scanner.example.net"
    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["command_fingerprint"] == {
        "handler_id": HANDLER_ID,
        "procedure": PROCEDURE_NAME,
        "target": target,
        "scan_type": "syn",
        "ports": "22,443",
        "rpc_ssh_credential_pk": 7,
        "rpc_ssh_host": "scanner.example.net",
    }


def test_nmap_scan_normalizes_safe_hostname_and_port_string(jobs_module) -> None:
    execution = _execution(
        {
            "target": "Host-01.Example.NET",
            "ports": "22,80,443,1000-1010",
        }
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "host-01.example.net"
    assert normalized["ports"] == "22,80,443,1000-1010"
    assert normalized["scan_type"] == "connect"


@pytest.mark.parametrize(
    "params",
    [
        {"target": "198.51.100.10;id"},
        {"target": "198.51.100.1/24"},
        {"target": "0.0.0.0/0"},
        {"target": "10.0.0.0/8"},
        {"target": "192.168.0.0/16"},
        {"target": "scanner_name.example.net"},
        {"target": "scan.example.net", "scan_type": "udp"},
        {"target": "scan.example.net", "ports": "22,443;id"},
        {"target": "scan.example.net", "ports": [22, 0]},
        {"target": "scan.example.net", "ports": list(range(1, 34))},
    ],
)
def test_nmap_scan_rejects_unsafe_params(jobs_module, params: dict) -> None:
    execution = _execution(params)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def _execution(params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=PROCEDURE_NAME, handler_id=HANDLER_ID),
        params=params,
        target_display="scanner-01",
        target_model_label="dcim.device",
    )


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


class _FakeQuerySet:
    def __init__(self, manager: _FakeProcedureManager, name: str) -> None:
        self.manager = manager
        self.name = name

    def delete(self) -> None:
        self.manager.rows.pop(self.name, None)


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.rows[name] = dict(defaults)
        return SimpleNamespace(name=name, **defaults), True

    def filter(self, *, name: str) -> _FakeQuerySet:
        return _FakeQuerySet(self, name)


class _FakeRPCProcedure:
    objects: _FakeProcedureManager


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
    netbox_rpc_models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)

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

    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
