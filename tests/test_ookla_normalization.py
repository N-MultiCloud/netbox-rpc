from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OOKLA_PROCEDURES = (
    "os.linux.ubuntu.24.ookla.diagnose",
    "os.linux.ubuntu.24.ookla.check_service",
    "os.linux.ubuntu.24.ookla.check_listeners",
    "os.linux.ubuntu.24.ookla.check_tls",
    "os.linux.ubuntu.24.ookla.check_firewall",
)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.mark.parametrize("procedure_name", OOKLA_PROCEDURES)
def test_ookla_procedures_normalize_for_a_registered_device(
    jobs_module,
    procedure_name: str,
) -> None:
    execution = _execution(procedure_name, procedure_name, {})

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "speedtest-01"
    assert normalized["command_fingerprint"]["handler_id"] == procedure_name
    assert normalized["command_fingerprint"]["procedure"] == procedure_name
    # Device-targeted: SSH resolves from the DeviceService, no override keys.
    assert "rpc_ssh_host" not in normalized
    assert "rpc_ssh_credential_pk" not in normalized


def test_ookla_normalizes_ad_hoc_ssh_overrides(jobs_module) -> None:
    execution = _execution(
        "os.linux.ubuntu.24.ookla.diagnose",
        "os.linux.ubuntu.24.ookla.diagnose",
        {
            "rpc_ssh_host": "203.0.113.10",
            "rpc_ssh_port": 2222,
            "rpc_ssh_credential_pk": 77,
            "rpc_ssh_strict_host_key_checking": False,
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_host"] == "203.0.113.10"
    assert normalized["rpc_ssh_port"] == 2222
    assert normalized["rpc_ssh_credential_pk"] == 77
    assert normalized["rpc_ssh_strict_host_key_checking"] is False
    assert normalized["command_fingerprint"]["rpc_ssh_host"] == "203.0.113.10"
    assert normalized["command_fingerprint"]["rpc_ssh_credential_pk"] == 77


def test_ookla_echoes_validated_hints(jobs_module) -> None:
    execution = _execution(
        "os.linux.ubuntu.24.ookla.check_service",
        "os.linux.ubuntu.24.ookla.check_service",
        {
            "install_dir": "/opt/ookla",
            "config_path": "/opt/ookla/OoklaServer.properties",
            "ports": [5060, 8080, 8443],
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["install_dir"] == "/opt/ookla"
    assert normalized["config_path"] == "/opt/ookla/OoklaServer.properties"
    assert normalized["ports"] == [5060, 8080, 8443]
    assert normalized["command_fingerprint"]["ports"] == [5060, 8080, 8443]


@pytest.mark.parametrize(
    "params",
    [
        {"install_dir": "relative/path"},
        {"config_path": "../etc/passwd"},
        {"ports": [0]},
        {"ports": [70000]},
        {"ports": list(range(1, 20))},
        {"ports": "8080"},
    ],
)
def test_ookla_rejects_invalid_hints(jobs_module, params: dict) -> None:
    execution = _execution(
        "os.linux.ubuntu.24.ookla.diagnose",
        "os.linux.ubuntu.24.ookla.diagnose",
        params,
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_ookla_procedure_catalog_shape(jobs_module) -> None:
    from netbox_rpc import constants

    catalog = {p["name"]: p for p in constants.OOKLA_DIAGNOSTIC_PROCEDURES}
    assert set(catalog) == set(OOKLA_PROCEDURES)
    for proc in catalog.values():
        assert proc["effect"] == "read"
        assert proc["approval_required"] is False
        assert proc["handler_id"] == proc["name"]
        assert proc["params_schema"]["additionalProperties"] is False
        assert proc["target_models"] == [
            "dcim.device",
            "virtualization.virtualmachine",
        ]


def _execution(procedure_name: str, handler_id: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=handler_id),
        params=params,
        target_display="speedtest-01",
        target_model_label="dcim.device",
    )


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
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
