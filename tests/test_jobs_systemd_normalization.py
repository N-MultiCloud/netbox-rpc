from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

SERVICE_PROCEDURES = (
    ("os.linux.ubuntu.24.status_service", "os.linux_ubuntu_24.status_service"),
    ("os.linux.ubuntu.24.start_service", "os.linux_ubuntu_24.start_service"),
    ("os.linux.ubuntu.24.stop_service", "os.linux_ubuntu_24.stop_service"),
    ("os.linux.ubuntu.24.reload_service", "os.linux_ubuntu_24.reload_service"),
    ("os.linux.ubuntu.24.enable_service", "os.linux_ubuntu_24.enable_service"),
    ("os.linux.ubuntu.24.disable_service", "os.linux_ubuntu_24.disable_service"),
    ("os.linux.ubuntu.24.journal_tail", "os.linux_ubuntu_24.journal_tail"),
)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.mark.parametrize(("procedure_name", "handler_id"), SERVICE_PROCEDURES)
def test_systemd_service_procedures_normalize_allowlisted_service(
    jobs_module,
    procedure_name: str,
    handler_id: str,
) -> None:
    allow = SimpleNamespace(systemd_unit="nginx.service", target_models=["dcim.device"])
    filter_mock = _mock_allowlist(jobs_module, allow)
    execution = _execution(
        procedure_name,
        handler_id,
        {"service_slug": " nginx "},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "edge-01"
    assert normalized["service_slug"] == "nginx"
    assert normalized["systemd_unit"] == "nginx.service"
    assert normalized["command_fingerprint"]["handler_id"] == handler_id
    assert normalized["command_fingerprint"]["systemd_unit"] == "nginx.service"
    if procedure_name == "os.linux.ubuntu.24.journal_tail":
        assert normalized["lines"] == 100
    filter_mock.assert_called_once_with(slug="nginx", enabled=True)


@pytest.mark.parametrize(("procedure_name", "handler_id"), SERVICE_PROCEDURES)
def test_systemd_service_procedures_reject_not_allowlisted_service(
    jobs_module,
    procedure_name: str,
    handler_id: str,
) -> None:
    filter_mock = _mock_allowlist(jobs_module, None)
    execution = _execution(procedure_name, handler_id, {"service_slug": "missing"})

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_LINUX_SERVICE_NOT_ALLOWLISTED"
    assert "missing" in str(exc_info.value)
    filter_mock.assert_called_once_with(slug="missing", enabled=True)


def test_daemon_reload_skips_allowlist_lookup(jobs_module) -> None:
    filter_mock = MagicMock()
    jobs_module.RPCLinuxServiceAllowlist.objects = SimpleNamespace(filter=filter_mock)
    execution = _execution(
        "os.linux.ubuntu.24.daemon_reload",
        "os.linux_ubuntu_24.daemon_reload",
        {},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized == {
        "target": "edge-01",
        "command_fingerprint": {"handler_id": "os.linux_ubuntu_24.daemon_reload"},
    }
    filter_mock.assert_not_called()


@pytest.mark.parametrize(("params", "expected_lines"), [({}, 100), ({"lines": 250}, 250)])
def test_journal_tail_normalizes_lines(
    jobs_module,
    params: dict[str, int],
    expected_lines: int,
) -> None:
    allow = SimpleNamespace(systemd_unit="nginx.service", target_models=["dcim.device"])
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        "os.linux.ubuntu.24.journal_tail",
        "os.linux_ubuntu_24.journal_tail",
        {"service_slug": "nginx", **params},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["lines"] == expected_lines


def test_linux_service_normalization_includes_ssh_credential_override_pk(
    jobs_module,
) -> None:
    allow = SimpleNamespace(
        systemd_unit="nginx.service",
        target_models=["dcim.device"],
        ssh_credential_override_id=42,
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        "os.linux.ubuntu.24.status_service",
        "os.linux_ubuntu_24.status_service",
        {"service_slug": "nginx"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 42


def test_linux_service_normalization_omits_ssh_credential_override_pk_when_unset(
    jobs_module,
) -> None:
    allow = SimpleNamespace(
        systemd_unit="nginx.service",
        target_models=["dcim.device"],
        ssh_credential_override_id=None,
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        "os.linux.ubuntu.24.status_service",
        "os.linux_ubuntu_24.status_service",
        {"service_slug": "nginx"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert "rpc_ssh_credential_pk" not in normalized


def test_call_backend_wraps_request_errors_as_backend_unreachable(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = SimpleNamespace(
        backend_url="http://nms-backend.example",
        get_auth_headers=MagicMock(return_value={"Authorization": "Token test"}),
        verify_ssl=True,
    )
    execution = SimpleNamespace(pk=123, procedure=SimpleNamespace(timeout_seconds=20))
    post_mock = MagicMock(
        side_effect=jobs_module.requests.exceptions.ConnectionError("connection refused")
    )
    monkeypatch.setattr(jobs_module.requests, "post", post_mock)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module._call_backend(backend, execution)

    assert exc_info.value.code == "RPC_BACKEND_UNREACHABLE"
    post_mock.assert_called_once_with(
        "http://nms-backend.example/rpc/executions/123/run",
        headers={"Authorization": "Token test"},
        json={},
        verify=True,
        timeout=(10, 30),
    )


def _execution(procedure_name: str, handler_id: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=handler_id),
        params=params,
        target_display="edge-01",
        target_model_label="dcim.device",
    )


def _mock_allowlist(jobs_module, allow):
    if allow is not None and not hasattr(allow, "ssh_credential_override_id"):
        allow.ssh_credential_override_id = None
    query = SimpleNamespace(first=MagicMock(return_value=allow))
    filter_mock = MagicMock(return_value=query)
    jobs_module.RPCLinuxServiceAllowlist.objects = SimpleNamespace(filter=filter_mock)
    return filter_mock


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

    netbox_nms = types.ModuleType("netbox_nms")
    netbox_nms_backend = types.ModuleType("netbox_nms.backend")
    netbox_nms_backend.get_backend = MagicMock(return_value=None)

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
    # Stub requests so jobs.py can be imported without the package installed.
    # Include a requests.exceptions namespace so _call_backend's
    # `except requests.exceptions.RequestException` path is exercisable even when
    # the real requests package is installed (CI installs requests, which would
    # otherwise be shadowed by this bare stub and lack .exceptions).
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
    monkeypatch.setitem(sys.modules, "netbox_nms", netbox_nms)
    monkeypatch.setitem(sys.modules, "netbox_nms.backend", netbox_nms_backend)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
