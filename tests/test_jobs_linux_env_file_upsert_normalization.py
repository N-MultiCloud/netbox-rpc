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

PROCEDURE_NAME = "os.linux_env_file.upsert_var"
HANDLER_ID = "os.linux_env_file.upsert_var"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.fixture()
def jobs_module_open(jobs_module, monkeypatch: pytest.MonkeyPatch):
    """jobs_module with the hard-coded os.linux_env_file.upsert_var gate open.

    The gate (_LINUX_ENV_FILE_UPSERT_AVAILABLE) defaults to False in
    production; these downstream-validation tests open it explicitly so they
    keep exercising allowlist/param logic once the gate lifts. Gate-closed
    behavior itself is covered by test_upsert_var_gate_blocks_by_default.
    """

    normalization_module = sys.modules["netbox_rpc.domain.normalization"]
    monkeypatch.setattr(
        normalization_module, "_LINUX_ENV_FILE_UPSERT_AVAILABLE", True
    )
    return jobs_module


def test_upsert_var_gate_blocks_by_default(jobs_module) -> None:
    filter_mock = _mock_allowlist(
        jobs_module,
        SimpleNamespace(
            systemd_unit="netbox.service",
            environment_file="/opt/netbox/netbox.env",
            target_models=["dcim.device"],
        ),
    )
    execution = _execution(
        {"service_slug": "netbox", "var_name": "FOO", "credential_pk": 1}
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PROCEDURE_NOT_AVAILABLE"
    filter_mock.assert_not_called()


def test_upsert_var_normalizes_allowlisted_service(jobs_module_open) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file="/opt/netbox/netbox.env",
        target_models=["dcim.device"],
    )
    filter_mock = _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": " netbox ", "var_name": "NMS_FILESERVER_PACKAGE_READ_USER", "credential_pk": 7}
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "edge-01"
    assert normalized["service_slug"] == "netbox"
    assert normalized["systemd_unit"] == "netbox.service"
    assert normalized["environment_file"] == "/opt/netbox/netbox.env"
    assert normalized["var_name"] == "NMS_FILESERVER_PACKAGE_READ_USER"
    assert normalized["credential_pk"] == 7
    assert normalized["command_fingerprint"] == {
        "handler_id": HANDLER_ID,
        "systemd_unit": "netbox.service",
        "environment_file": "/opt/netbox/netbox.env",
        "var_name": "NMS_FILESERVER_PACKAGE_READ_USER",
        "credential_pk": 7,
    }
    filter_mock.assert_called_once_with(slug="netbox", enabled=True)


def test_upsert_var_rejects_not_allowlisted_service(jobs_module_open) -> None:
    jobs_module = jobs_module_open
    _mock_allowlist(jobs_module, None)
    execution = _execution(
        {"service_slug": "missing", "var_name": "FOO", "credential_pk": 1}
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_LINUX_SERVICE_NOT_ALLOWLISTED"


def test_upsert_var_rejects_target_model_not_allowed(jobs_module_open) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file="/opt/netbox/netbox.env",
        target_models=["virtualization.virtualmachine"],
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": "netbox", "var_name": "FOO", "credential_pk": 1}
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_LINUX_SERVICE_TARGET_DENIED"


def test_upsert_var_rejects_missing_environment_file(jobs_module_open) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file="",
        target_models=["dcim.device"],
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": "netbox", "var_name": "FOO", "credential_pk": 1}
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_LINUX_SERVICE_ENVIRONMENT_FILE_MISSING"


@pytest.mark.parametrize(
    "environment_file",
    ["relative/path.env", "/etc/../etc/passwd", "/opt/env\nfile", "/opt/env;rm -rf"],
)
def test_upsert_var_rejects_malformed_environment_file(
    jobs_module_open, environment_file: str
) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file=environment_file,
        target_models=["dcim.device"],
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": "netbox", "var_name": "FOO", "credential_pk": 1}
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_LINUX_SERVICE_ENVIRONMENT_FILE_MISSING"


@pytest.mark.parametrize("var_name", ["foo", "1FOO", "FOO-BAR", "FOO\nBAR", ""])
def test_upsert_var_rejects_invalid_var_name(jobs_module_open, var_name: str) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file="/opt/netbox/netbox.env",
        target_models=["dcim.device"],
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": "netbox", "var_name": var_name, "credential_pk": 1}
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_upsert_var_rejects_non_integer_credential_pk(jobs_module_open) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file="/opt/netbox/netbox.env",
        target_models=["dcim.device"],
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": "netbox", "var_name": "FOO", "credential_pk": "not-an-int"}
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_upsert_var_includes_ssh_credential_override_pk(jobs_module_open) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file="/opt/netbox/netbox.env",
        target_models=["dcim.device"],
        ssh_credential_override_id=42,
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": "netbox", "var_name": "FOO", "credential_pk": 1}
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 42


def test_upsert_var_omits_ssh_credential_override_pk_when_unset(
    jobs_module_open,
) -> None:
    jobs_module = jobs_module_open
    allow = SimpleNamespace(
        systemd_unit="netbox.service",
        environment_file="/opt/netbox/netbox.env",
        target_models=["dcim.device"],
        ssh_credential_override_id=None,
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        {"service_slug": "netbox", "var_name": "FOO", "credential_pk": 1}
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert "rpc_ssh_credential_pk" not in normalized


def _execution(params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=PROCEDURE_NAME, handler_id=HANDLER_ID),
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

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
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
