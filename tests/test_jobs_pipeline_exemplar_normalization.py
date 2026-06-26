from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

PVESH = "os.linux.proxmox.pvesh_json"
PVESH_HANDLER = "os.linux.proxmox.pvesh_json"
COLLECT_FACTS = "os.linux.collect_facts"
COLLECT_FACTS_HANDLER = "os.linux.collect_facts"
SHOW_VERSION_STRUCTURED = (
    "network.device.dell_os10.s5232f_on.show_version_structured"
)
SHOW_VERSION_STRUCTURED_HANDLER = (
    "network.dell_os10_s5232f_on.show_version_structured"
)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_pvesh_json_normalizer_forwards_validated_semantic_params(jobs_module) -> None:
    execution = _execution(
        PVESH,
        PVESH_HANDLER,
        {
            "pvesh_path": "/nodes/pve01/status",
            "timeout": "45",
            "rpc_ssh_credential_pk": 7,
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "edge-01"
    assert normalized["pvesh_path"] == "/nodes/pve01/status"
    assert normalized["timeout"] == 45
    assert normalized["rpc_ssh_credential_pk"] == 7
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["handler_id"] == PVESH_HANDLER
    assert fingerprint["pvesh_path"] == "/nodes/pve01/status"
    assert fingerprint["timeout"] == 45
    assert fingerprint["rpc_ssh_credential_pk"] == 7
    assert "commands" not in normalized
    assert "command" not in normalized


def test_pvesh_json_normalizer_rejects_free_text_path(jobs_module) -> None:
    execution = _execution(PVESH, PVESH_HANDLER, {"pvesh_path": "/x;rm"})

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "pvesh_path" in str(exc_info.value)


def test_collect_facts_normalizer_uses_fixed_handler_fingerprint(jobs_module) -> None:
    execution = _execution(COLLECT_FACTS, COLLECT_FACTS_HANDLER, {})

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized == {
        "target": "edge-01",
        "command_fingerprint": {"handler_id": COLLECT_FACTS_HANDLER},
    }


def test_show_version_structured_normalizer_uses_fixed_handler_fingerprint(
    jobs_module,
) -> None:
    execution = _execution(
        SHOW_VERSION_STRUCTURED,
        SHOW_VERSION_STRUCTURED_HANDLER,
        {},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized == {
        "target": "edge-01",
        "command_fingerprint": {"handler_id": SHOW_VERSION_STRUCTURED_HANDLER},
    }


def _execution(procedure_name: str, handler_id: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=handler_id),
        params=params,
        target_display="edge-01",
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

    netbox_nms = types.ModuleType("netbox_nms")
    netbox_nms_backend = types.ModuleType("netbox_nms.backend")
    netbox_nms_backend.get_backend = MagicMock(return_value=None)

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
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
    monkeypatch.setitem(sys.modules, "netbox_nms", netbox_nms)
    monkeypatch.setitem(sys.modules, "netbox_nms.backend", netbox_nms_backend)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
