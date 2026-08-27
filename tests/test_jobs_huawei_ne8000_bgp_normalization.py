"""Tests for the Huawei NE8000-F1A BGP peer normalizer."""

from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


PROCEDURE_NAME = "network.device.huawei.router.ne8000.f1a.show_bgp_peer"
HANDLER_ID = "network.huawei_ne8000_f1a.show_bgp_peer"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    normalization_module = sys.modules["netbox_rpc.domain.normalization"]
    monkeypatch.setattr(normalization_module, "_HUAWEI_NE8000_BGP_AVAILABLE", True)
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_huawei_ne8000_bgp_normalizer_accepts_vrf(
    jobs_module,
) -> None:
    execution = _execution(
        params={"vrf": "customer-a"},
        target=" NE8000-01 ",
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized == {
        "target": "NE8000-01",
        "target_object": {"content_type": "dcim.device", "object_id": 17},
        "vrf": "customer-a",
        "command_fingerprint": {
            "handler_id": HANDLER_ID,
            "target_object": {"content_type": "dcim.device", "object_id": 17},
            "vrf": "customer-a",
        },
    }


def test_huawei_ne8000_bgp_normalizer_applies_empty_vrf_default(
    jobs_module,
) -> None:
    normalized = jobs_module.normalize_execution_params(_execution())

    assert normalized["target"] == "NE8000-01"
    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 17,
    }
    assert normalized["vrf"] == ""
    assert normalized["command_fingerprint"] == {
        "handler_id": HANDLER_ID,
        "target_object": {"content_type": "dcim.device", "object_id": 17},
        "vrf": "",
    }
    assert "rpc_ssh_credential_pk" not in normalized


@pytest.mark.parametrize("unknown_key", ["target", "command", "extra"])
def test_huawei_ne8000_bgp_normalizer_rejects_unknown_fields(
    jobs_module,
    unknown_key: str,
) -> None:
    execution = _execution(params={unknown_key: "unsafe"})

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert unknown_key in str(exc_info.value)


@pytest.mark.parametrize(
    "target",
    ["", " ", "NE8000 01", "NE8000;reboot", "x" * 256],
)
def test_huawei_ne8000_bgp_normalizer_rejects_invalid_target(
    jobs_module,
    target: str,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution(target=target))

    assert exc_info.value.code == "RPC_TARGET_INVALID"


def test_huawei_ne8000_bgp_normalizer_requires_device_target(jobs_module) -> None:
    execution = _execution(target_model_label="virtualization.virtualmachine")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_TARGET_INVALID"


@pytest.mark.parametrize(
    "vrf",
    [
        7,
        " customer-a",
        "customer-a ",
        "customer-a\n",
        "customer-a\x00",
        "customer vrf",
        "customer;display",
        "x" * 32,
    ],
)
def test_huawei_ne8000_bgp_normalizer_rejects_invalid_vrf(
    jobs_module,
    vrf: object,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution(params={"vrf": vrf}))

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "vrf" in str(exc_info.value).lower()


def test_huawei_ne8000_bgp_normalizer_rejects_credential_override(
    jobs_module,
) -> None:
    execution = _execution(params={"rpc_ssh_credential_pk": 17})

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "rpc_ssh_credential_pk" in str(exc_info.value)


def test_huawei_ne8000_bgp_worker_gate_blocks_by_default(
    jobs_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalization_module = sys.modules["netbox_rpc.domain.normalization"]
    monkeypatch.setattr(normalization_module, "_HUAWEI_NE8000_BGP_AVAILABLE", False)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution())

    assert exc_info.value.code == "RPC_PROCEDURE_NOT_AVAILABLE"
    assert "cannot run yet" in str(exc_info.value)


def _execution(
    *,
    params: dict[str, object] | None = None,
    target: str = "NE8000-01",
    target_model_label: str = "dcim.device",
):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=PROCEDURE_NAME, handler_id=HANDLER_ID),
        params={} if params is None else params,
        target_display=target,
        target_model_label=target_model_label,
        assigned_object_type=SimpleNamespace(app_label="dcim", model="device"),
        assigned_object_id=17,
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
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    # netbox_rpc.domain.normalization imports this alongside the service
    # allowlist for netbox.plugin.install (#262); without it every module
    # that stubs netbox_rpc.models fails at import, not just that one.
    netbox_rpc_models.RPCNetBoxPluginAllowlist = type(
        "RPCNetBoxPluginAllowlist", (), {}
    )
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")

    class _RequestException(Exception):
        pass

    requests_exceptions.RequestException = _RequestException
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
