from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


# ---------------------------------------------------------------------------
# configure_port_channel
# ---------------------------------------------------------------------------


def test_configure_port_channel_normalizes_required_params(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 1},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dell-s5232f"
    assert normalized["port_channel_id"] == 1
    assert normalized["remove"] is False
    assert normalized["write_memory"] is True
    assert "trunk_vlans" not in normalized
    assert "description" not in normalized
    assert normalized["command_fingerprint"]["handler_id"] == (
        "network.dell_os10_s5232f_on.configure_port_channel"
    )
    assert normalized["command_fingerprint"]["port_channel_id"] == 1
    assert "trunk_vlans" not in normalized["command_fingerprint"]


def test_configure_port_channel_includes_trunk_vlans(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 2, "trunk_vlans": "20,111"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["trunk_vlans"] == "20,111"
    assert normalized["command_fingerprint"]["trunk_vlans"] == "20,111"


def test_configure_port_channel_accepts_vlan_range(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 3, "trunk_vlans": "10-20,100"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["trunk_vlans"] == "10-20,100"


def test_configure_port_channel_rejects_invalid_trunk_vlans(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 1, "trunk_vlans": "not-vlans"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "trunk_vlans" in str(exc_info.value)


def test_configure_port_channel_includes_description(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 1, "description": "uplink-to-sw02"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["description"] == "uplink-to-sw02"
    assert "description_sha256" in normalized["command_fingerprint"]


def test_configure_port_channel_remove_flag_round_trips(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 5, "remove": True},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["remove"] is True
    assert normalized["command_fingerprint"]["remove"] is True


def test_configure_port_channel_rejects_port_channel_out_of_range(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 4097},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def test_configure_port_channel_accepts_credential_override(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_port_channel",
        "network.dell_os10_s5232f_on.configure_port_channel",
        {"port_channel_id": 1, "rpc_ssh_credential_pk": 42},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 42
    assert normalized["command_fingerprint"]["rpc_ssh_credential_pk"] == 42


# ---------------------------------------------------------------------------
# configure_interface_lacp
# ---------------------------------------------------------------------------


def test_configure_interface_lacp_normalizes_required_params(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {"interface_name": "ethernet1/1/1", "port_channel_id": 1},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dell-s5232f"
    assert normalized["interface_name"] == "ethernet1/1/1"
    assert normalized["port_channel_id"] == 1
    assert normalized["lacp_mode"] == "active"
    assert normalized["remove"] is False
    assert normalized["write_memory"] is False
    assert "description" not in normalized
    assert normalized["command_fingerprint"]["handler_id"] == (
        "network.dell_os10_s5232f_on.configure_interface_lacp"
    )
    assert normalized["command_fingerprint"]["interface_name"] == "ethernet1/1/1"
    assert normalized["command_fingerprint"]["port_channel_id"] == 1
    assert normalized["command_fingerprint"]["lacp_mode"] == "active"


def test_configure_interface_lacp_accepts_passive_mode(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {
            "interface_name": "ethernet1/1/2",
            "port_channel_id": 2,
            "lacp_mode": "passive",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["lacp_mode"] == "passive"
    assert normalized["command_fingerprint"]["lacp_mode"] == "passive"


def test_configure_interface_lacp_rejects_invalid_lacp_mode(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {"interface_name": "ethernet1/1/1", "port_channel_id": 1, "lacp_mode": "on"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "lacp_mode" in str(exc_info.value)


def test_configure_interface_lacp_rejects_invalid_interface_name(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {"interface_name": "0bad-name!", "port_channel_id": 1},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "interface_name" in str(exc_info.value)


def test_configure_interface_lacp_accepts_colon_subinterface(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {"interface_name": "ethernet1/1/1:1", "port_channel_id": 3},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["interface_name"] == "ethernet1/1/1:1"


def test_configure_interface_lacp_includes_description(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {
            "interface_name": "ethernet1/1/1",
            "port_channel_id": 1,
            "description": "member-link",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["description"] == "member-link"
    assert "description_sha256" in normalized["command_fingerprint"]


def test_configure_interface_lacp_remove_flag_round_trips(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {"interface_name": "ethernet1/1/1", "port_channel_id": 1, "remove": True},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["remove"] is True
    assert normalized["command_fingerprint"]["remove"] is True


def test_configure_interface_lacp_write_memory_true(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {"interface_name": "ethernet1/1/1", "port_channel_id": 1, "write_memory": True},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["write_memory"] is True


def test_configure_interface_lacp_rejects_port_channel_out_of_range(
    jobs_module,
) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {"interface_name": "ethernet1/1/1", "port_channel_id": 0},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def test_configure_interface_lacp_accepts_credential_override(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "network.dell_os10_s5232f_on.configure_interface_lacp",
        {
            "interface_name": "ethernet1/1/1",
            "port_channel_id": 1,
            "rpc_ssh_credential_pk": 7,
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["command_fingerprint"]["rpc_ssh_credential_pk"] == 7


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _execution(procedure_name: str, handler_id: str, params: dict):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=handler_id),
        params=params,
        target_display="dell-s5232f",
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
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "netbox_nms", netbox_nms)
    monkeypatch.setitem(sys.modules, "netbox_nms.backend", netbox_nms_backend)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
