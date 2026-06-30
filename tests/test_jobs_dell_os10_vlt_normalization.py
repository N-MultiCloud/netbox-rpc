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
# show_vlt
# ---------------------------------------------------------------------------


def test_show_vlt_defaults_domain_id_to_one(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.show_vlt",
        "network.dell_os10_s5232f_on.show_vlt",
        {},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dell-s5232f"
    assert normalized["domain_id"] == 1
    assert normalized["command_fingerprint"]["domain_id"] == 1
    assert normalized["command_fingerprint"]["handler_id"] == (
        "network.dell_os10_s5232f_on.show_vlt"
    )


def test_show_vlt_accepts_explicit_domain_id(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.show_vlt",
        "network.dell_os10_s5232f_on.show_vlt",
        {"domain_id": 7},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["domain_id"] == 7
    assert normalized["command_fingerprint"]["domain_id"] == 7


def test_show_vlt_rejects_domain_id_out_of_range(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.show_vlt",
        "network.dell_os10_s5232f_on.show_vlt",
        {"domain_id": 256},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def test_show_vlt_accepts_credential_override(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.show_vlt",
        "network.dell_os10_s5232f_on.show_vlt",
        {"rpc_ssh_credential_pk": 5},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 5
    assert normalized["command_fingerprint"]["rpc_ssh_credential_pk"] == 5


# ---------------------------------------------------------------------------
# configure_vlt_domain
# ---------------------------------------------------------------------------


def test_configure_vlt_domain_normalizes_required_params(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.dell_os10_s5232f_on.configure_vlt_domain",
        {
            "domain_id": 1,
            "unit_id": 1,
            "discovery_port_channel": 100,
            "backup_destination": "10.0.30.204",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dell-s5232f"
    assert normalized["domain_id"] == 1
    assert normalized["unit_id"] == 1
    assert normalized["discovery_port_channel"] == 100
    assert normalized["backup_destination"] == "10.0.30.204"
    assert normalized["primary_priority"] == 32768
    assert normalized["write_memory"] is True
    assert "vlt_mac" not in normalized


def test_configure_vlt_domain_includes_optional_vlt_mac(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.dell_os10_s5232f_on.configure_vlt_domain",
        {
            "domain_id": 1,
            "unit_id": 2,
            "discovery_port_channel": 200,
            "backup_destination": "192.168.1.10",
            "vlt_mac": "00:1A:2B:3C:4D:5E",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["vlt_mac"] == "00:1A:2B:3C:4D:5E"
    assert normalized["command_fingerprint"]["vlt_mac"] == "00:1A:2B:3C:4D:5E"


def test_configure_vlt_domain_rejects_invalid_ip(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.dell_os10_s5232f_on.configure_vlt_domain",
        {
            "domain_id": 1,
            "unit_id": 1,
            "discovery_port_channel": 100,
            "backup_destination": "not-an-ip",
        },
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "backup_destination" in str(exc_info.value)


def test_configure_vlt_domain_rejects_invalid_mac(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.dell_os10_s5232f_on.configure_vlt_domain",
        {
            "domain_id": 1,
            "unit_id": 1,
            "discovery_port_channel": 100,
            "backup_destination": "10.0.30.204",
            "vlt_mac": "not-a-mac",
        },
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "vlt_mac" in str(exc_info.value)


def test_configure_vlt_domain_rejects_unit_id_out_of_range(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.dell_os10_s5232f_on.configure_vlt_domain",
        {
            "domain_id": 1,
            "unit_id": 3,
            "discovery_port_channel": 100,
            "backup_destination": "10.0.30.204",
        },
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def test_configure_vlt_domain_backup_destination_not_in_fingerprint_when_empty(
    jobs_module,
) -> None:
    """backup_destination must appear in command_fingerprint for dedup/audit."""
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.dell_os10_s5232f_on.configure_vlt_domain",
        {
            "domain_id": 1,
            "unit_id": 1,
            "discovery_port_channel": 100,
            "backup_destination": "10.0.30.204",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert "backup_destination" in normalized["command_fingerprint"]


def test_configure_vlt_domain_accepts_omitted_unit_id(jobs_module) -> None:
    """unit_id is optional — Dell OS10 10.5.x auto-negotiates VLT role."""
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.dell_os10_s5232f_on.configure_vlt_domain",
        {
            "domain_id": 1,
            "discovery_port_channel": 50,
            "backup_destination": "10.0.30.204",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["domain_id"] == 1
    assert normalized["discovery_port_channel"] == 50
    assert normalized["backup_destination"] == "10.0.30.204"
    assert "unit_id" not in normalized
    assert "unit_id" not in normalized["command_fingerprint"]


# ---------------------------------------------------------------------------
# configure_vlt_peer
# ---------------------------------------------------------------------------


def test_configure_vlt_peer_normalizes_required_params(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_peer",
        "network.dell_os10_s5232f_on.configure_vlt_peer",
        {"port_channel_id": 10, "vlt_port_channel_id": 10},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dell-s5232f"
    assert normalized["port_channel_id"] == 10
    assert normalized["vlt_port_channel_id"] == 10
    assert normalized["remove"] is False
    assert normalized["write_memory"] is True
    assert normalized["command_fingerprint"]["handler_id"] == (
        "network.dell_os10_s5232f_on.configure_vlt_peer"
    )


def test_configure_vlt_peer_remove_flag_round_trips(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_peer",
        "network.dell_os10_s5232f_on.configure_vlt_peer",
        {"port_channel_id": 20, "vlt_port_channel_id": 20, "remove": True},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["remove"] is True
    assert normalized["command_fingerprint"]["remove"] is True


def test_configure_vlt_peer_rejects_port_channel_out_of_range(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_peer",
        "network.dell_os10_s5232f_on.configure_vlt_peer",
        {"port_channel_id": 4097, "vlt_port_channel_id": 10},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def test_configure_vlt_peer_accepts_credential_override(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.configure_vlt_peer",
        "network.dell_os10_s5232f_on.configure_vlt_peer",
        {"port_channel_id": 5, "vlt_port_channel_id": 5, "rpc_ssh_credential_pk": 99},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 99
    assert normalized["command_fingerprint"]["rpc_ssh_credential_pk"] == 99


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
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
