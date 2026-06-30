"""Tests for the os.linux.proxmox.convert_mellanox_nic_to_ethernet normalizer.

These verify that _normalize_convert_mellanox_nic_execution() in jobs.py:
- resolves SSH details via netbox_nms.proxmox_ssh.resolve_proxmox_endpoint_ssh
- emits exactly the rpc_ssh_* host-override keys nms-backend consumes
- carries the behaviour flags (reboot / apply_network / interfaces_content / dry_run)
- raises a structured error when no binding exists or the host is unresolved
"""

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
# Happy path
# ---------------------------------------------------------------------------


def test_mellanox_normalizes_with_binding(jobs_module) -> None:
    _set_resolver(
        jobs_module,
        {
            "host": "10.0.30.156",
            "port": 22,
            "credential_pk": 7,
            "known_hosts_entry": "10.0.30.156 ssh-ed25519 AAAA...",
            "strict_host_key_checking": True,
        },
    )
    execution = _execution(proxmox_endpoint_id=42, reboot=True, apply_network=True)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "pve01"
    assert normalized["rpc_ssh_host"] == "10.0.30.156"
    assert normalized["rpc_ssh_port"] == 22
    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["rpc_ssh_known_hosts_entry"].startswith("10.0.30.156 ssh-ed25519")
    assert normalized["rpc_ssh_strict_host_key_checking"] is True
    assert normalized["reboot"] is True
    assert normalized["apply_network"] is True
    assert normalized["dry_run"] is False
    assert normalized["interfaces_content"] == ""
    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == "os.linux_proxmox.convert_mellanox_nic_to_ethernet"
    assert fp["proxmox_endpoint_id"] == 42


def test_mellanox_defaults_and_interfaces_hash(jobs_module) -> None:
    _set_resolver(
        jobs_module,
        {"host": "host.example", "port": 2222, "credential_pk": 1},
    )
    execution = _execution(proxmox_endpoint_id=5, interfaces_content="auto lo\n")

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_port"] == 2222
    # strict default True when resolver omits the key
    assert normalized["rpc_ssh_strict_host_key_checking"] is True
    assert normalized["reboot"] is False
    assert normalized["apply_network"] is False
    assert normalized["dry_run"] is False
    assert normalized["interfaces_content"] == "auto lo\n"
    assert normalized["command_fingerprint"]["interfaces_content_sha"]  # non-empty hash
    # Bond defaults: bond1, no VLAN filtering, jumbo MTU.
    assert normalized["bond_name"] == "bond1"
    assert normalized["bond_vlans"] == ""
    assert normalized["bond_mtu"] == 9216
    assert normalized["command_fingerprint"]["bond_name"] == "bond1"
    assert normalized["command_fingerprint"]["bond_vlans"] == ""
    assert normalized["command_fingerprint"]["bond_mtu"] == 9216


def test_mellanox_forwards_custom_bond_params(jobs_module) -> None:
    _set_resolver(
        jobs_module,
        {"host": "host.example", "port": 22, "credential_pk": 1},
    )
    execution = _execution(
        proxmox_endpoint_id=5,
        bond_name="bond7",
        bond_vlans="100, 200,300-310",
        bond_mtu=1500,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["bond_name"] == "bond7"
    assert normalized["bond_vlans"] == "100,200,300-310"
    assert normalized["bond_mtu"] == 1500
    fp = normalized["command_fingerprint"]
    assert fp["bond_name"] == "bond7"
    assert fp["bond_vlans"] == "100,200,300-310"
    assert fp["bond_mtu"] == 1500


def test_mellanox_bond_mtu_out_of_range_raises(jobs_module) -> None:
    _set_resolver(
        jobs_module,
        {"host": "host.example", "port": 22, "credential_pk": 1},
    )
    execution = _execution(proxmox_endpoint_id=5, bond_mtu=10000)

    with pytest.raises(jobs_module.RPCExecutionError):
        jobs_module.normalize_execution_params(execution)


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_mellanox_missing_binding_raises(jobs_module) -> None:
    _set_resolver(jobs_module, None)
    execution = _execution(proxmox_endpoint_id=99)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PROXMOX_SSH_BINDING_NOT_FOUND"


def test_mellanox_unresolved_host_raises(jobs_module) -> None:
    _set_resolver(jobs_module, {"host": "", "port": 22, "credential_pk": 3})
    execution = _execution(proxmox_endpoint_id=10)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PROXMOX_SSH_HOST_UNRESOLVED"


def test_mellanox_missing_endpoint_id_raises(jobs_module) -> None:
    _set_resolver(jobs_module, {"host": "h", "port": 22, "credential_pk": 3})
    execution = _execution(proxmox_endpoint_id=None)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_resolver(jobs_module, return_value) -> None:
    sys.modules["netbox_nms.proxmox_ssh"].resolve_proxmox_endpoint_ssh = MagicMock(
        return_value=return_value
    )


def _execution(
    proxmox_endpoint_id,
    reboot: bool = False,
    apply_network: bool = False,
    interfaces_content: str = "",
    dry_run: bool = False,
    **extra_params,
):
    params: dict = {
        "reboot": reboot,
        "apply_network": apply_network,
        "interfaces_content": interfaces_content,
        "dry_run": dry_run,
        **extra_params,
    }
    if proxmox_endpoint_id is not None:
        params["proxmox_endpoint_id"] = proxmox_endpoint_id
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name="os.linux.proxmox.convert_mellanox_nic_to_ethernet",
            handler_id="os.linux_proxmox.convert_mellanox_nic_to_ethernet",
        ),
        params=params,
        target_display="pve01",
        target_model_label="netbox_proxbox.proxmoxendpoint",
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
    netbox_nms_proxmox_ssh = types.ModuleType("netbox_nms.proxmox_ssh")
    netbox_nms_proxmox_ssh.resolve_proxmox_endpoint_ssh = MagicMock(return_value=None)

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
    monkeypatch.setitem(sys.modules, "netbox_nms.proxmox_ssh", netbox_nms_proxmox_ssh)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
