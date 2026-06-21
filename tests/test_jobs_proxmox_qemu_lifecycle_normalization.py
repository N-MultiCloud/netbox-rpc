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


def test_proxmox_qemu_lifecycle_normalizes_structured_payload(jobs_module) -> None:
    _set_resolver(
        {
            "host": "10.0.30.71",
            "port": 22,
            "credential_pk": 7,
            "known_hosts_entry": "10.0.30.71 ssh-ed25519 AAAA...",
            "strict_host_key_checking": True,
        }
    )
    execution = _execution(
        operations=["configure", "resize", "start"],
        vmid=163,
        node="node05",
        memory_mb=8192,
        cores=4,
        ciuser="root",
        agent_enabled=True,
        search_domain="nmulti.cloud",
        dns_servers=["168.0.96.26", "168.0.96.27", "8.8.8.8"],
        disk_gb=8192,
        networks=[
            {"index": 0, "model": "virtio", "bridge": "vmbr1", "tag": 111},
            {"index": 1, "model": "virtio", "bridge": "vmbr1", "tag": 20},
        ],
        ipconfigs=[
            {"index": 0, "ip": "10.0.30.138/24", "gw": "10.0.30.1"},
            {"index": 1, "ip": "10.0.20.138/24"},
        ],
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "CLUSTER01-DC01"
    assert normalized["rpc_ssh_host"] == "10.0.30.71"
    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["operations"] == ["configure", "resize", "start"]
    assert normalized["vmid"] == 163
    assert normalized["node"] == "node05"
    assert normalized["agent_enabled"] is True
    assert normalized["search_domain"] == "nmulti.cloud"
    assert normalized["dns_servers"] == ["168.0.96.26", "168.0.96.27", "8.8.8.8"]
    assert normalized["disk_gb"] == 8192
    assert normalized["resize_disk"] == "scsi0"
    assert normalized["networks"][0]["tag"] == 111
    assert normalized["ipconfigs"][0]["gw"] == "10.0.30.1"
    assert normalized["command_fingerprint"]["dns_servers"] == [
        "168.0.96.26",
        "168.0.96.27",
        "8.8.8.8",
    ]
    assert normalized["command_fingerprint"]["handler_id"] == "os.linux_proxmox.qemu_vm_lifecycle"


def test_proxmox_qemu_lifecycle_requires_node_for_start(jobs_module) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(operations=["start"], vmid=163)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_proxmox_qemu_lifecycle_accepts_nextid_without_vmid(jobs_module) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(operations=["nextid"])

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["operations"] == ["nextid"]
    assert "vmid" not in normalized
    assert normalized["command_fingerprint"]["operations"] == ["nextid"]
    assert "vmid" not in normalized["command_fingerprint"]


def test_proxmox_qemu_lifecycle_rejects_nextid_combined_with_vm_operations(
    jobs_module,
) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(operations=["nextid", "status"], vmid=163, node="node05")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_proxmox_qemu_lifecycle_accepts_agent_network_interfaces(jobs_module) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(
        operations=["agent_network_get_interfaces"],
        vmid=163,
        node="node05",
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["operations"] == ["agent_network_get_interfaces"]
    assert normalized["node"] == "node05"
    assert normalized["command_fingerprint"]["operations"] == [
        "agent_network_get_interfaces"
    ]


def test_proxmox_qemu_lifecycle_accepts_debian_network_repair(jobs_module) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(
        operations=["agent_configure_debian_network"],
        vmid=163,
        node="node05",
        search_domain="nmulti.cloud",
        dns_servers=["168.0.96.26", "168.0.96.27", "8.8.8.8"],
        guest_networks=[
            {"interface": "eth0", "address": "10.0.30.138/24", "gateway": "10.0.30.1"},
            {"interface": "eth1", "address": "10.0.20.138/24"},
        ],
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["operations"] == ["agent_configure_debian_network"]
    assert normalized["guest_networks"][0]["interface"] == "eth0"
    assert normalized["guest_networks"][0]["gateway"] == "10.0.30.1"
    assert normalized["guest_networks"][1]["address"] == "10.0.20.138/24"
    assert normalized["search_domain"] == "nmulti.cloud"
    assert normalized["dns_servers"][2] == "8.8.8.8"


def test_proxmox_qemu_lifecycle_accepts_guest_password_reference(jobs_module) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(
        operations=["agent_set_user_password"],
        vmid=163,
        node="node05",
        guest_credential_pk=31,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["operations"] == ["agent_set_user_password"]
    assert normalized["guest_credential_pk"] == 31
    assert normalized["command_fingerprint"]["guest_credential_pk"] == 31


def test_proxmox_qemu_lifecycle_accepts_pbs_zabbix_status(jobs_module) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(
        operations=["agent_pbs_zabbix_status"],
        vmid=163,
        node="node05",
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["operations"] == ["agent_pbs_zabbix_status"]
    assert normalized["zabbix_server"] == "zabbix.nmulti.cloud"
    assert normalized["command_fingerprint"]["zabbix_server"] == "zabbix.nmulti.cloud"


def test_proxmox_qemu_lifecycle_accepts_zabbix_agent2_configure(jobs_module) -> None:
    _set_resolver({"host": "10.0.30.71", "port": 22, "credential_pk": 7})
    execution = _execution(
        operations=["agent_configure_zabbix_agent2"],
        vmid=163,
        node="node05",
        zabbix_server="zabbix.nmulti.cloud",
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["operations"] == ["agent_configure_zabbix_agent2"]
    assert normalized["zabbix_server"] == "zabbix.nmulti.cloud"


def _set_resolver(return_value) -> None:
    sys.modules["netbox_nms.proxmox_ssh"].resolve_proxmox_endpoint_ssh = MagicMock(
        return_value=return_value
    )


def _execution(**params):
    params.setdefault("proxmox_endpoint_id", 5)
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name="os.linux.proxmox.qemu_vm_lifecycle",
            handler_id="os.linux_proxmox.qemu_vm_lifecycle",
        ),
        params=params,
        target_display="CLUSTER01-DC01",
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
    netbox_nms_backend = types.ModuleType("netbox_nms.backend")
    netbox_nms_backend.get_backend = MagicMock(return_value=None)
    netbox_nms_proxmox_ssh = types.ModuleType("netbox_nms.proxmox_ssh")
    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})
    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()

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
    monkeypatch.setitem(sys.modules, "netbox_nms.proxmox_ssh", netbox_nms_proxmox_ssh)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
