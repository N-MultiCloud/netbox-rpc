"""Tests for the packer.vm.* normalizer (netbox_rpc.packer_normalizer).

These verify that normalize_packer_vm_execution():
- lazy-imports netbox_packer and raises RPC_PACKER_PLUGIN_MISSING when absent
  (proving netbox-rpc does NOT hard-depend on netbox-packer)
- resolves the SSH host from the template's proxmox_node (or ssh_host override)
- emits exactly the rpc_ssh_* host-override keys nms-backend consumes
- requires rpc_ssh_credential_pk and validates the optional services list
- raises structured errors for a wrong target, a missing host, or a missing
  credential

The netbox-packer plugin is not installed in netbox-rpc CI, so a stub
``netbox_packer.models.PackerTemplate`` is injected into ``sys.modules`` and the
execution's ``assigned_object`` is made a real instance of it (so ``isinstance``
works exactly as it would in production).
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
    sys.modules.pop("netbox_rpc.packer_normalizer", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.packer_normalizer", None)


class _StubPackerTemplate:
    """Stand-in for netbox_packer.models.PackerTemplate."""

    def __init__(self, proxmox_node="", proxmox_template_id=None):
        self.proxmox_node = proxmox_node
        self.proxmox_template_id = proxmox_template_id


def _install_packer_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox_packer = types.ModuleType("netbox_packer")
    netbox_packer_models = types.ModuleType("netbox_packer.models")
    netbox_packer_models.PackerTemplate = _StubPackerTemplate
    monkeypatch.setitem(sys.modules, "netbox_packer", netbox_packer)
    monkeypatch.setitem(sys.modules, "netbox_packer.models", netbox_packer_models)


def _packer_template_cls() -> type:
    return sys.modules["netbox_packer.models"].PackerTemplate


def _execution(
    name="packer.vm.test_ssh_connectivity",
    handler_id="packer.vm.test_ssh_connectivity",
    assigned_object=None,
    **params,
):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=name, handler_id=handler_id),
        params=params,
        assigned_object=assigned_object,
        target_display="zabbix-7.4-ubuntu-2604",
        target_model_label="netbox_packer.packertemplate",
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_packer_test_ssh_normalizes_from_proxmox_node(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    template = _packer_template_cls()(
        proxmox_node="10.0.30.139", proxmox_template_id=9010
    )
    execution = _execution(assigned_object=template, rpc_ssh_credential_pk=7)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "zabbix-7.4-ubuntu-2604"
    assert normalized["rpc_ssh_host"] == "10.0.30.139"
    assert normalized["rpc_ssh_port"] == 22
    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["proxmox_template_id"] == 9010
    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == "packer.vm.test_ssh_connectivity"
    assert fp["proxmox_node"] == "10.0.30.139"
    assert fp["proxmox_template_id"] == 9010
    # services only present for verify_services
    assert "services" not in normalized


def test_packer_ssh_host_and_port_override(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    template = _packer_template_cls()(
        proxmox_node="pve01proxbox", proxmox_template_id=1
    )
    execution = _execution(
        assigned_object=template,
        rpc_ssh_credential_pk=3,
        ssh_host="10.0.30.200",
        ssh_port=2222,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_host"] == "10.0.30.200"
    assert normalized["rpc_ssh_port"] == 2222


def test_packer_verify_services_default_when_empty(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    template = _packer_template_cls()(proxmox_node="10.0.30.139", proxmox_template_id=2)
    execution = _execution(
        name="packer.vm.verify_services",
        handler_id="packer.vm.verify_services",
        assigned_object=template,
        rpc_ssh_credential_pk=1,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["services"] == ["qemu-guest-agent"]
    assert normalized["command_fingerprint"]["services"] == ["qemu-guest-agent"]


def test_packer_verify_services_explicit_list(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    template = _packer_template_cls()(proxmox_node="10.0.30.139", proxmox_template_id=2)
    execution = _execution(
        name="packer.vm.verify_services",
        handler_id="packer.vm.verify_services",
        assigned_object=template,
        rpc_ssh_credential_pk=1,
        services=["zabbix-agent2", "qemu-guest-agent"],
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["services"] == ["zabbix-agent2", "qemu-guest-agent"]


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_packer_missing_plugin_raises(jobs_module, monkeypatch) -> None:
    # Ensure netbox_packer is NOT importable.
    monkeypatch.delitem(sys.modules, "netbox_packer", raising=False)
    monkeypatch.delitem(sys.modules, "netbox_packer.models", raising=False)
    execution = _execution(assigned_object=SimpleNamespace(), rpc_ssh_credential_pk=1)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PACKER_PLUGIN_MISSING"


def test_packer_wrong_target_raises(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    # assigned_object is not a PackerTemplate instance
    execution = _execution(
        assigned_object=SimpleNamespace(proxmox_node="x"), rpc_ssh_credential_pk=1
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_packer_missing_host_raises(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    template = _packer_template_cls()(proxmox_node="", proxmox_template_id=1)
    execution = _execution(assigned_object=template, rpc_ssh_credential_pk=1)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PACKER_HOST_UNRESOLVED"


def test_packer_missing_credential_raises(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    template = _packer_template_cls()(proxmox_node="10.0.30.139", proxmox_template_id=1)
    execution = _execution(assigned_object=template)  # no rpc_ssh_credential_pk

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_packer_invalid_services_raises(jobs_module, monkeypatch) -> None:
    _install_packer_stub(monkeypatch)
    template = _packer_template_cls()(proxmox_node="10.0.30.139", proxmox_template_id=1)
    execution = _execution(
        name="packer.vm.verify_services",
        handler_id="packer.vm.verify_services",
        assigned_object=template,
        rpc_ssh_credential_pk=1,
        services=["bad name; rm -rf /"],
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


# ---------------------------------------------------------------------------
# Stubs (mirror tests/test_jobs_mellanox_normalization.py)
# ---------------------------------------------------------------------------


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
