"""Tests for direct-SSH Ubuntu agent install normalizers."""

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


def test_install_qemu_guest_agent_forwards_direct_ssh_overrides(jobs_module) -> None:
    execution = _execution(
        "install_qemu_guest_agent",
        rpc_ssh_credential_pk=7,
        rpc_ssh_host=" 10.0.30.44 ",
        rpc_ssh_port="2222",
        rpc_ssh_known_hosts_entry="10.0.30.44 ssh-ed25519 AAAATEST",
        rpc_ssh_strict_host_key_checking=False,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "vm01"
    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["rpc_ssh_host"] == "10.0.30.44"
    assert normalized["rpc_ssh_port"] == 2222
    assert normalized["rpc_ssh_known_hosts_entry"].startswith("10.0.30.44 ")
    assert normalized["rpc_ssh_strict_host_key_checking"] is False
    assert "zabbix_server" not in normalized
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["handler_id"] == "os.linux_ubuntu_24.install_qemu_guest_agent"
    assert fingerprint["rpc_ssh_credential_pk"] == 7
    assert fingerprint["rpc_ssh_host"] == "10.0.30.44"
    assert fingerprint["rpc_ssh_port"] == 2222
    assert fingerprint["rpc_ssh_known_hosts_entry_sha256"]
    assert fingerprint["rpc_ssh_strict_host_key_checking"] is False


def test_install_zabbix_agent2_uses_configured_default_server(jobs_module) -> None:
    """With no explicit param, the configured 'default_zabbix_server' plugin setting is used."""
    execution = _execution("install_zabbix_agent2")

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["zabbix_server"] == "zabbix.example.com"
    assert (
        normalized["command_fingerprint"]["handler_id"]
        == "os.linux_ubuntu_24.install_zabbix_agent2"
    )
    assert normalized["command_fingerprint"]["zabbix_server"] == "zabbix.example.com"


def test_install_zabbix_agent2_requires_server_when_unconfigured(
    jobs_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With neither an explicit param nor a configured default, normalization fails clearly."""
    import django.conf as django_conf  # the stubbed module

    monkeypatch.setattr(django_conf.settings, "PLUGINS_CONFIG", {"netbox_rpc": {}})
    execution = _execution("install_zabbix_agent2")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_install_zabbix_agent2_strips_and_validates_server(jobs_module) -> None:
    execution = _execution(
        "install_zabbix_agent2",
        zabbix_server=" zabbix.example.com. ",
        rpc_ssh_credential_pk=11,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["zabbix_server"] == "zabbix.example.com"
    assert normalized["rpc_ssh_credential_pk"] == 11


@pytest.mark.parametrize(
    "zabbix_server",
    ["bad host", "_bad.example", "-bad.example", "bad.example:10051"],
)
def test_install_zabbix_agent2_rejects_invalid_server(
    jobs_module,
    zabbix_server: str,
) -> None:
    execution = _execution("install_zabbix_agent2", zabbix_server=zabbix_server)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_install_agent_rejects_invalid_ssh_override_port(jobs_module) -> None:
    execution = _execution("install_qemu_guest_agent", rpc_ssh_port=70000)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def _execution(procedure_suffix: str, **params):
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name=f"os.linux.ubuntu.24.{procedure_suffix}",
            handler_id=f"os.linux_ubuntu_24.{procedure_suffix}",
        ),
        params=params,
        target_display="vm01",
        target_model_label="virtualization.virtualmachine",
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
    django_conf = types.ModuleType("django.conf")
    django_conf.settings = SimpleNamespace(
        PLUGINS_CONFIG={"netbox_rpc": {"default_zabbix_server": "zabbix.example.com"}}
    )
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
    monkeypatch.setitem(sys.modules, "django.conf", django_conf)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
