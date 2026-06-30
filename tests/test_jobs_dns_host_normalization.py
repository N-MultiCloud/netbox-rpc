"""Tests for DNS host stack procedure normalization."""

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


def test_dns_host_deploy_emits_ssh_overrides_and_fingerprint(jobs_module) -> None:
    execution = _execution(
        "os.linux.dns_host.deploy_dns_stack",
        target="dns01",
        rpc_ssh_credential_pk=7,
        rpc_ssh_host="10.0.30.11",
        rpc_ssh_port=2222,
        rpc_ssh_known_hosts_entry="10.0.30.11 ssh-ed25519 AAAA...",
        rpc_ssh_strict_host_key_checking=False,
        force_recreate=True,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dns01"
    assert normalized["rpc_ssh_host"] == "10.0.30.11"
    assert normalized["rpc_ssh_port"] == 2222
    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["rpc_ssh_known_hosts_entry"].startswith("10.0.30.11")
    assert normalized["rpc_ssh_strict_host_key_checking"] is False
    assert normalized["compose_project"] == "powerdns-dns-api"
    assert normalized["force_recreate"] is True
    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == "os.linux.dns_host.deploy_dns_stack"
    assert fp["procedure"] == "os.linux.dns_host.deploy_dns_stack"
    assert fp["target"] == "dns01"
    assert fp["compose_project"] == "powerdns-dns-api"
    assert fp["rpc_ssh_host"] == "10.0.30.11"
    assert fp["rpc_ssh_port"] == 2222
    assert fp["force_recreate"] is True


def test_dns_host_status_defaults_host_from_target(jobs_module) -> None:
    execution = _execution(
        "os.linux.dns_host.status_dns_stack",
        target="dns02",
        rpc_ssh_credential_pk=8,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dns02"
    assert normalized["rpc_ssh_host"] == "dns02.example.com"
    assert normalized["rpc_ssh_port"] == 22
    assert normalized["rpc_ssh_credential_pk"] == 8
    assert normalized["rpc_ssh_known_hosts_entry"] == ""
    assert normalized["rpc_ssh_strict_host_key_checking"] is True
    assert normalized["compose_project"] == "powerdns-dns-api"
    assert "force_recreate" not in normalized
    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == "os.linux.dns_host.status_dns_stack"
    assert fp["procedure"] == "os.linux.dns_host.status_dns_stack"
    assert fp["target"] == "dns02"
    assert fp["compose_project"] == "powerdns-dns-api"


def test_dns_host_deploy_defaults_force_recreate_false(jobs_module) -> None:
    execution = _execution(
        "os.linux.dns_host.deploy_dns_stack",
        target="dns01",
        rpc_ssh_credential_pk=9,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_host"] == "dns01.example.com"
    assert normalized["force_recreate"] is False
    assert normalized["command_fingerprint"]["force_recreate"] is False


def test_dns_host_missing_credential_raises(jobs_module) -> None:
    execution = _execution("os.linux.dns_host.status_dns_stack", target="dns01")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def _execution(procedure_name: str, **params):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=procedure_name),
        params=params,
        target_display="",
        target_model_label="",
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
        PLUGINS_CONFIG={"netbox_rpc": {"dns_host_domain": "example.com"}}
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
