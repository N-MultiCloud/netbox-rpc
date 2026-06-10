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


def test_bootstrap_normalizer_uses_credential_reference_not_password(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.bootstrap_restconf",
        "network.dell_os10_s5232f_on.bootstrap_restconf",
        {
            "configure_user": True,
            "restconf_credential_pk": 42,
            "certificate_name": "switch.example.net",
            "session_timeout": 60,
            "cipher_suites": [
                "ecdhe-rsa-with-aes-256-gcm-SHA384",
                "ecdhe-rsa-with-aes-128-gcm-SHA256",
            ],
            "rpc_ssh_credential_pk": 7,
            "write_memory": "true",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dell-s5232f"
    assert normalized["configure_user"] is True
    assert normalized["restconf_credential_pk"] == 42
    assert normalized["rpc_ssh_credential_pk"] == 7
    assert normalized["command_fingerprint"]["restconf_credential_pk"] == 42
    assert "password" not in str(normalized).lower()


def test_bootstrap_configure_user_requires_credential(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.bootstrap_restconf",
        "network.dell_os10_s5232f_on.bootstrap_restconf",
        {"configure_user": True},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "restconf_credential_pk" in str(exc_info.value)


def test_interface_description_hashes_description_in_fingerprint(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.set_interface_description",
        "network.dell_os10_s5232f_on.set_interface_description",
        {
            "interface_name": "ethernet1/1/1",
            "description": "RESTCONF fallback smoke",
            "write_memory": "false",
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["interface_name"] == "ethernet1/1/1"
    assert normalized["description"] == "RESTCONF fallback smoke"
    assert normalized["write_memory"] is False
    fingerprint = normalized["command_fingerprint"]
    assert "description_sha256" in fingerprint
    assert fingerprint["description_sha256"] != "RESTCONF fallback smoke"
    assert "RESTCONF fallback smoke" not in str(fingerprint)


def test_vlan_description_validates_vlan_range(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.set_vlan_description",
        "network.dell_os10_s5232f_on.set_vlan_description",
        {"vlan_id": 4095, "description": "too high"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def test_description_rejects_control_characters(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.set_vlan_description",
        "network.dell_os10_s5232f_on.set_vlan_description",
        {"vlan_id": 111, "description": "bad\nline"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_version_accepts_ssh_credential_override(jobs_module) -> None:
    execution = _execution(
        "network.device.dell_os10.s5232f_on.show_version",
        "network.dell_os10_s5232f_on.show_version",
        {"rpc_ssh_credential_pk": 9},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "dell-s5232f"
    assert normalized["rpc_ssh_credential_pk"] == 9
    assert normalized["command_fingerprint"]["handler_id"] == (
        "network.dell_os10_s5232f_on.show_version"
    )


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
    netbox_rpc_models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
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
