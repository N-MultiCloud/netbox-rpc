"""Behavioral tests for Minecraft stack procedure normalization."""

from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

SERVER_UUID = "123E4567-E89B-12D3-A456-426614174000"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)


def test_plugin_install_url_normalizes_public_url_and_fingerprint(
    jobs_module,
) -> None:
    execution = _execution(
        "services.minecraft.plugin.install_url",
        server_uuid=SERVER_UUID,
        source_url="https://downloads.example.org/releases/ViaBackwards.jar",
        filename="ViaBackwards.jar",
        restart=True,
        rpc_ssh_host=" node01.example.net ",
        rpc_ssh_port=2222,
        rpc_ssh_credential_pk=9,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "minecraft-node-01"
    assert normalized["server_uuid"] == SERVER_UUID.lower()
    assert normalized["source_url"].startswith("https://downloads.example.org/")
    assert normalized["filename"] == "ViaBackwards.jar"
    assert normalized["restart"] is True
    assert normalized["rpc_ssh_host"] == "node01.example.net"
    assert normalized["rpc_ssh_port"] == 2222
    assert normalized["rpc_ssh_credential_pk"] == 9
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["handler_id"] == "services.minecraft.plugin.install_url"
    assert fingerprint["filename"] == "ViaBackwards.jar"
    assert "source_url" not in fingerprint
    assert len(fingerprint["source_url_sha256"]) == 64


def test_viaversion_install_normalizes_custom_plugin_order(jobs_module) -> None:
    execution = _execution(
        "services.minecraft.viaversion.install",
        server_uuid=SERVER_UUID,
        plugins=["viarewind", "viaversion"],
        restart=True,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["server_uuid"] == SERVER_UUID.lower()
    assert normalized["preset"] == "custom"
    assert normalized["plugins"] == ["viaversion", "viarewind"]
    assert normalized["restart"] is True
    assert normalized["command_fingerprint"]["plugins"] == [
        "viaversion",
        "viarewind",
    ]


def test_papermc_install_normalizes_build_and_server_jar(jobs_module) -> None:
    execution = _execution(
        "services.minecraft.papermc.install",
        server_uuid=SERVER_UUID,
        project="paper",
        version="1.21.4",
        build_id=151,
        server_jarfile="paper-1.21.4.jar",
        restart=False,
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["server_uuid"] == SERVER_UUID.lower()
    assert normalized["project"] == "paper"
    assert normalized["version"] == "1.21.4"
    assert normalized["build_id"] == 151
    assert normalized["server_jarfile"] == "paper-1.21.4.jar"
    assert normalized["restart"] is False
    assert normalized["command_fingerprint"]["build_id"] == 151


@pytest.mark.parametrize(
    "source_url",
    [
        "http://localhost/plugin.jar",
        "http://169.254.169.254/latest/meta-data/plugin.jar",
        "http://10.0.0.5/plugin.jar",
        "file:///tmp/plugin.jar",
        f"https://downloads.example.org/{'a' * 2049}.jar",
    ],
)
def test_plugin_install_url_rejects_non_public_or_invalid_source_url(
    jobs_module,
    source_url: str,
) -> None:
    execution = _execution(
        "services.minecraft.plugin.install_url",
        server_uuid=SERVER_UUID,
        source_url=source_url,
        filename="plugin.jar",
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    "filename",
    [
        "../../etc/passwd.jar",
        "plugin.jar\\x00.sh",
        "plugin.jar\x00.sh",
        "plugin.txt",
    ],
)
def test_plugin_install_url_rejects_unsafe_jar_filename(
    jobs_module,
    filename: str,
) -> None:
    execution = _execution(
        "services.minecraft.plugin.install_url",
        server_uuid=SERVER_UUID,
        source_url="https://downloads.example.org/plugin.jar",
        filename=filename,
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    "rpc_ssh_host",
    [
        "node01.example.net bad",
        "node01.example.net\nbad",
        "node01.example.net\tbad",
        f"{'a' * 256}.example.net",
    ],
)
def test_shared_ssh_host_override_rejects_whitespace_and_overlong_values(
    jobs_module,
    rpc_ssh_host: str,
) -> None:
    execution = _execution(
        "services.minecraft.plugin.install_url",
        server_uuid=SERVER_UUID,
        source_url="https://downloads.example.org/plugin.jar",
        filename="plugin.jar",
        rpc_ssh_host=rpc_ssh_host,
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def _execution(procedure_name: str, **params):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=procedure_name),
        params=params,
        target_display="minecraft-node-01",
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
