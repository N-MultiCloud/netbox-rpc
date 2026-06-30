"""Tests for the os.linux.ubuntu.24.install_ssh_key normalizer.

These tests verify that _normalize_ssh_install_key_execution() in jobs.py:
- requires public_key and rejects missing/empty values
- rejects multi-line public keys (newlines forbidden)
- rejects keys that don't start with a recognized key-type prefix
- strips the comment field before forwarding (defence-in-depth)
- accepts an optional POSIX username and rejects invalid ones
- builds the expected normalized dict structure
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


def test_install_ssh_key_normalizes_ed25519_key(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbc123xyz ops@host"
    execution = _execution("install_ssh_key", public_key=public_key)

    normalized = jobs_module.normalize_execution_params(execution)

    # Comment field must be stripped — only key-type + base64 blob forwarded
    assert normalized["public_key"] == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbc123xyz"
    assert normalized["target"] == "edge-01"
    assert "command_fingerprint" in normalized
    assert (
        normalized["command_fingerprint"]["handler_id"]
        == "os.linux_ubuntu_24.install_ssh_key"
    )
    # Without username param, username key must not be present
    assert "username" not in normalized


def test_install_ssh_key_strips_comment_from_public_key(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA this is a comment with spaces"
    execution = _execution("install_ssh_key", public_key=public_key)

    normalized = jobs_module.normalize_execution_params(execution)

    # Only key-type + blob, comment stripped
    assert normalized["public_key"] == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
    assert "this is a comment" not in normalized["public_key"]


def test_install_ssh_key_normalizes_rsa_key(jobs_module) -> None:
    public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC testcomment"
    execution = _execution("install_ssh_key", public_key=public_key)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["public_key"].startswith("ssh-rsa AAAAB3NzaC1yc2E")
    assert "testcomment" not in normalized["public_key"]


def test_install_ssh_key_normalizes_ecdsa_key(jobs_module) -> None:
    public_key = (
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBTest"
    )
    execution = _execution("install_ssh_key", public_key=public_key)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["public_key"].startswith("ecdsa-sha2-nistp256 ")


def test_install_ssh_key_accepts_valid_posix_username(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA blob"
    execution = _execution("install_ssh_key", public_key=public_key, username="ubuntu")

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["username"] == "ubuntu"


def test_install_ssh_key_key_without_comment_still_normalizes(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
    execution = _execution("install_ssh_key", public_key=public_key)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["public_key"] == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"


def test_install_ssh_key_command_fingerprint_includes_key_prefix(jobs_module) -> None:
    public_key = "ssh-ed25519 " + "A" * 68 + " comment"
    execution = _execution("install_ssh_key", public_key=public_key)

    normalized = jobs_module.normalize_execution_params(execution)

    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == "os.linux_ubuntu_24.install_ssh_key"
    assert "public_key_prefix" in fp
    assert len(fp["public_key_prefix"]) <= 64


# ---------------------------------------------------------------------------
# Rejection tests
# ---------------------------------------------------------------------------


def test_install_ssh_key_rejects_missing_public_key(jobs_module) -> None:
    execution = _execution("install_ssh_key", public_key="")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "public_key" in str(exc_info.value)


def test_install_ssh_key_rejects_newline_in_public_key(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\nssh-rsa other key"
    execution = _execution("install_ssh_key", public_key=public_key)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "newline" in str(exc_info.value).lower()


def test_install_ssh_key_rejects_unknown_key_type_prefix(jobs_module) -> None:
    public_key = "dss AAA some-dsa-key"
    execution = _execution("install_ssh_key", public_key=public_key)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert (
        "key type" in str(exc_info.value).lower()
        or "prefix" in str(exc_info.value).lower()
    )


def test_install_ssh_key_rejects_username_with_spaces(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
    execution = _execution(
        "install_ssh_key", public_key=public_key, username="bad user"
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_install_ssh_key_rejects_username_starting_with_dash(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
    execution = _execution("install_ssh_key", public_key=public_key, username="-root")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_install_ssh_key_rejects_username_with_semicolons(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
    execution = _execution(
        "install_ssh_key", public_key=public_key, username="root;rm -rf"
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_install_ssh_key_rejects_username_with_uppercase(jobs_module) -> None:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
    execution = _execution("install_ssh_key", public_key=public_key, username="Root")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _execution(
    procedure_suffix: str,
    public_key: str = "",
    username: str | None = None,
):
    params: dict = {"public_key": public_key}
    if username is not None:
        params["username"] = username
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name=f"os.linux.ubuntu.24.{procedure_suffix}",
            handler_id=f"os.linux_ubuntu_24.{procedure_suffix}",
        ),
        params=params,
        target_display="edge-01",
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

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    # Stub requests so jobs.py can be imported without the package installed
    requests_mod = types.ModuleType("requests")
    request_exception = type("RequestException", (Exception,), {})
    connection_error = type("ConnectionError", (request_exception,), {})
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_mod.exceptions = SimpleNamespace(
        RequestException=request_exception,
        ConnectionError=connection_error,
    )

    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
