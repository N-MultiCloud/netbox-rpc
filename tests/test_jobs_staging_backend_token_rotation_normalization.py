from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


PROCEDURE_ID = "service.netbox.staging.rotate_backend_token"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_staging_rotation_normalizer_emits_only_pinned_target_metadata(
    jobs_module,
) -> None:
    execution = _execution(
        {
            "_timeout_seconds_snapshot": 1800,
            "_intent": 8,
            "_intent_name": "staging-recovery",
        }
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized == {
        "target": "nms-front-door",
        "target_object": {
            "content_type": "dcim.device",
            "object_id": 32,
        },
        "command_fingerprint": {
            "handler_id": PROCEDURE_ID,
            "target": "nms-front-door",
            "assigned_object_id": 32,
            "target_object_sha256": (
                "027fdf95d08b711262aa69b3a7b237c71b719744f37ad233c1c4644eceb92f10"
            ),
        },
    }
    assert not any(
        key in normalized or key in normalized["command_fingerprint"]
        for key in ("token", "token_value", "secret", "value", "command")
    )


def test_staging_rotation_normalizer_allows_target_owned_ssh_resolution(
    jobs_module,
) -> None:
    assert jobs_module.normalize_execution_params(_execution({})) == {
        "target": "nms-front-door",
        "target_object": {
            "content_type": "dcim.device",
            "object_id": 32,
        },
        "command_fingerprint": {
            "handler_id": PROCEDURE_ID,
            "target": "nms-front-door",
            "assigned_object_id": 32,
            "target_object_sha256": (
                "027fdf95d08b711262aa69b3a7b237c71b719744f37ad233c1c4644eceb92f10"
            ),
        },
    }


@pytest.mark.parametrize(
    "params",
    [
        {"token": "must-not-enter-rpc"},
        {"token_value": "must-not-enter-rpc"},
        {"command": "rotate --token must-not-enter-rpc"},
        {"rpc_ssh_credential_pk": 20},
        {"rpc_ssh_host": "10.0.30.207"},
        {"rpc_ssh_port": 2222},
        {"rpc_ssh_known_hosts_entry": "host ssh-ed25519 key"},
        {"rpc_ssh_strict_host_key_checking": True},
        [],
        "rpc_ssh_host=deploy01",
    ],
)
def test_staging_rotation_normalizer_rejects_secret_or_unbounded_params(
    jobs_module,
    params: object,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution(params))

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    ("target", "target_model_label"),
    [
        ("", "dcim.device"),
        ("x" * 256, "dcim.device"),
        ("deploy\n01", "dcim.device"),
        (None, "dcim.device"),
        ("different-device", "dcim.device"),
        ("nms-front-door", "ipam.ipaddress"),
    ],
)
def test_staging_rotation_normalizer_requires_bounded_device_or_vm_target(
    jobs_module,
    target: object,
    target_model_label: str,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(
            _execution({}, target=target, target_model_label=target_model_label)
        )

    assert exc_info.value.code == "RPC_TARGET_INVALID"


@pytest.mark.parametrize("assigned_object_id", [None, 0, -1, True, 33])
def test_staging_rotation_normalizer_binds_exact_assigned_object_id(
    jobs_module,
    assigned_object_id: object,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(
            _execution({}, assigned_object_id=assigned_object_id)
        )

    assert exc_info.value.code == "RPC_TARGET_INVALID"


def _execution(
    params: object,
    *,
    target: object = "nms-front-door",
    target_model_label: str = "dcim.device",
    assigned_object_id: object = 32,
):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=PROCEDURE_ID, handler_id=PROCEDURE_ID),
        params=params,
        target_display=target,
        target_model_label=target_model_label,
        assigned_object_id=assigned_object_id,
        assigned_object=(
            SimpleNamespace(name=target, pk=32) if isinstance(target, str) else None
        ),
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

    class _ConnectionError(_RequestException):
        pass

    requests_exceptions.RequestException = _RequestException
    requests_exceptions.ConnectionError = _ConnectionError
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
