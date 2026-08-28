"""Worker normalization tests for the typed Akvorado v1 procedure family."""

from __future__ import annotations

import hashlib
import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

PROCEDURE_NAMES = (
    "service.akvorado.1.config_read",
    "service.akvorado.1.config_deploy",
    "service.akvorado.1.status_stack",
    "service.akvorado.1.restart_stack",
)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.mark.parametrize(
    ("procedure_name", "params"),
    [
        ("service.akvorado.1.config_read", {}),
        (
            "service.akvorado.1.config_deploy",
            {"config_content": "inlet:\n  kafka:\n    topic: flows\n"},
        ),
        ("service.akvorado.1.status_stack", {}),
        ("service.akvorado.1.restart_stack", {}),
    ],
)
def test_all_akvorado_procedures_normalize_for_worker_dispatch(
    jobs_module,
    procedure_name: str,
    params: dict[str, object],
) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(procedure_name, {"target": "127.0.0.1", **params})
    )

    assert normalized["target"] == "akvorado-01"
    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 41,
    }
    assert "rpc_ssh_host" not in normalized
    assert normalized["command_fingerprint"]["handler_id"] == procedure_name
    assert normalized["command_fingerprint"]["procedure"] == procedure_name
    assert normalized["command_fingerprint"]["target_object"] == normalized[
        "target_object"
    ]

    if "config_content" in params:
        content = str(params["config_content"])
        assert normalized["config_content"] == content
        fingerprint = normalized["command_fingerprint"]
        assert content not in str(fingerprint)
        assert fingerprint["config_content_sha256"] == hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()
        assert fingerprint["config_content_bytes"] == len(content.encode("utf-8"))
    else:
        assert "config_content" not in normalized


@pytest.mark.parametrize("procedure_name", PROCEDURE_NAMES)
def test_akvorado_normalization_requires_existing_assigned_object(
    jobs_module,
    procedure_name: str,
) -> None:
    execution = _execution(procedure_name, {})
    execution.assigned_object = None

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_TARGET_REQUIRED"


@pytest.mark.parametrize(
    ("content", "error_code"),
    [
        ("", "RPC_PARAM_INVALID"),
        (" \n", "RPC_PARAM_INVALID"),
        ("x" * (1024 * 1024 + 1), "RPC_PARAM_INVALID"),
        ("inlet:\x00\n", "RPC_PARAM_INVALID"),
        ("inlet:\u0001\n", "RPC_PARAM_INVALID"),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        ("password: plaintext\n", "RPC_PARAM_SECRET_FORBIDDEN"),
        ('password: " hunter2"\n', "RPC_PARAM_SECRET_FORBIDDEN"),
        ("authorization: Bearer-token\n", "RPC_PARAM_SECRET_FORBIDDEN"),
        ("Authorization: Bearer hunter2\n", "RPC_PARAM_SECRET_FORBIDDEN"),
        ("authorization=hunter2\n", "RPC_PARAM_SECRET_FORBIDDEN"),
        (
            "endpoint: https://user:pass@example.net\n",
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        ("password: /hunter2\n", "RPC_PARAM_SECRET_FORBIDDEN"),
        (
            "password: |\n  hunter2\n  more-secret-line\n",
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        ("password: |2\n  hunter2\n", "RPC_PARAM_SECRET_FORBIDDEN"),
        ("password: |-2\n  hunter2\n", "RPC_PARAM_SECRET_FORBIDDEN"),
        ("password: |2-\n  hunter2\n", "RPC_PARAM_SECRET_FORBIDDEN"),
    ],
)
def test_akvorado_normalization_rejects_unsafe_config_content(
    jobs_module,
    content: str,
    error_code: str,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(
            _execution(
                "service.akvorado.1.config_deploy",
                {"config_content": content},
            )
        )

    assert exc_info.value.code == error_code


def test_akvorado_content_validation_rejects_decoded_sensitive_yaml_key(
    jobs_module,
) -> None:
    normalization = importlib.import_module("netbox_rpc.domain.normalization")
    content = '"p\\u0061ssword": hunter2\n'
    assert "password" not in content.lower()

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        normalization.validate_akvorado_content_params(
            "service.akvorado.1.config_deploy",
            {"config_content": content},
        )

    assert exc_info.value.code == "RPC_PARAM_SECRET_FORBIDDEN"


def test_akvorado_content_validation_allows_legitimate_decoded_yaml_tree(
    jobs_module,
) -> None:
    normalization = importlib.import_module("netbox_rpc.domain.normalization")
    content = "inlet:\n  kafka:\n    topic: flows\n"

    normalization.validate_akvorado_content_params(
        "service.akvorado.1.config_deploy",
        {"config_content": content},
    )


def test_akvorado_normalization_allows_non_secret_block_and_author_text(
    jobs_module,
) -> None:
    content = "description: |2\n  hello\nbiographer: the author wrote this\n"

    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.akvorado.1.config_deploy",
            {"config_content": content},
        )
    )

    assert normalized["config_content"] == content


def test_akvorado_target_identity_disambiguates_duplicate_display_names(
    jobs_module,
) -> None:
    device_execution = _execution("service.akvorado.1.config_read", {})
    device_execution.assigned_object = SimpleNamespace(name="akvorado-shared")
    device_execution.assigned_object_id = 41
    device_execution.assigned_object_type = SimpleNamespace(
        app_label="dcim",
        model="device",
    )
    vm_execution = _execution("service.akvorado.1.config_read", {})
    vm_execution.assigned_object = SimpleNamespace(name="akvorado-shared")
    vm_execution.assigned_object_id = 84
    vm_execution.assigned_object_type = SimpleNamespace(
        app_label="virtualization",
        model="virtualmachine",
    )

    device_normalized = jobs_module.normalize_execution_params(device_execution)
    vm_normalized = jobs_module.normalize_execution_params(vm_execution)

    assert device_normalized["target"] == vm_normalized["target"]
    assert device_normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 41,
    }
    assert vm_normalized["target_object"] == {
        "content_type": "virtualization.virtualmachine",
        "object_id": 84,
    }
    assert device_normalized["target_object"] != vm_normalized["target_object"]
    assert jobs_module._hash_json(
        device_normalized["command_fingerprint"]
    ) != jobs_module._hash_json(vm_normalized["command_fingerprint"])


def _execution(procedure_name: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=procedure_name),
        params=params,
        assigned_object=SimpleNamespace(name="akvorado-01"),
        assigned_object_type=SimpleNamespace(app_label="dcim", model="device"),
        assigned_object_id=41,
        target_display="caller-controlled-fallback",
        target_model_label="dcim.device",
    )


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})

    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"
    netbox_jobs = types.ModuleType("netbox.jobs")
    netbox_jobs.JobRunner = type(
        "JobRunner",
        (),
        {"enqueue": classmethod(lambda cls, *args, **kwargs: None)},
    )

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    # Imported by netbox_rpc.domain.normalization for netbox.plugin.install
    # (#262); the stub must define it or this module fails at import.
    models.RPCNetBoxPluginAllowlist = type("RPCNetBoxPluginAllowlist", (), {})
    models.RPCExecution = type("RPCExecution", (), {})
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")
    requests_exceptions.RequestException = type("RequestException", (Exception,), {})
    requests_exceptions.ConnectionError = type("ConnectionError", (Exception,), {})
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
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
