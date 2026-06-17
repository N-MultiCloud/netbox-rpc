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
# PTERODACTYL_BOOTSTRAP_API_KEY normalizer
# ---------------------------------------------------------------------------


def test_bootstrap_api_key_uses_default_container_name(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.bootstrap_api_key",
        "services.pterodactyl.bootstrap_api_key",
        {},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "panel-host"
    assert normalized["container_name"] == "pterodactyl-panel-1"
    assert normalized["command_fingerprint"]["handler_id"] == (
        "services.pterodactyl.bootstrap_api_key"
    )


def test_bootstrap_api_key_accepts_custom_container_name(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.bootstrap_api_key",
        "services.pterodactyl.bootstrap_api_key",
        {"container_name": "ptero-panel-prod-1"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["container_name"] == "ptero-panel-prod-1"
    assert normalized["command_fingerprint"]["handler_id"] == (
        "services.pterodactyl.bootstrap_api_key"
    )


def test_bootstrap_api_key_rejects_invalid_container_name(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.bootstrap_api_key",
        "services.pterodactyl.bootstrap_api_key",
        {"container_name": "panel; rm -rf /"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "container_name" in str(exc_info.value).lower()


def test_bootstrap_api_key_rejects_empty_container_name_via_default(jobs_module) -> None:
    # Passing an empty string falls through to the default "pterodactyl-panel-1"
    execution = _execution(
        "services.pterodactyl.bootstrap_api_key",
        "services.pterodactyl.bootstrap_api_key",
        {"container_name": ""},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    # Empty string → falsy → default applied
    assert normalized["container_name"] == "pterodactyl-panel-1"


def test_bootstrap_api_key_includes_no_command_text_in_result(jobs_module) -> None:
    """Normalizer must not include any free-text command in the result."""
    execution = _execution(
        "services.pterodactyl.bootstrap_api_key",
        "services.pterodactyl.bootstrap_api_key",
        {},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert "command" not in normalized
    result_str = str(normalized)
    assert "artisan" not in result_str
    assert "docker exec" not in result_str


# ---------------------------------------------------------------------------
# PTERODACTYL_ARTISAN normalizer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "queue:status",
        "schedule:run",
        "cache:clear",
        "config:clear",
        "queue:restart",
        "migrate",
    ],
)
def test_artisan_accepts_all_allowlisted_commands(jobs_module, command: str) -> None:
    execution = _execution(
        "services.pterodactyl.artisan",
        "services.pterodactyl.artisan",
        {"command": command},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "panel-host"
    assert normalized["command"] == command
    assert normalized["container_name"] == "pterodactyl-panel-1"
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["handler_id"] == "services.pterodactyl.artisan"
    assert fingerprint["command"] == command
    assert fingerprint["container_name"] == "pterodactyl-panel-1"


def test_artisan_rejects_unlisted_command(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.artisan",
        "services.pterodactyl.artisan",
        {"command": "tinker"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "command" in str(exc_info.value).lower()


def test_artisan_rejects_empty_command(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.artisan",
        "services.pterodactyl.artisan",
        {"command": ""},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_artisan_rejects_missing_command_key(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.artisan",
        "services.pterodactyl.artisan",
        {},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_artisan_accepts_custom_container_name(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.artisan",
        "services.pterodactyl.artisan",
        {"command": "cache:clear", "container_name": "ptero-dev-1"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["container_name"] == "ptero-dev-1"
    assert normalized["command_fingerprint"]["container_name"] == "ptero-dev-1"


def test_artisan_rejects_invalid_container_name(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.artisan",
        "services.pterodactyl.artisan",
        {"command": "cache:clear", "container_name": "panel$(whoami)"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_artisan_fingerprint_includes_command_and_container(jobs_module) -> None:
    """command_fingerprint is used for idempotency; must carry both command and container."""
    execution = _execution(
        "services.pterodactyl.artisan",
        "services.pterodactyl.artisan",
        {"command": "queue:restart", "container_name": "ptero-staging-1"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == "services.pterodactyl.artisan"
    assert fp["command"] == "queue:restart"
    assert fp["container_name"] == "ptero-staging-1"


# ---------------------------------------------------------------------------
# PTERODACTYL_CONTAINER_LOGS normalizer
# ---------------------------------------------------------------------------


def test_container_logs_uses_default_lines_and_container(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.container_logs",
        "services.pterodactyl.container_logs",
        {},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "panel-host"
    assert normalized["container_name"] == "pterodactyl-panel-1"
    assert normalized["lines"] == 100
    assert normalized["command_fingerprint"]["handler_id"] == (
        "services.pterodactyl.container_logs"
    )
    assert normalized["command_fingerprint"]["lines"] == 100


def test_container_logs_accepts_custom_line_count(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.container_logs",
        "services.pterodactyl.container_logs",
        {"lines": 250},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["lines"] == 250
    assert normalized["command_fingerprint"]["lines"] == 250


def test_container_logs_clamps_lines_to_minimum_1(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.container_logs",
        "services.pterodactyl.container_logs",
        {"lines": 0},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["lines"] == 1


def test_container_logs_clamps_lines_to_maximum_500(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.container_logs",
        "services.pterodactyl.container_logs",
        {"lines": 9999},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["lines"] == 500


def test_container_logs_accepts_custom_container_name(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.container_logs",
        "services.pterodactyl.container_logs",
        {"container_name": "ptero-panel-staging"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["container_name"] == "ptero-panel-staging"
    assert normalized["command_fingerprint"]["container_name"] == "ptero-panel-staging"


def test_container_logs_rejects_invalid_container_name(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.container_logs",
        "services.pterodactyl.container_logs",
        {"container_name": "../etc/passwd"},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert "container_name" in str(exc_info.value).lower()


def test_container_logs_fingerprint_includes_container_and_lines(jobs_module) -> None:
    execution = _execution(
        "services.pterodactyl.container_logs",
        "services.pterodactyl.container_logs",
        {"container_name": "ptero-prod-1", "lines": 50},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == "services.pterodactyl.container_logs"
    assert fp["container_name"] == "ptero-prod-1"
    assert fp["lines"] == 50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _execution(procedure_name: str, handler_id: str, params: dict, target: str = "panel-host"):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=handler_id),
        params=params,
        target_display=target,
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
