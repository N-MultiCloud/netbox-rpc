from __future__ import annotations

import hashlib
import importlib
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DAEMON_RELOAD = "os.linux.ubuntu.24.daemon_reload"
DAEMON_RELOAD_HANDLER = "os.linux_ubuntu_24.daemon_reload"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def _procedure(
    name: str = DAEMON_RELOAD,
    handler_id: str = DAEMON_RELOAD_HANDLER,
    **driver_fields: object,
):
    return SimpleNamespace(name=name, handler_id=handler_id, **driver_fields)


def _execution(procedure, params: dict[str, object] | None = None):
    return SimpleNamespace(
        procedure=procedure,
        params=params or {},
        target_display="edge-01",
        target_model_label="dcim.device",
    )


# --- Direct unit tests of the central injection helper --------------------------


def test_apply_overrides_injects_non_default_driver_and_parser(jobs_module) -> None:
    schema = {"template": "show_version.textfsm"}
    procedure = _procedure(
        transport_driver="scrapli",
        output_parser="textfsm",
        output_schema=schema,
    )
    normalized = {"target": "edge-01", "command_fingerprint": {"handler_id": "h"}}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert normalized["transport_driver"] == "scrapli"
    assert normalized["output_parser"] == "textfsm"
    assert normalized["output_schema"] == schema
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["transport_driver"] == "scrapli"
    assert fingerprint["output_parser"] == "textfsm"
    expected_hash = hashlib.sha256(
        json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert fingerprint["output_schema_sha256"] == expected_hash


def test_apply_overrides_skips_default_values(jobs_module) -> None:
    procedure = _procedure(
        transport_driver="asyncssh",
        output_parser="none",
        output_schema={},
    )
    normalized = {"target": "edge-01", "command_fingerprint": {"handler_id": "h"}}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert "transport_driver" not in normalized
    assert "output_parser" not in normalized
    assert "output_schema" not in normalized
    assert normalized["command_fingerprint"] == {"handler_id": "h"}


def test_apply_overrides_tolerates_missing_attributes(jobs_module) -> None:
    # Legacy procedure stubs (no driver fields) must inject nothing.
    procedure = _procedure()
    normalized = {"target": "edge-01", "command_fingerprint": {"handler_id": "h"}}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert normalized == {
        "target": "edge-01",
        "command_fingerprint": {"handler_id": "h"},
    }


def test_apply_overrides_without_command_fingerprint_does_not_crash(
    jobs_module,
) -> None:
    procedure = _procedure(transport_driver="netmiko", output_parser="json")
    normalized: dict[str, object] = {"target": "edge-01"}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert normalized["transport_driver"] == "netmiko"
    assert normalized["output_parser"] == "json"


@pytest.mark.parametrize(
    "driver",
    ["scrapli", "netmiko", "paramiko", "napalm"],
)
def test_apply_overrides_each_non_default_driver(jobs_module, driver: str) -> None:
    procedure = _procedure(transport_driver=driver)
    normalized = {"target": "edge-01", "command_fingerprint": {"handler_id": "h"}}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert normalized["transport_driver"] == driver
    assert normalized["command_fingerprint"]["transport_driver"] == driver


# --- End-to-end tests through normalize_execution_params ------------------------


def test_normalize_default_procedure_payload_unchanged(jobs_module) -> None:
    # A procedure with no driver fields produces the exact legacy payload.
    procedure = _procedure()
    normalized = jobs_module.normalize_execution_params(_execution(procedure))

    assert normalized == {
        "target": "edge-01",
        "command_fingerprint": {"handler_id": DAEMON_RELOAD_HANDLER},
    }


def test_normalize_threads_driver_selection_end_to_end(jobs_module) -> None:
    procedure = _procedure(
        transport_driver="napalm",
        output_parser="auto",
        output_schema={"getter": "get_facts"},
    )
    normalized = jobs_module.normalize_execution_params(_execution(procedure))

    assert normalized["target"] == "edge-01"
    assert normalized["transport_driver"] == "napalm"
    assert normalized["output_parser"] == "auto"
    assert normalized["output_schema"] == {"getter": "get_facts"}
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["handler_id"] == DAEMON_RELOAD_HANDLER
    assert fingerprint["transport_driver"] == "napalm"
    assert fingerprint["output_parser"] == "auto"
    assert "output_schema_sha256" in fingerprint


# --- Driver priority + fallback chain -------------------------------------------


def test_apply_overrides_injects_transport_driver_chain(jobs_module) -> None:
    chain = ["asyncssh", "paramiko", "subprocess"]
    procedure = _procedure(transport_driver_chain=chain)
    normalized = {"target": "edge-01", "command_fingerprint": {"handler_id": "h"}}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert normalized["transport_driver_chain"] == chain
    assert normalized["command_fingerprint"]["transport_driver_chain"] == chain


def test_apply_overrides_skips_empty_chain(jobs_module) -> None:
    # An empty chain injects nothing, keeping legacy payloads byte-for-byte.
    procedure = _procedure(transport_driver_chain=[])
    normalized = {"target": "edge-01", "command_fingerprint": {"handler_id": "h"}}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert "transport_driver_chain" not in normalized
    assert normalized["command_fingerprint"] == {"handler_id": "h"}


def test_apply_overrides_strips_blank_chain_entries(jobs_module) -> None:
    procedure = _procedure(transport_driver_chain=[" asyncssh ", "", "  ", "netmiko"])
    normalized = {"target": "edge-01", "command_fingerprint": {"handler_id": "h"}}

    jobs_module._apply_driver_pipeline_overrides(_execution(procedure), normalized)

    assert normalized["transport_driver_chain"] == ["asyncssh", "netmiko"]


def test_normalize_threads_driver_chain_end_to_end(jobs_module) -> None:
    procedure = _procedure(transport_driver_chain=["scrapli", "netmiko", "napalm"])
    normalized = jobs_module.normalize_execution_params(_execution(procedure))

    assert normalized["transport_driver_chain"] == ["scrapli", "netmiko", "napalm"]
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["transport_driver_chain"] == ["scrapli", "netmiko", "napalm"]


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

    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
