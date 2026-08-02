"""Backend success-boundary result-schema validation tests."""

from __future__ import annotations

import importlib
import sys
import types
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
import yaml


@pytest.fixture()
def event_store_module(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_db.transaction = SimpleNamespace(atomic=lambda: nullcontext())
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = lambda: None
    django_utils.timezone = django_timezone

    models = types.ModuleType("netbox_rpc.models")
    models.RPCExecution = type("RPCExecution", (), {})
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.delitem(sys.modules, "netbox_rpc.event_store", raising=False)

    module = importlib.import_module("netbox_rpc.event_store")
    events = []
    monkeypatch.setattr(module, "_append_and_project", lambda execution, event: events.append(event))
    yield module, events


@pytest.mark.parametrize(
    ("procedure_name", "required_field"),
    [
        ("service.akvorado.1.config_deploy", "deploy_status"),
        ("service.akvorado.1.status_stack", "status"),
    ],
)
def test_truthy_backend_ok_with_malformed_akvorado_result_fails_closed(
    event_store_module,
    procedure_name: str,
    required_field: str,
) -> None:
    event_store, events = event_store_module
    schema = _result_schema(required_field)
    execution = SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, result_schema=schema)
    )

    event_store.record_backend_response(
        execution,
        {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": procedure_name,
                "target": "akvorado-01",
                "unexpected_secret": "must-not-appear-in-error",
            },
        },
    )

    assert len(events) == 1
    failure = events[0]
    assert failure.event_name == "ExecutionFailed"
    assert failure.code == "RPC_RESULT_SCHEMA_MISMATCH"
    assert "Backend result schema mismatch" in failure.error_message
    assert len(failure.error_message) <= 512
    assert "must-not-appear-in-error" not in failure.error_message


def test_schema_valid_backend_result_still_records_success(event_store_module) -> None:
    event_store, events = event_store_module
    procedure_name = "service.akvorado.1.config_deploy"
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name=procedure_name,
            result_schema=_result_schema("deploy_status"),
        )
    )

    event_store.record_backend_response(
        execution,
        {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": procedure_name,
                "target": "akvorado-01",
                "deploy_status": "deployed",
            },
        },
    )

    assert [event.event_name for event in events] == ["ExecutionSucceeded"]


def test_schema_bounded_large_config_read_content_is_not_truncated(
    event_store_module,
) -> None:
    event_store, events = event_store_module
    procedure_name = "service.akvorado.1.config_read"
    content = (
        "inlet:\n"
        "  interface: eth0\n"
        "  retention: 90\n"
        f"  notes: {'x' * (event_store.MAX_EVENT_STRING_LENGTH + 1024)}\n"
    )
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name=procedure_name,
            result_schema={
                "type": "object",
                "required": ["ok", "procedure", "target", "content"],
                "additionalProperties": False,
                "properties": {
                    "ok": {"type": "boolean"},
                    "procedure": {"type": "string"},
                    "target": {"type": "string"},
                    "content": {"type": "string", "maxLength": 1024 * 1024},
                },
            },
        )
    )

    event_store.record_backend_response(
        execution,
        {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": procedure_name,
                "target": "akvorado-01",
                "content": content,
            },
        },
    )

    assert len(events) == 1
    stored_content = events[0].result["content"]
    assert yaml.safe_load(stored_content) == yaml.safe_load(content)
    assert "...[truncated]" not in stored_content


def test_schema_bounded_large_config_read_redacts_secret_content(
    event_store_module,
) -> None:
    event_store, events = event_store_module
    procedure_name = "service.akvorado.1.config_read"
    prefix = (
        "inlet:\n"
        "  interface: eth0\n"
        "  retention: 90\n"
        f"  notes: {'x' * (event_store.MAX_EVENT_STRING_LENGTH + 1024)}\n"
    )
    suffix = "outlet:\n  kafka:\n    topic: flows\n"
    content = f"{prefix}password: hunter2\n{suffix}"
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name=procedure_name,
            result_schema={
                "type": "object",
                "required": ["ok", "procedure", "target", "content"],
                "additionalProperties": False,
                "properties": {
                    "ok": {"type": "boolean"},
                    "procedure": {"type": "string"},
                    "target": {"type": "string"},
                    "content": {"type": "string", "maxLength": 1024 * 1024},
                },
            },
        )
    )

    event_store.record_backend_response(
        execution,
        {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": procedure_name,
                "target": "akvorado-01",
                "content": content,
            },
        },
    )

    assert len(events) == 1
    stored_content = events[0].result["content"]
    expected = yaml.safe_load(content)
    expected["password"] = "[REDACTED]"
    assert yaml.safe_load(stored_content) == expected
    assert "hunter2" not in stored_content


def test_large_compose_content_redacts_block_scalar_secret(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = (
        "services:\n"
        "  akvorado:\n"
        "    environment:\n"
        "      password: |\n"
        "        hunter2\n"
        "        more-secret-line\n"
    )

    redacted = event_store.redact_event_data(
        {"normalized_params": {"compose_content": content}},
        string_limits={
            ("normalized_params", "compose_content"): 1024 * 1024,
        },
    )

    stored_content = redacted["normalized_params"]["compose_content"]
    assert "hunter2" not in stored_content
    assert "more-secret-line" not in stored_content
    assert yaml.safe_load(stored_content)["services"]["akvorado"]["environment"][
        "password"
    ] == "[REDACTED]"


def test_large_compose_content_redacts_single_line_secret(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = "environment:\n  secret: hunter2\n"

    redacted = event_store.redact_event_data(
        {"normalized_params": {"compose_content": content}},
        string_limits={
            ("normalized_params", "compose_content"): 1024 * 1024,
        },
    )

    stored_content = redacted["normalized_params"]["compose_content"]
    assert "hunter2" not in stored_content
    assert yaml.safe_load(stored_content)["environment"]["secret"] == "[REDACTED]"


def test_large_compose_content_redacts_secret_shaped_scalars(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    contents = (
        "endpoints:\n  - https://alice:hunter2@example.invalid/api\n",
        "args:\n  - PASSWORD=hunter2\n",
    )

    for content in contents:
        redacted = event_store.redact_event_data(
            {"normalized_params": {"compose_content": content}},
            string_limits={
                ("normalized_params", "compose_content"): 1024 * 1024,
            },
        )

        assert "hunter2" not in str(redacted)


def test_large_non_yaml_content_keeps_existing_regex_fallback_behavior(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = "root preexec = /bin/sh -c 'echo hunter2'\n"

    redacted = event_store.redact_event_data(
        {"normalized_params": {"content": content}},
        string_limits={
            ("normalized_params", "content"): 1024 * 1024,
        },
    )

    assert redacted["normalized_params"]["content"] == content


def _result_schema(required_field: str) -> dict[str, object]:
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", required_field],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"type": "string"},
            "target": {"type": "string"},
            required_field: {"type": "string"},
        },
    }
