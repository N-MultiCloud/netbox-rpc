"""Backend success-boundary result-schema validation tests."""

from __future__ import annotations

import importlib
import sys
import types
from contextlib import nullcontext
from types import SimpleNamespace

import pytest


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
    assert stored_content == content
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
    expected = f"{prefix}[REDACTED]\n{suffix}"
    assert stored_content == expected
    assert "hunter2" not in stored_content


def test_large_config_content_redacts_block_scalar_secret(
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
        {"normalized_params": {"config_content": content}},
        string_limits={
            ("normalized_params", "config_content"): 1024 * 1024,
        },
    )

    stored_content = redacted["normalized_params"]["config_content"]
    assert stored_content == "services:\n  akvorado:\n    environment:\n[REDACTED]"
    assert "hunter2" not in stored_content
    assert "more-secret-line" not in stored_content


@pytest.mark.parametrize("indicator", ("|2", "|-2", "|2-"))
def test_block_scalar_indent_indicators_redact_the_full_secret_body(
    event_store_module,
    indicator: str,
) -> None:
    event_store, _ = event_store_module
    content = f"password: {indicator}\n  hunter2\n"

    redacted = event_store.redact_event_data({"detail": content})

    assert redacted["detail"] == "[REDACTED]"
    assert "hunter2" not in redacted["detail"]


def test_block_scalar_with_header_comment_redacts_the_full_secret_body(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = "password: |2 # rotated 2026-08-01\n  hunter2\n"

    redacted = event_store.redact_event_data({"detail": content})

    assert redacted["detail"] == "[REDACTED]"
    assert "rotated" not in redacted["detail"]
    assert "hunter2" not in redacted["detail"]


@pytest.mark.parametrize(
    "content",
    ("Authorization: Bearer hunter2", "authorization=hunter2"),
)
def test_authorization_redaction_consumes_the_rest_of_the_line(
    event_store_module,
    content: str,
) -> None:
    event_store, _ = event_store_module

    redacted = event_store.redact_event_data({"detail": content})

    assert redacted["detail"] == "[REDACTED]"
    assert "hunter2" not in redacted["detail"]


def test_authorization_redaction_consumes_crlf_line(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = "Authorization: Bearer hunter2\r\n"

    redacted = event_store.redact_event_data({"detail": content})

    assert redacted["detail"] == "[REDACTED]\r\n"
    assert "hunter2" not in redacted["detail"]


def test_non_secret_block_scalar_and_author_word_are_untouched(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = "description: |2\n  hello\nbiographer: the author wrote this\n"

    redacted = event_store.redact_event_data({"detail": content})

    assert redacted["detail"] == content


def test_dispatch_lease_key_lineage_references_are_not_redacted(
    event_store_module,
) -> None:
    from netbox_rpc.domain.events import DispatchLeaseIssued

    event_store, _ = event_store_module
    redacted = event_store.redact_event_data(
        {"key_id": "rpc-sign", "key_version": 7, "api_key": "hunter2"}
    )

    assert redacted == {
        "api_key": "[REDACTED]",
        "key_id": "rpc-sign",
        "key_version": 7,
    }
    reconstructed = DispatchLeaseIssued.from_data(redacted)
    assert reconstructed.key_id == "rpc-sign"
    assert reconstructed.key_version == 7


def test_large_config_content_redacts_single_line_secret(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = "environment:\n  secret: hunter2\n"

    redacted = event_store.redact_event_data(
        {"normalized_params": {"config_content": content}},
        string_limits={
            ("normalized_params", "config_content"): 1024 * 1024,
        },
    )

    stored_content = redacted["normalized_params"]["config_content"]
    assert stored_content == "environment:\n[REDACTED]\n"
    assert "hunter2" not in stored_content


def test_large_config_content_redacts_secret_shaped_scalars(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    cases = (
        (
            "endpoints:\n  - https://alice:hunter2@example.invalid/api\n",
            "endpoints:\n  - [REDACTED]example.invalid/api\n",
        ),
        (
            "args:\n  - PASSWORD=hunter2\n",
            "args:\n  [REDACTED]\n",
        ),
    )

    for content, expected in cases:
        redacted = event_store.redact_event_data(
            {"normalized_params": {"config_content": content}},
            string_limits={
                ("normalized_params", "config_content"): 1024 * 1024,
            },
        )

        assert redacted["normalized_params"]["config_content"] == expected


def test_large_config_content_redacts_slash_prefixed_secret(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    content = "settings:\n  password: /hunter2\n"

    redacted = event_store.redact_event_data(
        {"normalized_params": {"config_content": content}},
        string_limits={
            ("normalized_params", "config_content"): 1024 * 1024,
        },
    )

    assert redacted["normalized_params"]["config_content"] == (
        "settings:\n[REDACTED]\n"
    )


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
