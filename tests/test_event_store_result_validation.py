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


def test_oversized_wide_field_does_not_mask_unrelated_pattern_violation(
    event_store_module,
) -> None:
    """#215 round 3: relaxing ``maxLength`` at a wide-override path must not
    weaken any other validator on the same schema. Round 2's
    clamp-then-validate approach validated a truncated *copy* of the oversized
    field, which happened to pass either way in this scenario -- the point of
    this test is that round 3's relax-then-validate-raw approach still fails
    closed on a ``pattern`` violation elsewhere in the result, proving the
    schema relaxation is scoped to exactly the wide-override path and not a
    blanket ``maxLength`` removal.
    """
    event_store, events = event_store_module
    procedure_name = "os.linux.ubuntu.24.upgrade_26.run_upgrade"
    schema = {
        "type": "object",
        "required": ["ok", "procedure", "target", "content", "mode"],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"type": "string"},
            "target": {"type": "string"},
            "content": {"type": "string", "maxLength": 1024 * 1024},
            "mode": {"type": "string", "pattern": "^(safe|unsafe)$"},
        },
    }
    execution = SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, result_schema=schema)
    )
    oversized_content = "x" * (1024 * 1024 + 2048)

    event_store.record_backend_response(
        execution,
        {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": procedure_name,
                "target": "edge-01",
                "content": oversized_content,
                # A genuine, unrelated schema violation -- must still be
                # caught even though `content` (in the same result) is
                # oversized and schema-relaxed for validation.
                "mode": "not-a-valid-mode",
            },
        },
    )

    assert len(events) == 1
    failure = events[0]
    assert failure.event_name == "ExecutionFailed"
    assert failure.code == event_store.RESULT_SCHEMA_MISMATCH_CODE


def test_oversized_wide_field_truncates_within_its_own_schema_max_length(
    event_store_module,
) -> None:
    """#215 round 3: a persisted truncated value must never exceed the
    schema's own declared ``maxLength`` for that field.
    ``_result_schema_string_limits()`` reserves ``len(_TRUNCATION_MARKER)``
    bytes of headroom out of the schema-declared limit specifically so that
    ``content[:limit] + marker`` always fits inside the original bound --
    a record marked ``ExecutionSucceeded`` must never store a value that
    would itself fail the schema it was validated against.
    """
    event_store, events = event_store_module
    procedure_name = "os.linux.ubuntu.24.upgrade_26.run_upgrade"
    schema_max_length = 5000  # just above MAX_EVENT_STRING_LENGTH (4096)
    schema = {
        "type": "object",
        "required": ["ok", "procedure", "target", "log_tail"],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"type": "string"},
            "target": {"type": "string"},
            "log_tail": {"type": "string", "maxLength": schema_max_length},
        },
    }
    execution = SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, result_schema=schema)
    )
    oversized_tail = "y" * (schema_max_length + 1000)

    event_store.record_backend_response(
        execution,
        {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": procedure_name,
                "target": "edge-01",
                "log_tail": oversized_tail,
            },
        },
    )

    assert len(events) == 1
    success = events[0]
    assert success.event_name == "ExecutionSucceeded"
    stored_tail = success.result["log_tail"]
    assert stored_tail.endswith(event_store._TRUNCATION_MARKER)
    assert len(stored_tail) <= schema_max_length
    truncated_length = schema_max_length - len(event_store._TRUNCATION_MARKER)
    assert stored_tail == (
        f"{oversized_tail[:truncated_length]}{event_store._TRUNCATION_MARKER}"
    )


def test_truncation_introduced_pattern_violation_fails_closed(
    event_store_module,
) -> None:
    """#215 round 3 follow-up (adversarial review finding 1): a raw value can
    satisfy a ``pattern`` constraint before truncation and violate it after --
    ``redact_event_value()`` appends ``"...[truncated]"`` to any string over
    its limit, and that marker is not made of the pattern's allowed
    characters. The relaxed-schema pass over the *raw* result only proves the
    raw value is valid; it says nothing about the *persisted* (truncated)
    value that actually gets stored and marked ``ExecutionSucceeded``. This
    must fail closed as ``RESULT_SCHEMA_MISMATCH_CODE`` instead.
    """
    event_store, events = event_store_module
    procedure_name = "os.linux.ubuntu.24.upgrade_26.run_upgrade"
    schema_max_length = 5000  # above MAX_EVENT_STRING_LENGTH (4096)
    schema = {
        "type": "object",
        "required": ["ok", "procedure", "target", "log_tail"],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"type": "string"},
            "target": {"type": "string"},
            "log_tail": {
                "type": "string",
                "maxLength": schema_max_length,
                # Only ever emits the letter "a" -- the raw oversized value
                # below satisfies this, but the persisted marker-suffixed
                # copy cannot.
                "pattern": "^a+$",
            },
        },
    }
    execution = SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, result_schema=schema)
    )
    # Oversized but entirely valid against the raw, relaxed-maxLength schema.
    oversized_tail = "a" * (schema_max_length + 1000)

    event_store.record_backend_response(
        execution,
        {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": procedure_name,
                "target": "edge-01",
                "log_tail": oversized_tail,
            },
        },
    )

    assert len(events) == 1
    failure = events[0]
    assert failure.event_name == "ExecutionFailed"
    assert failure.code == event_store.RESULT_SCHEMA_MISMATCH_CODE


def test_relax_schema_string_lengths_only_strips_wide_override_paths(
    event_store_module,
) -> None:
    """Direct unit coverage of the schema-relaxation helpers: only paths
    present in ``string_limits`` lose their ``maxLength``, every other
    constraint (including a sibling field's own ``maxLength``) is left
    byte-for-byte unchanged, and the input schema is never mutated in place.
    """
    event_store, _ = event_store_module
    schema = {
        "type": "object",
        "properties": {
            "content": {"type": "string", "maxLength": 1024 * 1024},
            "mode": {
                "type": "string",
                "maxLength": 10,
                "pattern": "^(safe|unsafe)$",
            },
            "items": {
                "type": "array",
                "items": {"type": "string", "maxLength": 1024 * 1024},
            },
        },
    }
    string_limits = {
        ("content",): 1024 * 1024,
        ("items", "*"): 1024 * 1024,
    }

    relaxed = event_store._relax_schema_string_lengths(
        schema, string_limits=string_limits
    )

    assert "maxLength" not in relaxed["properties"]["content"]
    assert relaxed["properties"]["mode"]["maxLength"] == 10
    assert relaxed["properties"]["mode"]["pattern"] == "^(safe|unsafe)$"
    assert "maxLength" not in relaxed["properties"]["items"]["items"]
    # The input schema must be a deep copy target, not mutated in place.
    assert schema["properties"]["content"]["maxLength"] == 1024 * 1024
    assert schema["properties"]["items"]["items"]["maxLength"] == 1024 * 1024


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


def test_samba_password_fingerprint_is_preserved_but_plaintext_is_redacted(
    event_store_module,
) -> None:
    event_store, _ = event_store_module
    fingerprint = "a" * 64

    redacted = event_store.redact_event_data(
        {
            "password": "hunter2",
            "password_sha256": fingerprint,
            "password_bytes": 7,
        }
    )

    assert redacted == {
        "password": "[REDACTED]",
        "password_bytes": 7,
        "password_sha256": fingerprint,
    }


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
