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
