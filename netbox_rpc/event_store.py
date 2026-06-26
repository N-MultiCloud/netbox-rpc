from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from typing import Any

from django.db import IntegrityError
from django.utils import timezone

from .models import RPCExecution, RPCExecutionEvent

try:
    from django.db import transaction
except ImportError:

    class _TransactionShim:
        @staticmethod
        def atomic():
            return nullcontext()

    transaction = _TransactionShim()

SENSITIVE_KEY_FRAGMENTS = (
    "auth",
    "community",
    "credential",
    "key",
    "password",
    "private",
    "secret",
    "token",
)
MAX_EVENT_STRING_LENGTH = 4096
MAX_EVENT_LIST_ITEMS = 50
MAX_EVENT_DICT_ITEMS = 100


class RPCEventStoreError(RuntimeError):
    """Raised when the RPC execution event ledger cannot append an event."""


def _json_dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _stable_hash(value: object) -> str:
    return hashlib.sha256(_json_dump(value).encode("utf-8")).hexdigest()


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact_event_value(value: object, *, parent_key: str = "") -> object:
    if parent_key and _is_sensitive_key(parent_key):
        return "[REDACTED]"
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        items = sorted(value.items(), key=lambda pair: str(pair[0]))
        for index, (key, item) in enumerate(items):
            if index >= MAX_EVENT_DICT_ITEMS:
                redacted["_truncated"] = True
                break
            redacted[str(key)] = redact_event_value(item, parent_key=str(key))
        return redacted
    if isinstance(value, list):
        items = [
            redact_event_value(item, parent_key=parent_key)
            for item in value[:MAX_EVENT_LIST_ITEMS]
        ]
        if len(value) > MAX_EVENT_LIST_ITEMS:
            items.append(
                {"_truncated": True, "remaining": len(value) - MAX_EVENT_LIST_ITEMS}
            )
        return items
    if isinstance(value, str):
        if len(value) > MAX_EVENT_STRING_LENGTH:
            return f"{value[:MAX_EVENT_STRING_LENGTH]}...[truncated]"
        return value
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)


def redact_event_data(data: dict[str, Any] | None) -> dict[str, Any]:
    redacted = redact_event_value(data or {})
    return redacted if isinstance(redacted, dict) else {}


def _next_event_sequence(execution: RPCExecution) -> int:
    latest = (
        execution.events.order_by("-sequence")
        .values_list("sequence", flat=True)
        .first()
    )
    return int(latest or 0) + 1


def append_execution_event(
    execution: RPCExecution,
    level: str,
    event: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> RPCExecutionEvent:
    """Append one durable execution event with per-execution sequence ordering."""
    sequence = _next_event_sequence(execution)
    event_data = redact_event_data(data)
    payload_hash = _stable_hash(
        {
            "level": level,
            "event": event,
            "message": message,
            "data": event_data,
        }
    )
    for _ in range(3):
        try:
            with transaction.atomic():
                return RPCExecutionEvent.objects.create(
                    execution=execution,
                    sequence=sequence,
                    level=level,
                    event=event,
                    message=message,
                    data=event_data,
                    payload_hash=payload_hash,
                )
        except IntegrityError:
            sequence = _next_event_sequence(execution)
    raise RPCEventStoreError(
        "RPCExecutionEvent sequence collision exhausted retries for execution "
        f"{execution.pk} (event={event!r})."
    )


def mark_execution_running(execution: RPCExecution) -> None:
    now = timezone.now()
    with transaction.atomic():
        append_execution_event(
            execution,
            "info",
            "ExecutionStarted",
            "RPC execution started.",
            {"status": RPCExecution.STATUS_RUNNING, "started_at": now.isoformat()},
        )
        execution.status = RPCExecution.STATUS_RUNNING
        execution.started_at = now
        execution.save(update_fields=["status", "started_at"])


def mark_execution_failed(
    execution: RPCExecution,
    message: str,
    code: str,
    *,
    event_name: str = "ExecutionFailed",
) -> None:
    now = timezone.now()
    with transaction.atomic():
        append_execution_event(
            execution,
            "error",
            event_name,
            message,
            {
                "status": RPCExecution.STATUS_FAILED,
                "code": code,
                "finished_at": now.isoformat(),
            },
        )
        execution.status = RPCExecution.STATUS_FAILED
        execution.error_code = code
        execution.error_message = message
        execution.finished_at = now
        execution.save(
            update_fields=["status", "error_code", "error_message", "finished_at"]
        )


def record_execution_normalized(
    execution: RPCExecution,
    normalized_params: dict[str, Any],
    resolved_command_hash: str,
) -> None:
    with transaction.atomic():
        append_execution_event(
            execution,
            "info",
            "ParametersNormalized",
            "Execution parameters normalized by NetBox.",
            {
                "command_hash": resolved_command_hash,
                "normalized_params": normalized_params,
            },
        )
        execution.normalized_params = normalized_params
        execution.resolved_command_hash = resolved_command_hash
        execution.save(update_fields=["normalized_params", "resolved_command_hash"])


def record_backend_response(execution: RPCExecution, response: dict[str, Any]) -> None:
    ok = bool(response.get("ok"))
    result = redact_event_data(
        response.get("result") if isinstance(response.get("result"), dict) else {}
    )
    error_code = str(response.get("error_code") or "")
    error_message = str(response.get("error_message") or "")
    finished_at = timezone.now()
    with transaction.atomic():
        for item in response.get("events") or []:
            append_execution_event(
                execution,
                str(item.get("level") or "info"),
                str(item.get("event") or "BackendEventRecorded"),
                str(item.get("message") or ""),
                item.get("data") if isinstance(item.get("data"), dict) else {},
            )
        if ok:
            append_execution_event(
                execution,
                "info",
                "ExecutionSucceeded",
                "RPC execution completed.",
                {
                    "status": RPCExecution.STATUS_SUCCEEDED,
                    "result": result,
                    "finished_at": finished_at.isoformat(),
                },
            )
        else:
            append_execution_event(
                execution,
                "error",
                "ExecutionFailed",
                error_message or "RPC execution failed.",
                {
                    "status": RPCExecution.STATUS_FAILED,
                    "code": error_code or "RPC_EXECUTION_FAILED",
                    "finished_at": finished_at.isoformat(),
                },
            )
        execution.result = result
        execution.error_code = error_code
        execution.error_message = error_message
        execution.status = (
            RPCExecution.STATUS_SUCCEEDED if ok else RPCExecution.STATUS_FAILED
        )
        execution.finished_at = finished_at
        execution.save(
            update_fields=[
                "result",
                "error_code",
                "error_message",
                "status",
                "finished_at",
            ]
        )
