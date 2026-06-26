from __future__ import annotations

import logging
from typing import Any

from django.db import IntegrityError
from django.utils import timezone

from .models import RPCExecution, RPCExecutionEvent

logger = logging.getLogger(__name__)


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
) -> None:
    """Append one durable execution event with per-execution sequence ordering."""
    sequence = _next_event_sequence(execution)
    for _ in range(3):
        try:
            RPCExecutionEvent.objects.create(
                execution=execution,
                sequence=sequence,
                level=level,
                event=event,
                message=message,
                data=data or {},
            )
            return
        except IntegrityError:
            sequence = _next_event_sequence(execution)
    try:
        RPCExecutionEvent.objects.create(
            execution=execution,
            sequence=sequence,
            level=level,
            event=event,
            message=message,
            data=data or {},
        )
    except IntegrityError:
        logger.warning(
            "RPCExecutionEvent sequence collision exhausted retries for execution %s "
            "(event=%r). Event dropped.",
            execution.pk,
            event,
        )


def mark_execution_running(execution: RPCExecution) -> None:
    execution.status = RPCExecution.STATUS_RUNNING
    execution.started_at = timezone.now()
    execution.save(update_fields=["status", "started_at"])
    append_execution_event(execution, "info", "ExecutionStarted", "RPC execution started.")


def mark_execution_failed(
    execution: RPCExecution,
    message: str,
    code: str,
    *,
    event_name: str = "ExecutionFailed",
) -> None:
    execution.status = RPCExecution.STATUS_FAILED
    execution.error_code = code
    execution.error_message = message
    execution.finished_at = timezone.now()
    execution.save(update_fields=["status", "error_code", "error_message", "finished_at"])
    append_execution_event(execution, "error", event_name, message, {"code": code})


def record_execution_normalized(
    execution: RPCExecution,
    normalized_params: dict[str, Any],
    resolved_command_hash: str,
) -> None:
    execution.normalized_params = normalized_params
    execution.resolved_command_hash = resolved_command_hash
    execution.save(update_fields=["normalized_params", "resolved_command_hash"])
    append_execution_event(
        execution,
        "info",
        "ParametersNormalized",
        "Execution parameters normalized by NetBox.",
        {"command_hash": resolved_command_hash},
    )


def record_backend_response(execution: RPCExecution, response: dict[str, Any]) -> None:
    ok = bool(response.get("ok"))
    execution.result = response.get("result") or {}
    execution.error_code = str(response.get("error_code") or "")
    execution.error_message = str(response.get("error_message") or "")
    execution.status = RPCExecution.STATUS_SUCCEEDED if ok else RPCExecution.STATUS_FAILED
    execution.finished_at = timezone.now()
    execution.save(
        update_fields=["result", "error_code", "error_message", "status", "finished_at"]
    )
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
        )
    else:
        append_execution_event(
            execution,
            "error",
            "ExecutionFailed",
            execution.error_message or "RPC execution failed.",
            {"code": execution.error_code or "RPC_EXECUTION_FAILED"},
        )
