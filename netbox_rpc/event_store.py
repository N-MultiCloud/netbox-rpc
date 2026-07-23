from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from typing import Any

from django.db import IntegrityError
from django.utils import timezone

from .domain import events as domain_events
from .domain.projection import ProjectionState, apply, rebuild
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
SAFE_REFERENCE_KEYS = {
    "credential_pk",
    "guest_credential_pk",
    "restconf_credential_pk",
    "rpc_ssh_credential_pk",
}
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
    if normalized in SAFE_REFERENCE_KEYS or normalized.endswith("_credential_pk"):
        return False
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


def _append_and_project(
    execution: RPCExecution,
    event: domain_events.DomainEvent,
) -> RPCExecutionEvent:
    record = append_execution_event(
        execution,
        event.level,
        event.event_name,
        event.message,
        event.data,
    )
    projected = apply(ProjectionState.from_execution(execution), event)
    _write_projection(execution, projected)
    return record


def _write_projection(execution: RPCExecution, state: ProjectionState) -> None:
    update_fields = []
    for field_name, value in state.as_update_dict().items():
        if getattr(execution, field_name) != value:
            setattr(execution, field_name, value)
            update_fields.append(field_name)
    if update_fields:
        execution.save(update_fields=update_fields)


def record_execution_queued(execution: RPCExecution) -> None:
    requested_by = getattr(execution, "requested_by", None)
    requested_by_id = getattr(requested_by, "pk", None) or getattr(
        execution,
        "requested_by_id",
        None,
    )
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionQueued(requested_by_id=requested_by_id),
        )


def record_execution_enqueued(execution: RPCExecution, job_id: object) -> None:
    with transaction.atomic():
        _append_and_project(execution, domain_events.JobEnqueued(job_id=job_id))


def mark_execution_running(execution: RPCExecution) -> None:
    now = timezone.now()
    with transaction.atomic():
        _append_and_project(execution, domain_events.ExecutionStarted(started_at=now))


def record_dispatch_lease_issued(
    execution: RPCExecution,
    *,
    nonce: str,
    key_id: str,
    key_version: int,
    stream_version: int,
    audience: str,
    expires_at: Any,
    envelope_version: int,
) -> None:
    """Append the audit event for a minted signed dispatch lease (#168).

    References only — the nonce, key lineage, stream version, audience, and
    expiry. Never the signature or any secret; ``redact_event_data`` bounds the
    payload like every other ledger event.
    """
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.DispatchLeaseIssued(
                nonce=nonce,
                key_id=key_id,
                key_version=key_version,
                stream_version=stream_version,
                audience=audience,
                expires_at=expires_at,
                envelope_version=envelope_version,
            ),
        )


def mark_execution_failed(
    execution: RPCExecution,
    message: str,
    code: str,
    *,
    event_name: str = "ExecutionFailed",
) -> None:
    now = timezone.now()
    if event_name == domain_events.ExecutionEnqueueFailed.EVENT_NAME:
        event: domain_events.DomainEvent = domain_events.ExecutionEnqueueFailed(
            error_message=message,
            code=code,
            finished_at=now,
        )
    else:
        event = domain_events.ExecutionFailed(
            error_message=message,
            code=code,
            finished_at=now,
        )
    with transaction.atomic():
        _append_and_project(execution, event)


def record_execution_normalized(
    execution: RPCExecution,
    normalized_params: dict[str, Any],
    resolved_command_hash: str,
) -> None:
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ParametersNormalized(
                normalized_params=normalized_params,
                resolved_command_hash=resolved_command_hash,
            ),
        )


def record_execution_succeeded(
    execution: RPCExecution,
    result: dict[str, Any],
) -> None:
    finished_at = timezone.now()
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionSucceeded(
                result=redact_event_data(result),
                finished_at=finished_at,
            ),
        )


def record_execution_cancelled(
    execution: RPCExecution,
    *,
    user: object | None = None,
    reason: str = "",
) -> None:
    finished_at = timezone.now()
    cancelled_by_id = getattr(user, "pk", None)
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionCancelled(
                finished_at=finished_at,
                cancelled_by_id=cancelled_by_id,
                reason=reason,
            ),
        )


def record_execution_requested(
    execution: RPCExecution,
    *,
    requested_by_id: object | None = None,
) -> None:
    if requested_by_id is None:
        requested_by = getattr(execution, "requested_by", None)
        requested_by_id = getattr(requested_by, "pk", None) or getattr(
            execution, "requested_by_id", None
        )
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionRequested(requested_by_id=requested_by_id),
        )


def record_approval_requested(
    execution: RPCExecution,
    *,
    snapshot_hash: str,
    expires_at: object | None = None,
    requested_by_id: object | None = None,
) -> None:
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ApprovalRequested(
                snapshot_hash=snapshot_hash,
                expires_at=expires_at,
                requested_by_id=requested_by_id,
            ),
        )


def record_execution_approved(
    execution: RPCExecution,
    *,
    approved_by_id: object,
    snapshot_hash: str,
    reason: str = "",
) -> None:
    decided_at = timezone.now()
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionApproved(
                approved_by_id=approved_by_id,
                snapshot_hash=snapshot_hash,
                decided_at=decided_at,
                reason=reason,
            ),
        )


def record_execution_rejected(
    execution: RPCExecution,
    *,
    rejected_by_id: object,
    reason: str = "",
) -> None:
    decided_at = timezone.now()
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionRejected(
                rejected_by_id=rejected_by_id,
                decided_at=decided_at,
                reason=reason,
            ),
        )


def record_execution_expired(
    execution: RPCExecution,
    *,
    reason: str = "",
) -> None:
    expired_at = timezone.now()
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionExpired(expired_at=expired_at, reason=reason),
        )


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
            _append_and_project(
                execution,
                domain_events.BackendEventRecorded(
                    event_level=str(item.get("level") or "info"),
                    backend_event=str(item.get("event") or "BackendEventRecorded"),
                    event_message=str(item.get("message") or ""),
                    backend_data=item.get("data")
                    if isinstance(item.get("data"), dict)
                    else {},
                ),
            )
        if ok:
            _append_and_project(
                execution,
                domain_events.ExecutionSucceeded(
                    result=result,
                    finished_at=finished_at,
                ),
            )
        else:
            _append_and_project(
                execution,
                domain_events.ExecutionFailed(
                    error_message=error_message or "RPC execution failed.",
                    code=error_code or "RPC_EXECUTION_FAILED",
                    finished_at=finished_at,
                ),
            )


def rebuild_projection(execution: RPCExecution) -> ProjectionState:
    events = (
        domain_events.from_record(record.event, record.data or {})
        for record in execution.events.all().order_by("sequence", "created")
    )
    return rebuild(events)


def reproject(execution: RPCExecution) -> ProjectionState:
    state = rebuild_projection(execution)
    with transaction.atomic():
        _write_projection(execution, state)
    return state
