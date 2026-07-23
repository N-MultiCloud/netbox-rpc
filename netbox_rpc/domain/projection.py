from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Iterable

from .events import (
    ApprovalRequested,
    BackendEventRecorded,
    DispatchLeaseIssued,
    DomainEvent,
    ExecutionApproved,
    ExecutionCancelled,
    ExecutionEnqueueFailed,
    ExecutionExpired,
    ExecutionFailed,
    ExecutionQueued,
    ExecutionRejected,
    ExecutionRequested,
    ExecutionStarted,
    ExecutionSucceeded,
    JobEnqueued,
    ParametersNormalized,
)
from .value_objects import ExecutionStatus


@dataclass(frozen=True)
class ProjectionState:
    status: str = ExecutionStatus.QUEUED.value
    started_at: Any | None = None
    finished_at: Any | None = None
    error_code: str = ""
    error_message: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    normalized_params: dict[str, Any] = field(default_factory=dict)
    resolved_command_hash: str = ""
    job_id: Any | None = None

    FIELD_NAMES = (
        "status",
        "started_at",
        "finished_at",
        "error_code",
        "error_message",
        "result",
        "normalized_params",
        "resolved_command_hash",
        "job_id",
    )

    @classmethod
    def initial(cls) -> ProjectionState:
        return cls()

    @classmethod
    def from_execution(cls, execution: object) -> ProjectionState:
        return cls(
            status=str(
                getattr(execution, "status", None) or ExecutionStatus.QUEUED.value
            ),
            started_at=getattr(execution, "started_at", None),
            finished_at=getattr(execution, "finished_at", None),
            error_code=str(getattr(execution, "error_code", None) or ""),
            error_message=str(getattr(execution, "error_message", None) or ""),
            result=dict(getattr(execution, "result", None) or {}),
            normalized_params=dict(getattr(execution, "normalized_params", None) or {}),
            resolved_command_hash=str(
                getattr(execution, "resolved_command_hash", None) or ""
            ),
            job_id=getattr(execution, "job_id", None),
        )

    def as_update_dict(self) -> dict[str, Any]:
        return {
            field_name: getattr(self, field_name) for field_name in self.FIELD_NAMES
        }


def apply(state: ProjectionState, event: DomainEvent) -> ProjectionState:
    if isinstance(event, ExecutionRequested):
        return replace(state, status=ExecutionStatus.REQUESTED.value)
    if isinstance(event, ApprovalRequested):
        return replace(state, status=ExecutionStatus.PENDING_APPROVAL.value)
    if isinstance(event, ExecutionApproved):
        return replace(state, status=ExecutionStatus.APPROVED.value)
    if isinstance(event, ExecutionRejected):
        return replace(
            state,
            status=ExecutionStatus.REJECTED.value,
            error_code="",
            error_message="",
            finished_at=_coerce_datetime(event.decided_at),
        )
    if isinstance(event, ExecutionExpired):
        return replace(
            state,
            status=ExecutionStatus.EXPIRED.value,
            error_code="",
            error_message="",
            finished_at=_coerce_datetime(event.expired_at),
        )
    if isinstance(event, ExecutionQueued):
        return replace(state, status=ExecutionStatus.QUEUED.value)
    if isinstance(event, ExecutionStarted):
        return replace(
            state,
            status=ExecutionStatus.RUNNING.value,
            started_at=_coerce_datetime(event.started_at),
        )
    if isinstance(event, ParametersNormalized):
        return replace(
            state,
            normalized_params=dict(event.normalized_params),
            resolved_command_hash=event.resolved_command_hash,
        )
    if isinstance(event, JobEnqueued):
        return replace(state, job_id=event.job_id)
    if isinstance(event, DispatchLeaseIssued):
        # Audit-only (#168): issuing a signed dispatch lease does not advance
        # the execution status — the stream already sits at RUNNING via start().
        return state
    if isinstance(event, BackendEventRecorded):
        return state
    if isinstance(event, ExecutionSucceeded):
        return replace(
            state,
            status=ExecutionStatus.SUCCEEDED.value,
            result=dict(event.result),
            error_code="",
            error_message="",
            finished_at=_coerce_datetime(event.finished_at),
        )
    if isinstance(event, ExecutionFailed):
        return replace(
            state,
            status=ExecutionStatus.FAILED.value,
            error_code=event.code or "RPC_EXECUTION_FAILED",
            error_message=event.message,
            finished_at=_coerce_datetime(event.finished_at),
        )
    if isinstance(event, ExecutionEnqueueFailed):
        return replace(
            state,
            status=ExecutionStatus.FAILED.value,
            error_code=event.code or "RPC_ENQUEUE_FAILED",
            error_message=event.message,
            finished_at=_coerce_datetime(event.finished_at),
        )
    if isinstance(event, ExecutionCancelled):
        return replace(
            state,
            status=ExecutionStatus.CANCELLED.value,
            error_code="",
            error_message="",
            finished_at=_coerce_datetime(event.finished_at),
        )
    return state


def rebuild(events: Iterable[DomainEvent]) -> ProjectionState:
    state = ProjectionState.initial()
    for event in events:
        state = apply(state, event)
    return state


def _coerce_datetime(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
