from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from .value_objects import ExecutionStatus


def _serialize_datetime(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


@dataclass(frozen=True)
class ExecutionQueued:
    requested_by_id: Any | None = None

    EVENT_NAME: ClassVar[str] = "ExecutionQueued"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "RPC execution queued."

    @property
    def data(self) -> dict[str, Any]:
        data: dict[str, Any] = {"status": ExecutionStatus.QUEUED.value}
        if self.requested_by_id is not None:
            data["requested_by_id"] = self.requested_by_id
        return data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionQueued:
        return cls(requested_by_id=data.get("requested_by_id"))


@dataclass(frozen=True)
class ExecutionStarted:
    started_at: Any

    EVENT_NAME: ClassVar[str] = "ExecutionStarted"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "RPC execution started."

    @property
    def data(self) -> dict[str, Any]:
        return {
            "status": ExecutionStatus.RUNNING.value,
            "started_at": _serialize_datetime(self.started_at),
        }

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionStarted:
        return cls(started_at=data.get("started_at"))


@dataclass(frozen=True)
class ParametersNormalized:
    normalized_params: dict[str, Any]
    resolved_command_hash: str

    EVENT_NAME: ClassVar[str] = "ParametersNormalized"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "Execution parameters normalized by NetBox."

    @property
    def data(self) -> dict[str, Any]:
        return {
            "command_hash": self.resolved_command_hash,
            "normalized_params": self.normalized_params,
        }

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ParametersNormalized:
        return cls(
            normalized_params=dict(data.get("normalized_params") or {}),
            resolved_command_hash=str(
                data.get("command_hash") or data.get("resolved_command_hash") or ""
            ),
        )


@dataclass(frozen=True)
class JobEnqueued:
    job_id: Any

    EVENT_NAME: ClassVar[str] = "JobEnqueued"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "RPC execution job enqueued."

    @property
    def data(self) -> dict[str, Any]:
        return {"job_id": self.job_id}

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> JobEnqueued:
        return cls(job_id=data.get("job_id"))


@dataclass(frozen=True)
class BackendEventRecorded:
    backend_event: str = "BackendEventRecorded"
    backend_data: dict[str, Any] = field(default_factory=dict)
    event_level: str = "info"
    event_message: str = ""

    EVENT_NAME: ClassVar[str] = "BackendEventRecorded"

    @property
    def event_name(self) -> str:
        return self.backend_event or self.EVENT_NAME

    @property
    def level(self) -> str:
        return self.event_level or "info"

    @property
    def message(self) -> str:
        return self.event_message

    @property
    def data(self) -> dict[str, Any]:
        return self.backend_data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> BackendEventRecorded:
        return cls(backend_data=dict(data or {}))


@dataclass(frozen=True)
class ExecutionSucceeded:
    result: dict[str, Any]
    finished_at: Any

    EVENT_NAME: ClassVar[str] = "ExecutionSucceeded"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "RPC execution completed."

    @property
    def data(self) -> dict[str, Any]:
        return {
            "status": ExecutionStatus.SUCCEEDED.value,
            "result": self.result,
            "finished_at": _serialize_datetime(self.finished_at),
        }

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionSucceeded:
        return cls(
            result=dict(data.get("result") or {}),
            finished_at=data.get("finished_at"),
        )


@dataclass(frozen=True)
class ExecutionFailed:
    error_message: str
    code: str
    finished_at: Any

    EVENT_NAME: ClassVar[str] = "ExecutionFailed"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "error"

    @property
    def message(self) -> str:
        return self.error_message or "RPC execution failed."

    @property
    def data(self) -> dict[str, Any]:
        return {
            "status": ExecutionStatus.FAILED.value,
            "code": self.code or "RPC_EXECUTION_FAILED",
            "error_message": self.message,
            "finished_at": _serialize_datetime(self.finished_at),
        }

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionFailed:
        return cls(
            error_message=str(data.get("error_message") or "RPC execution failed."),
            code=str(data.get("code") or "RPC_EXECUTION_FAILED"),
            finished_at=data.get("finished_at"),
        )


@dataclass(frozen=True)
class ExecutionEnqueueFailed:
    error_message: str
    code: str
    finished_at: Any

    EVENT_NAME: ClassVar[str] = "ExecutionEnqueueFailed"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "error"

    @property
    def message(self) -> str:
        return self.error_message or "Failed to enqueue RPC job."

    @property
    def data(self) -> dict[str, Any]:
        return {
            "status": ExecutionStatus.FAILED.value,
            "code": self.code or "RPC_ENQUEUE_FAILED",
            "error_message": self.message,
            "finished_at": _serialize_datetime(self.finished_at),
        }

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionEnqueueFailed:
        return cls(
            error_message=str(
                data.get("error_message") or "Failed to enqueue RPC job."
            ),
            code=str(data.get("code") or "RPC_ENQUEUE_FAILED"),
            finished_at=data.get("finished_at"),
        )


@dataclass(frozen=True)
class ExecutionCancelled:
    finished_at: Any
    cancelled_by_id: Any | None = None
    reason: str = ""

    EVENT_NAME: ClassVar[str] = "ExecutionCancelled"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "warning"

    @property
    def message(self) -> str:
        return self.reason or "RPC execution cancelled."

    @property
    def data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "status": ExecutionStatus.CANCELLED.value,
            "finished_at": _serialize_datetime(self.finished_at),
        }
        if self.cancelled_by_id is not None:
            data["cancelled_by_id"] = self.cancelled_by_id
        if self.reason:
            data["reason"] = self.reason
        return data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionCancelled:
        return cls(
            finished_at=data.get("finished_at"),
            cancelled_by_id=data.get("cancelled_by_id"),
            reason=str(data.get("reason") or ""),
        )


@dataclass(frozen=True)
class ExecutionRequested:
    """First event of an approval-gated stream (issue #164).

    Marks that a requester has asked for an execution that requires approval.
    It intentionally carries no command detail — the immutable snapshot in
    ``ApprovalRequested`` is the authoritative, hashed record.
    """

    requested_by_id: Any | None = None

    EVENT_NAME: ClassVar[str] = "ExecutionRequested"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "RPC execution requested (approval required)."

    @property
    def data(self) -> dict[str, Any]:
        data: dict[str, Any] = {"status": ExecutionStatus.REQUESTED.value}
        if self.requested_by_id is not None:
            data["requested_by_id"] = self.requested_by_id
        return data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionRequested:
        return cls(requested_by_id=data.get("requested_by_id"))


@dataclass(frozen=True)
class ApprovalRequested:
    """Pending-approval decision point with the immutable snapshot fingerprint.

    ``snapshot_hash`` is the tamper-evident hash over the protected snapshot
    fields (procedure id/version/effect, target snapshot, normalized params /
    command fingerprint, backend, credential policy, requester, expiry). A
    later approval must re-present the same hash or it is invalidated.
    """

    snapshot_hash: str
    expires_at: Any | None = None
    requested_by_id: Any | None = None

    EVENT_NAME: ClassVar[str] = "ApprovalRequested"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "Approval requested; execution is pending a second-actor decision."

    @property
    def data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "status": ExecutionStatus.PENDING_APPROVAL.value,
            "snapshot_hash": self.snapshot_hash,
        }
        if self.expires_at is not None:
            data["expires_at"] = _serialize_datetime(self.expires_at)
        if self.requested_by_id is not None:
            data["requested_by_id"] = self.requested_by_id
        return data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ApprovalRequested:
        return cls(
            snapshot_hash=str(data.get("snapshot_hash") or ""),
            expires_at=data.get("expires_at"),
            requested_by_id=data.get("requested_by_id"),
        )


@dataclass(frozen=True)
class ExecutionApproved:
    """Second-actor approval. ``approved_by_id`` MUST differ from the requester
    (segregation of duties is enforced in the aggregate)."""

    approved_by_id: Any
    snapshot_hash: str
    decided_at: Any
    reason: str = ""

    EVENT_NAME: ClassVar[str] = "ExecutionApproved"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return self.reason or "RPC execution approved."

    @property
    def data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "status": ExecutionStatus.APPROVED.value,
            "approved_by_id": self.approved_by_id,
            "snapshot_hash": self.snapshot_hash,
            "decided_at": _serialize_datetime(self.decided_at),
        }
        if self.reason:
            data["reason"] = self.reason
        return data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionApproved:
        return cls(
            approved_by_id=data.get("approved_by_id"),
            snapshot_hash=str(data.get("snapshot_hash") or ""),
            decided_at=data.get("decided_at"),
            reason=str(data.get("reason") or ""),
        )


@dataclass(frozen=True)
class ExecutionRejected:
    """Terminal rejection decision by a distinct second actor."""

    rejected_by_id: Any
    decided_at: Any
    reason: str = ""

    EVENT_NAME: ClassVar[str] = "ExecutionRejected"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "warning"

    @property
    def message(self) -> str:
        return self.reason or "RPC execution rejected."

    @property
    def data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "status": ExecutionStatus.REJECTED.value,
            "rejected_by_id": self.rejected_by_id,
            "decided_at": _serialize_datetime(self.decided_at),
        }
        if self.reason:
            data["reason"] = self.reason
        return data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionRejected:
        return cls(
            rejected_by_id=data.get("rejected_by_id"),
            decided_at=data.get("decided_at"),
            reason=str(data.get("reason") or ""),
        )


@dataclass(frozen=True)
class ExecutionExpired:
    """Terminal expiry of a pending approval that was never decided in time."""

    expired_at: Any
    reason: str = ""

    EVENT_NAME: ClassVar[str] = "ExecutionExpired"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "warning"

    @property
    def message(self) -> str:
        return self.reason or "Approval request expired before a decision."

    @property
    def data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "status": ExecutionStatus.EXPIRED.value,
            "expired_at": _serialize_datetime(self.expired_at),
        }
        if self.reason:
            data["reason"] = self.reason
        return data

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ExecutionExpired:
        return cls(
            expired_at=data.get("expired_at"),
            reason=str(data.get("reason") or ""),
        )


@dataclass(frozen=True)
class DispatchLeaseIssued:
    """Audit event (#168): a one-time signed dispatch lease was minted for a
    just-claimed execution. Records the nonce, key lineage, stream version,
    audience, and expiry — references only, never the signature or any secret.
    Audit-only: it does not advance the execution status."""

    nonce: str = ""
    key_id: str = ""
    key_version: int = 1
    stream_version: int = 0
    audience: str = ""
    expires_at: Any = None
    envelope_version: int = 1

    EVENT_NAME: ClassVar[str] = "DispatchLeaseIssued"

    @property
    def event_name(self) -> str:
        return self.EVENT_NAME

    @property
    def level(self) -> str:
        return "info"

    @property
    def message(self) -> str:
        return "Signed dispatch lease issued."

    @property
    def data(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "stream_version": self.stream_version,
            "audience": self.audience,
            "expires_at": _serialize_datetime(self.expires_at),
            "envelope_version": self.envelope_version,
        }

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> DispatchLeaseIssued:
        return cls(
            nonce=str(data.get("nonce") or ""),
            key_id=str(data.get("key_id") or ""),
            key_version=int(data.get("key_version") or 1),
            stream_version=int(data.get("stream_version") or 0),
            audience=str(data.get("audience") or ""),
            expires_at=data.get("expires_at"),
            envelope_version=int(data.get("envelope_version") or 1),
        )


DomainEvent = (
    ExecutionRequested
    | ApprovalRequested
    | ExecutionApproved
    | ExecutionRejected
    | ExecutionExpired
    | ExecutionQueued
    | ExecutionStarted
    | ParametersNormalized
    | JobEnqueued
    | DispatchLeaseIssued
    | BackendEventRecorded
    | ExecutionSucceeded
    | ExecutionFailed
    | ExecutionEnqueueFailed
    | ExecutionCancelled
)

EVENT_TYPES = {
    event_type.EVENT_NAME: event_type
    for event_type in (
        ExecutionRequested,
        ApprovalRequested,
        ExecutionApproved,
        ExecutionRejected,
        ExecutionExpired,
        ExecutionQueued,
        ExecutionStarted,
        ParametersNormalized,
        JobEnqueued,
        DispatchLeaseIssued,
        BackendEventRecorded,
        ExecutionSucceeded,
        ExecutionFailed,
        ExecutionEnqueueFailed,
        ExecutionCancelled,
    )
}


def from_record(name: str, data: dict[str, Any] | None) -> DomainEvent:
    event_type = EVENT_TYPES.get(name)
    event_data = dict(data or {})
    if event_type is None:
        return BackendEventRecorded(backend_event=name, backend_data=event_data)
    return event_type.from_data(event_data)
