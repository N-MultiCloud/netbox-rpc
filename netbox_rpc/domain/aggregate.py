from __future__ import annotations

from typing import Any

from .value_objects import ExecutionStatus


TERMINAL_STATUSES = {
    ExecutionStatus.SUCCEEDED.value,
    ExecutionStatus.FAILED.value,
    ExecutionStatus.CANCELLED.value,
    ExecutionStatus.REJECTED.value,
    ExecutionStatus.EXPIRED.value,
}


class RPCExecutionAggregateError(RuntimeError):
    code = "RPC_EXECUTION_INVALID_TRANSITION"


class RPCExecutionAggregate:
    """Invariant wrapper around the RPCExecution command aggregate."""

    def __init__(self, execution: object) -> None:
        self.execution = execution

    @property
    def status(self) -> str:
        return str(getattr(self.execution, "status", ExecutionStatus.QUEUED.value))

    def queue(self) -> None:
        if self.status != ExecutionStatus.QUEUED.value:
            raise RPCExecutionAggregateError("Only a queued execution can be queued.")
        events = getattr(self.execution, "events", None)
        if events is not None and hasattr(events, "exists") and events.exists():
            raise RPCExecutionAggregateError(
                "ExecutionQueued must be the first event in a stream."
            )
        from .. import event_store

        event_store.record_execution_queued(self.execution)

    def enqueue(self, job_id: Any) -> None:
        self._ensure_not_terminal()
        if self.status != ExecutionStatus.QUEUED.value:
            raise RPCExecutionAggregateError(
                "Only a queued execution can record job enqueue."
            )
        from .. import event_store

        event_store.record_execution_enqueued(self.execution, job_id)

    def start(self) -> None:
        self._ensure_not_terminal()
        if self.status != ExecutionStatus.QUEUED.value:
            raise RPCExecutionAggregateError("Only a queued execution can start.")
        from .. import event_store

        event_store.mark_execution_running(self.execution)

    def normalize(
        self,
        normalized_params: dict[str, Any],
        resolved_command_hash: str,
    ) -> None:
        self._ensure_not_terminal()
        if self.status != ExecutionStatus.RUNNING.value:
            raise RPCExecutionAggregateError(
                "Only a running execution can record normalized parameters."
            )
        from .. import event_store

        event_store.record_execution_normalized(
            self.execution,
            normalized_params,
            resolved_command_hash,
        )

    def record_backend_response(self, response: dict[str, Any]) -> None:
        self._ensure_not_terminal()
        if self.status != ExecutionStatus.RUNNING.value:
            raise RPCExecutionAggregateError(
                "Only a running execution can record a backend response."
            )
        from .. import event_store

        event_store.record_backend_response(self.execution, response)

    def record_dispatch_lease_issued(
        self,
        *,
        nonce: str,
        key_id: str,
        key_version: int,
        stream_version: int,
        audience: str,
        expires_at: Any,
        envelope_version: int,
    ) -> None:
        """Audit a minted signed dispatch lease (#168).

        Only a running execution — one that has passed the atomic queued →
        claimed (``start``) transition — can have a lease issued, so a
        cancelled / terminal / expired stream can never mint one.
        """
        self._ensure_not_terminal()
        if self.status != ExecutionStatus.RUNNING.value:
            raise RPCExecutionAggregateError(
                "Only a running execution can issue a dispatch lease."
            )
        from .. import event_store

        event_store.record_dispatch_lease_issued(
            self.execution,
            nonce=nonce,
            key_id=key_id,
            key_version=key_version,
            stream_version=stream_version,
            audience=audience,
            expires_at=expires_at,
            envelope_version=envelope_version,
        )

    def succeed(self, result: dict[str, Any]) -> None:
        self._ensure_not_terminal()
        from .. import event_store

        event_store.record_execution_succeeded(self.execution, result)

    def fail(self, message: str, code: str) -> None:
        self._ensure_not_terminal()
        from .. import event_store

        event_store.mark_execution_failed(self.execution, message, code)

    def cancel(self, user: object | None = None) -> None:
        if self.status not in (
            ExecutionStatus.QUEUED.value,
            ExecutionStatus.PENDING_APPROVAL.value,
        ):
            raise RPCExecutionAggregateError(
                "Only a queued or pending-approval execution can be cancelled."
            )
        from .. import event_store

        event_store.record_execution_cancelled(self.execution, user=user)

    # -- Approval workflow (issue #164) ------------------------------------
    # Additive: these transitions add the request/pending/decision surface.
    # Existing procedures still go straight to QUEUED via ``queue()``; routing
    # ``approval_required`` work through here (enforcement) is deferred to #165.

    def request(self, requested_by_id: Any | None = None) -> None:
        """Open an approval-gated stream. ``ExecutionRequested`` must be first."""
        events = getattr(self.execution, "events", None)
        if events is not None and hasattr(events, "exists") and events.exists():
            raise RPCExecutionAggregateError(
                "ExecutionRequested must be the first event in a stream."
            )
        from .. import event_store

        event_store.record_execution_requested(
            self.execution, requested_by_id=requested_by_id
        )

    def request_approval(
        self,
        *,
        snapshot_hash: str,
        expires_at: Any | None = None,
        requested_by_id: Any | None = None,
    ) -> None:
        """Move a requested execution to pending approval (never enqueues)."""
        if self.status != ExecutionStatus.REQUESTED.value:
            raise RPCExecutionAggregateError(
                "Only a requested execution can enter pending approval."
            )
        if not snapshot_hash:
            raise RPCExecutionAggregateError(
                "An approval snapshot hash is required to request approval."
            )
        from .. import event_store

        event_store.record_approval_requested(
            self.execution,
            snapshot_hash=snapshot_hash,
            expires_at=expires_at,
            requested_by_id=requested_by_id,
        )

    def approve(
        self,
        *,
        approver_id: Any,
        current_protected: dict[str, Any] | None = None,
        reason: str = "",
    ) -> None:
        """Second-actor approval. Enforces segregation of duties + snapshot match."""
        snapshot = self._require_snapshot()
        self._require_distinct_actor(approver_id, snapshot)
        if current_protected is not None and not snapshot.matches_current(
            current_protected
        ):
            raise RPCExecutionAggregateError(
                "Approval snapshot no longer matches the current execution "
                "state; a new request is required.",
            )

        def _record() -> None:
            from .. import event_store

            event_store.record_execution_approved(
                self.execution,
                approved_by_id=approver_id,
                snapshot_hash=snapshot.payload_hash,
                reason=reason,
            )

        self._decide_from_pending(_record)

    def reject(self, *, rejecter_id: Any, reason: str = "") -> None:
        """Terminal rejection by a distinct second actor."""
        snapshot = self._require_snapshot()
        self._require_distinct_actor(rejecter_id, snapshot)

        def _record() -> None:
            from .. import event_store

            event_store.record_execution_rejected(
                self.execution, rejected_by_id=rejecter_id, reason=reason
            )

        self._decide_from_pending(_record)

    def expire(self, *, reason: str = "") -> None:
        """Terminal expiry of a pending approval (a system action, no actor)."""

        def _record() -> None:
            from .. import event_store

            event_store.record_execution_expired(self.execution, reason=reason)

        self._decide_from_pending(_record)

    def _require_snapshot(self) -> Any:
        snapshot = getattr(self.execution, "approval_request", None)
        if snapshot is None:
            raise RPCExecutionAggregateError(
                "Execution has no approval request snapshot to decide."
            )
        return snapshot

    @staticmethod
    def _require_distinct_actor(actor_id: Any, snapshot: Any) -> None:
        requester_id = getattr(snapshot, "requested_by_id", None)
        if actor_id is None:
            raise RPCExecutionAggregateError(
                "An authenticated approver is required to decide an approval."
            )
        if requester_id is not None and str(actor_id) == str(requester_id):
            raise RPCExecutionAggregateError(
                "The requester cannot approve or reject their own execution "
                "(segregation of duties)."
            )

    def _decide_from_pending(self, record: Any) -> None:
        """Serialise a pending-approval decision with a row lock + status recheck.

        The ``select_for_update`` lock plus the in-transaction status recheck
        make double/concurrent approvals, approval-vs-cancel, and expiry-vs-decision
        resolve to a single deterministic event.
        """
        from django.db import transaction

        from ..models import RPCExecution

        with transaction.atomic():
            locked = RPCExecution.objects.select_for_update().get(pk=self.execution.pk)
            if str(locked.status) != ExecutionStatus.PENDING_APPROVAL.value:
                raise RPCExecutionAggregateError(
                    "Only a pending-approval execution can be decided "
                    f"(currently {locked.status!r})."
                )
            # Fold from the committed status so the projection write is correct.
            self.execution.status = locked.status
            record()

    def _ensure_not_terminal(self) -> None:
        if self.status in TERMINAL_STATUSES:
            raise RPCExecutionAggregateError(
                f"Cannot transition execution from terminal status {self.status!r}."
            )
