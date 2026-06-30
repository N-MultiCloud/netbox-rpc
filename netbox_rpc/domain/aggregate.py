from __future__ import annotations

from typing import Any

from .value_objects import ExecutionStatus


TERMINAL_STATUSES = {
    ExecutionStatus.SUCCEEDED.value,
    ExecutionStatus.FAILED.value,
    ExecutionStatus.CANCELLED.value,
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

    def succeed(self, result: dict[str, Any]) -> None:
        self._ensure_not_terminal()
        from .. import event_store

        event_store.record_execution_succeeded(self.execution, result)

    def fail(self, message: str, code: str) -> None:
        self._ensure_not_terminal()
        from .. import event_store

        event_store.mark_execution_failed(self.execution, message, code)

    def cancel(self, user: object | None = None) -> None:
        if self.status != ExecutionStatus.QUEUED.value:
            raise RPCExecutionAggregateError(
                "Only a queued execution can be cancelled."
            )
        from .. import event_store

        event_store.record_execution_cancelled(self.execution, user=user)

    def _ensure_not_terminal(self) -> None:
        if self.status in TERMINAL_STATUSES:
            raise RPCExecutionAggregateError(
                f"Cannot transition execution from terminal status {self.status!r}."
            )
