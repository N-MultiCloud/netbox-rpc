"""NetBox-managed periodic jobs for the RPC plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from netbox.constants import RQ_QUEUE_DEFAULT
from netbox.jobs import JobRunner, system_job

from . import netbox_rq_worker_contract

if TYPE_CHECKING:
    from core.models import Job


@system_job(interval=netbox_rq_worker_contract.EXPIRY_SWEEP_INTERVAL_MINUTES)
class RPCExecutionQueueExpirySweepJob(JobRunner):
    """Expire overdue restarts independently from the control consumer."""

    class Meta:
        name = "RPC Execution Queue Expiry Sweep"

    @classmethod
    def enqueue(cls, *args: Any, **kwargs: Any) -> Job:
        kwargs.setdefault("queue_name", RQ_QUEUE_DEFAULT)
        kwargs.setdefault("job_timeout", 60)
        return super().enqueue(*args, **kwargs)

    def run(self, *args: object, **kwargs: object) -> None:
        from .application.command_handlers import expire_stale_restart_executions

        expired = expire_stale_restart_executions()
        self.logger.info("Expired %d overdue production NetBox RQ restarts.", expired)


__all__ = ("RPCExecutionQueueExpirySweepJob",)
