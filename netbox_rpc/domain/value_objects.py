from __future__ import annotations

from enum import StrEnum


class ExecutionStatus(StrEnum):
    # Approval-workflow states (issue #164). ``REQUESTED`` and
    # ``PENDING_APPROVAL`` precede the existing execution lifecycle; an
    # approval-required request may only reach ``QUEUED`` after a distinct
    # second actor records ``APPROVED``. ``REJECTED`` and ``EXPIRED`` are
    # terminal decisions that can never fold back into an active run.
    #
    # These states are ADDITIVE: the pre-existing direct flow still starts at
    # ``QUEUED``. Routing ``approval_required`` procedures through the
    # request/pending path (enforcement) is deferred to issue #165 — this
    # module only makes the vocabulary and folds available.
    REQUESTED = "requested"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @classmethod
    def approval_terminal(cls) -> frozenset[ExecutionStatus]:
        """Terminal approval decisions that must never replay as an approval."""
        return frozenset({cls.REJECTED, cls.EXPIRED})


class Effect(StrEnum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class ExecutionMode(StrEnum):
    """How the procedures grouped by an ``RPCIntent`` are triggered.

    An intent declares *what* needs to be done; its grouped procedures (with
    their commands) declare *how*. The mode declares the trigger topology:

    - ``SEQUENTIAL`` — the grouped procedures are nested and triggered one after
      another in the declared ``sequence`` order.
    - ``PARALLEL`` — the grouped procedures are triggered concurrently, with no
      nesting at all (the per-procedure ``sequence`` is then informational).
    """

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
