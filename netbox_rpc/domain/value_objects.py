from __future__ import annotations

from enum import StrEnum


class ExecutionStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


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
