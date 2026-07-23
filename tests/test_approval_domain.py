"""Pure-domain tests for the two-person approval foundation (issue #164).

These stub ``netbox.plugins`` and exercise the domain layer (value objects,
typed events, projection folds, and the pre-DB aggregate guards) with no
database. The DB-backed lifecycle (real models, event store, immutability,
concurrency, snapshot invalidation) lives in
``netbox_rpc/tests/test_approval_workflow.py``.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest


def _install_netbox_stub() -> None:
    if "netbox.plugins" in sys.modules:
        return
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig
    sys.modules["netbox"] = netbox
    sys.modules["netbox.plugins"] = netbox_plugins


_install_netbox_stub()

from netbox_rpc.domain.aggregate import (  # noqa: E402
    TERMINAL_STATUSES,
    RPCExecutionAggregate,
    RPCExecutionAggregateError,
)
from netbox_rpc.domain.events import (  # noqa: E402
    ApprovalRequested,
    ExecutionApproved,
    ExecutionExpired,
    ExecutionRejected,
    ExecutionRequested,
    from_record,
)
from netbox_rpc.domain.projection import ProjectionState, apply, rebuild  # noqa: E402
from netbox_rpc.domain.value_objects import ExecutionStatus  # noqa: E402


DECIDED_AT = datetime(2026, 1, 2, 3, 6, 5, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2026, 1, 2, 4, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


def test_new_approval_statuses_exist() -> None:
    assert ExecutionStatus.REQUESTED.value == "requested"
    assert ExecutionStatus.PENDING_APPROVAL.value == "pending_approval"
    assert ExecutionStatus.APPROVED.value == "approved"
    assert ExecutionStatus.REJECTED.value == "rejected"
    assert ExecutionStatus.EXPIRED.value == "expired"


def test_approval_terminal_is_reject_and_expire_only() -> None:
    assert ExecutionStatus.approval_terminal() == frozenset(
        {ExecutionStatus.REJECTED, ExecutionStatus.EXPIRED}
    )
    # Rejected/expired are aggregate-terminal; approved/pending are not.
    assert ExecutionStatus.REJECTED.value in TERMINAL_STATUSES
    assert ExecutionStatus.EXPIRED.value in TERMINAL_STATUSES
    assert ExecutionStatus.APPROVED.value not in TERMINAL_STATUSES
    assert ExecutionStatus.PENDING_APPROVAL.value not in TERMINAL_STATUSES


# ---------------------------------------------------------------------------
# Projection folds
# ---------------------------------------------------------------------------


def test_fold_request_then_pending_then_approved() -> None:
    events = [
        ExecutionRequested(requested_by_id=7),
        ApprovalRequested(snapshot_hash="deadbeef", expires_at=EXPIRES_AT),
        ExecutionApproved(
            approved_by_id=9, snapshot_hash="deadbeef", decided_at=DECIDED_AT
        ),
    ]
    assert rebuild(events).status == ExecutionStatus.APPROVED.value


def test_fold_rejected_is_terminal_with_finished_at() -> None:
    events = [
        ExecutionRequested(requested_by_id=7),
        ApprovalRequested(snapshot_hash="h"),
        ExecutionRejected(rejected_by_id=9, decided_at=DECIDED_AT, reason="no"),
    ]
    state = rebuild(events)
    assert state.status == ExecutionStatus.REJECTED.value
    assert state.finished_at == DECIDED_AT


def test_fold_expired_is_terminal_with_finished_at() -> None:
    events = [
        ExecutionRequested(),
        ApprovalRequested(snapshot_hash="h"),
        ExecutionExpired(expired_at=DECIDED_AT),
    ]
    state = rebuild(events)
    assert state.status == ExecutionStatus.EXPIRED.value
    assert state.finished_at == DECIDED_AT


def test_pending_approval_does_not_project_a_job() -> None:
    state = rebuild([ExecutionRequested(), ApprovalRequested(snapshot_hash="h")])
    assert state.status == ExecutionStatus.PENDING_APPROVAL.value
    assert state.job_id is None  # pending approval never enqueues


# ---------------------------------------------------------------------------
# Event serialization round-trips (append-only ledger fidelity)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        ExecutionRequested(requested_by_id=7),
        ApprovalRequested(
            snapshot_hash="abc", expires_at=EXPIRES_AT, requested_by_id=7
        ),
        ExecutionApproved(
            approved_by_id=9, snapshot_hash="abc", decided_at=DECIDED_AT, reason="ok"
        ),
        ExecutionRejected(rejected_by_id=9, decided_at=DECIDED_AT, reason="no"),
        ExecutionExpired(expired_at=DECIDED_AT, reason="timed out"),
    ],
)
def test_event_round_trips_through_record(event) -> None:
    restored = from_record(event.event_name, event.data)
    assert restored.event_name == event.event_name
    # The status the projection cares about survives the round-trip.
    assert (
        apply(ProjectionState.initial(), restored).status
        == apply(ProjectionState.initial(), event).status
    )


# ---------------------------------------------------------------------------
# Aggregate guards that raise BEFORE any DB work
# ---------------------------------------------------------------------------


@dataclass
class FakeSnapshot:
    requested_by_id: object | None
    payload_hash: str = "snap-hash"
    _matches: bool = True

    def matches_current(self, current) -> bool:  # noqa: ANN001
        return self._matches


@dataclass
class FakeExecution:
    status: str
    approval_request: object | None = None
    events: object | None = None


def test_request_approval_requires_requested_status() -> None:
    agg = RPCExecutionAggregate(FakeExecution(status=ExecutionStatus.QUEUED.value))
    with pytest.raises(RPCExecutionAggregateError, match="requested execution"):
        agg.request_approval(snapshot_hash="h")


def test_request_approval_requires_snapshot_hash() -> None:
    agg = RPCExecutionAggregate(FakeExecution(status=ExecutionStatus.REQUESTED.value))
    with pytest.raises(RPCExecutionAggregateError, match="snapshot hash is required"):
        agg.request_approval(snapshot_hash="")


def test_requester_cannot_approve_own_execution() -> None:
    snap = FakeSnapshot(requested_by_id=7)
    agg = RPCExecutionAggregate(
        FakeExecution(
            status=ExecutionStatus.PENDING_APPROVAL.value, approval_request=snap
        )
    )
    with pytest.raises(RPCExecutionAggregateError, match="segregation of duties"):
        agg.approve(approver_id=7, current_protected={"any": "thing"})


def test_reject_requires_authenticated_actor() -> None:
    snap = FakeSnapshot(requested_by_id=7)
    agg = RPCExecutionAggregate(
        FakeExecution(
            status=ExecutionStatus.PENDING_APPROVAL.value, approval_request=snap
        )
    )
    with pytest.raises(RPCExecutionAggregateError, match="authenticated approver"):
        agg.reject(rejecter_id=None)


def test_approve_fails_when_snapshot_no_longer_matches() -> None:
    snap = FakeSnapshot(requested_by_id=7, _matches=False)
    agg = RPCExecutionAggregate(
        FakeExecution(
            status=ExecutionStatus.PENDING_APPROVAL.value, approval_request=snap
        )
    )
    with pytest.raises(RPCExecutionAggregateError, match="no longer matches"):
        agg.approve(approver_id=9, current_protected={"drifted": True})


def test_decide_requires_a_snapshot() -> None:
    agg = RPCExecutionAggregate(
        FakeExecution(
            status=ExecutionStatus.PENDING_APPROVAL.value, approval_request=None
        )
    )
    with pytest.raises(
        RPCExecutionAggregateError, match="no approval request snapshot"
    ):
        agg.approve(approver_id=9)
