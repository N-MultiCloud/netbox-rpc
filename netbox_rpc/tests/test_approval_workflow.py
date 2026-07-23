"""DB-backed integration tests for the two-person approval foundation (#164).

Exercises the real ``RPCExecution`` aggregate, ``RPCApprovalRequest`` immutable
snapshot, and event store against a NetBox test database: pending approval never
enqueues, segregation of duties, terminal reject/expire, concurrency-safe single
decision, snapshot invalidation + immutability, and event-replay parity.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase

from netbox_rpc import event_store
from netbox_rpc.domain.aggregate import (
    RPCExecutionAggregate,
    RPCExecutionAggregateError,
)
from netbox_rpc.domain.value_objects import ExecutionStatus
from netbox_rpc.models import RPCApprovalRequest

from ._common import device_ct, event_names, make_execution, make_user


def _make_snapshot(execution, requester, **overrides) -> RPCApprovalRequest:
    fields = {
        "execution": execution,
        "procedure_id": execution.procedure_id,
        "procedure_version": "1",
        "effect": "write",
        "target_type_id": device_ct().pk,
        "target_id": execution.assigned_object_id,
        "target_snapshot_hash": "target-hash",
        "normalized_params": {"target": "edge-01"},
        "command_fingerprint": {"handler_id": "handler"},
        "backend_id": None,
        "credential_policy_ref": "cred-policy:1",
        "requested_by_id": requester.pk,
        "expires_at": None,
        "stream_version": 1,
    }
    fields.update(overrides)
    return RPCApprovalRequest.objects.create(**fields)


def _open_pending(*, requester, approver=None):
    """Drive an execution to PENDING_APPROVAL and return (execution, snapshot)."""
    ex = make_execution(user=requester)
    agg = RPCExecutionAggregate(ex)
    agg.request(requested_by_id=requester.pk)
    snap = _make_snapshot(ex, requester)
    agg.request_approval(snapshot_hash=snap.payload_hash, requested_by_id=requester.pk)
    ex.refresh_from_db()
    return ex, snap


class ApprovalWorkflowTests(TestCase):
    def setUp(self):
        self.requester = make_user("rpc-requester", superuser=False)
        self.approver = make_user("rpc-approver", superuser=False)

    def test_pending_approval_never_enqueues(self):
        ex, _ = _open_pending(requester=self.requester)
        assert ex.status == ExecutionStatus.PENDING_APPROVAL.value
        assert event_names(ex) == ["ExecutionRequested", "ApprovalRequested"]
        # No queue/enqueue/backend events, no job id.
        assert "ExecutionQueued" not in event_names(ex)
        assert "JobEnqueued" not in event_names(ex)
        assert ex.job_id is None

    def test_requester_cannot_approve_own_execution(self):
        ex, snap = _open_pending(requester=self.requester)
        agg = RPCExecutionAggregate(ex)
        with self.assertRaises(RPCExecutionAggregateError):
            agg.approve(
                approver_id=self.requester.pk,
                current_protected=snap.protected_payload(),
            )
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.PENDING_APPROVAL.value

    def test_second_actor_can_approve(self):
        ex, snap = _open_pending(requester=self.requester)
        RPCExecutionAggregate(ex).approve(
            approver_id=self.approver.pk,
            current_protected=snap.protected_payload(),
        )
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.APPROVED.value
        assert "ExecutionApproved" in event_names(ex)

    def test_reject_is_terminal_and_cannot_be_approved(self):
        ex, snap = _open_pending(requester=self.requester)
        RPCExecutionAggregate(ex).reject(rejecter_id=self.approver.pk, reason="no")
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.REJECTED.value
        assert ex.finished_at is not None
        with self.assertRaises(RPCExecutionAggregateError):
            RPCExecutionAggregate(ex).approve(
                approver_id=self.approver.pk,
                current_protected=snap.protected_payload(),
            )

    def test_expire_is_terminal(self):
        ex, _ = _open_pending(requester=self.requester)
        RPCExecutionAggregate(ex).expire(reason="timed out")
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.EXPIRED.value
        assert ex.finished_at is not None

    def test_double_approval_yields_one_decision(self):
        ex, snap = _open_pending(requester=self.requester)
        RPCExecutionAggregate(ex).approve(
            approver_id=self.approver.pk,
            current_protected=snap.protected_payload(),
        )
        ex.refresh_from_db()
        # A second decision on an already-decided execution is rejected.
        with self.assertRaises(RPCExecutionAggregateError):
            RPCExecutionAggregate(ex).approve(
                approver_id=self.approver.pk,
                current_protected=snap.protected_payload(),
            )
        assert event_names(ex).count("ExecutionApproved") == 1

    def test_snapshot_drift_invalidates_approval(self):
        ex, snap = _open_pending(requester=self.requester)
        drifted = dict(snap.protected_payload())
        drifted["effect"] = "destructive"  # a protected field changed
        with self.assertRaises(RPCExecutionAggregateError):
            RPCExecutionAggregate(ex).approve(
                approver_id=self.approver.pk, current_protected=drifted
            )
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.PENDING_APPROVAL.value

    def test_snapshot_matches_current_hash_semantics(self):
        ex, snap = _open_pending(requester=self.requester)
        assert snap.payload_hash  # stamped on save
        assert snap.matches_current(snap.protected_payload()) is True
        drifted = dict(snap.protected_payload())
        drifted["normalized_params"] = {"target": "somewhere-else"}
        assert snap.matches_current(drifted) is False

    def test_snapshot_is_immutable(self):
        ex, snap = _open_pending(requester=self.requester)
        snap.credential_policy_ref = "cred-policy:tampered"
        with self.assertRaises(ValidationError):
            snap.save()
        with self.assertRaises(ValidationError):
            snap.delete()

    def test_event_replay_reconstructs_approved_projection(self):
        ex, snap = _open_pending(requester=self.requester)
        RPCExecutionAggregate(ex).approve(
            approver_id=self.approver.pk,
            current_protected=snap.protected_payload(),
        )
        ex.refresh_from_db()
        rebuilt = event_store.rebuild_projection(ex)
        assert rebuilt.status == ExecutionStatus.APPROVED.value
        assert rebuilt.status == ex.status  # projection parity

    def test_request_must_be_first_event(self):
        ex = make_execution(user=self.requester)
        event_store.record_execution_queued(ex)  # a non-approval stream
        with self.assertRaises(RPCExecutionAggregateError):
            RPCExecutionAggregate(ex).request(requested_by_id=self.requester.pk)
