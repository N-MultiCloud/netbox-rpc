"""Command-only approve/reject API + object authorization tests (issue #165).

Builds on the #164 aggregate: the API actions add permission + object-scope
gates, and delegate segregation-of-duties + single-decision concurrency to the
aggregate. State is never mutated via CRUD (PUT/PATCH/DELETE disabled).
"""

from __future__ import annotations

from django.test import TestCase
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APIClient
from django.urls import reverse

from netbox_rpc.application.command_handlers import approve_execution
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.domain.value_objects import ExecutionStatus
from netbox_rpc.models import RPCApprovalRequest

from ._common import device_ct, make_execution, make_procedure, make_user


def _make_pending(requester):
    ex = make_execution(user=requester)
    agg = RPCExecutionAggregate(ex)
    agg.request(requested_by_id=requester.pk)
    snap = RPCApprovalRequest.objects.create(
        execution=ex,
        procedure_id=ex.procedure_id,
        procedure_version="1",
        effect="write",
        target_type_id=device_ct().pk,
        target_id=ex.assigned_object_id,
        target_snapshot_hash="target-hash",
        normalized_params={"target": "edge-01"},
        command_fingerprint={"handler_id": "handler"},
        credential_policy_ref="cred-policy:1",
        requested_by_id=requester.pk,
        stream_version=1,
    )
    agg.request_approval(snapshot_hash=snap.payload_hash, requested_by_id=requester.pk)
    ex.refresh_from_db()
    return ex


def _url(name, ex):
    return reverse(f"plugins-api:netbox_rpc-api:rpcexecution-{name}", args=[ex.pk])


class ApprovalApiTests(TestCase):
    def setUp(self):
        self.requester = make_user("api-requester", superuser=True)
        self.approver = make_user("api-approver", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.approver)

    def test_second_actor_can_approve_via_api(self):
        ex = _make_pending(self.requester)
        resp = self.client.post(_url("approve", ex), {"reason": "ok"}, format="json")
        assert resp.status_code == 200, resp.content
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.APPROVED.value

    def test_requester_cannot_approve_own_via_api(self):
        ex = _make_pending(self.requester)
        self.client.force_authenticate(user=self.requester)
        resp = self.client.post(_url("approve", ex), {}, format="json")
        # Aggregate segregation-of-duties -> ValidationError -> HTTP 400.
        assert resp.status_code == 400, resp.content
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.PENDING_APPROVAL.value

    def test_reject_via_api_is_terminal(self):
        ex = _make_pending(self.requester)
        resp = self.client.post(_url("reject", ex), {"reason": "no"}, format="json")
        assert resp.status_code == 200, resp.content
        ex.refresh_from_db()
        assert ex.status == ExecutionStatus.REJECTED.value

    def test_double_approve_via_api_yields_single_decision(self):
        ex = _make_pending(self.requester)
        assert (
            self.client.post(_url("approve", ex), {}, format="json").status_code == 200
        )
        # Second decision on an already-decided execution is rejected.
        assert (
            self.client.post(_url("approve", ex), {}, format="json").status_code == 400
        )
        ex.refresh_from_db()
        names = list(ex.events.values_list("event", flat=True))
        assert names.count("ExecutionApproved") == 1

    def test_approve_action_is_post_only(self):
        ex = _make_pending(self.requester)
        # GET/PUT/PATCH/DELETE are not valid on the command action / aggregate.
        assert self.client.get(_url("approve", ex)).status_code == 405
        assert (
            self.client.put(_url("approve", ex), {}, format="json").status_code == 405
        )
        assert self.client.delete(_url("approve", ex)).status_code == 405


class ApprovalAuthorizationTests(TestCase):
    """Handler-level object authorization for the decision command."""

    def setUp(self):
        self.requester = make_user("authz-requester", superuser=True)

    def test_missing_approve_permission_is_denied(self):
        ex = _make_pending(self.requester)
        nobody = make_user("authz-nobody", superuser=False)
        with self.assertRaises(PermissionDenied):
            approve_execution(ex, nobody)

    def test_object_scoped_out_actor_is_denied(self):
        from core.models import ObjectType
        from users.models import ObjectPermission

        ex = _make_pending(self.requester)
        scoped = make_user("authz-scoped", superuser=False)
        # Grant approve+view on procedures, but constrained to a DIFFERENT
        # procedure so the target procedure is outside the actor's scope.
        perm = ObjectPermission.objects.create(
            name="scoped-approve",
            actions=["view", "approve"],
            constraints={"name": "some.other.procedure"},
        )
        perm.object_types.set(
            [ObjectType.objects.get_for_model(make_procedure().__class__)]
        )
        perm.users.set([scoped])
        scoped = make_user("authz-scoped", superuser=False)  # refresh perm cache
        with self.assertRaises(PermissionDenied):
            approve_execution(ex, scoped)
