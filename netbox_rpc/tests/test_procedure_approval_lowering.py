"""REST and form guards for lowering approval_required on an RPC procedure (#406)."""

from __future__ import annotations

from types import SimpleNamespace

from django.test import TestCase
from django.urls import reverse
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient
from utilities.exceptions import AbortRequest

from netbox_rpc.api.serializers import RPCProcedureSerializer
from netbox_rpc.forms import RPCProcedureForm
from netbox_rpc.models import RPCProcedure

from ._common import make_procedure, make_user


def _grant(user, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    scope = "scoped" if constraints else "all"
    permission = ObjectPermission.objects.create(
        name=f"lower-approval-{user.username}-{'-'.join(actions)}-{scope}",
        actions=list(actions),
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(RPCProcedure)])
    permission.users.set([user])
    return permission


class ApprovalLoweringGuardTests(TestCase):
    def setUp(self):
        # The procedure is not transport-pinned, so only the approval gate can refuse.
        self.procedure = make_procedure("os.linux.test.approval")
        self.procedure.approval_required = True
        self.procedure.save()
        self.editor = make_user("approval-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        self.approver = make_user("approval-approver", superuser=False)
        _grant(self.approver, ["view", "change", "approve"])
        self.scoped = make_user("approval-scoped", superuser=False)
        _grant(self.scoped, ["view", "change"])
        _grant(
            self.scoped,
            ["view", "approve"],
            constraints={"name": "os.linux.test.other"},
        )
        self.creator = make_user("approval-creator", superuser=False)
        _grant(self.creator, ["view", "add"])
        self.url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail",
            args=[self.procedure.pk],
        )
        self.list_url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-list")

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def _other_required(self, name):
        other = make_procedure(name)
        other.approval_required = True
        other.save()
        return other

    def _full_payload(self, **overrides):
        proc = self.procedure
        payload = {
            "name": proc.name,
            "handler_id": proc.handler_id,
            "version": proc.version,
            "enabled": proc.enabled,
            "target_models": list(proc.target_models or []),
            "effect": proc.effect,
            "timeout_seconds": proc.timeout_seconds,
            "approval_required": proc.approval_required,
            "params_schema": proc.params_schema,
            "result_schema": proc.result_schema,
            "transport_driver": proc.transport_driver,
            "transport_driver_chain": list(proc.transport_driver_chain or []),
            "transport_pinned": proc.transport_pinned,
            "output_parser": proc.output_parser,
            "output_schema": proc.output_schema,
            "description": proc.description,
        }
        payload.update(overrides)
        return payload

    def _required_after(self, procedure):
        procedure.refresh_from_db()
        return procedure.approval_required

    def test_rest_patch_lowering_without_approve_is_refused(self):
        resp = self._client(self.editor).patch(
            self.url, {"approval_required": False}, format="json"
        )
        assert resp.status_code == 400, resp.content
        assert "approval_required" in resp.json()
        assert self._required_after(self.procedure) is True

    def test_rest_patch_lowering_with_approve_is_allowed(self):
        resp = self._client(self.approver).patch(
            self.url, {"approval_required": False}, format="json"
        )
        assert resp.status_code == 200, resp.content
        assert self._required_after(self.procedure) is False

    def test_rest_patch_lowering_with_approval_scoped_to_another_procedure_is_refused(
        self,
    ):
        resp = self._client(self.scoped).patch(
            self.url, {"approval_required": False}, format="json"
        )
        assert resp.status_code == 400, resp.content
        assert self._required_after(self.procedure) is True

    def test_rest_put_lowering_without_approve_is_refused(self):
        payload = self._full_payload(approval_required=False)
        resp = self._client(self.editor).put(self.url, payload, format="json")
        assert resp.status_code == 400, resp.content
        assert "approval_required" in resp.json()
        assert self._required_after(self.procedure) is True

    def test_rest_put_lowering_with_approve_is_allowed(self):
        # Same payload as the refused PUT, so the 400 above comes from the gate.
        payload = self._full_payload(approval_required=False)
        resp = self._client(self.approver).put(self.url, payload, format="json")
        assert resp.status_code == 200, resp.content
        assert self._required_after(self.procedure) is False

    def test_rest_patch_that_omits_the_flag_is_allowed(self):
        resp = self._client(self.editor).patch(
            self.url, {"description": "still required"}, format="json"
        )
        assert resp.status_code == 200, resp.content
        assert self._required_after(self.procedure) is True

    def test_rest_patch_keeping_the_flag_is_allowed(self):
        resp = self._client(self.editor).patch(
            self.url, {"approval_required": True}, format="json"
        )
        assert resp.status_code == 200, resp.content
        assert self._required_after(self.procedure) is True

    def test_rest_patch_on_a_procedure_already_disabled_is_allowed(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(approval_required=False)
        resp = self._client(self.editor).patch(
            self.url, {"approval_required": False}, format="json"
        )
        assert resp.status_code == 200, resp.content
        assert self._required_after(self.procedure) is False

    def test_rest_create_with_approval_disabled_is_allowed(self):
        resp = self._client(self.creator).post(
            self.list_url,
            {
                "name": "os.linux.test.created",
                "handler_id": "os.linux.test.created",
                "approval_required": False,
            },
            format="json",
        )
        assert resp.status_code == 201, resp.content
        created = RPCProcedure.objects.get(name="os.linux.test.created")
        assert created.approval_required is False

    def test_rest_bulk_lowering_without_approve_is_refused_and_changes_nothing(self):
        other = self._other_required("os.linux.test.approval.second")
        resp = self._client(self.editor).patch(
            self.list_url,
            [
                {"id": self.procedure.pk, "approval_required": False},
                {"id": other.pk, "approval_required": False},
            ],
            format="json",
        )
        assert resp.status_code == 400, resp.content
        assert self._required_after(self.procedure) is True
        assert self._required_after(other) is True

    def test_rest_bulk_lowering_with_approve_is_allowed(self):
        other = self._other_required("os.linux.test.approval.third")
        resp = self._client(self.approver).patch(
            self.list_url,
            [
                {"id": self.procedure.pk, "approval_required": False},
                {"id": other.pk, "approval_required": False},
            ],
            format="json",
        )
        assert resp.status_code == 200, resp.content
        assert self._required_after(self.procedure) is False
        assert self._required_after(other) is False

    def test_rest_bulk_refusal_rolls_back_an_earlier_valid_write(self):
        # The valid item has the lower pk, so the batch writes it before refusing the other.
        other = self._other_required("os.linux.test.approval.later")
        resp = self._client(self.editor).patch(
            self.list_url,
            [
                {"id": self.procedure.pk, "description": "batch edit"},
                {"id": other.pk, "approval_required": False},
            ],
            format="json",
        )
        assert resp.status_code == 400, resp.content
        self.procedure.refresh_from_db()
        other.refresh_from_db()
        assert self.procedure.description != "batch edit"
        assert other.approval_required is True

    def test_rest_lowering_both_protected_flags_reports_both(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=True)
        resp = self._client(self.editor).patch(
            self.url,
            {"approval_required": False, "transport_pinned": False},
            format="json",
        )
        assert resp.status_code == 400, resp.content
        assert set(resp.json()) >= {"approval_required", "transport_pinned"}
        self.procedure.refresh_from_db()
        assert self.procedure.approval_required is True
        assert self.procedure.transport_pinned is True

    def test_stale_copy_cannot_clear_approval_set_by_a_concurrent_write(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(approval_required=False)
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        # A concurrent write requires approval again after this request has read its copy.
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(approval_required=True)
        serializer = RPCProcedureSerializer(
            stale,
            data={"approval_required": False},
            partial=True,
            context={"request": SimpleNamespace(user=self.editor)},
        )
        # The early check reads the stale copy and passes. The locked check refuses.
        assert serializer.is_valid(), serializer.errors
        with self.assertRaises(ValidationError):
            serializer.save()
        assert self._required_after(self.procedure) is True

    def test_omitted_flag_does_not_write_back_a_stale_copy(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(approval_required=False)
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(approval_required=True)
        serializer = RPCProcedureSerializer(
            stale,
            data={"description": "edited"},
            partial=True,
            context={"request": SimpleNamespace(user=self.editor)},
        )
        assert serializer.is_valid(), serializer.errors
        serializer.save()
        self.procedure.refresh_from_db()
        assert self.procedure.description == "edited"
        assert self.procedure.approval_required is True

    def test_approve_grant_revoked_before_the_write_is_refused(self):
        revocable = make_user("approval-revoked", superuser=False)
        grant = _grant(revocable, ["view", "change", "approve"])
        serializer = RPCProcedureSerializer(
            self.procedure,
            data={"approval_required": False},
            partial=True,
            context={"request": SimpleNamespace(user=revocable)},
        )
        # The grant is in force at validation, so the early check passes.
        assert serializer.is_valid(), serializer.errors
        # The grant is revoked after validation and before the write.
        grant.delete()
        with self.assertRaises(ValidationError):
            serializer.save()
        assert self._required_after(self.procedure) is True

    def test_form_lock_path_refuses_a_stale_lowering_without_approve(self):
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        stale._netbox_rpc_request = SimpleNamespace(user=self.editor)
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"approval_required": False}
        with self.assertRaises(AbortRequest):
            form._refuse_unpin_under_lock()
        assert self._required_after(self.procedure) is True

    def test_form_lock_path_allows_lowering_with_approve(self):
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        stale._netbox_rpc_request = SimpleNamespace(user=self.approver)
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"approval_required": False}
        # The approver may lower the flag, so the locked check raises nothing.
        form._refuse_unpin_under_lock()
