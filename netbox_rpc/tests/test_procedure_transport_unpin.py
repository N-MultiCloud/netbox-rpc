"""REST and form guards for un-pinning a transport-pinned procedure (#246)."""

from __future__ import annotations

from types import SimpleNamespace

from django.test import TestCase
from django.urls import reverse
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient
from utilities.exceptions import AbortRequest

from extras.models import Tag

from netbox_rpc.api.serializers import RPCProcedureSerializer
from netbox_rpc.forms import RPCProcedureForm
from netbox_rpc.models import RPCProcedure

from ._common import make_procedure, make_user


def _grant(user, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    scope = "scoped" if constraints else "all"
    permission = ObjectPermission.objects.create(
        name=f"unpin-{user.username}-{'-'.join(actions)}-{scope}",
        actions=list(actions),
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(RPCProcedure)])
    permission.users.set([user])
    return permission


class TransportUnpinGuardTests(TestCase):
    def setUp(self):
        self.procedure = make_procedure("os.linux.test.pinned")
        self.procedure.transport_pinned = True
        self.procedure.save()
        self.editor = make_user("unpin-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        self.approver = make_user("unpin-approver", superuser=False)
        _grant(self.approver, ["view", "change", "approve"])
        self.tagged = make_user("unpin-tagged", superuser=False)
        _grant(self.tagged, ["view", "change"])
        self.scoped = make_user("unpin-scoped", superuser=False)
        _grant(self.scoped, ["view", "change"])
        _grant(
            self.scoped,
            ["view", "approve"],
            constraints={"name": "os.linux.test.other"},
        )
        self.url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail",
            args=[self.procedure.pk],
        )
        self.list_url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-list")

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def _other_pinned(self, name):
        other = make_procedure(name)
        other.transport_pinned = True
        other.save()
        return other

    def _bulk_unpin(self, other):
        return [
            {"id": self.procedure.pk, "transport_pinned": False},
            {"id": other.pk, "transport_pinned": False},
        ]

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

    def test_rest_patch_unpin_without_approve_is_refused(self):
        resp = self._client(self.editor).patch(
            self.url, {"transport_pinned": False}, format="json"
        )
        assert resp.status_code == 400, resp.content
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_rest_patch_unpin_with_approve_is_allowed(self):
        resp = self._client(self.approver).patch(
            self.url, {"transport_pinned": False}, format="json"
        )
        assert resp.status_code == 200, resp.content
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is False

    def test_rest_patch_unpin_with_approval_scoped_to_another_procedure_is_refused(
        self,
    ):
        resp = self._client(self.scoped).patch(
            self.url, {"transport_pinned": False}, format="json"
        )
        assert resp.status_code == 400, resp.content
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_rest_put_unpin_without_approve_is_refused(self):
        payload = self._full_payload(transport_pinned=False)
        resp = self._client(self.editor).put(self.url, payload, format="json")
        assert resp.status_code == 400, resp.content
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_rest_put_unpin_with_approve_is_allowed(self):
        # Same payload as the refused PUT, so the 400 above comes from the gate.
        payload = self._full_payload(transport_pinned=False)
        resp = self._client(self.approver).put(self.url, payload, format="json")
        assert resp.status_code == 200, resp.content
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is False

    def test_rest_patch_that_omits_the_pin_is_allowed(self):
        resp = self._client(self.editor).patch(
            self.url, {"description": "still pinned"}, format="json"
        )
        assert resp.status_code == 200, resp.content
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_rest_bulk_unpin_without_approve_is_refused_and_changes_nothing(self):
        other = self._other_pinned("os.linux.test.pinned.second")
        resp = self._client(self.editor).patch(
            self.list_url, self._bulk_unpin(other), format="json"
        )
        assert resp.status_code == 400, resp.content
        self.procedure.refresh_from_db()
        other.refresh_from_db()
        assert self.procedure.transport_pinned is True
        assert other.transport_pinned is True

    def test_rest_bulk_unpin_with_approval_scoped_to_another_procedure_is_refused(
        self,
    ):
        other = self._other_pinned("os.linux.test.pinned.third")
        resp = self._client(self.scoped).patch(
            self.list_url, self._bulk_unpin(other), format="json"
        )
        assert resp.status_code == 400, resp.content
        self.procedure.refresh_from_db()
        other.refresh_from_db()
        assert self.procedure.transport_pinned is True
        assert other.transport_pinned is True

    def test_rest_bulk_unpin_with_approve_is_allowed(self):
        other = self._other_pinned("os.linux.test.pinned.fourth")
        resp = self._client(self.approver).patch(
            self.list_url, self._bulk_unpin(other), format="json"
        )
        assert resp.status_code == 200, resp.content
        self.procedure.refresh_from_db()
        other.refresh_from_db()
        assert self.procedure.transport_pinned is False
        assert other.transport_pinned is False

    def test_serializer_allows_creating_an_unpinned_procedure(self):
        serializer = RPCProcedureSerializer(
            data={
                "name": "os.linux.test.createdunpinned",
                "handler_id": "os.linux.test.createdunpinned",
                "transport_pinned": False,
            },
            context={"request": SimpleNamespace(user=self.editor)},
        )
        serializer.is_valid(raise_exception=True)
        created = serializer.save()
        created.refresh_from_db()
        assert created.transport_pinned is False

    def _bound_form(self, user, data):
        setattr(self.procedure, "_netbox_rpc_request", SimpleNamespace(user=user))
        return RPCProcedureForm(data=data, instance=self.procedure)

    def _minimal_data(self):
        # Other required fields are left out on purpose. The assertions only read
        # the error keys that the gates add. An unchecked box is absent from data.
        return {"name": self.procedure.name, "handler_id": self.procedure.handler_id}

    def test_bound_form_refuses_unpin_without_approve(self):
        form = self._bound_form(self.editor, self._minimal_data())
        assert form.is_valid() is False
        assert "transport_pinned" in form.errors

    def test_bound_form_refuses_unpin_with_approval_scoped_to_another_procedure(self):
        form = self._bound_form(self.scoped, self._minimal_data())
        assert form.is_valid() is False
        assert "transport_pinned" in form.errors

    def test_bound_form_allows_unpin_with_approve(self):
        form = self._bound_form(self.approver, self._minimal_data())
        form.is_valid()
        assert "transport_pinned" not in form.errors

    def test_bound_form_refuses_lowering_approval_required_without_approve(self):
        self.procedure.approval_required = True
        self.procedure.save()
        data = self._minimal_data()
        data["transport_pinned"] = "on"
        form = self._bound_form(self.editor, data)
        form.is_valid()
        assert "approval_required" in form.errors

    def test_stale_copy_cannot_clear_a_pin_set_by_a_concurrent_write(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=False)
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        # A concurrent write re-pins the row after this request has read its copy.
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=True)
        serializer = RPCProcedureSerializer(
            stale,
            data={"transport_pinned": False},
            partial=True,
            context={"request": SimpleNamespace(user=self.editor)},
        )
        # The early check reads the stale copy and passes. The locked check refuses.
        assert serializer.is_valid(), serializer.errors
        with self.assertRaises(ValidationError):
            serializer.save()
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_omitted_pin_does_not_write_back_a_stale_copy(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=False)
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=True)
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
        assert self.procedure.transport_pinned is True

    def test_form_save_check_reads_the_committed_pin_under_the_lock(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=False)
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=True)
        setattr(stale, "_netbox_rpc_request", SimpleNamespace(user=self.editor))
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"transport_pinned": False}
        with self.assertRaises(AbortRequest):
            form._refuse_unpin_under_lock()
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_form_save_check_allows_the_unpin_with_approve(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=False)
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(transport_pinned=True)
        setattr(stale, "_netbox_rpc_request", SimpleNamespace(user=self.approver))
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"transport_pinned": False}
        # The approver may un-pin, so the locked check raises nothing.
        form._refuse_unpin_under_lock()

    def test_approve_scope_removed_before_the_write_is_refused(self):
        tag = Tag.objects.create(name="Pin approvers", slug="pin-approvers")
        self.procedure.tags.add(tag)
        _grant(
            self.tagged,
            ["view", "approve"],
            constraints={"tags__slug": "pin-approvers"},
        )
        serializer = RPCProcedureSerializer(
            self.procedure,
            data={"transport_pinned": False},
            partial=True,
            context={"request": SimpleNamespace(user=self.tagged)},
        )
        # The tag still qualifies the user when the request is validated.
        assert serializer.is_valid(), serializer.errors
        # Another write removes the qualifying tag before this write takes the lock.
        self.procedure.tags.remove(tag)
        with self.assertRaises(ValidationError):
            serializer.save()
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_form_approve_scope_is_read_at_write_time(self):
        tag = Tag.objects.create(name="Pin approvers", slug="pin-approvers")
        self.procedure.tags.add(tag)
        _grant(
            self.tagged,
            ["view", "approve"],
            constraints={"tags__slug": "pin-approvers"},
        )
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        setattr(stale, "_netbox_rpc_request", SimpleNamespace(user=self.tagged))
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"transport_pinned": False}
        # While the tag qualifies the user, the un-pin is allowed.
        form._refuse_unpin_under_lock()
        # Once the tag is gone, the same request is refused at write time.
        self.procedure.tags.remove(tag)
        with self.assertRaises(AbortRequest):
            form._refuse_unpin_under_lock()
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_rest_bulk_refusal_rolls_back_an_earlier_valid_write(self):
        # The valid item has the lower pk, so the batch writes it before refusing the other.
        other = self._other_pinned("os.linux.test.pinned.later")
        resp = self._client(self.editor).patch(
            self.list_url,
            [
                {"id": self.procedure.pk, "description": "batch edit"},
                {"id": other.pk, "transport_pinned": False},
            ],
            format="json",
        )
        assert resp.status_code == 400, resp.content
        self.procedure.refresh_from_db()
        other.refresh_from_db()
        assert self.procedure.description != "batch edit"
        assert other.transport_pinned is True

    def test_approve_grant_revoked_before_the_write_is_refused(self):
        revocable = make_user("unpin-revoked", superuser=False)
        grant = _grant(revocable, ["view", "change", "approve"])
        serializer = RPCProcedureSerializer(
            self.procedure,
            data={"transport_pinned": False},
            partial=True,
            context={"request": SimpleNamespace(user=revocable)},
        )
        # The grant is in force at validation, so the early check passes.
        assert serializer.is_valid(), serializer.errors
        # The grant is revoked after validation and before the write.
        grant.delete()
        with self.assertRaises(ValidationError):
            serializer.save()
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True

    def test_form_approve_grant_revoked_before_the_save_is_refused(self):
        revocable = make_user("unpin-revoked-form", superuser=False)
        grant = _grant(revocable, ["view", "change", "approve"])
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        setattr(stale, "_netbox_rpc_request", SimpleNamespace(user=revocable))
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"transport_pinned": False}
        # While the grant is in force, the un-pin is allowed.
        form._refuse_unpin_under_lock()
        grant.delete()
        with self.assertRaises(AbortRequest):
            form._refuse_unpin_under_lock()
        self.procedure.refresh_from_db()
        assert self.procedure.transport_pinned is True
