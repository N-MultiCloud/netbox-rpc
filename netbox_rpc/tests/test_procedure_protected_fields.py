"""REST and form guards for the protected RPC procedure fields (issue 424).

A user with the change permission and without the approve permission scoped to
the stored procedure cannot lower ``effect``, enable a disabled procedure, or
change the driver fields, the dispatch identity (handler, name, version), the
target models, the parameter or result schema, the timeout, or the output
parser and schema. The response is 400, or a form error, and the stored row is
unchanged.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient
from utilities.exceptions import AbortRequest

from netbox_rpc.api.serializers import RPCProcedureSerializer
from netbox_rpc.forms import RPCProcedureForm
from netbox_rpc.models import RPCProcedure

from ._common import make_procedure, make_user

_STORED = {
    "effect": "destructive",
    "enabled": False,
    "transport_driver": "asyncssh",
    "transport_driver_chain": ["asyncssh"],
}
# One refused change per protected field, as a REST PATCH body.
_REFUSED_CHANGES = {
    "effect-destructive-to-write": {"effect": "write"},
    "effect-destructive-to-read": {"effect": "read"},
    "enable-disabled": {"enabled": True},
    "driver-change": {"transport_driver": "ansible"},
    "driver-chain-change": {"transport_driver_chain": ["ansible", "asyncssh"]},
    "driver-chain-cleared": {"transport_driver_chain": []},
    "handler-change": {"handler_id": "os.linux.test.other_handler"},
    "rename": {"name": "os.linux.test.renamed"},
    "version-change": {"version": 2},
    "target-models-change": {"target_models": ["dcim.device"]},
    "params-schema-change": {"params_schema": {"type": "object"}},
    "timeout-change": {"timeout_seconds": 90},
    "result-schema-change": {"result_schema": {"type": "object"}},
    "output-parser-change": {"output_parser": "json"},
    "output-schema-change": {"output_schema": {"regex": "x"}},
}
# Every protected field, read back to prove a refused write changed nothing.
_ALL_PROTECTED = (
    "transport_pinned",
    "approval_required",
    "effect",
    "enabled",
    "transport_driver",
    "transport_driver_chain",
    "handler_id",
    "name",
    "version",
    "target_models",
    "params_schema",
    "timeout_seconds",
    "result_schema",
    "output_parser",
    "output_schema",
)


def _grant(user, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    scope = "scoped" if constraints else "all"
    permission = ObjectPermission.objects.create(
        name=f"protected-{user.username}-{'-'.join(actions)}-{scope}",
        actions=list(actions),
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(RPCProcedure)])
    permission.users.set([user])
    return permission


class ProtectedProcedureFieldTests(TestCase):
    def setUp(self):
        # Neither pinned nor approval-gated, so only the fields under test can refuse.
        self.procedure = make_procedure("os.linux.test.protected")
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(
            approval_required=False, transport_pinned=False, **_STORED
        )
        self.procedure.refresh_from_db()
        self.editor = make_user("protected-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        self.approver = make_user("protected-approver", superuser=False)
        _grant(self.approver, ["view", "change", "approve"])
        self.scoped = make_user("protected-scoped", superuser=False)
        _grant(self.scoped, ["view", "change"])
        _grant(self.scoped, ["view", "approve"], constraints={"name": "os.linux.test.other"})
        self.url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[self.procedure.pk]
        )
        self.list_url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-list")

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def _stored(self):
        row = RPCProcedure.objects.get(pk=self.procedure.pk)
        return {field: getattr(row, field) for field in _STORED}

    def _all_protected(self):
        row = RPCProcedure.objects.get(pk=self.procedure.pk)
        return {field: getattr(row, field) for field in _ALL_PROTECTED}

    def _patch(self, user, body):
        return self._client(user).patch(self.url, body, format="json")

    def test_rest_changes_without_approve_are_refused_and_change_nothing(self):
        before = self._all_protected()
        for label, body in _REFUSED_CHANGES.items():
            with self.subTest(label):
                resp = self._patch(self.editor, body)
                assert resp.status_code == 400, resp.content
                assert set(body) <= set(resp.json()), resp.json()
                assert self._all_protected() == before

    def test_rest_changes_with_approval_scoped_to_another_procedure_are_refused(self):
        before = self._all_protected()
        for label, body in _REFUSED_CHANGES.items():
            with self.subTest(label):
                resp = self._patch(self.scoped, body)
                assert resp.status_code == 400, resp.content
                assert self._all_protected() == before

    def test_rest_changes_with_approve_are_allowed(self):
        before = self._all_protected()
        for label, body in _REFUSED_CHANGES.items():
            with self.subTest(label):
                RPCProcedure.objects.filter(pk=self.procedure.pk).update(**before)
                resp = self._patch(self.approver, body)
                assert resp.status_code == 200, resp.content
                row = RPCProcedure.objects.get(pk=self.procedure.pk)
                for field, value in body.items():
                    assert getattr(row, field) == value, field

    def test_rest_put_lowering_effect_without_approve_is_refused(self):
        proc = self.procedure
        payload = {
            "name": proc.name,
            "handler_id": proc.handler_id,
            "version": proc.version,
            "enabled": proc.enabled,
            "target_models": list(proc.target_models or []),
            "effect": "read",
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
        resp = self._client(self.editor).put(self.url, payload, format="json")
        assert resp.status_code == 400, resp.content
        assert "effect" in resp.json()
        assert self._stored() == _STORED
        # The same payload succeeds for the approver, so the 400 comes from the gate.
        resp = self._client(self.approver).put(self.url, payload, format="json")
        assert resp.status_code == 200, resp.content

    def test_rest_tightening_and_unchanged_values_are_allowed(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(effect="read", enabled=True)
        for body in (
            {"effect": "write"},
            {"effect": "destructive"},
            {"enabled": False},
            {"transport_driver": "asyncssh", "transport_driver_chain": ["asyncssh"]},
            {"description": "edited"},
        ):
            with self.subTest(body):
                resp = self._patch(self.editor, body)
                assert resp.status_code == 200, resp.content
        row = RPCProcedure.objects.get(pk=self.procedure.pk)
        assert row.effect == "destructive"
        assert row.enabled is False

    def test_rest_bulk_change_without_approve_is_refused_and_changes_nothing(self):
        other = make_procedure("os.linux.test.protected.second")
        RPCProcedure.objects.filter(pk=other.pk).update(**_STORED)
        resp = self._client(self.editor).patch(
            self.list_url,
            [
                {"id": self.procedure.pk, "description": "batch edit"},
                {"id": other.pk, "effect": "read"},
            ],
            format="json",
        )
        assert resp.status_code == 400, resp.content
        assert RPCProcedure.objects.get(pk=other.pk).effect == "destructive"
        assert RPCProcedure.objects.get(pk=self.procedure.pk).description != "batch edit"

    def test_stale_copy_cannot_lower_an_effect_raised_by_a_concurrent_write(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(effect="read")
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(effect="destructive")
        serializer = RPCProcedureSerializer(
            stale,
            data={"effect": "read"},
            partial=True,
            context={"request": SimpleNamespace(user=self.editor)},
        )
        # The early check reads the stale copy and passes. The locked check refuses.
        assert serializer.is_valid(), serializer.errors
        with self.assertRaises(ValidationError):
            serializer.save()
        assert self._stored() == _STORED

    def test_omitted_fields_do_not_write_back_a_stale_copy(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(
            effect="read", enabled=True, transport_driver="ansible", transport_driver_chain=[]
        )
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(**_STORED)
        serializer = RPCProcedureSerializer(
            stale,
            data={"description": "edited"},
            partial=True,
            context={"request": SimpleNamespace(user=self.editor)},
        )
        assert serializer.is_valid(), serializer.errors
        serializer.save()
        assert self._stored() == _STORED
        assert RPCProcedure.objects.get(pk=self.procedure.pk).description == "edited"

    def _form_data(self, **overrides):
        proc = self.procedure
        data = {
            "name": proc.name,
            "handler_id": proc.handler_id,
            "version": proc.version,
            "target_models": "[]",
            "effect": proc.effect,
            "timeout_seconds": proc.timeout_seconds,
            "params_schema": "{}",
            "result_schema": "{}",
            "transport_driver": proc.transport_driver,
            "transport_driver_chain": ",".join(proc.transport_driver_chain),
            "output_parser": proc.output_parser,
            "output_schema": "{}",
        }
        data.update(overrides)
        return data

    def _bound_form(self, user, data):
        instance = RPCProcedure.objects.get(pk=self.procedure.pk)
        instance._netbox_rpc_request = SimpleNamespace(user=user)
        return RPCProcedureForm(data=data, instance=instance)

    def test_form_refuses_each_change_without_approve(self):
        cases = {
            "effect": {"effect": "write"},
            "enabled": {"enabled": "on"},
            "transport_driver": {"transport_driver": "ansible"},
            "transport_driver_chain": {"transport_driver_chain": "ansible,asyncssh"},
            "handler_id": {"handler_id": "os.linux.test.other_handler"},
            "name": {"name": "os.linux.test.renamed"},
            "version": {"version": 2},
            "target_models": {"target_models": '["dcim.device"]'},
            "params_schema": {"params_schema": '{"type": "object"}'},
            "timeout_seconds": {"timeout_seconds": 90},
            "result_schema": {"result_schema": '{"type": "object"}'},
            "output_parser": {"output_parser": "json"},
            "output_schema": {"output_schema": '{"regex": "x"}'},
        }
        for field, overrides in cases.items():
            with self.subTest(field):
                form = self._bound_form(self.editor, self._form_data(**overrides))
                assert form.is_valid() is False
                assert field in form.errors, form.errors
                scoped = self._bound_form(self.scoped, self._form_data(**overrides))
                assert scoped.is_valid() is False
                assert field in scoped.errors, scoped.errors

    def test_form_accepts_an_unchanged_submission_and_each_change_with_approve(self):
        form = self._bound_form(self.editor, self._form_data(description="edited"))
        assert form.is_valid(), form.errors
        for overrides in (
            {"effect": "read"},
            {"enabled": "on"},
            {"transport_driver": "ansible"},
            {"transport_driver_chain": "ansible"},
            {"handler_id": "os.linux.test.other_handler"},
            {"target_models": '["dcim.device"]'},
            {"params_schema": '{"type": "object"}'},
            {"timeout_seconds": 90},
        ):
            with self.subTest(overrides):
                form = self._bound_form(self.approver, self._form_data(**overrides))
                assert form.is_valid(), form.errors

    def test_form_lock_path_refuses_a_stale_change_without_approve(self):
        for field, value in (
            ("effect", "read"),
            ("enabled", True),
            ("transport_driver", "ansible"),
            ("transport_driver_chain", ["ansible"]),
            ("handler_id", "os.linux.test.other_handler"),
            ("name", "os.linux.test.renamed"),
            ("target_models", ["dcim.device"]),
            ("params_schema", {"type": "object"}),
        ):
            with self.subTest(field):
                stale = RPCProcedure.objects.get(pk=self.procedure.pk)
                stale._netbox_rpc_request = SimpleNamespace(user=self.editor)
                form = RPCProcedureForm(instance=stale)
                form.cleaned_data = {field: value}
                with self.assertRaises(AbortRequest):
                    form._refuse_unpin_under_lock()
                assert self._stored() == _STORED

    def test_form_lock_path_allows_a_change_with_approve(self):
        stale = RPCProcedure.objects.get(pk=self.procedure.pk)
        stale._netbox_rpc_request = SimpleNamespace(user=self.approver)
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"effect": "read", "enabled": True, "transport_driver": "ansible"}
        form._refuse_unpin_under_lock()


def _canonical(value):
    # PostgreSQL jsonb reorders keys; json.dumps still tells true from 1 and 1 from 1.0.
    return json.dumps(value, sort_keys=True)


class TypeExactChangeTests(TestCase):
    """A value of another type is a change, even where Python's == says it is equal."""

    _CASES = {
        "bool-to-int": ({"type": "object", "x": True}, {"type": "object", "x": 1}),
        "int-to-float": ({"type": "object", "x": 1}, {"type": "object", "x": 1.0}),
        "zero-to-false": ({"type": "object", "x": 0}, {"type": "object", "x": False}),
    }

    def setUp(self):
        self.procedure = make_procedure("os.linux.test.typeexact")
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(
            approval_required=False, transport_pinned=False
        )
        self.editor = make_user("typeexact-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        self.approver = make_user("typeexact-approver", superuser=False)
        _grant(self.approver, ["view", "change", "approve"])
        self.url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[self.procedure.pk]
        )

    def _set_schema(self, schema):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(params_schema=schema)

    def _schema(self):
        return RPCProcedure.objects.get(pk=self.procedure.pk).params_schema

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def test_rest_type_change_is_refused_without_approve_and_allowed_with_it(self):
        for label, (stored, requested) in self._CASES.items():
            with self.subTest(label):
                self._set_schema(stored)
                resp = self._client(self.editor).patch(
                    self.url, {"params_schema": requested}, format="json"
                )
                assert resp.status_code == 400, resp.content
                assert "params_schema" in resp.json()
                assert _canonical(self._schema()) == _canonical(stored)
                resp = self._client(self.approver).patch(
                    self.url, {"params_schema": requested}, format="json"
                )
                assert resp.status_code == 200, resp.content
                assert _canonical(self._schema()) == _canonical(requested)

    def test_form_type_change_is_refused_without_approve_and_allowed_with_it(self):
        for label, (stored, requested) in self._CASES.items():
            with self.subTest(label):
                self._set_schema(stored)
                for user, refused in ((self.editor, True), (self.approver, False)):
                    instance = RPCProcedure.objects.get(pk=self.procedure.pk)
                    instance._netbox_rpc_request = SimpleNamespace(user=user)
                    form = RPCProcedureForm(instance=instance)
                    form.cleaned_data = {"params_schema": requested}
                    if refused:
                        with self.assertRaises(AbortRequest):
                            form._refuse_unpin_under_lock()
                    else:
                        form._refuse_unpin_under_lock()
                assert _canonical(self._schema()) == _canonical(stored)

    def test_same_items_as_a_tuple_or_a_list_are_unchanged_on_both_paths(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(
            transport_driver_chain=["ansible", "asyncssh"]
        )
        instance = RPCProcedure.objects.get(pk=self.procedure.pk)
        instance._netbox_rpc_request = SimpleNamespace(user=self.editor)
        form = RPCProcedureForm(instance=instance)
        form.cleaned_data = {"transport_driver_chain": ("ansible", "asyncssh")}
        form._refuse_unpin_under_lock()
        resp = self._client(self.editor).patch(
            self.url, {"transport_driver_chain": ["ansible", "asyncssh"]}, format="json"
        )
        assert resp.status_code == 200, resp.content


def _supports_add_remove_tags() -> bool:
    from netbox.api.serializers.features import TaggableModelSerializer

    return "add_tags" in TaggableModelSerializer._declared_fields


class ApprovalScopeAttributeTests(TestCase):
    """Tags and custom fields can confer approval scope, so changing them needs approval."""

    def setUp(self):
        from core.models import ObjectType
        from extras.models import Tag
        from users.models import ObjectPermission

        self.procedure = make_procedure("os.linux.test.scopeattr")
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(
            approval_required=False, transport_pinned=False
        )
        self.tag = Tag.objects.create(name="Scope approvers", slug="scope-approvers")
        # A change-only user whose approve grant is scoped to tagged procedures.
        self.editor = make_user("scopeattr-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        _grant(self.editor, ["view", "approve"], constraints={"tags__slug": "scope-approvers"})
        self.approver = make_user("scopeattr-approver", superuser=False)
        _grant(self.approver, ["view", "change", "approve"])
        self.other = make_user("scopeattr-other", superuser=False)
        _grant(self.other, ["view", "change"])
        # Nested tag lookups are restricted to tags the user can view.
        tag_view = ObjectPermission.objects.create(name="scopeattr-tag-view", actions=["view"])
        tag_view.object_types.set([ObjectType.objects.get_for_model(Tag)])
        tag_view.users.set([self.editor, self.approver, self.other])
        self.url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[self.procedure.pk]
        )

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def _tag_slugs(self):
        return sorted(RPCProcedure.objects.get(pk=self.procedure.pk).tags.values_list("slug", flat=True))

    def test_rest_tag_change_without_approve_is_refused_for_every_tag_field(self):
        bodies = [{"tags": [{"slug": "scope-approvers"}]}]
        if _supports_add_remove_tags():
            bodies.append({"add_tags": [{"slug": "scope-approvers"}]})
        for body in bodies:
            with self.subTest(body):
                resp = self._client(self.editor).patch(self.url, body, format="json")
                assert resp.status_code == 400, resp.content
                assert "approve_rpcprocedure" in str(resp.json().get("tags")), resp.json()
                assert self._tag_slugs() == []

    def test_rest_tag_removal_without_approve_is_refused(self):
        self.procedure.tags.add(self.tag)
        resp = self._client(self.other).patch(
            self.url, {"remove_tags": [{"slug": "scope-approvers"}]}, format="json"
        )
        if _supports_add_remove_tags():
            assert resp.status_code == 400, resp.content
            assert "approve_rpcprocedure" in str(resp.json().get("tags")), resp.json()
        else:
            # NetBox releases without remove_tags ignore the field.
            assert resp.status_code == 200, resp.content
        assert self._tag_slugs() == ["scope-approvers"]

    def test_acquired_tag_cannot_be_used_to_lower_effect_afterwards(self):
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(effect="destructive")
        resp = self._client(self.editor).patch(
            self.url, {"tags": [{"slug": "scope-approvers"}]}, format="json"
        )
        assert resp.status_code == 400, resp.content
        assert "approve_rpcprocedure" in str(resp.json().get("tags")), resp.json()
        resp = self._client(self.editor).patch(self.url, {"effect": "read"}, format="json")
        assert resp.status_code == 400, resp.content
        assert RPCProcedure.objects.get(pk=self.procedure.pk).effect == "destructive"

    def test_rest_tag_change_with_approve_is_allowed(self):
        resp = self._client(self.approver).patch(
            self.url, {"tags": [{"slug": "scope-approvers"}]}, format="json"
        )
        assert resp.status_code == 200, resp.content
        assert self._tag_slugs() == ["scope-approvers"]

    def test_form_tag_change_without_approve_is_refused_on_both_checks(self):
        from extras.models import Tag

        instance = RPCProcedure.objects.get(pk=self.procedure.pk)
        instance._netbox_rpc_request = SimpleNamespace(user=self.editor)
        form = RPCProcedureForm(instance=instance)
        form.cleaned_data = {"tags": Tag.objects.filter(pk=self.tag.pk)}
        with self.assertRaises(AbortRequest):
            form._refuse_unpin_under_lock()
        assert self._tag_slugs() == []
        approver_instance = RPCProcedure.objects.get(pk=self.procedure.pk)
        approver_instance._netbox_rpc_request = SimpleNamespace(user=self.approver)
        form = RPCProcedureForm(instance=approver_instance)
        form.cleaned_data = {"tags": Tag.objects.filter(pk=self.tag.pk)}
        form._refuse_unpin_under_lock()

    def test_custom_field_change_without_approve_is_refused_on_both_paths(self):
        from core.models import ObjectType
        from extras.models import CustomField

        field = CustomField.objects.create(name="rpc_scope", type="text")
        field.object_types.set([ObjectType.objects.get_for_model(RPCProcedure)])
        resp = self._client(self.editor).patch(
            self.url, {"custom_fields": {"rpc_scope": "approvers"}}, format="json"
        )
        assert resp.status_code == 400, resp.content
        assert "approve_rpcprocedure" in str(resp.json().get("custom_field_data")), resp.json()
        assert RPCProcedure.objects.get(pk=self.procedure.pk).custom_field_data.get("rpc_scope") in (
            None,
            "",
        )
        instance = RPCProcedure.objects.get(pk=self.procedure.pk)
        instance._netbox_rpc_request = SimpleNamespace(user=self.editor)
        form = RPCProcedureForm(instance=instance)
        form.cleaned_data = {}
        instance.custom_field_data = {**instance.custom_field_data, "rpc_scope": "approvers"}
        with self.assertRaises(AbortRequest):
            form._refuse_unpin_under_lock()
        resp = self._client(self.approver).patch(
            self.url, {"custom_fields": {"rpc_scope": "approvers"}}, format="json"
        )
        assert resp.status_code == 200, resp.content


class FormOmittedFieldTests(TestCase):
    """An omitted protected field in the form must not write back a stale copy."""

    def test_omitted_json_fields_keep_a_value_tightened_after_the_form_was_read(self):
        procedure = make_procedure("os.linux.test.omitted")
        RPCProcedure.objects.filter(pk=procedure.pk).update(
            approval_required=False, transport_pinned=False, params_schema={"type": "object"}
        )
        editor = make_user("omitted-editor", superuser=False)
        _grant(editor, ["view", "change"])
        stale = RPCProcedure.objects.get(pk=procedure.pk)
        stale._netbox_rpc_request = SimpleNamespace(user=editor)
        # An approver tightens the schema after this form read the row.
        tightened = {"type": "object", "additionalProperties": False}
        RPCProcedure.objects.filter(pk=procedure.pk).update(params_schema=tightened)
        form = RPCProcedureForm(instance=stale)
        form.cleaned_data = {"description": "edited", "params_schema": None}
        form._refuse_unpin_under_lock()
        stale.description = "edited"
        stale.save()
        assert _canonical(RPCProcedure.objects.get(pk=procedure.pk).params_schema) == _canonical(
            tightened
        )


class ApprovalScopeGainTests(TestCase):
    """An edit must not bring the procedure into the editor's own approve scope."""

    def setUp(self):
        self.procedure = make_procedure("os.linux.test.scopegain")
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(
            approval_required=False, transport_pinned=False, effect="destructive",
            enabled=True, description="",
        )
        self.url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[self.procedure.pk]
        )

    def _editor(self, name, constraints):
        user = make_user(name, superuser=False)
        _grant(user, ["view", "change"])
        _grant(user, ["view", "approve"], constraints=constraints)
        return user

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def _row(self):
        return RPCProcedure.objects.get(pk=self.procedure.pk)

    def test_rest_edit_that_gains_approve_scope_is_refused_and_rolled_back(self):
        for field, value, constraints in (
            ("description", "approval-scope", {"description": "approval-scope"}),
            ("comments", "approval-scope", {"comments": "approval-scope"}),
            ("enabled", False, {"enabled": False}),
        ):
            with self.subTest(field):
                editor = self._editor(f"scopegain-{field}", constraints)
                resp = self._client(editor).patch(self.url, {field: value}, format="json")
                assert resp.status_code == 400, resp.content
                assert "approve_rpcprocedure" in str(resp.json()), resp.json()
                assert getattr(self._row(), field) != value
                # The second step of the attack, lowering effect, is still refused.
                resp = self._client(editor).patch(self.url, {"effect": "read"}, format="json")
                assert resp.status_code == 400, resp.content
                assert self._row().effect == "destructive"

    def test_rest_edit_by_an_editor_already_in_scope_is_allowed(self):
        editor = self._editor("scopegain-inscope", {"name": self.procedure.name})
        resp = self._client(editor).patch(
            self.url, {"description": "still in scope"}, format="json"
        )
        assert resp.status_code == 200, resp.content
        assert self._row().description == "still in scope"

    def test_rest_edit_that_does_not_gain_scope_is_allowed(self):
        editor = self._editor("scopegain-unrelated", {"description": "other-scope"})
        resp = self._client(editor).patch(self.url, {"description": "notes"}, format="json")
        assert resp.status_code == 200, resp.content
        assert self._row().description == "notes"

    def test_form_save_that_gains_approve_scope_is_refused_and_rolled_back(self):
        editor = self._editor("scopegain-form", {"description": "approval-scope"})
        instance = self._row()
        instance._netbox_rpc_request = SimpleNamespace(user=editor)
        form = RPCProcedureForm(instance=instance)
        form.cleaned_data = {"description": "approval-scope"}
        instance.description = "approval-scope"
        form._save_m2m = lambda: None
        with self.assertRaises(AbortRequest):
            form.save()
        assert self._row().description == ""


class CrossProcedureScopeGainTests(TestCase):
    """An edit to one procedure must not bring another into the editor's approve scope."""

    def setUp(self):
        from netbox_rpc.models import RPCIntent, RPCIntentProcedure

        self.first = make_procedure("os.linux.test.crossfirst")
        self.second = make_procedure("os.linux.test.crosssecond")
        RPCProcedure.objects.filter(pk__in=[self.first.pk, self.second.pk]).update(
            approval_required=False, transport_pinned=False, effect="destructive", description=""
        )
        intent = RPCIntent.objects.create(name="intent.test.crossscope")
        RPCIntentProcedure.objects.create(intent=intent, procedure=self.first, sequence=1)
        RPCIntentProcedure.objects.create(intent=intent, procedure=self.second, sequence=2)
        self.editor = make_user("cross-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        _grant(
            self.editor,
            ["view", "approve"],
            constraints={
                "name": self.second.name,
                "intents__procedures__description": "approval-scope",
            },
        )

    def _url(self, procedure):
        return reverse("plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[procedure.pk])

    def _client(self):
        client = APIClient()
        client.force_authenticate(user=self.editor)
        return client

    def test_rest_edit_that_gains_scope_on_another_procedure_is_refused(self):
        resp = self._client().patch(
            self._url(self.first), {"description": "approval-scope"}, format="json"
        )
        assert resp.status_code == 400, resp.content
        assert "approve_rpcprocedure" in str(resp.json()), resp.json()
        assert RPCProcedure.objects.get(pk=self.first.pk).description == ""
        resp = self._client().patch(self._url(self.second), {"effect": "read"}, format="json")
        assert resp.status_code == 400, resp.content
        assert RPCProcedure.objects.get(pk=self.second.pk).effect == "destructive"

    def test_form_save_that_gains_scope_on_another_procedure_is_refused(self):
        instance = RPCProcedure.objects.get(pk=self.first.pk)
        instance._netbox_rpc_request = SimpleNamespace(user=self.editor)
        form = RPCProcedureForm(instance=instance)
        form.cleaned_data = {"description": "approval-scope"}
        instance.description = "approval-scope"
        form._save_m2m = lambda: None
        with self.assertRaises(AbortRequest):
            form.save()
        assert RPCProcedure.objects.get(pk=self.first.pk).description == ""


class ConcurrentScopeGainTests(TransactionTestCase):
    """Concurrent edits to two related procedures must not jointly grant approve scope."""

    def setUp(self):
        from netbox_rpc.models import RPCIntent, RPCIntentProcedure

        self.first = make_procedure("os.linux.test.concurrentfirst")
        self.second = make_procedure("os.linux.test.concurrentsecond")
        RPCProcedure.objects.filter(pk__in=[self.first.pk, self.second.pk]).update(
            approval_required=False,
            transport_pinned=False,
            effect="destructive",
            description="",
            comments="",
        )
        intent = RPCIntent.objects.create(name="intent.test.concurrentscope")
        RPCIntentProcedure.objects.create(intent=intent, procedure=self.first, sequence=1)
        RPCIntentProcedure.objects.create(intent=intent, procedure=self.second, sequence=2)
        self.editor = make_user("concurrent-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        _grant(
            self.editor,
            ["view", "approve"],
            constraints={
                "description": "approval-scope",
                "intents__procedures__comments": "ready",
            },
        )

    def _patch(self, procedure, body):
        from django.db import connections

        try:
            client = APIClient()
            client.force_authenticate(user=self.editor)
            url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[procedure.pk])
            return client.patch(url, body, format="json").status_code
        finally:
            connections["default"].close()

    def test_second_edit_waits_for_the_first_and_then_sees_the_scope_gain(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        from netbox_rpc.api import serializers as api_serializers

        first_checked = threading.Event()
        release_first = threading.Event()
        original = api_serializers.refuse_approval_scope_gain

        def pause_first(user, before, error):
            original(user, before, error)
            if threading.current_thread().name.startswith("first"):
                first_checked.set()
                assert release_first.wait(20)

        with mock.patch.object(api_serializers, "refuse_approval_scope_gain", pause_first):
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="first") as first_pool:
                first = first_pool.submit(
                    self._patch, self.second, {"description": "approval-scope"}
                )
                assert first_checked.wait(20)
                with ThreadPoolExecutor(max_workers=1, thread_name_prefix="second") as second_pool:
                    second = second_pool.submit(self._patch, self.first, {"comments": "ready"})
                    # The second edit waits on the procedure scope lock while the first
                    # transaction is open.
                    with self.assertRaises(TimeoutError):
                        second.result(timeout=1)
                    release_first.set()
                    assert first.result(timeout=20) == 200
                    # It then sees the first edit, and its own edit would grant approval
                    # scope on the second procedure, so it is refused.
                    assert second.result(timeout=20) == 400
        assert RPCProcedure.objects.get(pk=self.first.pk).comments == ""
        assert self._patch(self.second, {"effect": "read"}) == 400
        assert RPCProcedure.objects.get(pk=self.second.pk).effect == "destructive"


class ProcedureScopeLockOrderTests(TestCase):
    """Every procedure edit takes the scope lock before any row lock."""

    def setUp(self):
        self.procedure = make_procedure("os.linux.test.lockorder")
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(
            approval_required=False, transport_pinned=False
        )
        self.editor = make_user("lockorder-editor", superuser=False)
        _grant(self.editor, ["view", "change"])
        self.url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[self.procedure.pk]
        )
        self.list_url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-list")

    def _lock_positions(self, send):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        with CaptureQueriesContext(connection) as captured:
            resp = send()
        assert resp.status_code == 200, resp.content
        sql = [entry["sql"] for entry in captured.captured_queries]
        scope = [i for i, text in enumerate(sql) if "pg_advisory_xact_lock" in text]
        rows = [i for i, text in enumerate(sql) if "FOR UPDATE" in text]
        return scope, rows

    def test_conditional_and_ordinary_updates_take_the_scope_lock_first(self):
        client = APIClient()
        client.force_authenticate(user=self.editor)
        etag = client.get(self.url).headers.get("ETag")
        headers = {"HTTP_IF_MATCH": etag} if etag else {}
        for label, send in (
            ("conditional", lambda: client.patch(self.url, {"description": "a"}, format="json", **headers)),
            ("ordinary", lambda: client.patch(self.url, {"description": "b"}, format="json")),
            (
                "bulk",
                lambda: client.patch(
                    self.list_url, [{"id": self.procedure.pk, "description": "c"}], format="json"
                ),
            ),
        ):
            with self.subTest(label):
                scope, rows = self._lock_positions(send)
                assert scope, label
                assert rows, label
                assert scope[0] < rows[0], (label, scope, rows)
