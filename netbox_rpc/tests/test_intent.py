"""DB integration tests for the RPCIntent declarative grouping model.

RPCIntent groups RPCProcedures (the "what") and declares an execution mode —
``sequential`` (nested, ordered) or ``parallel`` (concurrent, not nested). These
tests cover the ORM invariants, the ordered through model, the REST API
(create/update/list/filter with ordered ``procedure_ids``), and the edit form's
selection-order reconciliation.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.db.models import ProtectedError
from django.http import QueryDict
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.models import RPCIntent, RPCIntentProcedure, RPCProcedure

from ._common import make_procedure, make_user


class IntentModelTests(TestCase):
    def test_default_execution_mode_is_sequential(self):
        intent = RPCIntent.objects.create(name="intent.default")
        assert intent.execution_mode == RPCIntent.MODE_SEQUENTIAL

    def test_ordered_intent_procedures_follow_sequence(self):
        a = make_procedure("os.linux.test.a")
        b = make_procedure("os.linux.test.b")
        c = make_procedure("os.linux.test.c")
        intent = RPCIntent.objects.create(
            name="intent.ordered", execution_mode=RPCIntent.MODE_SEQUENTIAL
        )
        # Insert out of order; ordering must come from `sequence`, not insert order.
        RPCIntentProcedure.objects.create(intent=intent, procedure=b, sequence=2)
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        RPCIntentProcedure.objects.create(intent=intent, procedure=c, sequence=3)
        ordered = [ip.procedure_id for ip in intent.ordered_intent_procedures]
        assert ordered == [a.pk, b.pk, c.pk]
        assert intent.procedure_count == 3

    def test_unique_procedure_per_intent(self):
        a = make_procedure("os.linux.test.uniq")
        intent = RPCIntent.objects.create(name="intent.unique")
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=2)

    def test_grouped_procedure_is_protected_from_delete(self):
        a = make_procedure("os.linux.test.protected")
        intent = RPCIntent.objects.create(name="intent.protect")
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        with self.assertRaises(ProtectedError):
            a.delete()

    def test_intent_delete_cascades_through_rows_but_keeps_procedure(self):
        a = make_procedure("os.linux.test.cascade")
        intent = RPCIntent.objects.create(name="intent.cascade")
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        intent.delete()
        assert not RPCIntentProcedure.objects.filter(procedure=a).exists()
        assert RPCProcedure.objects.filter(pk=a.pk).exists()

    def test_sequence_zero_rejected_by_check_constraint(self):
        a = make_procedure("os.linux.test.seqzero")
        intent = RPCIntent.objects.create(name="intent.seqzero")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RPCIntentProcedure.objects.create(
                    intent=intent, procedure=a, sequence=0
                )

    def test_serialize_object_includes_ordered_procedures(self):
        a = make_procedure("os.linux.test.ser.a")
        b = make_procedure("os.linux.test.ser.b")
        intent = RPCIntent.objects.create(name="intent.serialize")
        # Insert out of order; serialize_object must return sequence order.
        RPCIntentProcedure.objects.create(intent=intent, procedure=b, sequence=2)
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        data = intent.serialize_object()
        assert data["intent_procedures"] == [
            {"procedure": a.pk, "sequence": 1},
            {"procedure": b.pk, "sequence": 2},
        ]


class IntentApiTests(TestCase):
    def setUp(self):
        self.user = make_user("intent-api-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def _list_url(self):
        return reverse("plugins-api:netbox_rpc-api:rpcintent-list")

    def _detail_url(self, pk):
        return reverse("plugins-api:netbox_rpc-api:rpcintent-detail", args=[pk])

    def test_create_with_ordered_procedure_ids(self):
        a = make_procedure("os.linux.api.a")
        b = make_procedure("os.linux.api.b")
        resp = self.client.post(
            self._list_url(),
            {
                "name": "intent.api.create",
                "execution_mode": "parallel",
                "procedure_ids": [b.pk, a.pk],
            },
            format="json",
        )
        assert resp.status_code == 201, resp.content
        intent = RPCIntent.objects.get(pk=resp.data["id"])
        assert intent.execution_mode == "parallel"
        rows = list(
            intent.intent_procedures.order_by("sequence").values_list(
                "procedure_id", "sequence"
            )
        )
        assert rows == [(b.pk, 1), (a.pk, 2)]
        # Read representation exposes the ordered procedures with their sequence.
        assert [p["id"] for p in resp.data["procedures"]] == [b.pk, a.pk]
        assert [p["sequence"] for p in resp.data["procedures"]] == [1, 2]

    def test_update_replaces_procedures(self):
        a = make_procedure("os.linux.api.u.a")
        b = make_procedure("os.linux.api.u.b")
        intent = RPCIntent.objects.create(name="intent.api.update")
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        resp = self.client.patch(
            self._detail_url(intent.pk),
            {"procedure_ids": [b.pk]},
            format="json",
        )
        assert resp.status_code == 200, resp.content
        rows = list(intent.intent_procedures.values_list("procedure_id", flat=True))
        assert rows == [b.pk]

    def test_update_without_procedure_ids_preserves_grouping(self):
        a = make_procedure("os.linux.api.keep")
        intent = RPCIntent.objects.create(name="intent.api.keep")
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        resp = self.client.patch(
            self._detail_url(intent.pk),
            {"description": "renamed"},
            format="json",
        )
        assert resp.status_code == 200, resp.content
        assert list(intent.intent_procedures.values_list("procedure_id", flat=True)) == [
            a.pk
        ]

    def test_list_filter_by_execution_mode(self):
        RPCIntent.objects.create(name="intent.seq", execution_mode="sequential")
        RPCIntent.objects.create(name="intent.par", execution_mode="parallel")
        resp = self.client.get(self._list_url(), {"execution_mode": "parallel"})
        assert resp.status_code == 200
        names = [r["name"] for r in resp.data["results"]]
        assert "intent.par" in names
        assert "intent.seq" not in names

    def test_list_filter_by_enabled(self):
        RPCIntent.objects.create(name="intent.on", enabled=True)
        RPCIntent.objects.create(name="intent.off", enabled=False)
        resp = self.client.get(self._list_url(), {"enabled": "false"})
        assert resp.status_code == 200
        names = [r["name"] for r in resp.data["results"]]
        assert "intent.off" in names
        assert "intent.on" not in names

    def test_list_filter_by_procedure_id(self):
        a = make_procedure("os.linux.api.f.a")
        b = make_procedure("os.linux.api.f.b")
        with_a = RPCIntent.objects.create(name="intent.with.a")
        RPCIntentProcedure.objects.create(intent=with_a, procedure=a, sequence=1)
        without_a = RPCIntent.objects.create(name="intent.without.a")
        RPCIntentProcedure.objects.create(intent=without_a, procedure=b, sequence=1)
        resp = self.client.get(self._list_url(), {"procedure_id": a.pk})
        assert resp.status_code == 200
        names = [r["name"] for r in resp.data["results"]]
        assert "intent.with.a" in names
        assert "intent.without.a" not in names

    def test_create_rejects_duplicate_procedure_ids(self):
        a = make_procedure("os.linux.api.dup")
        resp = self.client.post(
            self._list_url(),
            {"name": "intent.api.dup", "procedure_ids": [a.pk, a.pk]},
            format="json",
        )
        assert resp.status_code == 400, resp.content
        assert "procedure_ids" in resp.data
        # No partial intent should have been created.
        assert not RPCIntent.objects.filter(name="intent.api.dup").exists()

    def test_update_rejects_duplicate_procedure_ids(self):
        a = make_procedure("os.linux.api.dup.u")
        intent = RPCIntent.objects.create(name="intent.api.dup.u")
        resp = self.client.patch(
            self._detail_url(intent.pk),
            {"procedure_ids": [a.pk, a.pk]},
            format="json",
        )
        assert resp.status_code == 400, resp.content

    def test_reorder_is_captured_in_object_changelog(self):
        from django.contrib.contenttypes.models import ContentType

        from core.models import ObjectChange

        a = make_procedure("os.linux.api.cl.a")
        b = make_procedure("os.linux.api.cl.b")
        resp = self.client.post(
            self._list_url(),
            {"name": "intent.changelog", "procedure_ids": [a.pk, b.pk]},
            format="json",
        )
        assert resp.status_code == 201, resp.content
        pk = resp.data["id"]
        # Reorder to [b, a]; the through rows are reconciled before the model save
        # so the ObjectChange postchange must reflect the new order.
        resp = self.client.patch(
            self._detail_url(pk),
            {"procedure_ids": [b.pk, a.pk]},
            format="json",
        )
        assert resp.status_code == 200, resp.content
        ct = ContentType.objects.get_for_model(RPCIntent)
        change = (
            ObjectChange.objects.filter(changed_object_type=ct, changed_object_id=pk)
            .order_by("-time")
            .first()
        )
        assert change is not None
        ordered = [
            (row["procedure"], row["sequence"])
            for row in change.postchange_data.get("intent_procedures", [])
        ]
        assert ordered == [(b.pk, 1), (a.pk, 2)]


class IntentFormTests(TestCase):
    def test_form_reconciles_through_rows_in_submitted_order(self):
        from netbox_rpc.forms import RPCIntentForm

        a = make_procedure("os.linux.form.a")
        b = make_procedure("os.linux.form.b")
        data = QueryDict(mutable=True)
        data["name"] = "intent.form"
        data["execution_mode"] = "sequential"
        data["enabled"] = "on"
        # Submit b before a; the through `sequence` must follow submission order.
        data.setlist("procedures", [str(b.pk), str(a.pk)])

        form = RPCIntentForm(data=data)
        assert form.is_valid(), form.errors
        intent = form.save()
        rows = list(
            intent.intent_procedures.order_by("sequence").values_list(
                "procedure_id", "sequence"
            )
        )
        assert rows == [(b.pk, 1), (a.pk, 2)]

    def test_form_edit_removes_deselected_procedures(self):
        from netbox_rpc.forms import RPCIntentForm

        a = make_procedure("os.linux.form.edit.a")
        b = make_procedure("os.linux.form.edit.b")
        intent = RPCIntent.objects.create(name="intent.form.edit")
        RPCIntentProcedure.objects.create(intent=intent, procedure=a, sequence=1)
        RPCIntentProcedure.objects.create(intent=intent, procedure=b, sequence=2)

        data = QueryDict(mutable=True)
        data["name"] = "intent.form.edit"
        data["execution_mode"] = "parallel"
        data["enabled"] = "on"
        data.setlist("procedures", [str(b.pk)])

        form = RPCIntentForm(data=data, instance=intent)
        assert form.is_valid(), form.errors
        form.save()
        assert list(
            intent.intent_procedures.values_list("procedure_id", flat=True)
        ) == [b.pk]
        assert intent.execution_mode == "parallel"

    def test_form_commit_false_defers_through_rows_to_save_m2m(self):
        from netbox_rpc.forms import RPCIntentForm

        a = make_procedure("os.linux.form.cf.a")
        b = make_procedure("os.linux.form.cf.b")
        data = QueryDict(mutable=True)
        data["name"] = "intent.form.commitfalse"
        data["execution_mode"] = "sequential"
        data["enabled"] = "on"
        data.setlist("procedures", [str(b.pk), str(a.pk)])

        form = RPCIntentForm(data=data)
        assert form.is_valid(), form.errors
        # Standard commit=False pattern: no through rows until save_m2m().
        instance = form.save(commit=False)
        instance.save()
        assert not instance.intent_procedures.exists()
        form.save_m2m()
        rows = list(
            instance.intent_procedures.order_by("sequence").values_list(
                "procedure_id", "sequence"
            )
        )
        assert rows == [(b.pk, 1), (a.pk, 2)]
