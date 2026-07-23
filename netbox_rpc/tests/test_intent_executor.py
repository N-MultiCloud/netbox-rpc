"""Intent executor tests (issue #130).

Running an ``RPCIntent`` fans out one child ``RPCExecution`` per grouped
procedure through ``command_handlers.execute_intent()``. The whole point of
this module is to prove that fan-out is not a side channel: every child goes
through the *exact same* ``create_execution()`` command path a direct
``RPCExecution`` POST uses, so every gate re-fires per child — including the
``approval_required`` gate, which must never be bypassed for a grouped
destructive/approval procedure. See ``AGENTS.md`` -> "Intents" and "LLM Agent
Safety Guardrails", and ``command_handlers.execute_intent`` for the full
no-bypass contract this module exercises.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.test import APIClient

from netbox_rpc.application import command_handlers
from netbox_rpc.models import RPCExecution, RPCIntent, RPCProcedure

from ._common import (
    device_ct,
    enable_rpc_integration,
    make_device,
    make_intent,
    make_procedure,
    make_user,
)


def _grant(user, *, model, actions=("execute",), constraints=None):
    """Grant a (optionally scoped) custom NetBox ObjectPermission.

    Mirrors the pattern already used by
    ``test_approval_api.ApprovalAuthorizationTests`` for
    ``approve_rpcprocedure`` — a plain non-superuser with zero grants is
    denied by ``has_perm()``; granting via ``ObjectPermission`` is how the
    integration tests exercise the positive/negative permission paths.
    """
    from core.models import ObjectType
    from users.models import ObjectPermission

    perm = ObjectPermission.objects.create(
        name=f"grant-{user.username}-{model.__name__}-{'-'.join(actions)}",
        actions=list(actions),
        constraints=constraints,
    )
    perm.object_types.set([ObjectType.objects.get_for_model(model)])
    perm.users.set([user])


def _executor_user(username: str) -> object:
    """A non-superuser who can run intents and execute non-approval procedures,
    but does NOT hold ``approve_rpcprocedure`` — the permission this module
    proves is never implicitly granted by the intent-run path.

    Grants ``add`` on ``RPCIntent`` in addition to ``execute``: DRF's
    ``TokenPermissions`` (``netbox.api.authentication``) maps every POST —
    including this custom ``run`` detail action — to the blanket
    ``add_rpcintent`` permission (``HTTP_ACTIONS['POST'] = 'add'`` also drives
    the queryset restriction ``get_object()`` uses), independently of the
    application-level ``execute_rpcintent``/``approve_rpcprocedure`` gates this
    module is actually testing. Without it, an HTTP-level test would 403/404
    at the generic DRF layer before ever reaching ``execute_intent()``, which
    would not prove anything about the approval gate specifically.
    """
    user = make_user(username, superuser=False)
    _grant(user, model=RPCIntent, actions=("execute", "add"))
    _grant(user, model=RPCProcedure)
    # Refresh: ObjectPermission grants are cached on a live user instance by
    # earlier has_perm() calls, so re-fetch to pick them up (same pattern as
    # ApprovalAuthorizationTests.test_object_scoped_out_actor_is_denied).
    return make_user(username, superuser=False)


class IntentExecutorFanOutTests(TestCase):
    """Requirement (a): sequential fan-out creates one child per grouped
    procedure, in sequence order, through the real create path."""

    def setUp(self):
        enable_rpc_integration()
        self.device = make_device()
        self.user = make_user("intent-exec-fanout", superuser=True)

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_sequential_fan_out_creates_one_child_per_procedure_in_order(
        self, enqueue, _fetch
    ):
        enqueue.return_value = mock.Mock(pk=1)
        proc_a = make_procedure("os.linux.test.intent.a")
        proc_b = make_procedure("os.linux.test.intent.b")
        proc_c = make_procedure("os.linux.test.intent.c")
        intent = make_intent(
            "intent.exec.sequential",
            execution_mode=RPCIntent.MODE_SEQUENTIAL,
            procedures=[proc_a, proc_b, proc_c],
        )

        children = command_handlers.execute_intent(
            intent,
            self.user,
            assigned_object_type=device_ct(),
            assigned_object_id=self.device.pk,
        )

        assert [child.procedure_id for child in children] == [
            proc_a.pk,
            proc_b.pk,
            proc_c.pk,
        ]
        assert (
            RPCExecution.objects.filter(pk__in=[c.pk for c in children]).count() == 3
        )
        # Each child went through the real, event-sourced create path.
        for child in children:
            names = list(
                child.events.order_by("sequence").values_list("event", flat=True)
            )
            assert "ExecutionQueued" in names

    def test_no_grouped_procedures_is_rejected(self):
        intent = make_intent("intent.exec.empty")
        with self.assertRaises(Exception):
            command_handlers.execute_intent(
                intent,
                self.user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )
        assert not RPCExecution.objects.exists()

    def test_disabled_intent_is_rejected(self):
        proc = make_procedure("os.linux.test.intent.disabled")
        intent = make_intent("intent.exec.disabled", procedures=[proc])
        intent.enabled = False
        intent.save()
        with self.assertRaises(Exception):
            command_handlers.execute_intent(
                intent,
                self.user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )
        assert not RPCExecution.objects.filter(procedure=proc).exists()

    def test_execute_rpcintent_permission_required(self):
        proc = make_procedure("os.linux.test.intent.noperm")
        intent = make_intent("intent.exec.noperm", procedures=[proc])
        nobody = make_user("intent-exec-nobody", superuser=False)
        with self.assertRaises(PermissionDenied):
            command_handlers.execute_intent(
                intent,
                nobody,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )
        assert not RPCExecution.objects.filter(procedure=proc).exists()

    def test_non_dict_params_is_rejected_cleanly(self):
        # RPCIntentRunSerializer.params is a bare JSONField; a non-object value
        # must fail closed with a clean ValidationError (400), never an uncaught
        # TypeError/ValueError from dict(params) (which would be a 500).
        proc = make_procedure("os.linux.test.intent.badparams")
        intent = make_intent("intent.exec.badparams", procedures=[proc])
        for bad in (5, [1, 2], "x"):
            with self.assertRaises(ValidationError):
                command_handlers.execute_intent(
                    intent,
                    self.user,
                    assigned_object_type=device_ct(),
                    assigned_object_id=self.device.pk,
                    params=bad,
                )
        assert not RPCExecution.objects.filter(procedure=proc).exists()


class IntentExecutorOriginMarkerTests(TestCase):
    """Requirement (c): the ``_intent``/``_intent_name`` origin marker lands in
    child params and the Runs-tab attribution reads ``Intent: <name>``."""

    def setUp(self):
        enable_rpc_integration()
        self.device = make_device()
        self.user = make_user("intent-exec-marker", superuser=True)

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_origin_marker_lands_in_child_params_and_runs_tab_label(
        self, enqueue, _fetch
    ):
        enqueue.return_value = mock.Mock(pk=1)
        proc = make_procedure("os.linux.test.intent.marker")
        intent = make_intent("intent.exec.marker", procedures=[proc])

        [child] = command_handlers.execute_intent(
            intent,
            self.user,
            assigned_object_type=device_ct(),
            assigned_object_id=self.device.pk,
        )

        child.refresh_from_db()
        assert child.params["_intent"] == intent.pk
        assert child.params["_intent_name"] == intent.name
        assert child.intent_reference == intent.name
        assert child.source_label == f"Intent: {intent.name}"

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_caller_params_survive_schema_validation_and_marker_is_added_after(
        self, enqueue, _fetch
    ):
        # additionalProperties: false is the common shape of seeded procedure
        # schemas -- proves the marker is stamped AFTER create_execution()'s
        # jsonschema.validate() call, not merged into the params it validates
        # (which would 400 for any real procedure using this schema shape).
        enqueue.return_value = mock.Mock(pk=1)
        proc = make_procedure(
            "os.linux.test.intent.schema",
            params_schema={
                "type": "object",
                "properties": {"foo": {"type": "string"}},
                "additionalProperties": False,
            },
        )
        intent = make_intent("intent.exec.schema", procedures=[proc])

        [child] = command_handlers.execute_intent(
            intent,
            self.user,
            assigned_object_type=device_ct(),
            assigned_object_id=self.device.pk,
            params={"foo": "bar"},
        )

        child.refresh_from_db()
        assert child.params["foo"] == "bar"
        assert child.params["_intent_name"] == intent.name
        assert child.params["_intent"] == intent.pk


class IntentExecutorGateRefireTests(TestCase):
    """Requirement (d): the #166 opt-in and #167 capability gates fire again
    for every child, not just once for the intent as a whole."""

    def setUp(self):
        enable_rpc_integration()
        self.device = make_device()
        self.user = make_user("intent-exec-gates", superuser=True)

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_optin_and_capability_gates_refire_per_child(self, enqueue, fetch):
        enqueue.return_value = mock.Mock(pk=1)
        procedures = [
            make_procedure(f"os.linux.test.intent.gate.{i}") for i in range(3)
        ]
        intent = make_intent("intent.exec.gates", procedures=procedures)

        original = command_handlers._require_enabled_and_authoritative_backend
        with mock.patch.object(
            command_handlers,
            "_require_enabled_and_authoritative_backend",
            wraps=original,
        ) as optin_gate:
            children = command_handlers.execute_intent(
                intent,
                self.user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )

        assert len(children) == 3
        # #166: the opt-in/backend-authority gate is re-evaluated once per
        # child, not cached/short-circuited across the fan-out.
        assert optin_gate.call_count == 3
        # #167: the backend capability manifest is re-verified per child too.
        assert fetch.call_count == 3

    def test_optin_gate_rejects_every_child_when_integration_disabled(self):
        from netbox_rpc.models import RpcPluginSettings

        settings_row = RpcPluginSettings.get_solo()
        settings_row.enabled = False
        settings_row.save()

        procedures = [
            make_procedure(f"os.linux.test.intent.disabled_optin.{i}")
            for i in range(2)
        ]
        intent = make_intent("intent.exec.disabled-optin", procedures=procedures)

        with self.assertRaises(PermissionDenied):
            command_handlers.execute_intent(
                intent,
                self.user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )
        # The very first child's #166 gate must refuse before any row exists.
        assert not RPCExecution.objects.filter(procedure__in=procedures).exists()


class IntentExecutorNoApprovalBypassTests(TestCase):
    """Requirement (b): the core no-bypass proof. An intent that groups an
    ``approval_required`` procedure must NOT auto-dispatch that child for a
    caller lacking ``approve_rpcprocedure`` -- it must be refused exactly as a
    direct ``RPCExecution`` create would refuse it."""

    def setUp(self):
        enable_rpc_integration()
        self.device = make_device()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_direct_create_of_approval_required_procedure_is_denied_control(
        self, enqueue, _fetch
    ):
        """Control case: prove what a DIRECT create does for this exact user
        and procedure, so the intent-run assertions below can honestly claim
        parity ("gated exactly like a direct create")."""
        from netbox_rpc.api.serializers import RPCExecutionSerializer

        enqueue.return_value = mock.Mock(pk=1)
        proc = make_procedure(
            "os.linux.test.intent.approval.control", approval_required=True
        )
        user = _executor_user("intent-exec-approval-control")

        serializer = RPCExecutionSerializer(
            data={
                "procedure_id": proc.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {},
            }
        )
        with self.assertRaises(PermissionDenied):
            command_handlers.create_execution(serializer=serializer, user=user)
        assert not RPCExecution.objects.filter(procedure=proc).exists()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_intent_run_does_not_bypass_approval_required_gate(
        self, enqueue, _fetch
    ):
        """The actual no-bypass proof: running an intent that groups ONLY an
        approval_required procedure raises the identical PermissionDenied a
        direct create would, and creates zero RPCExecution rows -- the child
        is refused, never silently created/queued/dispatched."""
        enqueue.return_value = mock.Mock(pk=1)
        proc = make_procedure(
            "os.linux.test.intent.approval.solo", approval_required=True
        )
        intent = make_intent("intent.exec.approval-solo", procedures=[proc])
        user = _executor_user("intent-exec-approval-solo")

        with self.assertRaises(PermissionDenied):
            command_handlers.execute_intent(
                intent,
                user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )
        assert not RPCExecution.objects.filter(procedure=proc).exists()
        enqueue.assert_not_called()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_sequential_run_stops_before_approval_gated_child(
        self, enqueue, _fetch
    ):
        """Mixed intent: [normal, approval_required] in sequence order. The
        first (non-gated) child is created normally; the second (gated) child
        is refused and never created -- fail-fast, no partial silent
        continuation past a refused child, and the already-created sibling is
        NOT rolled back (each child is its own independent commit)."""
        enqueue.return_value = mock.Mock(pk=1)
        normal_proc = make_procedure("os.linux.test.intent.approval.mixed.normal")
        approval_proc = make_procedure(
            "os.linux.test.intent.approval.mixed.gated", approval_required=True
        )
        intent = make_intent(
            "intent.exec.approval-mixed",
            procedures=[normal_proc, approval_proc],
        )
        user = _executor_user("intent-exec-approval-mixed")

        with self.assertRaises(PermissionDenied):
            command_handlers.execute_intent(
                intent,
                user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )

        assert RPCExecution.objects.filter(procedure=normal_proc).count() == 1
        assert RPCExecution.objects.filter(procedure=approval_proc).count() == 0


class IntentExecutorHttpTests(TestCase):
    """Trigger surface: ``POST /api/plugins/rpc/intents/{id}/run/`` end to end
    (ContentTypeField round-trip, response shape, happy path)."""

    def setUp(self):
        enable_rpc_integration()
        self.device = make_device()
        self.user = make_user("intent-exec-http", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_run_action_fans_out_children_over_http(self, enqueue, _fetch):
        enqueue.return_value = mock.Mock(pk=1)
        proc_a = make_procedure("os.linux.test.intent.http.a")
        proc_b = make_procedure("os.linux.test.intent.http.b")
        intent = make_intent("intent.exec.http", procedures=[proc_a, proc_b])

        url = reverse(
            "plugins-api:netbox_rpc-api:rpcintent-run", args=[intent.pk]
        )
        resp = self.client.post(
            url,
            {
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {},
            },
            format="json",
        )

        assert resp.status_code == 201, resp.content
        assert len(resp.data) == 2
        # `procedure_id` is write_only on RPCExecutionSerializer; the nested
        # read-only `procedure` object is what the response actually carries.
        assert [row["procedure"]["id"] for row in resp.data] == [
            proc_a.pk,
            proc_b.pk,
        ]
        for row in resp.data:
            assert row["params"]["_intent_name"] == intent.name

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_run_action_on_approval_required_intent_is_refused_over_http(
        self, enqueue, _fetch
    ):
        enqueue.return_value = mock.Mock(pk=1)
        proc = make_procedure(
            "os.linux.test.intent.http.approval", approval_required=True
        )
        intent = make_intent("intent.exec.http-approval", procedures=[proc])
        user = _executor_user("intent-exec-http-approval")
        client = APIClient()
        client.force_authenticate(user=user)

        url = reverse(
            "plugins-api:netbox_rpc-api:rpcintent-run", args=[intent.pk]
        )
        resp = client.post(
            url,
            {
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {},
            },
            format="json",
        )

        assert resp.status_code == 403, resp.content
        assert not RPCExecution.objects.filter(procedure=proc).exists()
