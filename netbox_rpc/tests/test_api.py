"""REST API integration tests: command-only write model + read-only event log."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from netbox_rpc.application import command_handlers
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCExecution, RPCProcedure

from ._common import (
    enable_rpc_integration,
    make_device,
    make_execution,
    make_procedure,
    make_user,
)


class _FakeJob:
    pk = 9999


def _grant(user, *, model, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    permission = ObjectPermission.objects.create(
        name=f"grant-{user.username}-{model.__name__}-{'-'.join(actions)}",
        actions=list(actions),
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(model)])
    permission.users.set([user])


def _akvorado_procedure(name: str, *, approval_required: bool = False):
    procedure = make_procedure(name)
    procedure.enabled = True
    procedure.approval_required = approval_required
    procedure.target_models = ["dcim.device", "virtualization.virtualmachine"]
    procedure.params_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    }
    procedure.save()
    return procedure


class ExecutionApiTests(TestCase):
    def setUp(self):
        self.user = make_user("api-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.proc = make_procedure("os.linux.test.echo")
        # #166: creating executions requires the integration to be opted in.
        enable_rpc_integration()

    def _detail_url(self, ex):
        return reverse("plugins-api:netbox_rpc-api:rpcexecution-detail", args=[ex.pk])

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_create_emits_queued_and_job_enqueued(self, _enqueue, _fetch):
        device = make_device()
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")
        resp = self.client.post(
            url,
            {
                "procedure_id": self.proc.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": device.pk,
                "params": {},
            },
            format="json",
        )
        assert resp.status_code == 201, resp.content
        ex = RPCExecution.objects.get(pk=resp.data["id"])
        names = list(ex.events.order_by("sequence").values_list("event", flat=True))
        assert "ExecutionQueued" in names
        assert "JobEnqueued" in names
        assert ex.job_id == _FakeJob.pk

    def test_akvorado_create_rejects_dangling_assigned_object(self):
        procedure = make_procedure("service.akvorado.1.config_read")
        procedure.enabled = True
        procedure.approval_required = False
        procedure.target_models = ["dcim.device", "virtualization.virtualmachine"]
        procedure.params_schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        }
        procedure.save()
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")

        resp = self.client.post(
            url,
            {
                "procedure_id": procedure.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": 999_999_999,
                "params": {},
            },
            format="json",
        )

        assert resp.status_code == 400, resp.content
        assert "does not exist" in str(resp.data["assigned_object_id"])
        assert not RPCExecution.objects.filter(procedure=procedure).exists()

    def test_put_and_patch_are_method_not_allowed(self):
        ex = make_execution(user=self.user)
        RPCExecutionAggregate(ex).queue()
        assert self.client.put(self._detail_url(ex), {}, format="json").status_code == 405
        assert self.client.patch(self._detail_url(ex), {}, format="json").status_code == 405

    def test_delete_is_method_not_allowed(self):
        # The aggregate + its append-only ledger are immutable history.
        ex = make_execution(user=self.user)
        RPCExecutionAggregate(ex).queue()
        assert self.client.delete(self._detail_url(ex)).status_code == 405
        assert RPCExecution.objects.filter(pk=ex.pk).exists()

    def test_cancel_action_cancels_queued_execution(self):
        ex = make_execution(user=self.user)
        RPCExecutionAggregate(ex).queue()
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-cancel", args=[ex.pk])
        resp = self.client.post(url)
        assert resp.status_code == 200, resp.content
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_CANCELLED

    def test_events_endpoint_is_readable(self):
        ex = make_execution(user=self.user)
        RPCExecutionAggregate(ex).queue()
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-events", args=[ex.pk])
        resp = self.client.get(url)
        assert resp.status_code == 200

    def test_event_viewset_is_read_only(self):
        url = reverse("plugins-api:netbox_rpc-api:rpcexecutionevent-list")
        # No create on the read-only event viewset.
        assert self.client.post(url, {}, format="json").status_code in (403, 405)


class AkvoradoCreationSecurityTests(TestCase):
    def setUp(self):
        enable_rpc_integration()
        self.device = make_device("akvorado-security-target")
        self.procedure = _akvorado_procedure("service.akvorado.1.config_read")

    def _serializer(self, *, procedure=None, params=None):
        return RPCExecutionSerializer(
            data={
                "procedure_id": (procedure or self.procedure).pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": params or {},
            }
        )

    def test_non_superuser_without_target_object_permission_is_rejected(self):
        user = make_user("akvorado-target-denied", superuser=False)
        _grant(user, model=RPCProcedure, actions=("execute",))
        user = make_user("akvorado-target-denied", superuser=False)

        with self.assertRaises(ValidationError) as exc_info:
            command_handlers.create_execution(
                serializer=self._serializer(),
                user=user,
            )

        assert "does not exist" in str(exc_info.exception)
        assert not RPCExecution.objects.filter(procedure=self.procedure).exists()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_non_superuser_with_target_object_permission_is_accepted(
        self,
        _enqueue,
        _fetch,
    ):
        from dcim.models import Device

        user = make_user("akvorado-target-allowed", superuser=False)
        _grant(user, model=RPCProcedure, actions=("execute",))
        _grant(
            user,
            model=Device,
            actions=("view",),
            constraints={"id": self.device.pk},
        )
        user = make_user("akvorado-target-allowed", superuser=False)

        execution = command_handlers.create_execution(
            serializer=self._serializer(),
            user=user,
        )

        assert execution.assigned_object_id == self.device.pk
        assert execution.requested_by_id == user.pk
