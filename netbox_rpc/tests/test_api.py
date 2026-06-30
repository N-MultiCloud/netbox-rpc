"""REST API integration tests: command-only write model + read-only event log."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCExecution

from ._common import make_device, make_execution, make_procedure, make_user


class _FakeJob:
    pk = 9999


class ExecutionApiTests(TestCase):
    def setUp(self):
        self.user = make_user("api-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.proc = make_procedure("os.linux.test.echo")

    def _detail_url(self, ex):
        return reverse("plugins-api:netbox_rpc-api:rpcexecution-detail", args=[ex.pk])

    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_create_emits_queued_and_job_enqueued(self, _enqueue):
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
