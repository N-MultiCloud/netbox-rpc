"""DB-backed proof that the Huawei NE8000 BGP rollout gate fails closed."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.models import RPCExecution, RPCProcedure

from ._common import enable_rpc_integration, make_device, make_user

_PROCEDURE_NAME = "network.device.huawei.router.ne8000.f1a.show_bgp_peer"


class _HuaweiBGPTestCase(TestCase):
    def setUp(self):
        self.user = make_user("huawei-bgp-gate-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.device = make_device()
        enable_rpc_integration()
        self.procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        # Simulate an operator bypassing the mutable catalog flag. The code
        # gate must remain authoritative until the backend rollout is ready.
        self.procedure.enabled = True
        self.procedure.save(update_fields=["enabled"])


class AdmissionTimeGateTests(_HuaweiBGPTestCase):
    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_create_execution_rejected_even_when_enabled(self, enqueue, _fetch):
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")
        resp = self.client.post(
            url,
            {
                "procedure_id": self.procedure.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {"vrf": "customer-a"},
            },
            format="json",
        )

        assert resp.status_code == 400, resp.content
        assert "cannot run yet" in str(resp.data)
        assert not RPCExecution.objects.filter(procedure=self.procedure).exists()
        enqueue.assert_not_called()


class AdvertisementTimeGateTests(_HuaweiBGPTestCase):
    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_available_excludes_gated_procedure_even_when_enabled(self, _fetch):
        url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-available")
        resp = self.client.get(url)

        assert resp.status_code == 200, resp.content
        returned = resp.data.get("results", resp.data)
        ids = {row["id"] for row in returned}
        assert self.procedure.pk not in ids
