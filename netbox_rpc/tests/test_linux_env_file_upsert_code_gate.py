"""DB-backed proof that the os.linux_env_file.upsert_var code-level gate
(_LINUX_ENV_FILE_UPSERT_AVAILABLE) is enforced at admission time
(create_execution) and advertisement time (/procedures/available/), not only
at worker-claim time (round-4 adversarial review on PR #202).

RPCProcedure.enabled is mutable catalog data an operator could flip without
knowing the gate below it is still closed (see the migration 0060 and
normalization.py module comments). These tests force enabled=True directly
via the ORM -- simulating exactly that operator action -- and prove both
call sites still refuse the procedure while the code gate stays closed. The
existing worker-claim-time test (test_upsert_var_gate_blocks_by_default in
tests/test_jobs_linux_env_file_upsert_normalization.py) continues to cover
that layer as defense in depth.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.models import RPCExecution, RPCProcedure

from ._common import enable_rpc_integration, make_device, make_user

_PROCEDURE_NAME = "os.linux_env_file.upsert_var"


class _UpsertVarTestCase(TestCase):
    def setUp(self):
        self.user = make_user("env-file-gate-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.device = make_device()
        enable_rpc_integration()
        self.procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        # Simulate an operator flipping the mutable catalog flag while the
        # hard-coded code gate (_LINUX_ENV_FILE_UPSERT_AVAILABLE) stays closed.
        self.procedure.enabled = True
        self.procedure.save(update_fields=["enabled"])


class AdmissionTimeGateTests(_UpsertVarTestCase):
    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_create_execution_rejected_even_when_enabled(self, enqueue, _fetch):
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")
        resp = self.client.post(
            url,
            {
                "procedure_id": self.procedure.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {
                    "service_slug": "netbox",
                    "var_name": "FOO",
                    "credential_pk": 1,
                },
            },
            format="json",
        )

        assert resp.status_code == 400, resp.content
        assert "cannot run yet" in str(resp.data)
        assert not RPCExecution.objects.filter(procedure=self.procedure).exists()
        enqueue.assert_not_called()


class AdvertisementTimeGateTests(_UpsertVarTestCase):
    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    def test_available_excludes_gated_procedure_even_when_enabled(self, _fetch):
        url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-available")
        resp = self.client.get(url)

        assert resp.status_code == 200, resp.content
        returned = resp.data.get("results", resp.data)
        ids = {row["id"] for row in returned}
        assert self.procedure.pk not in ids
