"""Authoritative opt-in + selected-backend enforcement tests (issue #166).

The ``RpcPluginSettings`` singleton is authoritative at execution creation and
at the worker claim: disabled / unconfigured integrations reject new work and
claims, and a normal requester cannot select an arbitrary backend.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.application import command_handlers
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCExecution, RpcPluginSettings

from ._common import (
    enable_rpc_integration,
    make_backend,
    make_device,
    make_execution,
    make_procedure,
    make_user,
)


class CreateEnforcementTests(TestCase):
    def setUp(self):
        self.user = make_user("optin-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.proc = make_procedure("os.linux.test.echo")
        self.device = make_device()

    def _create(self, **extra):
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")
        body = {
            "procedure_id": self.proc.pk,
            "assigned_object_type": "dcim.device",
            "assigned_object_id": self.device.pk,
            "params": {},
        }
        body.update(extra)
        return self.client.post(url, body, format="json")

    def test_create_rejected_when_integration_disabled(self):
        # Singleton defaults to enabled=False.
        assert RpcPluginSettings.get_solo().enabled is False
        resp = self._create()
        assert resp.status_code == 403, resp.content
        assert not RPCExecution.objects.exists()

    def test_create_rejected_when_no_backend_configured(self):
        settings_row = RpcPluginSettings.get_solo()
        settings_row.enabled = True
        settings_row.save()
        with mock.patch.object(
            RpcPluginSettings, "resolved_backend_target", return_value=None
        ):
            resp = self._create()
        assert resp.status_code == 400, resp.content
        assert not RPCExecution.objects.exists()

    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_requester_backend_id_is_ignored(self, enqueue):
        enqueue.return_value = mock.Mock(pk=4242)
        backend = make_backend()
        enable_rpc_integration(backend=backend)
        # Client tries to pick an arbitrary (non-existent) backend id.
        resp = self._create(backend_id=99999)
        assert resp.status_code == 201, resp.content
        ex = RPCExecution.objects.get(pk=resp.data["id"])
        # Authoritative selected backend wins over the client's choice.
        assert ex.backend == backend.pk


class ClaimEnforcementTests(TestCase):
    def test_worker_claim_rejected_when_disabled(self):
        enable_rpc_integration()
        ex = make_execution()
        RPCExecutionAggregate(ex).queue()
        # Operator disables the integration after the row was queued.
        settings_row = RpcPluginSettings.get_solo()
        settings_row.enabled = False
        settings_row.save()

        command_handlers.run_execution(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_FAILED
        assert ex.error_code == "RPC_INTEGRATION_DISABLED"

    @mock.patch.object(command_handlers, "resolve_backend")
    @mock.patch.object(command_handlers, "normalize_execution_params")
    @mock.patch("netbox_rpc.jobs._call_backend")
    def test_worker_claim_runs_when_enabled(self, call, norm, resolve):
        from netbox_rpc.backends import BackendTarget

        resolve.return_value = BackendTarget(
            url="http://backend.example", headers={}, verify_ssl=True
        )
        norm.return_value = {"command_fingerprint": {"handler_id": "x"}}
        call.return_value = {"ok": True, "result": {"stdout": "ok"}}
        enable_rpc_integration()
        ex = make_execution()
        RPCExecutionAggregate(ex).queue()
        command_handlers.run_execution(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_SUCCEEDED
