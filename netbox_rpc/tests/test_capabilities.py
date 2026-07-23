"""Backend capability handshake tests (issue #167).

Covers the shared contract-hash derivation, manifest verification statuses,
bounded/graceful fetch (missing / malformed / oversized / mismatched), and
fail-closed-before-enqueue + available-filtering enforcement.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc import capabilities
from netbox_rpc.backends import BackendTarget
from netbox_rpc.capabilities import (
    BackendCapabilityManifest,
    CapabilityStatus,
    HandlerCapability,
    derive_command_contract_hash,
    verify_procedure_capability,
)
from netbox_rpc.models import RPCExecution, RPCProcedureCommand

from ._common import (
    enable_rpc_integration,
    make_device,
    make_procedure,
    make_user,
)


def _matching_manifest(procedure, *, envelope=1) -> BackendCapabilityManifest:
    return BackendCapabilityManifest(
        envelope_version=envelope,
        handlers=[
            HandlerCapability(
                handler_id=procedure.handler_id,
                version=procedure.version,
                effect=procedure.effect,
                contract_hash=derive_command_contract_hash(procedure),
            )
        ],
    )


class ContractHashTests(TestCase):
    def test_hash_is_stable_and_command_sensitive(self):
        proc = make_procedure("os.linux.test.hash", handler_id="h.hash", effect="read")
        h1 = derive_command_contract_hash(proc)
        assert h1 == derive_command_contract_hash(proc)  # stable
        RPCProcedureCommand.objects.create(
            procedure=proc, sequence=1, step_type="shell_argv", argv=["echo", "hi"]
        )
        proc.refresh_from_db()
        assert derive_command_contract_hash(proc) != h1  # command changed the hash


class VerifyTests(TestCase):
    def setUp(self):
        self.proc = make_procedure(
            "os.linux.test.verify", handler_id="h.v", effect="read"
        )

    def test_none_manifest_is_unknown(self):
        assert verify_procedure_capability(self.proc, None) is CapabilityStatus.UNKNOWN

    def test_matching_manifest_is_compatible(self):
        assert (
            verify_procedure_capability(self.proc, _matching_manifest(self.proc))
            is CapabilityStatus.COMPATIBLE
        )

    def test_unsupported_envelope_is_mismatch(self):
        m = _matching_manifest(self.proc, envelope=999)
        assert verify_procedure_capability(self.proc, m) is CapabilityStatus.MISMATCH

    def test_absent_handler_is_mismatch(self):
        m = BackendCapabilityManifest(envelope_version=1, handlers=[])
        assert verify_procedure_capability(self.proc, m) is CapabilityStatus.MISMATCH

    def test_version_mismatch(self):
        m = _matching_manifest(self.proc)
        bad = m.model_copy(
            update={"handlers": [m.handlers[0].model_copy(update={"version": 999})]}
        )
        assert verify_procedure_capability(self.proc, bad) is CapabilityStatus.MISMATCH

    def test_contract_hash_mismatch(self):
        m = _matching_manifest(self.proc)
        bad = m.model_copy(
            update={
                "handlers": [
                    m.handlers[0].model_copy(update={"contract_hash": "deadbeef"})
                ]
            }
        )
        assert verify_procedure_capability(self.proc, bad) is CapabilityStatus.MISMATCH


def _fake_response(*, status=200, body=b""):
    resp = mock.Mock()
    resp.status_code = status
    resp.raw.read.return_value = body
    resp.close.return_value = None
    return resp


class FetchTests(TestCase):
    def setUp(self):
        self.target = BackendTarget(
            url="http://backend.test:16005", headers={}, verify_ssl=True
        )
        capabilities.clear_capability_cache()

    def test_missing_route_returns_none(self):
        with mock.patch(
            "netbox_rpc.capabilities.requests.get",
            return_value=_fake_response(status=404),
        ):
            assert (
                capabilities.fetch_backend_capabilities(self.target, use_cache=False)
                is None
            )

    def test_connection_error_returns_none(self):
        import requests

        with mock.patch(
            "netbox_rpc.capabilities.requests.get", side_effect=requests.ConnectionError
        ):
            assert (
                capabilities.fetch_backend_capabilities(self.target, use_cache=False)
                is None
            )

    def test_malformed_json_returns_none(self):
        with mock.patch(
            "netbox_rpc.capabilities.requests.get",
            return_value=_fake_response(body=b"not json"),
        ):
            assert (
                capabilities.fetch_backend_capabilities(self.target, use_cache=False)
                is None
            )

    def test_oversized_body_returns_none(self):
        big = b"x" * (capabilities._MAX_MANIFEST_BYTES + 1)
        with mock.patch(
            "netbox_rpc.capabilities.requests.get",
            return_value=_fake_response(body=big),
        ):
            assert (
                capabilities.fetch_backend_capabilities(self.target, use_cache=False)
                is None
            )

    def test_valid_manifest_is_parsed(self):
        body = b'{"envelope_version": 1, "handlers": [{"handler_id": "h", "version": 1, "effect": "read", "contract_hash": "abc"}]}'
        with mock.patch(
            "netbox_rpc.capabilities.requests.get",
            return_value=_fake_response(body=body),
        ):
            m = capabilities.fetch_backend_capabilities(self.target, use_cache=False)
        assert m is not None
        assert m.envelope_version == 1
        assert m.handler("h").effect == "read"


class EnforcementTests(TestCase):
    def setUp(self):
        self.user = make_user("cap-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.proc = make_procedure(
            "os.linux.test.cap", handler_id="h.cap", effect="read"
        )
        self.device = make_device()
        enable_rpc_integration()

    def _create(self):
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")
        return self.client.post(
            url,
            {
                "procedure_id": self.proc.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {},
            },
            format="json",
        )

    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_create_fails_closed_on_capability_mismatch(self, fetch, enqueue):
        enqueue.return_value = mock.Mock(pk=1)
        fetch.return_value = BackendCapabilityManifest(envelope_version=1, handlers=[])
        resp = self._create()
        assert resp.status_code == 400, resp.content
        assert not RPCExecution.objects.exists()

    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_create_proceeds_when_backend_advertises_nothing(self, fetch, enqueue):
        enqueue.return_value = mock.Mock(pk=1)
        resp = self._create()
        assert resp.status_code == 201, resp.content

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_available_filters_mismatched_procedures(self, fetch):
        # Manifest advertises nothing for this handler -> mismatch -> filtered out.
        fetch.return_value = BackendCapabilityManifest(envelope_version=1, handlers=[])
        url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-available")
        resp = self.client.get(url)
        assert resp.status_code == 200, resp.content
        returned = resp.data.get("results", resp.data)
        ids = {row["id"] for row in returned}
        assert self.proc.pk not in ids
