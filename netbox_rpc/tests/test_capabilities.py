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
    derive_legacy_command_contract_hash,
    verify_procedure_capability,
)
from netbox_rpc.constants import EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES
from netbox_rpc.models import RPCExecution, RPCProcedure, RPCProcedureCommand

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

    def test_akvorado_semantic_hashes_match_backend_ground_truth(self):
        expected = {
            "os.linux.debian.13.preflight_akvorado": (
                "0e255fae89badfaf7de2187cfa3c48c4e7a6d8b2b4c5837acf53952453878161"
            ),
            "os.linux.debian.13.install_akvorado": (
                "95795e4c7c08800a4fd844af86ee47018c8a267ddefcf47a46c4de8e838368ec"
            ),
            "service.akvorado.1.config_deploy": (
                "6a8d8fee107c3c825db6bf334ccecfdec8a71135bd6cd2e89734b85a00de2082"
            ),
            "service.akvorado.1.config_read": (
                "5c9faf273d18d2316c1f00453d03cdce0ea6ca6eae416a1f0168f7dd412f53e6"
            ),
            "service.akvorado.1.restart_stack": (
                "472ed07c0582ebeaaaa7b5da8490bdab2386f1183910a3593c5eee8d5c707d49"
            ),
            "service.akvorado.1.status_stack": (
                "682f89b76b6246cbc88d4ac223c9201cd69efabacaf8dcf2da7137a6b484b785"
            ),
        }
        for procedure_name, digest in expected.items():
            procedure = RPCProcedure.objects.get(name=procedure_name)
            assert derive_command_contract_hash(procedure) == digest

    def test_akvorado_semantic_hash_changes_with_policy_or_schema_drift(self):
        procedure = RPCProcedure.objects.get(
            name="os.linux.debian.13.install_akvorado"
        )
        expected = derive_command_contract_hash(procedure)

        procedure.timeout_seconds -= 1
        assert derive_command_contract_hash(procedure) != expected
        procedure.timeout_seconds += 1
        procedure.result_schema = {"type": "object"}
        assert derive_command_contract_hash(procedure) != expected

    def test_akvorado_lifecycle_hashes_bind_authorization_and_schema_policy(self):
        from netbox_rpc.akvorado_bootstrap_contract import (
            AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES,
        )

        mutations = {
            "approval_required": lambda value: not value,
            "timeout_seconds": lambda value: value - 1,
            "target_models": lambda value: list(reversed(value)) + ["extras.invalid"],
            "transport_driver": lambda _value: "paramiko",
            "transport_pinned": lambda value: not value,
            "params_schema": lambda _value: {"type": "object"},
            "result_schema": lambda _value: {"type": "object"},
        }
        for (
            procedure_name,
            expected,
        ) in AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES.items():
            procedure = RPCProcedure.objects.get(name=procedure_name)
            assert derive_command_contract_hash(procedure) == expected
            for field, mutate in mutations.items():
                original = getattr(procedure, field)
                setattr(procedure, field, mutate(original))
                with self.subTest(procedure=procedure_name, field=field):
                    assert derive_command_contract_hash(procedure) != expected
                setattr(procedure, field, original)

    def test_akvorado_lifecycle_mixed_version_matrix_is_bounded(self):
        from netbox_rpc.akvorado_bootstrap_contract import (
            AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES,
        )

        for (
            procedure_name,
            current_hash,
        ) in AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES.items():
            procedure = RPCProcedure.objects.get(name=procedure_name)
            legacy_hash = derive_legacy_command_contract_hash(procedure)
            old_backend = BackendCapabilityManifest(
                envelope_version=1,
                handlers=[
                    HandlerCapability(
                        handler_id=procedure.handler_id,
                        version=procedure.version,
                        effect=procedure.effect,
                        contract_hash=legacy_hash,
                    )
                ],
            )
            rolling_backend = BackendCapabilityManifest(
                envelope_version=1,
                handlers=[
                    HandlerCapability(
                        handler_id=procedure.handler_id,
                        version=procedure.version,
                        effect=procedure.effect,
                        contract_hash=legacy_hash,
                        compatible_contract_hashes=[current_hash],
                    )
                ],
            )
            assert (
                verify_procedure_capability(procedure, old_backend)
                is CapabilityStatus.COMPATIBLE
            )
            assert (
                verify_procedure_capability(procedure, rolling_backend)
                is CapabilityStatus.COMPATIBLE
            )
            original = procedure.approval_required
            procedure.approval_required = not original
            assert (
                verify_procedure_capability(procedure, old_backend)
                is CapabilityStatus.MISMATCH
            )
            procedure.approval_required = original


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

    def test_redirect_is_not_followed(self):
        with mock.patch(
            "netbox_rpc.capabilities.requests.get",
            return_value=_fake_response(status=307),
        ) as get:
            assert (
                capabilities.fetch_backend_capabilities(self.target, use_cache=False)
                is None
            )
        assert get.call_count == 1
        assert get.call_args.kwargs["allow_redirects"] is False

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

    def test_mid_body_transport_failure_returns_none_and_closes(self):
        response = _fake_response()
        response.raw.read.side_effect = RuntimeError("connection reset mid-body")
        with mock.patch(
            "netbox_rpc.capabilities.requests.get",
            return_value=response,
        ):
            assert (
                capabilities.fetch_backend_capabilities(self.target, use_cache=False)
                is None
            )
        response.close.assert_called_once_with()

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

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    def test_available_excludes_every_explicit_capability_without_manifest(self, fetch):
        procedures = RPCProcedure.objects.filter(
            name__in=EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES
        )
        assert procedures.count() == len(EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES)
        procedures.update(enabled=True)

        url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-available")
        resp = self.client.get(url)

        assert resp.status_code == 200, resp.content
        returned = resp.data.get("results", resp.data)
        ids = {row["id"] for row in returned}
        assert not ids & set(procedures.values_list("pk", flat=True))

    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    def test_akvorado_preflight_admission_requires_manifest(self, fetch, enqueue):
        procedure = RPCProcedure.objects.get(
            name="os.linux.debian.13.preflight_akvorado"
        )
        procedure.enabled = True
        procedure.save(update_fields=["enabled"])
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")

        resp = self.client.post(
            url,
            {
                "procedure_id": procedure.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {},
            },
            format="json",
        )

        assert resp.status_code == 400, resp.content
        assert not RPCExecution.objects.filter(procedure=procedure).exists()
        enqueue.assert_not_called()
