"""Real admission, worker, scope revocation and transactional reveal boundaries."""

import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import OperationalError, connections, transaction
from django.test import TestCase, TransactionTestCase
from rest_framework.exceptions import PermissionDenied
from rest_framework.exceptions import ValidationError as APIValidationError

from netbox_rpc import capabilities
from netbox_rpc import credential_authority as authority
from netbox_rpc import dispatch_lease as dl
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.application import command_handlers
from netbox_rpc.constants import UBUNTU_24_DAEMON_RELOAD
from netbox_rpc.credential_contract import apply_credential_fingerprint, canonical_hash
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.domain.normalization import RPCExecutionError
from netbox_rpc.models import RPCBackend, RPCExecution, RPCProcedure

from ._common import make_procedure, make_user
from .test_credential_authority import CredentialAuthorityFixture


def grant(user, model, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    permission = ObjectPermission.objects.create(
        name=f"credential-grant-{user.pk}-{'-'.join(actions)}",
        actions=actions,
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(model)])
    permission.users.add(user)
    return permission


class CredentialDispatchTests(CredentialAuthorityFixture, TestCase):
    def setUp(self):
        super().setUp()
        # Reuse a supported normalizer, without replacing normalization or any
        # authority guard. The catalog definition still undergoes real hashing.
        self.procedure = make_procedure(
            UBUNTU_24_DAEMON_RELOAD, target_models=["dcim.device"], effect="write"
        )
        # This low-risk-write fixture deliberately varies the supported
        # normalizer's catalog policy; protected policy is tested separately.
        # Set it explicitly whether historical seeds are present or flushed.
        self.procedure.approval_required = False
        self.procedure.result_schema = {}
        self.procedure.enabled = True
        self.procedure.save()
        self.manifest = capabilities.BackendCapabilityManifest(
            envelope_version=1,
            credential_reference_versions=[1],
            credential_provider_versions={"netbox-openbao": [1]},
            dispatch_lease_versions=[1],
            handlers=[capabilities.HandlerCapability(
                handler_id=self.procedure.handler_id,
                version=self.procedure.version,
                effect=self.procedure.effect,
                contract_hash=capabilities.derive_command_contract_hash(self.procedure),
            )],
        )
        patcher = mock.patch.object(
            capabilities, "fetch_backend_capabilities", return_value=self.manifest
        )
        self.capabilities_fetch = patcher.start()
        self.addCleanup(patcher.stop)

    def _admit(self, *, actor=None, references=True):
        serializer = RPCExecutionSerializer(data={
            "procedure_id": self.procedure.pk,
            "assigned_object_type": "dcim.device",
            "assigned_object_id": self.device.pk,
            "params": {},
            "credential_references": self.references if references else {},
        })
        provider = SimpleNamespace(capture_reference_identity=mock.Mock(return_value=self.provider_identity))
        with (
            mock.patch.dict(sys.modules, {"netbox_openbao.automation": provider}),
            mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue",
                       return_value=SimpleNamespace(pk=7309)) as enqueue,
        ):
            execution = command_handlers.create_execution(
                serializer=serializer, user=actor or self.actor
            )
        enqueue.assert_called_once()
        assert execution.credential_references == (self.references if references else {})
        return execution

    def _run_and_resolve(self, execution):
        captured = {}

        def backend(target, claimed, *, lease):
            claimed.refresh_from_db()
            assert claimed.status == RPCExecution.STATUS_RUNNING
            assert claimed.events.order_by("-sequence").first().event == "DispatchLeaseIssued"
            authorization = authority.validate_secret_resolution_dispatch(
                execution=claimed,
                dispatch_lease=lease.model_dump(),
                authenticated_executor=self.executor,
                reference_name="ssh",
            )
            assert authorization.initiating_actor.pk == self.actor.pk
            captured["lease"] = lease
            return {"ok": True, "result": {}}

        with mock.patch("netbox_rpc.jobs._call_backend", side_effect=backend) as dispatch:
            command_handlers.run_execution(execution)
        dispatch.assert_called_once()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_SUCCEEDED
        assert execution.normalized_params["command_fingerprint"][
            "credential_authority_sha256"
        ] == canonical_hash(execution.credential_authority)
        return captured["lease"]

    def test_real_admission_worker_issuance_resolution_ttl_matrix(self):
        configured_setting = dl._plugin_setting.side_effect
        for configured, expected in ((None, 120), (30, 30), (300, 300), (600, 300)):
            with self.subTest(configured=configured):
                execution = self._admit()

                def setting(name, default=None):
                    if name == dl._TTL_SETTING:
                        return configured
                    return configured_setting(name, default)

                with mock.patch.object(dl, "_plugin_setting", side_effect=setting):
                    lease = self._run_and_resolve(execution)
                lifetime = datetime.fromisoformat(lease.claims.expires_at) - datetime.fromisoformat(
                    lease.claims.issued_at
                )
                assert lifetime.total_seconds() == expected

    def test_non_reference_worker_preserves_configured_600_second_lease(self):
        execution = self._admit(references=False)
        configured_setting = dl._plugin_setting.side_effect

        def setting(name, default=None):
            return 600 if name == dl._TTL_SETTING else configured_setting(name, default)

        with (
            mock.patch.object(dl, "_plugin_setting", side_effect=setting),
            mock.patch("netbox_rpc.jobs._call_backend", return_value={"ok": True}) as dispatch,
        ):
            command_handlers.run_execution(execution)
        lease = dispatch.call_args.kwargs["lease"]
        assert (datetime.fromisoformat(lease.claims.expires_at)
                - datetime.fromisoformat(lease.claims.issued_at)).total_seconds() == 600

    def _assert_worker_denied(self, execution, error_type=authority.SecretResolutionDenied):
        with mock.patch("netbox_rpc.jobs._call_backend") as dispatch:
            with self.assertRaises(error_type):
                command_handlers.run_execution(execution)
        dispatch.assert_not_called()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_FAILED
        assert not execution.events.filter(event="DispatchLeaseIssued").exists()

    def test_missing_provider_capabilities_stop_worker_dispatch(self):
        for missing in ("credential_reference_versions", "credential_provider_versions",
                        "dispatch_lease_versions"):
            with self.subTest(missing=missing):
                execution = self._admit()
                absent = {} if missing == "credential_provider_versions" else []
                self.capabilities_fetch.return_value = self.manifest.model_copy(update={missing: absent})
                self._assert_worker_denied(execution)
                self.capabilities_fetch.return_value = self.manifest

    def test_missing_capability_manifest_stops_worker_dispatch(self):
        execution = self._admit()
        self.capabilities_fetch.return_value = None
        self._assert_worker_denied(execution)

    def test_missing_signing_key_stops_worker_dispatch(self):
        execution = self._admit()
        with mock.patch.object(dl, "load_active_signing_key", return_value=None):
            self._assert_worker_denied(execution)

    def test_signing_key_disappearing_after_readiness_stops_worker_dispatch(self):
        execution = self._admit()
        signing_key = dl.load_active_signing_key()
        with mock.patch.object(dl, "load_active_signing_key", side_effect=[signing_key, None]):
            self._assert_worker_denied(execution, RPCExecutionError)
        assert execution.error_code == "RPC_DISPATCH_LEASE_REQUIRED"

    def test_policy_drift_stops_worker_before_capability_or_dispatch(self):
        execution = self._admit()
        RPCProcedure.objects.filter(pk=self.procedure.pk).update(timeout_seconds=29)
        self.capabilities_fetch.reset_mock()
        self._assert_worker_denied(execution)
        self.capabilities_fetch.assert_not_called()

    def test_scoped_execution_permission_revocation_stops_worker(self):
        actor = make_user("scoped-credential-initiator", superuser=False)
        grant(actor, RPCProcedure, ["view"])
        permission = grant(actor, RPCProcedure, ["execute"], {"id": self.procedure.pk})
        grant(actor, RPCBackend, ["view"])
        grant(actor, type(self.device), ["view"])
        execution = self._admit(actor=actor)
        other = make_procedure("credential.other.executable")
        permission.constraints = {"id": other.pk}
        permission.save()
        refreshed = get_user_model().objects.get(pk=actor.pk)
        assert refreshed.has_perm("netbox_rpc.execute_rpcprocedure")
        self._assert_worker_denied(execution)

    def test_credential_policy_mismatch_is_not_issued(self):
        execution = self._admit()
        normalized = command_handlers.normalize_execution_params(execution)
        normalized["credential_policy_ref"] = "credential-authority:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "does not match"):
            command_handlers._issue_dispatch_lease(
                execution, RPCExecutionAggregate(execution), normalized
            )
        assert not execution.events.filter(event="DispatchLeaseIssued").exists()

    def test_non_reference_credential_policy_fallbacks_are_unchanged(self):
        execution = SimpleNamespace(procedure=SimpleNamespace(effect="read"))
        assert command_handlers._credential_policy_reference(
            {"ssh_policy_ref": "  approved-policy  "}, execution
        ) == "approved-policy"
        for invalid in (None, 7, "", "x" * 201, "bad\npolicy", "bad\x7fpolicy"):
            with self.subTest(invalid=invalid):
                normalized = {"ssh_policy_ref": invalid, "rpc_ssh_credential_pk": 19}
                assert command_handlers._credential_policy_reference(
                    normalized, execution
                ) == "device_credential:19"
        assert command_handlers._credential_policy_reference({}, execution) == "procedure_effect:read"

    def test_real_admission_rejects_missing_permission_and_disabled_procedure(self):
        actor = make_user("credential-no-permissions", superuser=False)
        with self.assertRaises(PermissionDenied):
            self._admit(actor=actor)
        self.procedure.enabled = False
        self.procedure.save()
        with self.assertRaises(APIValidationError):
            self._admit()

    def test_issuer_identity_and_ttl_fallback_paths(self):
        from django.utils import timezone

        now = timezone.now()
        for identity in (SimpleNamespace(pk=None, procedure=self.procedure),
                         SimpleNamespace(pk=1, procedure=None)):
            with self.subTest(identity=identity):
                assert dl.issue_dispatch_lease(
                    identity, stream_version=0, normalized_params={}, now=now
                ) is None
        for value, expected in (("invalid", 120), (-1, 1), (9999, 900)):
            with self.subTest(ttl=value):
                lease = dl.issue_dispatch_lease(
                    SimpleNamespace(pk=1, procedure=self.procedure),
                    stream_version=0, normalized_params={}, now=now, ttl_seconds=value,
                )
                assert (datetime.fromisoformat(lease.claims.expires_at) - now).total_seconds() == expected


class CredentialApprovalScopeTests(CredentialAuthorityFixture, TestCase):
    def _protected_execution(self):
        from netbox_rpc import staging_rotation_contract as contract

        defaults = {
            key: value for key, value in contract.PROCEDURE_POLICY.items()
            if key not in {"name", "command_contract_sha256"}
        }
        defaults.update(params_schema=contract.PARAMS_SCHEMA, result_schema=contract.RESULT_SCHEMA)
        self.procedure, _ = RPCProcedure.objects.update_or_create(
            name=contract.PROCEDURE_NAME, defaults=defaults
        )
        command = dict(contract.COMMAND_CONTRACT[0])
        sequence = command.pop("sequence")
        self.procedure.commands.update_or_create(sequence=sequence, defaults=command)
        self.execution = self._make_execution()
        normalized = {"command_fingerprint": {"target_object_sha256": "c" * 64}}
        apply_credential_fingerprint(self.execution, normalized)
        aggregate = RPCExecutionAggregate(self.execution)
        aggregate.request(requested_by_id=self.actor.pk)
        snapshot = command_handlers._create_approval_request(self.execution, normalized)
        aggregate.request_approval(snapshot_hash=snapshot.payload_hash, requested_by_id=self.actor.pk)
        return aggregate, normalized, snapshot

    def test_exact_approval_scope_is_rechecked_after_issuance(self):
        aggregate, normalized, snapshot = self._protected_execution()
        approver = make_user("scoped-credential-approver", superuser=False)
        grant(approver, RPCProcedure, ["view"])
        permission = grant(approver, RPCProcedure, ["approve"], {"id": self.procedure.pk})
        grant(approver, type(self.device), ["view"])
        aggregate.approve(approver_id=approver.pk, queue_after_approval=True)
        aggregate.start()
        aggregate.normalize(normalized, canonical_hash(normalized["command_fingerprint"]))
        self.lease = command_handlers._issue_dispatch_lease(self.execution, aggregate, normalized)
        assert self._authorize().approval_snapshot_hash == snapshot.payload_hash
        other = make_procedure("credential.other.approvable")
        permission.constraints = {"id": other.pk}
        permission.save()
        refreshed = get_user_model().objects.get(pk=approver.pk)
        assert refreshed.has_perm("netbox_rpc.approve_rpcprocedure")
        assert RPCProcedure.objects.restrict(refreshed, "view").filter(pk=self.procedure.pk).exists()
        with self.assertRaises(PermissionDenied):
            self._authorize()

    def test_invalid_public_metadata_is_redacted_before_persistence(self):
        from netbox_rpc.event_store import redact_event_value

        for key, value in (
            ("credential_references", {"ssh": self.references["ssh"] | {"password": "canary"}}),
            ("credential_authority_sha256", "canary"),
            ("credential_policy_ref", "credential-authority:canary"),
        ):
            with self.subTest(key=key):
                assert redact_event_value(value, parent_key=key) == "[REDACTED]"

    def test_event_redaction_bounds_and_unknown_value_are_preserved(self):
        from netbox_rpc import event_store

        value = {f"item-{index}": index for index in range(event_store.MAX_EVENT_DICT_ITEMS + 1)}
        assert event_store.redact_event_value(value)["_truncated"] is True
        value = [0] * (event_store.MAX_EVENT_LIST_ITEMS + 1)
        assert event_store.redact_event_value(value)[-1] == {"_truncated": True, "remaining": 1}
        assert event_store.redact_event_value(("bounded",)) == "('bounded',)"


def update_command_with_short_lock_timeout(command_id):
    from netbox_rpc.models import RPCProcedureCommand

    try:
        with transaction.atomic(), connections["default"].cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout = '250ms'")
            RPCProcedureCommand.objects.filter(pk=command_id).update(argv=["changed"])
    finally:
        connections["default"].close()


class CredentialCommandLockTests(CredentialAuthorityFixture, TransactionTestCase):
    def test_child_command_update_cannot_cross_authorized_reveal_transaction(self):
        from netbox_rpc.models import RPCProcedureCommand

        command = RPCProcedureCommand.objects.create(
            procedure=self.procedure, sequence=7, argv=["original"]
        )
        self.execution = self._make_execution()
        self.lease = self._start_and_issue(self.execution)
        with ThreadPoolExecutor(max_workers=1) as writers:
            with transaction.atomic():
                self._authorize()
                blocked = writers.submit(update_command_with_short_lock_timeout, command.pk)
                with self.assertRaises(OperationalError) as raised:
                    blocked.result(timeout=5)
                assert raised.exception.__cause__.sqlstate == "55P03"
                command.refresh_from_db()
                assert command.argv == ["original"]
            writers.submit(update_command_with_short_lock_timeout, command.pk).result(timeout=5)
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()
