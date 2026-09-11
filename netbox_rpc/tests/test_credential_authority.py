"""Real ORM, signature, event-ledger and revocation proofs for secret authority."""

from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.utils import timezone

from netbox_rpc import credential_authority as authority
from netbox_rpc.application import command_handlers
from netbox_rpc.credential_contract import apply_credential_fingerprint, canonical_hash
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCBackend, RPCExecution, RpcPluginSettings

from ._common import device_ct, make_device, make_procedure, make_user
from .test_dispatch_lease import _configure_key


class CredentialAuthorityFixture:
    def setUp(self):
        self.actor = make_user("credential-initiator")
        self.executor = make_user("credential-executor")
        self.device = make_device("credential-target")
        self.backend = RPCBackend.objects.create(
            name="credential-backend",
            base_url="https://executor.example.test",
            executor_identity=self.executor,
        )
        config = RpcPluginSettings.get_solo()
        config.enabled = True
        config.backend = self.backend
        config.save()
        self.procedure = make_procedure(
            "os.linux.test.references",
            target_models=["dcim.device"],
            effect="read",
            params_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        )
        self.references = {
            "ssh": {
                "schema_version": 1,
                "provider": "netbox-openbao",
                "assignment_id": 7,
                "target": {"object_type": "dcim.device", "object_id": self.device.pk},
                "purpose": "login",
                "fields": ["private_key", "passphrase"],
                "version": {"policy": "live"},
            }
        }
        self.key_patch = _configure_key("15" * 32)
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)
        self.execution = self._make_execution()
        self.lease = self._start_and_issue(self.execution)

    def _make_execution(self):
        serializer = SimpleNamespace(
            validated_data={
                "procedure": self.procedure,
                "assigned_object_type": device_ct(),
                "assigned_object_id": self.device.pk,
                "params": {},
                "credential_references": deepcopy(self.references),
            }
        )
        self.provider_identity = {
            "credential_uuid": "00000000-0000-0000-0000-000000000001",
            "assignment_id": 7,
            "username": "test-operator",
            "fingerprint": "",
            "target": self.references["ssh"]["target"],
            "purpose": "login",
            "credential_type": "ssh-key",
            "policy_id": 1,
            "engine_id": 1,
            "engine_identity_sha256": "a" * 64,
            "schema_sha256": "b" * 64,
        }
        with mock.patch.object(
            authority,
            "_capture_provider_identities",
            return_value={"ssh": self.provider_identity},
        ):
            authority.prepare_reference_execution(
                serializer, self.actor, self.backend.pk
            )
        return RPCExecution.objects.create(
            requested_by=self.actor,
            backend=self.backend.pk,
            **serializer.validated_data,
        )

    def _start_and_issue(self, execution):
        aggregate = RPCExecutionAggregate(execution)
        aggregate.queue()
        aggregate.start()
        normalized = {
            "command_fingerprint": {
                "operation": "read",
                "target_object_sha256": canonical_hash({"target": self.device.pk}),
            }
        }
        apply_credential_fingerprint(execution, normalized)
        aggregate.normalize(
            normalized, canonical_hash(normalized["command_fingerprint"])
        )
        return command_handlers._issue_dispatch_lease(execution, aggregate, normalized)

    def _authorize(self, **kwargs):
        arguments = {
            "execution": self.execution,
            "dispatch_lease": self.lease.model_dump(),
            "authenticated_executor": self.executor,
            "reference_name": "ssh",
        }
        arguments.update(kwargs)
        return authority.validate_secret_resolution_dispatch(**arguments)


class CredentialAuthorityTests(CredentialAuthorityFixture, TestCase):
    def test_authoritative_actor_target_reference_and_correlation(self):
        authorized = self._authorize()
        assert authorized.initiating_actor.pk == self.actor.pk
        assert authorized.executor_id == self.executor.pk
        assert authorized.target_object.pk == self.device.pk
        assert authorized.reference.to_mapping() == self.references["ssh"]
        assert (
            authorized.correlation_id
            == self.execution.credential_authority["correlation_id"]
        )
        assert authorized.dispatch_nonce == self.lease.claims.nonce
        assert authorized.step_id == ""
        assert authorized.provider_identity == self.provider_identity
        # The helper neither consumes a backend nonce nor creates a reveal receipt.
        assert self._authorize().dispatch_nonce == authorized.dispatch_nonce

    def test_passed_instance_is_not_authority(self):
        self.execution.requested_by = self.executor
        self.execution.credential_references = {"ssh": {"password": "canary"}}
        assert self._authorize().initiating_actor.pk == self.actor.pk

    def test_provider_identity_rejects_undeclared_material_and_binding_drift(self):
        reference = authority.CredentialReferenceV1.from_mapping(self.references["ssh"])
        for changes in (
            {"private_key": "secret-canary"},
            {"assignment_id": 8},
            {"purpose": "api"},
            {"engine_id": True},
            {"schema_sha256": "invalid"},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(authority.SecretResolutionDenied),
            ):
                authority._validated_provider_identity(
                    self.provider_identity | changes, reference
                )

    def test_optional_provider_missing_fails_closed(self):
        import sys

        with mock.patch.dict(sys.modules, {"netbox_openbao.automation": None}):
            with self.assertRaises(authority.SecretResolutionDenied):
                authority._capture_provider_identities(
                    self.references, self.actor, self.device, self.procedure
                )

    def test_capture_freezes_only_valid_provider_identity(self):
        import sys

        provider = SimpleNamespace(
            capture_reference_identity=mock.Mock(return_value=self.provider_identity)
        )
        with mock.patch.dict(sys.modules, {"netbox_openbao.automation": provider}):
            captured = authority._capture_provider_identities(
                self.references, self.actor, self.device, self.procedure
            )
        assert captured == {"ssh": self.provider_identity}
        assert captured["ssh"] is not self.provider_identity
        assert (
            provider.capture_reference_identity.call_args.kwargs["initiating_actor"]
            is self.actor
        )

    def test_credential_capability_versions_are_strict_and_bounded(self):
        from pydantic import ValidationError as ManifestValidationError

        from netbox_rpc.capabilities import BackendCapabilityManifest

        for bad in (True, 1.0, "1", 0, 256):
            for key in ("credential_reference_versions", "dispatch_lease_versions"):
                with (
                    self.subTest(bad=bad, key=key),
                    self.assertRaises(ManifestValidationError),
                ):
                    BackendCapabilityManifest(envelope_version=1, **{key: [bad]})
        with self.assertRaises(ManifestValidationError):
            BackendCapabilityManifest(
                envelope_version=1,
                credential_provider_versions={"netbox-openbao": [1] * 9},
            )

    def test_snapshot_is_immutable_through_orm_and_queryset(self):
        self.execution.credential_references = {}
        with self.assertRaises(ValidationError):
            self.execution.save()
        with self.assertRaises(DatabaseError), transaction.atomic():
            RPCExecution.objects.filter(pk=self.execution.pk).update(
                credential_authority={}
            )

    def test_rollback_binary_insert_can_omit_new_credential_columns(self):
        # Reproduce an old binary's explicit pre-expansion column list. Copy
        # ordinary values from a fixture, excluding the identity and new fields.
        excluded = {"id", "credential_references", "credential_authority"}
        columns = [
            field.column
            for field in RPCExecution._meta.concrete_fields
            if field.column not in excluded
        ]
        quoted = ", ".join(connection.ops.quote_name(column) for column in columns)
        table = connection.ops.quote_name(RPCExecution._meta.db_table)
        with connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO {table} ({quoted}) SELECT {quoted} FROM {table} WHERE id = %s RETURNING id",
                [self.execution.pk],
            )
            inserted_id = cursor.fetchone()[0]
        inserted = RPCExecution.objects.get(pk=inserted_id)
        assert inserted.credential_references == {}
        assert inserted.credential_authority == {}

    def test_reference_metadata_survives_event_redaction(self):
        self.execution.refresh_from_db()
        assert (
            self.execution.normalized_params["credential_references"] == self.references
        )
        assert self.execution.normalized_params["command_fingerprint"][
            "credential_authority_sha256"
        ] == canonical_hash(self.execution.credential_authority)

    def test_wrong_executor_and_unknown_step_are_refused(self):
        for changes in (
            {"authenticated_executor": self.actor},
            {"step_id": "future"},
            {"reference_name": "unknown"},
            {"dispatch_lease": {}},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(authority.SecretResolutionDenied),
            ):
                self._authorize(**changes)

    def test_actor_revocation_is_rechecked(self):
        self.actor.is_active = False
        self.actor.save()
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()

    def test_executor_revocation_is_rechecked(self):
        self.executor.is_active = False
        self.executor.save()
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()

    def test_backend_identity_change_invalidates_frozen_authority(self):
        self.backend.executor_identity = self.actor
        self.backend.save()
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()

    def test_target_revision_and_procedure_policy_changes_invalidate_authority(self):
        self.device.description = "Target changed after admission"
        self.device.save()
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()

    def test_procedure_policy_change_is_rejected(self):
        self.procedure.effect = "destructive"
        self.procedure.save()
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()

    def test_command_definition_drift_is_rejected(self):
        from netbox_rpc.models import RPCProcedureCommand

        RPCProcedureCommand.objects.create(
            procedure=self.procedure,
            sequence=1,
            step_type="shell_argv",
            argv=["echo", "changed"],
        )
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()

    def test_current_target_object_restriction_is_rechecked(self):
        with mock.patch.object(
            type(self.device).objects,
            "restrict",
            return_value=type(self.device).objects.none(),
        ):
            with self.assertRaises(authority.SecretResolutionDenied):
                self._authorize()

    def test_terminal_event_after_issuance_blocks_resolution(self):
        RPCExecutionAggregate(self.execution).fail(
            "Execution terminated.", "test_terminal"
        )
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize()

    def test_all_expected_claims_are_passed_to_reference_verifier(self):
        from netbox_rpc import dispatch_lease as dl

        with mock.patch.object(
            dl, "verify_dispatch_lease", wraps=dl.verify_dispatch_lease
        ) as verifier:
            self._authorize()
        arguments = verifier.call_args.kwargs
        assert arguments["expected_execution_id"] == self.execution.pk
        assert arguments["expected_stream_version"] == self.lease.claims.stream_version
        assert arguments["expected_handler_id"] == self.procedure.handler_id
        assert arguments["expected_handler_version"] == self.procedure.version
        assert arguments["expected_effect"] == "read"
        assert arguments["expected_requested_by_id"] == self.actor.pk
        assert arguments["expected_approved_by_id"] is None
        assert arguments["expected_contract_hash"] == self.lease.claims.contract_hash
        assert (
            arguments["expected_target_snapshot_hash"]
            == self.lease.claims.target_snapshot_hash
        )
        assert (
            arguments["expected_params_fingerprint"]
            == self.lease.claims.params_fingerprint
        )
        assert (
            arguments["expected_credential_policy"]
            == self.lease.claims.credential_policy
        )

    def test_signed_requester_mismatch_is_refused(self):

        from netbox_rpc import dispatch_lease as dl

        claims = self.lease.claims.model_copy(
            update={"requested_by_id": self.executor.pk}
        )
        changed = self.lease.model_copy(
            update={
                "claims": claims,
                "signature": dl.load_active_signing_key().sign(
                    claims.canonical_bytes()
                ),
            }
        )
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize(dispatch_lease=changed.model_dump())

    def test_every_signed_execution_binding_is_enforced(self):
        from netbox_rpc import dispatch_lease as dl

        cases = {
            "execution_id": self.execution.pk + 1,
            "handler_id": "different.handler",
            "handler_version": self.procedure.version + 1,
            "effect": "write",
            "contract_hash": "c" * 64,
            "target_snapshot_hash": "d" * 64,
            "params_fingerprint": "e" * 64,
            "credential_policy": "credential-authority:" + "f" * 64,
            "requested_by_id": self.executor.pk,
            "trace_id": "00000000-0000-0000-0000-000000000099",
            "stream_version": self.lease.claims.stream_version + 1,
        }
        for field, value in cases.items():
            claims = self.lease.claims.model_copy(update={field: value})
            changed = self.lease.model_copy(
                update={
                    "claims": claims,
                    "signature": dl.load_active_signing_key().sign(
                        claims.canonical_bytes()
                    ),
                }
            )
            with (
                self.subTest(field=field),
                self.assertRaises(authority.SecretResolutionDenied),
            ):
                self._authorize(dispatch_lease=changed.model_dump())

    def test_reference_dispatch_requires_all_explicit_capabilities(self):
        from netbox_rpc.backends import BackendTarget
        from netbox_rpc.capabilities import (
            BackendCapabilityManifest,
            derive_command_contract_hash,
        )

        payload = {
            "envelope_version": 1,
            "credential_reference_versions": [1],
            "credential_provider_versions": {"netbox-openbao": [1]},
            "dispatch_lease_versions": [1],
            "handlers": [
                {
                    "handler_id": self.procedure.handler_id,
                    "version": self.procedure.version,
                    "effect": "read",
                    "contract_hash": derive_command_contract_hash(self.procedure),
                }
            ],
        }
        target = BackendTarget(self.backend.backend_url, {}, self.backend.verify_ssl)
        with mock.patch(
            "netbox_rpc.capabilities.fetch_backend_capabilities",
            return_value=BackendCapabilityManifest(**payload),
        ):
            authority.require_reference_dispatch_ready(self.execution, target)
        for field in (
            "credential_reference_versions",
            "credential_provider_versions",
            "dispatch_lease_versions",
        ):
            missing = {key: value for key, value in payload.items() if key != field}
            with mock.patch(
                "netbox_rpc.capabilities.fetch_backend_capabilities",
                return_value=BackendCapabilityManifest(**missing),
            ):
                with (
                    self.subTest(field=field),
                    self.assertRaises(authority.SecretResolutionDenied),
                ):
                    authority.require_reference_dispatch_ready(self.execution, target)

    def test_nullable_approver_cannot_be_smuggled_into_read_execution(self):
        from netbox_rpc import dispatch_lease as dl

        claims = self.lease.claims.model_copy(
            update={"approved_by_id": self.executor.pk}
        )
        changed = self.lease.model_copy(
            update={
                "claims": claims,
                "signature": dl.load_active_signing_key().sign(
                    claims.canonical_bytes()
                ),
            }
        )
        with self.assertRaises(authority.SecretResolutionDenied):
            self._authorize(dispatch_lease=changed.model_dump())

    def test_future_naive_expired_and_overlong_lease_times_are_refused(self):
        now = timezone.now()
        cases = [
            (now + timedelta(seconds=1), now + timedelta(seconds=60)),
            (now.replace(tzinfo=None), now + timedelta(seconds=60)),
            (now - timedelta(seconds=60), now),
            (now, now + timedelta(seconds=301)),
        ]
        for issued, expires in cases:
            with (
                self.subTest(issued=issued, expires=expires),
                self.assertRaises(authority.SecretResolutionDenied),
            ):
                authority._lease_times(
                    SimpleNamespace(
                        issued_at=issued.isoformat(), expires_at=expires.isoformat()
                    ),
                    now,
                )

    def test_absent_capabilities_refuses_reference_dispatch(self):
        from netbox_rpc.backends import BackendTarget

        with mock.patch(
            "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
        ):
            with self.assertRaises(authority.SecretResolutionDenied):
                authority.require_reference_dispatch_ready(
                    self.execution,
                    BackendTarget(self.backend.backend_url, {}, True),
                )

    def test_approval_required_legacy_procedure_cannot_use_permission_only_approval(
        self,
    ):
        self.procedure.approval_required = True
        with self.assertRaises(authority.SecretResolutionDenied):
            authority.require_reference_approval(
                self.execution, self.execution.normalized_params
            )

    def test_protected_approval_delegates_snapshot_validation_and_rechecks_approver(
        self,
    ):
        approver = make_user("credential-approver")
        self.procedure.name = "service.gitea.production.upgrade_1_27_1"
        self.procedure.approval_required = True
        context = SimpleNamespace(
            procedure=self.procedure,
            procedure_id=self.procedure.pk,
            requested_by_id=self.actor.pk,
            approved_by_id=approver.pk,
            approved_by=approver,
            assigned_object_type=device_ct(),
            assigned_object_id=self.device.pk,
            backend_id=self.backend.pk,
            approval_request=SimpleNamespace(payload_hash="approved-snapshot"),
        )
        normalized = {"command_fingerprint": {"credential_authority_sha256": "a" * 64}}
        with mock.patch.object(
            command_handlers, "_require_current_protected_approval"
        ) as snapshot_guard:
            assert (
                authority._current_approval(context, normalized) == "approved-snapshot"
            )
        snapshot_guard.assert_called_once()
        assert snapshot_guard.call_args.args == (context, normalized)
        assert (
            snapshot_guard.call_args.kwargs["backend_target"].url
            == self.backend.backend_url
        )
        approver.is_active = False
        with self.assertRaises(authority.SecretResolutionDenied):
            authority._current_approval(context, normalized)

    def test_reference_backend_binding_and_non_reference_noop(self):
        authority.require_reference_backend(self.execution, self.backend.pk)
        with self.assertRaises(authority.SecretResolutionDenied):
            authority.require_reference_backend(self.execution, self.backend.pk + 1)
        authority.require_reference_backend(
            SimpleNamespace(credential_references={}), None
        )
        authority.require_reference_dispatch_ready(
            SimpleNamespace(credential_references={}), None
        )
        authority.require_reference_approval(
            SimpleNamespace(credential_references={}), {}
        )
