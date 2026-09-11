"""Protected public admission, signed worker dispatch and reference authority."""

import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import OperationalError, connections, transaction
from django.test import TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from netbox_rpc import capabilities
from netbox_rpc import credential_authority as authority
from netbox_rpc import staging_rotation_contract as contract
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.application import command_handlers
from netbox_rpc.backends import resolve_backend
from netbox_rpc.models import (
    RPCBackend,
    RPCExecution,
    RPCProcedure,
    RPCProcedureCommand,
)

from ._common import make_procedure, make_user
from .test_credential_authority import CredentialAuthorityFixture
from .test_credential_dispatch import grant


class ProtectedCredentialDispatchFixture(CredentialAuthorityFixture):
    def setUp(self):
        super().setUp()
        self.device.name = "nms-front-door"
        self.device.save()
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
        self.actor = make_user("protected-reference-requester", superuser=False)
        self.approver = make_user("protected-reference-approver", superuser=False)
        grant(self.actor, RPCProcedure, ["view"], {"id": self.procedure.pk})
        self.execute_permission = grant(
            self.actor, RPCProcedure, ["execute"], {"id": self.procedure.pk}
        )
        grant(self.actor, RPCBackend, ["view"])
        grant(self.actor, type(self.device), ["view"])
        grant(self.approver, RPCProcedure, ["view"])
        grant(self.approver, type(self.device), ["view"])
        self.approve_permission = grant(
            self.approver, RPCProcedure, ["approve"], {"id": self.procedure.pk}
        )
        manifest = capabilities.BackendCapabilityManifest(
            envelope_version=1, credential_reference_versions=[1],
            credential_provider_versions={"netbox-openbao": [1]}, dispatch_lease_versions=[1],
            handlers=[capabilities.HandlerCapability(
                handler_id=self.procedure.handler_id, version=1, effect="destructive",
                contract_hash=capabilities.derive_command_contract_hash(self.procedure),
            )],
        )
        patcher = mock.patch.object(capabilities, "fetch_backend_capabilities", return_value=manifest)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.provider = SimpleNamespace(
            capture_reference_identity=mock.Mock(return_value=self.provider_identity)
        )

    def _serializer(self, **extra):
        return RPCExecutionSerializer(data={
            "procedure_id": self.procedure.pk,
            "assigned_object_type": "dcim.device",
            "assigned_object_id": self.device.pk,
            "params": {},
            "credential_references": self.references,
            **extra,
        })

    def _request(self, **extra):
        with (
            mock.patch.dict(sys.modules, {"netbox_openbao.automation": self.provider}),
            mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue") as enqueue,
        ):
            execution = command_handlers.create_execution(
                serializer=self._serializer(**extra), user=self.actor
            )
        enqueue.assert_not_called()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL
        assert execution.credential_authority["provider_identities"]["ssh"] == self.provider_identity
        return execution

    def _approve(self, execution):
        with mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue",
                        return_value=SimpleNamespace(pk=9309)) as enqueue:
            approved = command_handlers.approve_execution(execution, self.approver)
        enqueue.assert_called_once()
        assert approved.status == RPCExecution.STATUS_QUEUED
        return approved

    def _resolve(self, execution, lease):
        return authority.validate_secret_resolution_dispatch(
            execution=execution, dispatch_lease=lease.model_dump(),
            authenticated_executor=self.executor, reference_name="ssh",
        )

    def _backend(self, target, execution, *, lease):
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_RUNNING
        assert execution.events.order_by("-sequence").first().event == "DispatchLeaseIssued"
        authorized = self._resolve(execution, lease)
        assert authorized.initiating_actor.pk == self.actor.pk
        assert authorized.approval_snapshot_hash == execution.approval_request.payload_hash
        assert authorized.provider_identity == self.provider_identity
        assert lease.claims.approved_by_id == self.approver.pk
        return {"ok": True, "result": {
            "ok": True, "procedure": contract.HANDLER_ID, "target": "nms-front-door",
            "rotated": True, "stage": "complete",
        }}


class ProtectedCredentialDispatchTests(ProtectedCredentialDispatchFixture, TestCase):
    def _assert_final_permission_revocation_denied(self, permission):
        execution = self._approve(self._request())
        authorizations = []

        def backend(target, claimed, *, lease):
            authorizations.append(self._resolve(claimed, lease))
            return self._backend(target, claimed, lease=lease)

        with mock.patch("netbox_rpc.jobs._call_backend", side_effect=backend):
            command_handlers.run_execution(execution)
        authorization = authorizations[0]
        authority.check_authorization_permissions(authorization)
        permission.constraints = {"id": make_procedure("protected.references.final.other").pk}
        permission.save()
        with self.assertRaises(authority.SecretResolutionDenied):
            authority.check_authorization_permissions(authorization)

    def test_final_check_refuses_revoked_exact_execute_scope(self):
        self._assert_final_permission_revocation_denied(self.execute_permission)

    def test_final_check_refuses_revoked_exact_approve_scope(self):
        self._assert_final_permission_revocation_denied(self.approve_permission)

    def test_public_protected_admission_approval_worker_and_resolution(self):
        execution = self._approve(self._request())
        with mock.patch("netbox_rpc.jobs._call_backend", side_effect=self._backend) as backend:
            command_handlers.run_execution(execution)
        backend.assert_called_once()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_SUCCEEDED

    def test_scoped_approver_revocation_after_public_approval_stops_worker(self):
        execution = self._approve(self._request())
        other = make_procedure("protected.references.other")
        self.approve_permission.constraints = {"id": other.pk}
        self.approve_permission.save()
        actor = get_user_model().objects.get(pk=self.approver.pk)
        assert actor.has_perm("netbox_rpc.approve_rpcprocedure")
        with mock.patch("netbox_rpc.jobs._call_backend") as backend:
            with self.assertRaises(authority.SecretResolutionDenied):
                command_handlers.run_execution(execution)
        backend.assert_not_called()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_FAILED
        assert not execution.events.filter(event="DispatchLeaseIssued").exists()

    def test_worker_reuses_backend_and_independent_resolver_failure_is_value_free(self):
        execution = self._approve(self._request())
        target = resolve_backend(self.backend.pk)
        canary = "opaque-provider-canary-309-round-two"

        def backend(resolved, claimed, *, lease):
            assert resolved is target
            return {"ok": True, "result": {
                "ok": True, "procedure": contract.HANDLER_ID, "target": "nms-front-door",
                "rotated": True, "stage": "complete",
            }}

        with (
            mock.patch.object(command_handlers, "resolve_backend", return_value=target) as initial,
            mock.patch("netbox_rpc.backends.resolve_backend", side_effect=RuntimeError(canary)) as later,
            mock.patch("netbox_rpc.jobs._call_backend", side_effect=backend) as dispatch,
        ):
            command_handlers.run_execution(execution)
        initial.assert_called_once()
        later.assert_not_called()
        dispatch.assert_called_once()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_SUCCEEDED
        with mock.patch("netbox_rpc.backends.resolve_backend", side_effect=RuntimeError(canary)):
            with self.assertRaises(authority.SecretResolutionDenied) as caught:
                authority.require_reference_approval(execution, execution.normalized_params)
        rendered = "".join(traceback.format_exception(caught.exception))
        assert canary not in rendered
        assert canary not in str(list(execution.events.values("message", "data")))

    def test_protected_shape_preserves_metadata_and_material_denials(self):
        before = RPCExecution.objects.count()
        malformed = {"ssh": self.references["ssh"] | {"password": "opaque-material-canary"}}
        for extra in ({"comments": "opaque-metadata-canary"},
                      {"credential_references": malformed},
                      {"credential_references": {"ssh": self.references["ssh"] | {"assignment_id": True}}}):
            with self.subTest(fields=tuple(extra)):
                with self.assertRaises(ValidationError):
                    self._request(**extra)
        assert RPCExecution.objects.count() == before
        self.provider.capture_reference_identity.assert_not_called()

    def test_protected_shape_requires_matching_validated_references(self):
        serializer = SimpleNamespace(
            initial_data={"credential_references": self.references}, validated_data={}
        )
        with self.assertRaises(ValidationError):
            command_handlers._require_protected_creation_shape(serializer, contract.PROCEDURE_NAME)


class CredentialLifetimeTests(CredentialAuthorityFixture, TestCase):
    def test_final_permissions_are_uncached_value_free_and_never_lock_rows(self):
        authorization = self._authorize()
        with CaptureQueriesContext(connections["default"]) as queries:
            authority.check_authorization_permissions(authorization)
        assert queries.captured_queries
        assert not any("FOR UPDATE" in item["sql"] or "FOR NO KEY UPDATE" in item["sql"]
                       for item in queries.captured_queries)
        get_user_model().objects.filter(pk=self.actor.pk).update(is_active=False)
        assert authorization.initiating_actor.is_active
        with self.assertRaises(authority.SecretResolutionDenied):
            authority.check_authorization_permissions(authorization)
        with self.assertRaises(authority.SecretResolutionDenied):
            authority.check_authorization_permissions(SimpleNamespace())
        with mock.patch.object(authority, "_fresh_execution_permissions",
                               side_effect=RuntimeError("opaque-permission-canary")):
            with self.assertRaises(authority.SecretResolutionDenied) as caught:
                authority.check_authorization_permissions(authorization)
        assert "opaque-permission-canary" not in "".join(traceback.format_exception(caught.exception))

    def test_verified_expiry_is_rechecked_without_queries(self):
        authorization = self._authorize()
        with self.assertNumQueries(0):
            authority.check_authorization_lifetime(authorization)
            for instant in (authorization.expires_at,
                            authorization.expires_at + timedelta(microseconds=1),
                            timezone.now().replace(tzinfo=None)):
                with self.subTest(instant=instant):
                    with self.assertRaises(authority.SecretResolutionDenied):
                        authority.check_authorization_lifetime(authorization, now=instant)
            for expiry in (authorization.expires_at.replace(tzinfo=None), "invalid", None):
                with self.subTest(expiry=expiry):
                    with self.assertRaises(authority.SecretResolutionDenied):
                        authority.check_authorization_lifetime(replace(authorization, expires_at=expiry))


def mutate_locked_authority(kind, pk):
    try:
        with transaction.atomic(), connections["default"].cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout = '250ms'")
            if kind == "actor":
                get_user_model().objects.filter(pk=pk).update(is_active=False)
            else:
                RPCProcedureCommand.objects.create(procedure_id=pk, sequence=99, argv=["true"])
    finally:
        connections["default"].close()


class CredentialActorLockTests(CredentialAuthorityFixture, TransactionTestCase):
    def test_actor_update_and_new_command_foreign_key_remain_blocked(self):
        for kind, pk in (("actor", self.actor.pk), ("command", self.procedure.pk)):
            with self.subTest(kind=kind), transaction.atomic():
                self._authorize()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    attempt = pool.submit(mutate_locked_authority, kind, pk)
                    with self.assertRaises(OperationalError) as caught:
                        attempt.result(timeout=10)
                assert caught.exception.__cause__.sqlstate == "55P03"


def revoke_exact_permission(permission_id, other_procedure_id):
    from users.models import ObjectPermission

    try:
        ObjectPermission.objects.filter(pk=permission_id).update(constraints={"id": other_procedure_id})
    finally:
        connections["default"].close()


class CredentialPermissionWaitTests(ProtectedCredentialDispatchFixture, TransactionTestCase):
    def _assert_resolver_wait_revocation_denied(self, permission):
        execution = self._approve(self._request())
        other = make_procedure("protected.references.revocation-destination")
        seen = []

        def resolve_after_revocation(backend_id):
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(revoke_exact_permission, permission.pk, other.pk).result(timeout=10)
            current = get_user_model().objects.get(pk=self.actor.pk)
            assert RPCProcedure.objects.restrict(current, "view").filter(pk=self.procedure.pk).exists()
            return resolve_backend(backend_id)

        def backend(target, claimed, *, lease):
            with mock.patch("netbox_rpc.backends.resolve_backend", side_effect=resolve_after_revocation):
                try:
                    self._resolve(claimed, lease)
                except authority.SecretResolutionDenied:
                    seen.append("denied")
                    raise
                seen.append("authorized")
            return {"ok": False}

        with mock.patch("netbox_rpc.jobs._call_backend", side_effect=backend):
            with self.assertRaises(authority.SecretResolutionDenied):
                command_handlers.run_execution(execution)
        assert seen == ["denied"]
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_FAILED

    def test_committed_exact_execute_revocation_during_resolver_wait_is_denied(self):
        self._assert_resolver_wait_revocation_denied(self.execute_permission)

    def test_committed_exact_approve_revocation_during_resolver_wait_is_denied(self):
        self._assert_resolver_wait_revocation_denied(self.approve_permission)
