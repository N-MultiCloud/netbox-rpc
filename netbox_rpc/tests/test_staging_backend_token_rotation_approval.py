"""End-to-end approval and lease policy for staging token rotation (#221)."""

from __future__ import annotations

import json
from datetime import datetime
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from django.test import TestCase
from django.urls import reverse
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.test import APIClient, APIRequestFactory

from netbox_rpc import dispatch_lease as dl
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.constants import NETBOX_STAGING_ROTATE_BACKEND_TOKEN
from netbox_rpc.domain.normalization import RPCExecutionError
from netbox_rpc.models import RPCExecution, RPCProcedure
from netbox_rpc import staging_rotation_contract as staging_contract

from ._common import (
    enable_rpc_integration,
    event_names,
    make_device,
    make_execution,
    make_procedure,
    make_user,
)


class _FakeJob:
    pk = 22100


def _grant(user, *, model, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    permission = ObjectPermission.objects.create(
        name=f"staging-grant-{user.username}-{'-'.join(actions)}",
        actions=list(actions),
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(model)])
    permission.users.set([user])


def _configure_signing_key(seed_hex: str):
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    pem = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode("ascii")
    entries = [
        {
            "key_id": "staging-rotation",
            "key_version": 1,
            "private_key_pem": pem,
            "active": True,
        }
    ]

    def _setting(name, default=None):
        return {
            dl._SIGNING_KEYS_SETTING: entries,
            dl._AUDIENCE_SETTING: "netbox-rpc-backend",
            dl._TTL_SETTING: 120,
        }.get(name, default)

    return mock.patch.object(dl, "_plugin_setting", side_effect=_setting), private_key


class StagingBackendTokenRotationApprovalTests(TestCase):
    def setUp(self):
        self.settings = enable_rpc_integration()
        self.device = make_device("nms-front-door")
        self.procedure = RPCProcedure.objects.get(
            name=NETBOX_STAGING_ROTATE_BACKEND_TOKEN
        )
        self.requester = make_user("staging-token-requester", superuser=True)
        self.approver = make_user("staging-token-approver", superuser=True)

    def _serializer(self, **extra):
        return RPCExecutionSerializer(
            data={
                "procedure_id": self.procedure.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {},
                **extra,
            }
        )

    def _request(self, *, user=None):
        with (
            mock.patch(
                "netbox_rpc.capabilities.fetch_backend_capabilities",
                return_value=None,
            ),
            mock.patch(
                "netbox_rpc.jobs.RPCExecutionJob.enqueue",
                return_value=_FakeJob(),
            ) as enqueue,
        ):
            execution = command_handlers.create_execution(
                serializer=self._serializer(),
                user=user or self.requester,
            )
        return execution, enqueue

    def _approve(self, execution, *, user=None):
        with mock.patch(
            "netbox_rpc.jobs.RPCExecutionJob.enqueue",
            return_value=_FakeJob(),
        ) as enqueue:
            approved = command_handlers.approve_execution(
                execution,
                user or self.approver,
            )
        return approved, enqueue

    def test_request_is_pending_and_never_enqueues_even_for_approver(self):
        execution, enqueue = self._request()
        execution.refresh_from_db()

        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL
        assert execution.requested_by_id == self.requester.pk
        assert execution.approved_by_id is None
        assert execution.job_id is None
        assert event_names(execution) == [
            "ExecutionRequested",
            "ApprovalRequested",
        ]
        snapshot = execution.approval_request
        assert (
            snapshot.procedure_policy_sha256
            == staging_contract.PROCEDURE_POLICY_SHA256
        )
        assert snapshot.params_schema_sha256 == staging_contract.PARAMS_SCHEMA_SHA256
        assert snapshot.result_schema_sha256 == staging_contract.RESULT_SCHEMA_SHA256
        assert len(snapshot.backend_target_sha256) == 64
        enqueue.assert_not_called()

    def test_request_rejects_all_caller_metadata_even_when_empty(self):
        opaque = "Bearer opaque-secret-" + ("x" * 8192)
        metadata = {
            "comments": opaque,
            "request_id": opaque,
            "trace_id": opaque,
            "backend_id": self.settings.backend_id,
            "tags": [],
            "custom_fields": {},
        }
        for field, value in metadata.items():
            with self.subTest(field=field):
                before = RPCExecution.objects.filter(
                    procedure=self.procedure
                ).count()
                with (
                    mock.patch(
                        "netbox_rpc.capabilities.fetch_backend_capabilities",
                        return_value=None,
                    ),
                    self.assertRaises(ValidationError),
                ):
                    command_handlers.create_execution(
                        serializer=self._serializer(**{field: value}),
                        user=self.requester,
                    )
                assert (
                    RPCExecution.objects.filter(procedure=self.procedure).count()
                    == before
                )

    def test_request_requires_concrete_authoritative_backend_binding(self):
        self.settings.backend = None
        self.settings.save(update_fields=["backend"])

        with (
            mock.patch(
                "netbox_rpc.capabilities.fetch_backend_capabilities",
                return_value=None,
            ),
            self.assertRaises(ValidationError),
        ):
            command_handlers.create_execution(
                serializer=self._serializer(),
                user=self.requester,
            )

        assert not RPCExecution.objects.filter(
            procedure=self.procedure,
            requested_by=self.requester,
        ).exists()

    def test_requester_cannot_approve_or_enqueue_their_own_request(self):
        execution, _ = self._request()

        with (
            mock.patch(
                "netbox_rpc.jobs.RPCExecutionJob.enqueue",
                return_value=_FakeJob(),
            ) as enqueue,
            self.assertRaises(ValidationError),
        ):
            command_handlers.approve_execution(execution, self.requester)

        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL
        assert execution.approved_by_id is None
        assert event_names(execution) == [
            "ExecutionRequested",
            "ApprovalRequested",
        ]
        enqueue.assert_not_called()

    def test_object_scoped_execute_permission_for_another_procedure_is_denied(self):
        from dcim.models import Device

        user = make_user("staging-token-wrong-execute-scope", superuser=False)
        other = make_procedure("service.netbox.staging.unrelated")
        _grant(
            user,
            model=RPCProcedure,
            actions=("execute",),
            constraints={"id": other.pk},
        )
        _grant(
            user,
            model=Device,
            actions=("view",),
            constraints={"id": self.device.pk},
        )
        user = make_user("staging-token-wrong-execute-scope", superuser=False)

        with (
            mock.patch(
                "netbox_rpc.capabilities.fetch_backend_capabilities",
                return_value=None,
            ),
            self.assertRaises(PermissionDenied),
        ):
            command_handlers.create_execution(serializer=self._serializer(), user=user)

        assert not RPCExecution.objects.filter(
            procedure=self.procedure,
            requested_by=user,
        ).exists()

    def test_object_scoped_approval_for_another_procedure_is_denied(self):
        execution, _ = self._request()
        user = make_user("staging-token-wrong-approve-scope", superuser=False)
        other = make_procedure("service.netbox.staging.other-approval")
        _grant(
            user,
            model=RPCProcedure,
            actions=("approve",),
            constraints={"id": other.pk},
        )
        _grant(
            user,
            model=RPCProcedure,
            actions=("view",),
            constraints={"id": self.procedure.pk},
        )
        user = make_user("staging-token-wrong-approve-scope", superuser=False)

        with (
            mock.patch(
                "netbox_rpc.jobs.RPCExecutionJob.enqueue",
                return_value=_FakeJob(),
            ) as enqueue,
            self.assertRaises(PermissionDenied),
        ):
            command_handlers.approve_execution(execution, user)

        enqueue.assert_not_called()
        with self.assertRaises(PermissionDenied):
            command_handlers.reject_execution(execution, user)
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL

    def test_distinct_approval_persists_identity_queues_once_and_is_read_only(self):
        execution, _ = self._request()
        approved, enqueue = self._approve(execution)

        approved.refresh_from_db()
        assert approved.status == RPCExecution.STATUS_QUEUED
        assert approved.requested_by_id == self.requester.pk
        assert approved.approved_by_id == self.approver.pk
        assert approved.job_id == _FakeJob.pk
        assert event_names(approved) == [
            "ExecutionRequested",
            "ApprovalRequested",
            "ExecutionApproved",
            "ExecutionQueued",
            "JobEnqueued",
        ]
        approval_event = approved.events.get(event="ExecutionApproved")
        assert approval_event.message == (
            command_handlers._STAGING_ROTATION_APPROVAL_REASON
        )
        assert approval_event.data["reason"] == (
            command_handlers._STAGING_ROTATION_APPROVAL_REASON
        )
        enqueue.assert_called_once()

        request = APIRequestFactory().get("/")
        wire = RPCExecutionSerializer(approved, context={"request": request}).data
        assert wire["requested_by_id"] == self.requester.pk
        assert wire["approved_by_id"] == self.approver.pk

        forged = self._serializer(
            requested_by_id=self.approver.pk,
            approved_by_id=self.requester.pk,
        )
        assert forged.is_valid(), forged.errors
        assert "requested_by_id" not in forged.validated_data
        assert "approved_by_id" not in forged.validated_data

    def test_approval_and_rejection_refuse_operator_notes(self):
        opaque = "Bearer opaque-secret-" + ("x" * 8192)
        execution, _ = self._request()

        with self.assertRaises(ValidationError):
            command_handlers.approve_execution(
                execution,
                self.approver,
                reason=opaque,
            )
        with self.assertRaises(ValidationError):
            command_handlers.reject_execution(
                execution,
                self.approver,
                reason=opaque,
            )

        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL
        assert opaque not in str(list(execution.events.values("message", "data")))

    def test_approval_and_rejection_reject_non_object_json_bodies(self):
        client = APIClient()
        client.force_authenticate(user=self.approver)
        for action in ("approve", "reject"):
            for payload in (None, [], 0, ""):
                with self.subTest(action=action, payload=payload):
                    execution, _ = self._request()
                    url = reverse(
                        f"plugins-api:netbox_rpc-api:rpcexecution-{action}",
                        args=[execution.pk],
                    )
                    response = client.generic(
                        "POST",
                        url,
                        data=json.dumps(payload),
                        content_type="application/json",
                    )

                    assert response.status_code == 400, response.content
                    execution.refresh_from_db()
                    assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL

    def test_rejection_uses_fixed_secret_silent_reason(self):
        execution, _ = self._request()

        rejected = command_handlers.reject_execution(execution, self.approver)

        rejected.refresh_from_db()
        event = rejected.events.get(event="ExecutionRejected")
        assert event.message == command_handlers._STAGING_ROTATION_REJECTION_REASON
        assert event.data["reason"] == (
            command_handlers._STAGING_ROTATION_REJECTION_REASON
        )

    def test_closed_failure_results_persist_on_failed_projection(self):
        results = (
            {
                "ok": False,
                "procedure": NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
                "target": "nms-front-door",
                "rotated": False,
                "stage": "execute",
            },
            {
                "ok": False,
                "procedure": NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
                "target": "nms-front-door",
                "rotated": True,
                "stage": "complete",
            },
            {
                "ok": False,
                "procedure": NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
                "target": "nms-front-door",
                "rotated": None,
                "stage": "indeterminate",
            },
        )
        for result in results:
            with self.subTest(stage=result["stage"], rotated=result["rotated"]):
                execution = make_execution(procedure=self.procedure)
                aggregate = command_handlers.RPCExecutionAggregate(execution)
                aggregate.queue()
                aggregate.start()
                aggregate.record_backend_response(
                    {
                        "ok": False,
                        "result": result,
                        "error_code": "RPC_REMOTE_FAILED",
                        "error_message": "Closed backend failure.",
                    }
                )

                execution.refresh_from_db()
                assert execution.status == RPCExecution.STATUS_FAILED
                assert execution.result == result
                failure = execution.events.get(event="ExecutionFailed")
                assert failure.data["result"] == result

    def test_malformed_failure_result_is_rejected_and_not_projected(self):
        execution = make_execution(procedure=self.procedure)
        aggregate = command_handlers.RPCExecutionAggregate(execution)
        aggregate.queue()
        aggregate.start()

        aggregate.record_backend_response(
            {
                "ok": False,
                "result": {
                    "ok": False,
                    "procedure": NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
                    "target": "nms-front-door",
                    "rotated": False,
                    "stage": "indeterminate",
                },
            }
        )

        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_FAILED
        assert execution.error_code == "RPC_RESULT_SCHEMA_MISMATCH"
        assert execution.result == {}
        failure = execution.events.get(event="ExecutionFailed")
        assert "result" not in failure.data

    @mock.patch("netbox_rpc.jobs._call_backend")
    @mock.patch.object(command_handlers, "resolve_backend")
    def test_signed_lease_binds_distinct_identities_and_replay_is_rejected(
        self,
        resolve_backend,
        call_backend,
    ):
        resolve_backend.return_value = BackendTarget(
            url="https://backend.example",
            headers={},
            verify_ssl=True,
        )
        execution, _ = self._request()
        approved, _ = self._approve(execution)
        call_backend.return_value = {
            "ok": True,
            "result": {
                "ok": True,
                "procedure": NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
                "target": "nms-front-door",
                "rotated": True,
                "stage": "complete",
            },
            "events": [],
        }

        key_patch, private_key = _configure_signing_key("42" * 32)
        with key_patch:
            command_handlers.run_execution(approved)

        lease = call_backend.call_args.kwargs["lease"]
        claims = lease.claims
        assert claims.effect == "destructive"
        assert claims.requested_by_id == self.requester.pk
        assert claims.approved_by_id == self.approver.pk
        assert claims.requested_by_id != claims.approved_by_id

        public_keys = {
            (claims.key_id, claims.key_version): private_key.public_key(),
        }
        replay = dl.verify_dispatch_lease(
            lease,
            public_keys=public_keys,
            audience=claims.audience,
            now=datetime.fromisoformat(claims.issued_at),
            seen_nonces={claims.nonce},
        )
        assert replay.is_valid is False
        assert replay.reason == "nonce replay"

        approved.refresh_from_db()
        assert approved.status == RPCExecution.STATUS_SUCCEEDED
        assert "DispatchLeaseIssued" in event_names(approved)

    @mock.patch("netbox_rpc.jobs._call_backend")
    @mock.patch.object(command_handlers, "resolve_backend")
    def test_missing_signing_key_fails_closed_without_backend_dispatch(
        self,
        resolve_backend,
        call_backend,
    ):
        resolve_backend.return_value = BackendTarget(
            url="https://backend.example",
            headers={},
            verify_ssl=True,
        )
        execution, _ = self._request()
        approved, _ = self._approve(execution)

        with mock.patch.object(dl, "_plugin_setting", return_value=None):
            with self.assertRaises(RPCExecutionError) as exc_info:
                command_handlers.run_execution(approved)

        assert exc_info.exception.code == "RPC_DISPATCH_LEASE_REQUIRED"
        call_backend.assert_not_called()
        approved.refresh_from_db()
        assert approved.status == RPCExecution.STATUS_FAILED
        assert approved.error_code == "RPC_DISPATCH_LEASE_REQUIRED"
        assert "DispatchLeaseIssued" not in event_names(approved)

    @mock.patch.object(command_handlers, "resolve_backend")
    def test_worker_backend_override_cannot_redirect_approved_execution(
        self,
        resolve_backend,
    ):
        execution, _ = self._request()
        approved, _ = self._approve(execution)
        resolve_backend.reset_mock()

        with self.assertRaises(RPCExecutionError) as exc_info:
            command_handlers.run_execution(
                approved,
                backend_pk=int(approved.backend_id) + 1,
            )

        assert exc_info.exception.code == "RPC_BACKEND_BINDING_INVALID"
        resolve_backend.assert_not_called()
        approved.refresh_from_db()
        assert approved.status == RPCExecution.STATUS_FAILED
        assert approved.error_code == "RPC_BACKEND_BINDING_INVALID"

    @mock.patch("netbox_rpc.jobs._call_backend")
    @mock.patch.object(command_handlers, "resolve_backend")
    def test_approval_snapshot_drift_fails_before_lease_or_backend(
        self,
        resolve_backend,
        call_backend,
    ):
        resolve_backend.return_value = BackendTarget(
            url="https://backend.example",
            headers={},
            verify_ssl=True,
        )
        execution, _ = self._request()
        approved, _ = self._approve(execution)
        self.procedure.version += 1
        self.procedure.save(update_fields=["version"])

        key_patch, _ = _configure_signing_key("43" * 32)
        with key_patch:
            command_handlers.run_execution(approved)

        call_backend.assert_not_called()
        approved.refresh_from_db()
        assert approved.status == RPCExecution.STATUS_FAILED
        assert approved.error_code == "RPC_APPROVAL_INVALIDATED"
        assert "DispatchLeaseIssued" not in event_names(approved)

    @mock.patch("netbox_rpc.jobs._call_backend")
    def test_backend_endpoint_or_tls_drift_invalidates_approval_before_dispatch(
        self,
        call_backend,
    ):
        execution, _ = self._request()
        approved, _ = self._approve(execution)
        backend = self.settings.backend
        backend.base_url = "https://changed-backend.example"
        backend.save(update_fields=["base_url"])

        key_patch, _ = _configure_signing_key("44" * 32)
        with key_patch:
            command_handlers.run_execution(approved)

        call_backend.assert_not_called()
        approved.refresh_from_db()
        assert approved.status == RPCExecution.STATUS_FAILED
        assert approved.error_code == "RPC_APPROVAL_INVALIDATED"

    def test_transport_and_output_policy_drift_is_rejected_at_admission(self):
        mutations = (
            ("transport_driver", "paramiko"),
            ("transport_driver_chain", ["paramiko"]),
            ("output_parser", "json"),
            ("output_schema", {"type": "object"}),
        )
        for field, hostile_value in mutations:
            with self.subTest(field=field):
                original = getattr(self.procedure, field)
                setattr(self.procedure, field, hostile_value)
                self.procedure.save(update_fields=[field])
                try:
                    with (
                        mock.patch(
                            "netbox_rpc.capabilities.fetch_backend_capabilities",
                            return_value=None,
                        ),
                        self.assertRaises(ValidationError),
                    ):
                        command_handlers.create_execution(
                            serializer=self._serializer(),
                            user=self.requester,
                        )
                finally:
                    setattr(self.procedure, field, original)
                    self.procedure.save(update_fields=[field])

    def test_command_contract_drift_is_rejected_at_admission(self):
        command = self.procedure.commands.get(sequence=1)
        original = command.argv
        command.argv = ["backend-orchestrated", "different-operation"]
        command.save(update_fields=["argv"])
        try:
            with (
                mock.patch(
                    "netbox_rpc.capabilities.fetch_backend_capabilities",
                    return_value=None,
                ),
                self.assertRaises(ValidationError),
            ):
                command_handlers.create_execution(
                    serializer=self._serializer(),
                    user=self.requester,
                )
        finally:
            command.argv = original
            command.save(update_fields=["argv"])

    def test_schema_drift_fails_before_approval_enqueue(self):
        execution, _ = self._request()
        original = self.procedure.result_schema
        self.procedure.result_schema = {"type": "object"}
        self.procedure.save(update_fields=["result_schema"])
        try:
            with (
                mock.patch(
                    "netbox_rpc.jobs.RPCExecutionJob.enqueue",
                    return_value=_FakeJob(),
                ) as enqueue,
                self.assertRaises(ValidationError),
            ):
                command_handlers.approve_execution(execution, self.approver)
        finally:
            self.procedure.result_schema = original
            self.procedure.save(update_fields=["result_schema"])

        enqueue.assert_not_called()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL
