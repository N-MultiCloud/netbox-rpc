"""DB-backed catalog and result persistence checks for issue #224."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from rest_framework.exceptions import ValidationError

from netbox_rpc import gitea_upgrade_contract as contract
from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.capabilities import CapabilityStatus
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.domain.normalization import RPCExecutionError
from netbox_rpc.models import RPCBackend, RPCExecution, RPCProcedure

from ._common import enable_rpc_integration, make_execution, make_user


class GiteaProductionUpgradeContractTests(TestCase):
    def setUp(self):
        self.procedure = RPCProcedure.objects.get(name=contract.PROCEDURE_NAME)

    def _approval_fixture(self, *, pending: bool = True):
        self.procedure.enabled = True
        self.procedure.save(update_fields=["enabled"])
        backend = RPCBackend.objects.create(
            pk=contract.BACKEND_ID,
            name="gitea-production-upgrade-test",
            base_url=contract.BACKEND_BASE_URL,
            verify_ssl=contract.BACKEND_VERIFY_SSL,
        )
        enable_rpc_integration(backend=backend)
        requester = make_user("gitea-upgrade-requester")
        approver = make_user("gitea-upgrade-approver")
        execution = make_execution(procedure=self.procedure, user=requester)
        execution.backend_id = backend.pk
        execution.save(update_fields=["backend"])
        normalized = {
            "command_fingerprint": {
                "target_object_sha256": "a" * 64,
            },
            "ssh_policy_ref": contract.SSH_POLICY_REF,
        }
        aggregate = RPCExecutionAggregate(execution)
        aggregate.request(requested_by_id=requester.pk)
        backend_target = BackendTarget(
            url=contract.BACKEND_BASE_URL,
            headers={},
            verify_ssl=contract.BACKEND_VERIFY_SSL,
        )
        with mock.patch.object(
            command_handlers,
            "resolve_backend",
            return_value=backend_target,
        ):
            snapshot = command_handlers._create_approval_request(
                execution,
                normalized,
            )
        if pending:
            aggregate.request_approval(
                snapshot_hash=snapshot.payload_hash,
                requested_by_id=requester.pk,
            )
        execution.refresh_from_db()
        return execution, snapshot, normalized, requester, approver, backend_target

    @staticmethod
    def _semantic_drift_patches():
        drifted_digest = "f" * 64
        return (
            mock.patch.object(
                contract,
                "SEMANTIC_CAPABILITY_SHA256",
                drifted_digest,
            ),
            mock.patch.dict(
                contract.PROCEDURE_POLICY,
                {"semantic_contract_sha256": drifted_digest},
            ),
        )

    def test_migration_seed_is_disabled_but_matches_exact_active_policy(self):
        procedure = self.procedure
        assert procedure.enabled is False
        assert procedure.handler_id == contract.HANDLER_ID
        assert procedure.target_models == ["virtualization.virtualmachine"]
        assert procedure.effect == "destructive"
        assert procedure.approval_required is True
        assert procedure.timeout_seconds == 1800
        assert procedure.params_schema == contract.PARAMS_SCHEMA
        assert procedure.result_schema == contract.RESULT_SCHEMA
        command = procedure.commands.get(sequence=1)
        assert [command.sequence, *command.argv] == [
            1,
            "backend-orchestrated",
            "gitea-production-upgrade-1-27-1",
        ]

        procedure.enabled = True
        procedure.save(update_fields=["enabled"])
        command_handlers._require_protected_procedure_policy(procedure)
        policy = command_handlers._protected_procedure_policy(procedure)
        assert policy["semantic_contract_sha256"] == contract.canonical_sha256(
            contract.SEMANTIC_CAPABILITY_EXTENSION
        )
        assert policy == contract.PROCEDURE_POLICY

    def test_backend_identity_is_exact_and_public_vhost_is_rejected(self):
        exact = BackendTarget(
            url=contract.BACKEND_BASE_URL,
            headers={},
            verify_ssl=contract.BACKEND_VERIFY_SSL,
        )
        assert command_handlers._protected_backend_target_sha256(
            contract.BACKEND_ID,
            procedure_name=contract.PROCEDURE_NAME,
            backend_target=exact,
        ) == contract.canonical_sha256(
            {
                "backend_id": 1,
                "url": "http://127.0.0.1:16005",
                "verify_ssl": False,
            }
        )

        invalid_targets = (
            BackendTarget(
                url="https://nms.nmulti.cloud",
                headers={},
                verify_ssl=True,
            ),
            BackendTarget(
                url=contract.BACKEND_BASE_URL,
                headers={},
                verify_ssl=True,
            ),
        )
        for target in invalid_targets:
            with self.subTest(target=target), self.assertRaises(ValidationError):
                command_handlers._protected_backend_target_sha256(
                    contract.BACKEND_ID,
                    procedure_name=contract.PROCEDURE_NAME,
                    backend_target=target,
                )
        with self.assertRaises(ValidationError):
            command_handlers._require_concrete_protected_backend_id(
                contract.BACKEND_ID + 1,
                contract.PROCEDURE_NAME,
            )

    def test_executable_only_drift_invalidates_requested_snapshot(self):
        execution, snapshot, normalized, _requester, _approver, backend_target = (
            self._approval_fixture(pending=False)
        )
        assert execution.status == RPCExecution.STATUS_REQUESTED

        first_patch, second_patch = self._semantic_drift_patches()
        with first_patch, second_patch:
            current = command_handlers._approval_protected_payload(
                execution,
                normalized,
                backend_target=backend_target,
            )
            assert snapshot.matches_current(current) is False

    def test_executable_only_drift_blocks_pending_approval_before_enqueue(self):
        execution, _snapshot, normalized, _requester, approver, backend_target = (
            self._approval_fixture()
        )
        first_patch, second_patch = self._semantic_drift_patches()
        with (
            first_patch,
            second_patch,
            mock.patch.object(
                command_handlers,
                "normalize_execution_params",
                return_value=normalized,
            ),
            mock.patch.object(
                command_handlers,
                "resolve_backend",
                return_value=backend_target,
            ),
            mock.patch.object(command_handlers, "_verify_backend_capability"),
            mock.patch(
                "netbox_rpc.jobs.RPCExecutionJob.enqueue",
            ) as enqueue,
            self.assertRaises(ValidationError),
        ):
            command_handlers._approve_protected_execution(execution, approver)

        enqueue.assert_not_called()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL

    def test_capability_drift_blocks_pending_approval_without_state_mutation(self):
        execution, snapshot, normalized, _requester, approver, backend_target = (
            self._approval_fixture()
        )
        initial_events = list(
            execution.events.order_by("sequence").values_list(
                "sequence",
                "event",
            )
        )

        with (
            mock.patch.object(
                command_handlers,
                "normalize_execution_params",
                return_value=normalized,
            ),
            mock.patch.object(
                command_handlers,
                "resolve_backend",
                return_value=backend_target,
            ),
            mock.patch(
                "netbox_rpc.capabilities.fetch_backend_capabilities",
                return_value={},
            ) as fetch_capabilities,
            mock.patch(
                "netbox_rpc.capabilities.verify_procedure_capability",
                return_value=CapabilityStatus.MISMATCH,
            ),
            mock.patch(
                "netbox_rpc.jobs.RPCExecutionJob.enqueue",
            ) as enqueue,
            self.assertRaises(ValidationError),
        ):
            command_handlers._approve_protected_execution(execution, approver)

        fetch_capabilities.assert_called_once_with(
            backend_target,
            use_cache=False,
        )
        enqueue.assert_not_called()
        execution.refresh_from_db()
        snapshot.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL
        assert execution.approved_by_id is None
        assert list(
            execution.events.order_by("sequence").values_list(
                "sequence",
                "event",
            )
        ) == initial_events

    def test_executable_only_drift_invalidates_approved_snapshot(self):
        execution, _snapshot, normalized, _requester, approver, backend_target = (
            self._approval_fixture()
        )
        current = command_handlers._approval_protected_payload(
            execution,
            normalized,
            backend_target=backend_target,
        )
        RPCExecutionAggregate(execution).approve(
            approver_id=approver.pk,
            current_protected=current,
        )
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_APPROVED

        first_patch, second_patch = self._semantic_drift_patches()
        with first_patch, second_patch, self.assertRaises(RPCExecutionError) as raised:
            command_handlers._require_current_protected_approval(
                execution,
                normalized,
                backend_target=backend_target,
            )
        assert raised.exception.code == "RPC_APPROVAL_INVALIDATED"

    def test_executable_only_drift_blocks_queued_dispatch_before_lease(self):
        execution, _snapshot, normalized, _requester, approver, backend_target = (
            self._approval_fixture()
        )
        current = command_handlers._approval_protected_payload(
            execution,
            normalized,
            backend_target=backend_target,
        )
        RPCExecutionAggregate(execution).approve(
            approver_id=approver.pk,
            current_protected=current,
            queue_after_approval=True,
        )
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_QUEUED

        first_patch, second_patch = self._semantic_drift_patches()
        with (
            first_patch,
            second_patch,
            mock.patch.object(command_handlers, "_verify_backend_capability"),
            mock.patch.object(
                command_handlers,
                "resolve_backend",
                return_value=backend_target,
            ),
            mock.patch.object(
                command_handlers,
                "normalize_execution_params",
                return_value=normalized,
            ),
            mock.patch.object(command_handlers, "_issue_dispatch_lease") as issue_lease,
            mock.patch("netbox_rpc.jobs._call_backend") as call_backend,
            self.assertRaises(RPCExecutionError) as raised,
        ):
            command_handlers.run_execution(execution)

        assert raised.exception.code == "RPC_APPROVAL_INVALIDATED"
        issue_lease.assert_not_called()
        call_backend.assert_not_called()
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_FAILED
        assert execution.error_code == "RPC_APPROVAL_INVALIDATED"

    def test_server_normalized_ssh_policy_is_bound_by_reference(self):
        reference = command_handlers._credential_policy_reference(
            {"ssh_policy_ref": contract.SSH_POLICY_REF},
            type("Execution", (), {"procedure": self.procedure})(),
        )
        assert reference == contract.SSH_POLICY_REF
        assert len(reference) <= 200

    def test_all_closed_failure_and_indeterminate_results_are_persisted(self):
        states = (
            (False, False, "execute"),
            (False, True, "rolled_back"),
            (True, False, "complete"),
            (None, None, "indeterminate"),
        )
        for changed, healthy, stage in states:
            with self.subTest(stage=stage, changed=changed, healthy=healthy):
                execution = make_execution(procedure=self.procedure)
                aggregate = RPCExecutionAggregate(execution)
                aggregate.queue()
                aggregate.start()
                result = {
                    "ok": False,
                    "procedure": contract.PROCEDURE_NAME,
                    "target": contract.TARGET_NAME,
                    "changed": changed,
                    "healthy": healthy,
                    "stage": stage,
                }
                aggregate.record_backend_response(
                    {
                        "ok": False,
                        "result": result,
                    }
                )
                execution.refresh_from_db()
                assert execution.status == RPCExecution.STATUS_FAILED
                assert execution.result == result
                expected_code, expected_message = contract.result_diagnostics(result)
                assert execution.error_code == expected_code
                assert execution.error_message == expected_message
                assert execution.events.get(event="ExecutionFailed").data["result"] == result

    def test_success_and_already_target_results_complete(self):
        for changed in (True, False):
            with self.subTest(changed=changed):
                execution = make_execution(procedure=self.procedure)
                aggregate = RPCExecutionAggregate(execution)
                aggregate.queue()
                aggregate.start()
                result = {
                    "ok": True,
                    "procedure": contract.PROCEDURE_NAME,
                    "target": contract.TARGET_NAME,
                    "changed": changed,
                    "healthy": True,
                    "stage": "complete",
                }
                aggregate.record_backend_response({"ok": True, "result": result})
                execution.refresh_from_db()
                assert execution.status == RPCExecution.STATUS_SUCCEEDED
                assert execution.result == result

    def test_malformed_failure_result_is_not_projected(self):
        execution = make_execution(procedure=self.procedure)
        aggregate = RPCExecutionAggregate(execution)
        aggregate.queue()
        aggregate.start()
        aggregate.record_backend_response(
            {
                "ok": False,
                "result": {
                    "ok": False,
                    "procedure": contract.PROCEDURE_NAME,
                    "target": contract.TARGET_NAME,
                    "changed": False,
                    "healthy": True,
                    "stage": "indeterminate",
                },
            }
        )
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_FAILED
        assert execution.error_code == "RPC_RESULT_SCHEMA_MISMATCH"
        assert execution.result == {}
