"""DB-backed catalog and result persistence checks for issue #224."""

from __future__ import annotations

from django.test import TestCase

from netbox_rpc import gitea_upgrade_contract as contract
from netbox_rpc.application import command_handlers
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCExecution, RPCProcedure

from ._common import make_execution


class GiteaProductionUpgradeContractTests(TestCase):
    def setUp(self):
        self.procedure = RPCProcedure.objects.get(name=contract.PROCEDURE_NAME)

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
