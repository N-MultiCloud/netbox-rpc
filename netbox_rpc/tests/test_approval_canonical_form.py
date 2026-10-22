"""Approval payloads and the lease-time check use the ledger form of normalized parameters.

The approval hash is computed when the request is created. The lease-time check
rebuilds it from the execution projection, which holds the redacted ledger form.
Both must agree, and the approval row must not hold a raw free-text secret.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase

from netbox_rpc import event_store
from netbox_rpc import staging_rotation_contract as contract
from netbox_rpc import jobs
from netbox_rpc.application import command_handlers
from netbox_rpc.domain.normalization import RPCExecutionError, _apply_target_object_context
from netbox_rpc.models import RPCBackend, RPCExecution, RPCProcedure, RPCProcedureCommand

from ._common import make_device, make_execution, make_user
from .test_credential_protected_dispatch import ProtectedCredentialDispatchFixture

_PROBE_SECRET = "password=fake-approval-probe-value"


class ApprovalCanonicalFormTests(TestCase):
    def setUp(self):
        defaults = {
            key: value
            for key, value in contract.PROCEDURE_POLICY.items()
            if key not in {"name", "command_contract_sha256"}
        }
        defaults.update(
            params_schema=contract.PARAMS_SCHEMA,
            result_schema=contract.RESULT_SCHEMA,
        )
        self.procedure, _ = RPCProcedure.objects.update_or_create(
            name=contract.PROCEDURE_NAME, defaults=defaults
        )
        self.requester = make_user("approval-canonical-requester", superuser=False)

    def _requested_with_approval(self, normalized):
        backend = RPCBackend.objects.create(
            name="approval-canonical-backend",
            base_url="https://executor.example.test",
        )
        execution = make_execution(procedure=self.procedure, user=self.requester)
        RPCExecution.objects.filter(pk=execution.pk).update(backend=backend.pk)
        execution.refresh_from_db()
        approval = command_handlers._create_approval_request(execution, normalized)
        event_store.record_execution_normalized(
            execution, normalized, "resolved-hash-canonical-form"
        )
        execution.refresh_from_db()
        return execution, approval

    def test_lease_time_check_accepts_an_approval_when_redaction_changes_a_parameter(self):
        normalized = {"probe_note": _PROBE_SECRET, "command_fingerprint": {}}
        execution, approval = self._requested_with_approval(normalized)

        current = command_handlers._approval_protected_payload(
            execution, execution.normalized_params
        )

        self.assertTrue(approval.matches_current(current))

    def test_approval_row_stores_the_ledger_form_and_no_raw_free_text_secret(self):
        normalized = {"probe_note": _PROBE_SECRET, "command_fingerprint": {}}
        execution, approval = self._requested_with_approval(normalized)

        self.assertNotIn("fake-approval-probe-value", repr(approval.normalized_params))
        self.assertEqual(approval.normalized_params, execution.normalized_params)

    def test_new_approval_matches_the_claim_time_recomputation_for_a_secret_mapping_name(
        self,
    ):
        normalized = {
            "probe_mapping": {"password=fake-approval-name-value": "routine value"},
            "command_fingerprint": {},
        }
        execution, approval = self._requested_with_approval(normalized)

        claim_time = command_handlers._ledger_command_source(normalized)
        current = command_handlers._approval_protected_payload(execution, claim_time)

        self.assertTrue(approval.matches_current(current))
        self.assertNotIn("fake-approval-name-value", repr(approval.normalized_params))

    def test_approval_from_before_the_placeholder_rule_fails_closed_at_claim_time(self):
        # Documented expected difference. An approval created before the placeholder
        # rule hashed the mapping name as written. The claim-time recomputation applies
        # the placeholder rule, so the approval is refused and must be requested again.
        normalized = {
            "probe_mapping": {"password=fake-approval-name-value": "routine value"},
            "command_fingerprint": {},
        }
        with mock.patch.object(
            event_store, "_keyed_mapping_name", side_effect=lambda name: name
        ):
            execution, approval = self._requested_with_approval(normalized)

        claim_time = command_handlers._ledger_command_source(normalized)
        current = command_handlers._approval_protected_payload(execution, claim_time)
        self.assertFalse(approval.matches_current(current))

        # The policy and identity gates are not under test here, so they are stubbed to
        # pass. The hash comparison that refuses the approval is the real code path.
        with (
            mock.patch.object(command_handlers, "_require_protected_procedure_policy"),
            mock.patch.object(
                command_handlers,
                "_approval_identities_are_authorized",
                return_value=True,
            ),
            self.assertRaises(RPCExecutionError) as raised,
        ):
            command_handlers._require_current_protected_approval(
                execution, claim_time, backend_target=None
            )
        self.assertEqual(raised.exception.code, "RPC_APPROVAL_INVALIDATED")

    def test_changing_an_unredacted_parameter_invalidates_the_approval(self):
        normalized = {
            "probe_mode": "read",
            "probe_note": _PROBE_SECRET,
            "command_fingerprint": {},
        }
        execution, approval = self._requested_with_approval(normalized)

        changed = dict(execution.normalized_params, probe_mode="write")
        current = command_handlers._approval_protected_payload(execution, changed)

        self.assertFalse(approval.matches_current(current))

    def test_free_text_target_secret_is_absent_from_the_approval_row_the_ledger_and_the_projection(self):
        RPCProcedureCommand.objects.create(
            procedure=self.procedure,
            sequence=99,
            step_type=RPCProcedureCommand.STEP_TYPE_SHELL_ARGV,
            argv=["echo", "{{ target.name }}"],
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
        )
        device = make_device("approval-canonical-device")
        device.comments = "rotate with password=fake-free-text-value"
        device.save(update_fields=["comments"])
        backend = RPCBackend.objects.create(
            name="approval-canonical-target-backend",
            base_url="https://executor.example.test",
        )
        execution = make_execution(procedure=self.procedure, user=self.requester)
        RPCExecution.objects.filter(pk=execution.pk).update(backend=backend.pk)
        execution.refresh_from_db()
        execution.assigned_object = device
        execution.save(update_fields=["assigned_object_type", "assigned_object_id"])
        normalized = {"command_fingerprint": {"handler_id": self.procedure.handler_id}}
        _apply_target_object_context(execution, normalized)
        approval = command_handlers._create_approval_request(execution, normalized)
        event_store.record_execution_normalized(execution, normalized, "resolved-hash-target")
        execution.refresh_from_db()

        secret = "fake-free-text-value"
        stored = execution.events.get(event="ParametersNormalized")
        assert secret not in repr(stored.data)
        assert secret not in repr(execution.normalized_params)
        assert secret not in repr(approval.normalized_params)
        assert secret not in repr(event_store.rebuild_projection(execution).normalized_params)
        assert approval.normalized_params["_target_object"]["comments"] == "[REDACTED]"

    def test_bounded_list_parameter_keeps_the_lease_time_hash_equal(self):
        normalized = {"probe_items": list(range(80)), "command_fingerprint": {}}
        execution, approval = self._requested_with_approval(normalized)

        current = command_handlers._approval_protected_payload(
            execution, execution.normalized_params
        )

        self.assertTrue(approval.matches_current(current))

    def test_bounded_mapping_parameter_keeps_the_lease_time_hash_after_storage(self):
        normalized = {
            "probe_fields": {f"field_{index:03d}": index for index in range(120)},
            "command_fingerprint": {},
        }
        execution, approval = self._requested_with_approval(normalized)

        current = command_handlers._approval_protected_payload(
            execution, execution.normalized_params
        )

        self.assertTrue(approval.matches_current(current))

    def test_approval_target_display_binds_a_matched_label_through_a_keyed_digest(self):
        first = command_handlers._approval_target_display("password=fake-display-target-a")
        second = command_handlers._approval_target_display("password=fake-display-target-b")

        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("keyed-display:"))
        self.assertNotIn("fake-display-target", first)
        self.assertEqual(
            command_handlers._approval_target_display("rack-b-router"), "rack-b-router"
        )

    def test_renaming_a_target_between_secret_shaped_labels_changes_the_snapshot_hash(self):
        execution = make_execution(procedure=self.procedure, user=self.requester)
        backend = RPCBackend.objects.create(
            name="approval-canonical-display-backend",
            base_url="https://executor.example.test",
        )
        RPCExecution.objects.filter(pk=execution.pk).update(backend=backend.pk)
        execution.refresh_from_db()
        normalized = {"command_fingerprint": {}}

        with mock.patch.object(
            RPCExecution, "target_display", new_callable=mock.PropertyMock,
            return_value="password=fake-target-a",
        ):
            first = command_handlers._approval_protected_payload(execution, normalized)
        with mock.patch.object(
            RPCExecution, "target_display", new_callable=mock.PropertyMock,
            return_value="password=fake-target-b",
        ):
            second = command_handlers._approval_protected_payload(execution, normalized)

        self.assertNotEqual(first["target_snapshot_hash"], second["target_snapshot_hash"])

    def test_command_source_is_the_projected_fingerprint_for_a_redaction_changed_fingerprint(self):
        normalized = {"command_fingerprint": {"target": "password=fake-fingerprint-value"}}
        execution = make_execution(procedure=self.procedure, user=self.requester)
        event_store.record_execution_normalized(
            execution, command_handlers._ledger_command_source(normalized), "resolved-hash-source"
        )
        execution.refresh_from_db()

        source = command_handlers._ledger_command_source(normalized)

        self.assertNotIn("fake-fingerprint-value", repr(source))
        self.assertEqual(source["command_fingerprint"], execution.normalized_params["command_fingerprint"])

    def test_secret_bearing_custom_field_name_is_absent_from_the_approval_row_and_the_ledger(self):
        RPCProcedureCommand.objects.create(
            procedure=self.procedure,
            sequence=98,
            step_type=RPCProcedureCommand.STEP_TYPE_SHELL_ARGV,
            argv=["echo", "{{ target.name }}"],
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
        )
        device = make_device("approval-canonical-key-device")
        device.custom_field_data = {"settings": {"password=fake-key-name-value": "routine value"}}
        device.save(update_fields=["custom_field_data"])
        backend = RPCBackend.objects.create(
            name="approval-canonical-key-backend",
            base_url="https://executor.example.test",
        )
        execution = make_execution(procedure=self.procedure, user=self.requester)
        RPCExecution.objects.filter(pk=execution.pk).update(backend=backend.pk)
        execution.refresh_from_db()
        execution.assigned_object = device
        execution.save(update_fields=["assigned_object_type", "assigned_object_id"])
        normalized = {"command_fingerprint": {"handler_id": self.procedure.handler_id}}
        _apply_target_object_context(execution, normalized)
        approval = command_handlers._create_approval_request(execution, normalized)
        event_store.record_execution_normalized(execution, normalized, "resolved-hash-key")
        execution.refresh_from_db()

        secret = "fake-key-name-value"
        stored = execution.events.get(event="ParametersNormalized")
        assert secret not in repr(approval.normalized_params)
        assert secret not in repr(execution.normalized_params)
        assert secret not in repr(stored.data)
        assert secret not in repr(event_store.rebuild_projection(execution).normalized_params)


class LedgerCommandSourceRunTests(ProtectedCredentialDispatchFixture, TestCase):
    """The run path hashes the command and issues the lease from the ledger form (issue 414)."""

    def test_run_path_uses_the_ledger_form_for_the_command_hash_and_the_lease(self):
        real_normalize = command_handlers.normalize_execution_params

        def normalize_with_redacted_fingerprint(execution):
            normalized = real_normalize(execution)
            fingerprint = dict(normalized.get("command_fingerprint") or {})
            fingerprint["probe_target"] = "password=fake-run-path-value"
            return dict(normalized, command_fingerprint=fingerprint)

        with mock.patch.object(
            command_handlers,
            "normalize_execution_params",
            side_effect=normalize_with_redacted_fingerprint,
        ):
            execution = self._approve(self._request())
            with (
                mock.patch("netbox_rpc.jobs._call_backend", side_effect=self._backend),
                mock.patch.object(
                    command_handlers,
                    "_issue_dispatch_lease",
                    wraps=command_handlers._issue_dispatch_lease,
                ) as issue,
            ):
                command_handlers.run_execution(execution)

        issued = issue.call_args.args[2]
        self.assertEqual(issued["command_fingerprint"]["probe_target"], "[REDACTED]")
        execution.refresh_from_db()
        stored = execution.events.get(event="ParametersNormalized").data
        self.assertEqual(
            stored["command_hash"],
            jobs._hash_json(issued["command_fingerprint"]),
        )
