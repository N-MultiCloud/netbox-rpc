"""DB-backed persistence tests for target-object snapshots and their digests."""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from netbox_rpc import event_store
from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.domain.normalization import (
    _apply_target_object_context,
    _build_target_object_snapshot,
    _hash_json,
)
from netbox_rpc.domain.projection import ProjectionState
from netbox_rpc.models import RPCProcedureCommand, compute_approval_snapshot_hash

from ._common import (
    event_names,
    make_backend,
    make_device,
    make_execution,
    make_procedure,
    make_user,
)


class TargetSnapshotLedgerTests(TestCase):
    """Exercise the persisted snapshot across the ledger and approval boundary."""

    secret_value = "password=fake-password-value"
    changed_secret_value = "password=fake-password-other"
    resolved_command_hash = "resolved-command-hash"

    def _record_snapshot(self):
        procedure = make_procedure(
            "os.linux.test.target_snapshot_ledger",
            target_models=["dcim.device"],
        )
        RPCProcedureCommand.objects.create(
            procedure=procedure,
            sequence=1,
            step_type=RPCProcedureCommand.STEP_TYPE_SHELL_ARGV,
            argv=["echo", "{{ target.name }}"],
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
        )
        device = make_device("target-snapshot-ledger-device")
        device.custom_field_data = {"operator_notes": self.secret_value}
        device.save(update_fields=["custom_field_data"])

        execution = make_execution(
            procedure=procedure,
            user=make_user("target-snapshot-ledger-user"),
        )
        execution.assigned_object = device
        execution.save(
            update_fields=["assigned_object_type", "assigned_object_id"]
        )

        raw_snapshot = _build_target_object_snapshot(execution.assigned_object)
        assert raw_snapshot is not None
        normalized = {
            "command_fingerprint": {"handler_id": procedure.handler_id},
        }
        _apply_target_object_context(execution, normalized)
        persisted_snapshot = normalized["_target_object"]
        event_store.record_execution_normalized(
            execution,
            normalized,
            self.resolved_command_hash,
        )
        return execution, device, normalized, raw_snapshot, persisted_snapshot

    def test_parameters_normalized_ledger_stores_redacted_snapshot_and_digests(
        self,
    ):
        execution, _device, normalized, raw_snapshot, persisted_snapshot = (
            self._record_snapshot()
        )

        assert event_names(execution) == ["ParametersNormalized"]
        stored = execution.events.get(event="ParametersNormalized")
        assert stored.data == {
            "command_hash": self.resolved_command_hash,
            "normalized_params": normalized,
        }
        assert stored.data["normalized_params"]["_target_object"] == (
            persisted_snapshot
        )
        assert self.secret_value in repr(raw_snapshot)
        assert self.secret_value not in repr(stored.data)

        fingerprint = stored.data["normalized_params"]["command_fingerprint"]
        assert fingerprint["target_object_sha256"] == _hash_json(
            persisted_snapshot
        )
        raw_hmac = fingerprint["target_object_raw_hmac_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", raw_hmac)
        assert raw_hmac != _hash_json(raw_snapshot)

    def test_rebuild_projection_preserves_snapshot_and_digests(self):
        execution, _device, _normalized, _raw_snapshot, persisted_snapshot = (
            self._record_snapshot()
        )
        stored = execution.events.get(event="ParametersNormalized")
        stored_fingerprint = stored.data["normalized_params"][
            "command_fingerprint"
        ]

        execution.refresh_from_db()
        rebuilt = event_store.rebuild_projection(execution)

        assert rebuilt.normalized_params["_target_object"] == persisted_snapshot
        assert (
            rebuilt.normalized_params["command_fingerprint"] == stored_fingerprint
        )
        assert rebuilt == ProjectionState.from_execution(execution)

    def test_approval_snapshot_hash_detects_redacted_target_secret_change(self):
        execution, device, normalized, _raw_snapshot, persisted_snapshot = (
            self._record_snapshot()
        )
        backend = make_backend("target-snapshot-ledger-backend")
        execution.backend_id = backend.pk
        execution.save(update_fields=["backend"])
        backend_target = BackendTarget(
            url="http://rpc-backend.test:16005",
            headers={},
            verify_ssl=True,
        )
        contract = SimpleNamespace(canonical_sha256=_hash_json)

        # This procedure is test-local, so patch only the protected-contract
        # lookup needed to exercise the real approval payload and model row.
        with mock.patch.object(
            command_handlers,
            "_protected_contract",
            return_value=contract,
        ):
            protected = command_handlers._approval_protected_payload(
                execution,
                normalized,
                backend_target=backend_target,
            )
            approval = command_handlers._create_approval_request(
                execution,
                normalized,
                backend_target=backend_target,
            )

            assert protected["normalized_params"]["_target_object"] == (
                persisted_snapshot
            )
            assert self.secret_value not in repr(protected["normalized_params"])
            assert (
                "target_object_raw_hmac_sha256"
                in protected["command_fingerprint"]
            )
            assert approval.payload_hash == compute_approval_snapshot_hash(
                protected
            )
            assert (
                approval.normalized_params["_target_object"]
                == persisted_snapshot
            )
            assert self.secret_value not in repr(approval.normalized_params)
            assert (
                "target_object_raw_hmac_sha256" in approval.command_fingerprint
            )

            device.custom_field_data = {
                "operator_notes": self.changed_secret_value,
            }
            device.save(update_fields=["custom_field_data"])
            execution.assigned_object = device
            changed_normalized = {
                "command_fingerprint": {
                    "handler_id": execution.procedure.handler_id,
                },
            }
            _apply_target_object_context(execution, changed_normalized)
            changed_protected = command_handlers._approval_protected_payload(
                execution,
                changed_normalized,
                backend_target=backend_target,
            )

        assert changed_normalized["_target_object"] == persisted_snapshot
        assert self.changed_secret_value not in repr(
            changed_protected["normalized_params"]
        )
        assert compute_approval_snapshot_hash(protected) != (
            compute_approval_snapshot_hash(changed_protected)
        )
        assert protected["command_fingerprint"][
            "target_object_raw_hmac_sha256"
        ] != changed_protected["command_fingerprint"][
            "target_object_raw_hmac_sha256"
        ]
        assert approval.matches_current(changed_protected) is False
