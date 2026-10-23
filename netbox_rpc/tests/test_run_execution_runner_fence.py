"""Characterization of the Gitea runner-scope fence inside run_execution (issue #421).

The fence reserves the runner scope before the backend call, records the Gitea
runner response, and blocks the scope when dispatch fails after a reservation. A
reconciliation takeover may own the fence by then, so the block tolerates that
error and the execution still fails. These tests mock the fence helpers and the
backend call, and they assert call order and the terminal outcome. They do not
prove the canonical scope ownership, which the Gitea runner tests cover.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase

from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.constants import GITEA_RUNNER_REGISTER
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.domain.normalization import RPCExecutionError
from netbox_rpc.models import RPCExecution

from ._common import enable_rpc_integration, make_execution, make_procedure

_TARGET = BackendTarget(url="http://backend.example", headers={}, verify_ssl=True)
_NORMALIZED = {"command_fingerprint": {"handler_id": "x"}}
_RESPONSE = {"ok": True, "result": {"ok": True}, "events": []}


def _queued(procedure_name: str) -> RPCExecution:
    # The migration seed may already hold the row disabled, and get_or_create keeps it.
    procedure = make_procedure(procedure_name)
    if not procedure.enabled:
        procedure.enabled = True
        procedure.save(update_fields=["enabled"])
    execution = make_execution(procedure=procedure)
    RPCExecutionAggregate(execution).queue()
    return execution


class RunExecutionRunnerFenceTests(TestCase):
    def setUp(self):
        enable_rpc_integration()
        patches = [
            mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET),
            mock.patch.object(
                command_handlers, "normalize_execution_params", return_value=_NORMALIZED
            ),
            mock.patch.object(
                command_handlers, "_ledger_command_source", side_effect=lambda value: value
            ),
            mock.patch.object(command_handlers, "_issue_dispatch_lease", return_value=None),
            mock.patch.object(command_handlers, "_verify_backend_capability"),
            mock.patch.object(command_handlers, "_reserve_gitea_runner_scope"),
            mock.patch.object(command_handlers, "_record_gitea_runner_response"),
            mock.patch.object(command_handlers, "_block_gitea_runner_scope"),
            mock.patch("netbox_rpc.jobs._call_backend", return_value=_RESPONSE),
            # The Gitea runner procedures are approval-gated. Stub the approval gates
            # that sit before the fence, so these tests reach the fence itself.
            mock.patch.object(command_handlers, "_approval_identities_are_authorized", return_value=True),
            mock.patch.object(command_handlers, "_require_current_protected_approval"),
            mock.patch.object(command_handlers, "_require_approved_backend_target_before_io"),
            mock.patch.object(command_handlers, "_require_protected_procedure_policy"),
            mock.patch.object(
                command_handlers,
                "_resolve_validated_protected_backend_target",
                return_value=_TARGET,
            ),
            mock.patch.object(command_handlers, "_requires_signed_dispatch", return_value=False),
            # The Gitea runner contract pins its backend id; bind to that pinned id.
            mock.patch.object(
                command_handlers,
                "_require_concrete_protected_backend_id",
                return_value=1,
            ),
        ]
        started = [patch.start() for patch in patches]
        for patch in patches:
            self.addCleanup(patch.stop)
        self.reserve = started[5]
        self.record = started[6]
        self.block = started[7]
        self.call = started[8]
        self.order: list[str] = []
        self.reserve.side_effect = lambda *a, **k: self.order.append("reserve")
        self.record.side_effect = lambda *a, **k: self.order.append("record")
        self.call.side_effect = lambda *a, **k: (self.order.append("call"), _RESPONSE)[1]

    def _run(self, procedure_name: str, call_side_effect=None):
        execution = _queued(procedure_name)
        if call_side_effect is not None:
            self.call.side_effect = call_side_effect
        return execution, self.call, self.order

    def test_gitea_runner_reserves_before_the_backend_call_and_records_the_response(self):
        execution, call, order = self._run(GITEA_RUNNER_REGISTER)

        command_handlers.run_execution(execution)

        self.reserve.assert_called_once_with(execution, _NORMALIZED)
        self.record.assert_called_once_with(execution, _NORMALIZED, _RESPONSE)
        self.assertEqual(order, ["reserve", "call", "record"])
        self.block.assert_not_called()
        execution.refresh_from_db()
        self.assertEqual(execution.status, RPCExecution.STATUS_RUNNING)

    def test_ordinary_procedure_skips_the_fence_and_records_the_backend_response(self):
        execution = _queued("os.linux.test.echo")

        with mock.patch.object(RPCExecutionAggregate, "record_backend_response") as record:
            command_handlers.run_execution(execution)

        self.call.assert_called_once()
        record.assert_called_once_with(_RESPONSE)
        self.reserve.assert_not_called()
        self.record.assert_not_called()
        self.block.assert_not_called()

    def test_reservation_failure_fails_without_blocking_the_scope(self):
        execution, call, _order = self._run(GITEA_RUNNER_REGISTER)
        self.reserve.side_effect = RPCExecutionError(
            "Runner scope is held.", code="RPC_GITEA_RUNNER_SCOPE_HELD"
        )

        with self.assertRaises(RPCExecutionError):
            command_handlers.run_execution(execution)

        call.assert_not_called()
        self.block.assert_not_called()
        execution.refresh_from_db()
        self.assertEqual(execution.status, RPCExecution.STATUS_FAILED)
        self.assertEqual(execution.error_code, "RPC_GITEA_RUNNER_SCOPE_HELD")

    def test_dispatch_failure_after_reservation_blocks_the_scope_and_fails(self):
        execution, _call, _order = self._run(
            GITEA_RUNNER_REGISTER,
            call_side_effect=RPCExecutionError(
                "Backend unreachable.", code="RPC_BACKEND_UNREACHABLE"
            ),
        )

        with self.assertRaises(RPCExecutionError):
            command_handlers.run_execution(execution)

        self.reserve.assert_called_once()
        self.block.assert_called_once_with(execution, _NORMALIZED)
        self.record.assert_not_called()
        execution.refresh_from_db()
        self.assertEqual(execution.status, RPCExecution.STATUS_FAILED)
        self.assertEqual(execution.error_code, "RPC_BACKEND_UNREACHABLE")

    def test_takeover_during_the_scope_block_is_tolerated_and_the_execution_still_fails(self):
        execution, _call, _order = self._run(
            GITEA_RUNNER_REGISTER,
            call_side_effect=RPCExecutionError(
                "Backend unreachable.", code="RPC_BACKEND_UNREACHABLE"
            ),
        )
        self.block.side_effect = RPCExecutionError(
            "Scope owned by a takeover.", code="RPC_GITEA_RUNNER_SCOPE_TAKEN"
        )

        with self.assertRaises(RPCExecutionError) as raised:
            command_handlers.run_execution(execution)

        self.assertEqual(raised.exception.code, "RPC_BACKEND_UNREACHABLE")
        self.block.assert_called_once()
        execution.refresh_from_db()
        self.assertEqual(execution.status, RPCExecution.STATUS_FAILED)
        self.assertEqual(execution.error_code, "RPC_BACKEND_UNREACHABLE")
