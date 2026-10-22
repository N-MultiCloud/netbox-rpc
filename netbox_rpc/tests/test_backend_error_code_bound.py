"""Persisted execution failure codes must match the catalog shape (issue #400).

``RPCExecution.error_code`` is ``CharField(max_length=100)``. A failure code that is
longer than the column, or that is not upper snake case, must never reach it. The
execution still reaches a terminal state, with the fixed fallback code. These tests
run against the real PostgreSQL test database. On a revision without the bound, an
over-length code raises ``DataError`` on the projection save.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from netbox_rpc import event_store, jobs
from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.domain.normalization import RPCExecutionError
from netbox_rpc.domain.projection import ProjectionState
from netbox_rpc.models import RPCExecution

from ._common import enable_rpc_integration, make_execution, make_procedure

EXECUTION_FALLBACK = "RPC_EXECUTION_FAILED"
ENQUEUE_FALLBACK = "RPC_ENQUEUE_FAILED"
# One character more than the RPCExecution.error_code column holds.
OVER_LENGTH_CODE = "RPC_" + "A" * 97


class _CodedError(Exception):
    """An exception whose ``code`` attribute is an integer, not a string."""

    def __init__(self, code: object) -> None:
        super().__init__("coded failure")
        self.code = code


def _respond(response: dict) -> object:
    return lambda *_args, **_kwargs: response


def _raise(error: BaseException) -> object:
    def _fail(*_args, **_kwargs):
        raise error

    return _fail


def _backend_error_body(code: str) -> object:
    """Feed a backend HTTP error body through the real normalizer."""

    def _fail(*_args, **_kwargs):
        jobs._normalize_generic_backend_response(
            SimpleNamespace(status_code=503),
            {"code": code, "detail": "Backend unavailable."},
        )

    return _fail


class BackendErrorCodeBoundTests(TestCase):
    def _queued_execution(self) -> RPCExecution:
        procedure = make_procedure(
            "os.linux.test.echo", handler_id="h.echo", effect="read"
        )
        execution = make_execution(procedure=procedure)
        RPCExecutionAggregate(execution).queue()
        return execution

    def _started_execution(self) -> RPCExecution:
        execution = make_execution()
        aggregate = RPCExecutionAggregate(execution)
        aggregate.queue()
        aggregate.start()
        return execution

    def _dispatch(self, execution: RPCExecution, backend: object) -> None:
        """Run the real worker claim, normalizer, and failure handling.

        Only the network call to the backend and the backend resolution are replaced.
        """
        enable_rpc_integration()
        with (
            mock.patch.object(
                command_handlers,
                "resolve_backend",
                return_value=BackendTarget(
                    url="http://backend.example", headers={}, verify_ssl=True
                ),
            ),
            mock.patch.object(
                command_handlers,
                "normalize_execution_params",
                return_value={"command_fingerprint": {"handler_id": "h.echo"}},
            ),
            mock.patch("netbox_rpc.jobs._call_backend", side_effect=backend),
        ):
            command_handlers.run_execution(execution)

    def _assert_failed_with(self, execution: RPCExecution, code: str) -> None:
        execution.refresh_from_db()
        self.assertEqual(execution.status, RPCExecution.STATUS_FAILED)
        self.assertEqual(execution.error_code, code)
        self.assertEqual(
            event_store.rebuild_projection(execution),
            ProjectionState.from_execution(execution),
        )

    def test_over_length_code_from_backend_error_body_reaches_terminal_state(self):
        execution = self._queued_execution()

        with self.assertRaises(RPCExecutionError):
            self._dispatch(execution, _backend_error_body(OVER_LENGTH_CODE))

        self._assert_failed_with(execution, EXECUTION_FALLBACK)

    def test_over_length_code_on_ordinary_failure_keeps_the_backend_message(self):
        execution = self._queued_execution()
        response = {
            "ok": False,
            "error_code": OVER_LENGTH_CODE,
            "error_message": "Backend rejected the request.",
        }

        self._dispatch(execution, _respond(response))

        self._assert_failed_with(execution, EXECUTION_FALLBACK)
        execution.refresh_from_db()
        self.assertEqual(execution.error_message, "Backend rejected the request.")
        stored = execution.events.get(event="ExecutionFailed").data
        self.assertEqual(stored["code"], EXECUTION_FALLBACK)

    def test_short_non_catalog_codes_are_replaced_by_the_fallback(self):
        for code in ("rpc_lower", "RPC-DASH", "RPC_TRAILING\n", "RPC EMBEDDED SPACE"):
            with self.subTest(code=code):
                execution = self._queued_execution()
                response = {
                    "ok": False,
                    "error_code": code,
                    "error_message": "Backend failed.",
                }

                self._dispatch(execution, _respond(response))

                self._assert_failed_with(execution, EXECUTION_FALLBACK)

    def test_non_string_exception_code_falls_back(self):
        execution = self._queued_execution()

        with self.assertRaises(_CodedError):
            self._dispatch(execution, _raise(_CodedError(5)))

        self._assert_failed_with(execution, EXECUTION_FALLBACK)

    def test_code_at_the_column_width_is_kept_and_one_more_character_falls_back(self):
        at_limit = "R" + "A" * 99
        over_limit = "R" + "A" * 100
        self.assertEqual(len(at_limit), 100)
        self.assertEqual(len(over_limit), 101)

        kept = self._started_execution()
        RPCExecutionAggregate(kept).fail("Kept at the column width.", at_limit)
        kept.refresh_from_db()
        self.assertEqual(kept.error_code, at_limit)

        replaced = self._started_execution()
        RPCExecutionAggregate(replaced).fail("Replaced.", over_limit)
        self._assert_failed_with(replaced, EXECUTION_FALLBACK)

    def test_enqueue_failure_code_is_bounded(self):
        execution = make_execution()

        event_store.mark_execution_failed(
            execution,
            "Failed to enqueue RPC job.",
            OVER_LENGTH_CODE,
            event_name="ExecutionEnqueueFailed",
        )

        self._assert_failed_with(execution, ENQUEUE_FALLBACK)

    def test_enqueue_failure_keeps_a_code_at_the_column_width(self):
        at_limit = "R" + "A" * 99
        execution = make_execution()

        event_store.mark_execution_failed(
            execution,
            "Failed to enqueue RPC job.",
            at_limit,
            event_name="ExecutionEnqueueFailed",
        )

        self._assert_failed_with(execution, at_limit)

    def test_catalog_shape_rule_accepts_only_the_column_safe_catalog_shape(self):
        accepted = ["A", "RPC_X", "RPC_" + "A" * 96, "R" + "A" * 99]
        rejected = [
            "",
            None,
            5,
            "rpc_x",
            "RPC-X",
            "RPC_X\n",
            "RPC X",
            "1RPC",
            "R" + "A" * 100,
        ]
        for code in accepted:
            with self.subTest(accepted=code):
                self.assertTrue(event_store._is_catalog_error_code(code))
        for code in rejected:
            with self.subTest(rejected=code):
                self.assertFalse(event_store._is_catalog_error_code(code))

    def test_stored_legacy_code_still_rebuilds_unchanged(self):
        """A ledger row written before the bound keeps its stored code on rebuild."""
        execution = make_execution()
        event_store.append_execution_event(
            execution,
            "error",
            "ExecutionFailed",
            "Legacy failure.",
            {
                "status": RPCExecution.STATUS_FAILED,
                "code": "rpc_legacy",
                "error_message": "Legacy failure.",
                "finished_at": None,
            },
        )

        self.assertEqual(
            event_store.rebuild_projection(execution).error_code, "rpc_legacy"
        )
        # Re-folding the historical ledger keeps the stored code, and the complete
        # projection stays equal to the rebuilt one.
        event_store.reproject(execution)
        execution.refresh_from_db()
        self.assertEqual(execution.error_code, "rpc_legacy")
        self.assertEqual(
            event_store.rebuild_projection(execution),
            ProjectionState.from_execution(execution),
        )
