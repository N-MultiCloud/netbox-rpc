"""Integration tests for the application command handlers (run/cancel + the
concurrency race), against a real NetBox test database."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from rest_framework.exceptions import ValidationError

from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCExecution

from ._common import (
    enable_rpc_integration,
    event_names,
    make_execution,
    make_procedure,
    make_user,
)

_TARGET = BackendTarget(url="http://backend.example", headers={}, verify_ssl=True)


def _queued():
    ex = make_execution()
    RPCExecutionAggregate(ex).queue()
    return ex


class RunExecutionTests(TestCase):
    def setUp(self):
        # #166: the worker claim is gated on the opt-in being enabled.
        enable_rpc_integration()

    @mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET)
    @mock.patch.object(command_handlers, "normalize_execution_params",
                       return_value={"command_fingerprint": {"handler_id": "x"}})
    @mock.patch("netbox_rpc.jobs._call_backend",
                return_value={"ok": True, "result": {"stdout": "ok"}})
    def test_run_success(self, _call, _norm, _resolve):
        ex = _queued()
        command_handlers.run_execution(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_SUCCEEDED
        assert "ExecutionStarted" in event_names(ex)
        assert "ExecutionSucceeded" in event_names(ex)

    @mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET)
    @mock.patch.object(command_handlers, "normalize_execution_params",
                       return_value={"command_fingerprint": {}})
    @mock.patch("netbox_rpc.jobs._call_backend",
                return_value={"ok": False, "error_code": "RPC_X", "error_message": "nope"})
    def test_run_backend_failure(self, _call, _norm, _resolve):
        ex = _queued()
        command_handlers.run_execution(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_FAILED
        assert ex.error_code == "RPC_X"

    @mock.patch.object(command_handlers, "resolve_backend", return_value=None)
    def test_run_no_backend_fails(self, _resolve):
        ex = _queued()
        with self.assertRaises(Exception):
            command_handlers.run_execution(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_FAILED
        assert ex.error_code == "RPC_BACKEND_NOT_CONFIGURED"

    def test_malformed_akvorado_config_deploy_result_fails_closed(self):
        self._assert_malformed_akvorado_result_fails_closed(
            "service.akvorado.1.config_deploy",
            required_fields=("deploy_status", "validation_output"),
            result={
                "ok": True,
                "procedure": "service.akvorado.1.config_deploy",
                "target": "akvorado-01",
                "validation_output": "valid",
            },
        )

    def test_malformed_akvorado_status_result_fails_closed(self):
        self._assert_malformed_akvorado_result_fails_closed(
            "service.akvorado.1.status_stack",
            required_fields=("status", "output"),
            result={
                "ok": True,
                "procedure": "service.akvorado.1.status_stack",
                "target": "akvorado-01",
                "output": "running",
            },
        )

    def _assert_malformed_akvorado_result_fails_closed(
        self,
        procedure_name,
        *,
        required_fields,
        result,
    ):
        procedure = make_procedure(procedure_name)
        procedure.result_schema = {
            "type": "object",
            "required": ["ok", "procedure", "target", *required_fields],
            "additionalProperties": False,
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                **{field: {"type": "string"} for field in required_fields},
            },
        }
        procedure.save()
        ex = make_execution(procedure=procedure)
        RPCExecutionAggregate(ex).queue()

        with (
            mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET),
            mock.patch.object(
                command_handlers,
                "normalize_execution_params",
                return_value={"command_fingerprint": {"handler_id": procedure_name}},
            ),
            mock.patch(
                "netbox_rpc.jobs._call_backend",
                return_value={"ok": True, "result": result},
            ),
        ):
            command_handlers.run_execution(ex)

        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_FAILED
        assert ex.error_code == "RPC_RESULT_SCHEMA_MISMATCH"
        assert "Backend result schema mismatch" in ex.error_message
        assert "ExecutionSucceeded" not in event_names(ex)


class CancelAndRaceTests(TestCase):
    def setUp(self):
        # Keep the cancel-vs-run race meaningful: run_execution is #166-gated on
        # the opt-in, so enable it or run_execution short-circuits on "disabled"
        # before it can exercise the cancel race.
        enable_rpc_integration()

    def test_cancel_queued(self):
        ex = _queued()
        command_handlers.cancel_execution(ex, make_user())
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_CANCELLED

    def test_cancel_running_is_rejected(self):
        ex = _queued()
        command_handlers._transition_locked(ex, lambda agg: agg.start())
        with self.assertRaises(ValidationError):
            command_handlers.cancel_execution(ex, make_user())

    @mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET)
    @mock.patch.object(command_handlers, "normalize_execution_params",
                       return_value={"command_fingerprint": {}})
    @mock.patch("netbox_rpc.jobs._call_backend", return_value={"ok": True, "result": {}})
    def test_cancel_then_start_is_skipped(self, _c, _n, _r):
        # The worker loses the race: the execution was cancelled first, so
        # run_execution returns early without ever appending ExecutionStarted.
        ex = _queued()
        command_handlers.cancel_execution(ex, make_user())
        command_handlers.run_execution(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_CANCELLED
        assert "ExecutionStarted" not in event_names(ex)

    def test_cancel_requires_permission(self):
        ex = _queued()
        user = make_user("nopriv", superuser=False)
        with self.assertRaises(Exception):
            command_handlers.cancel_execution(ex, user)
