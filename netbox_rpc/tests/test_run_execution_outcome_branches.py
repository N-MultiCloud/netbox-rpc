"""Outcome branches of run_execution that the dispatch tests do not reach.

Each test drives the worker claim with the backend resolver, the normalizer, and
the backend call mocked. The write rejections are simulated by mocking the
aggregate, so these tests do not prove a real race. The assertions cover only the
outcome of the branch under test. The Gitea runner-scope fence branches are not
exercised here.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from rest_framework import serializers as drf_serializers

from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.constants import NETBOX_STAGING_ROTATE_BACKEND_TOKEN
from netbox_rpc.domain.aggregate import (
    RPCExecutionAggregate,
    RPCExecutionAggregateError,
)
from netbox_rpc.domain.normalization import RPCExecutionError
from netbox_rpc.models import RPCExecution, RpcPluginSettings

from ._common import (
    enable_rpc_integration,
    event_names,
    make_backend,
    make_execution,
    make_procedure,
)

_TARGET = BackendTarget(url="http://backend.example", headers={}, verify_ssl=True)
_NORMALIZED = {"command_fingerprint": {"handler_id": "x"}}


def _queued(*, procedure=None) -> RPCExecution:
    execution = make_execution(procedure=procedure)
    RPCExecutionAggregate(execution).queue()
    return execution


class RunExecutionOutcomeBranchTests(TestCase):
    def test_disabled_claim_returns_quietly_when_the_failure_write_is_rejected(self):
        enable_rpc_integration()
        execution = _queued()
        settings_row = RpcPluginSettings.get_solo()
        settings_row.enabled = False
        settings_row.save()

        with mock.patch.object(
            RPCExecutionAggregate,
            "fail",
            side_effect=RPCExecutionAggregateError("already terminal"),
        ) as fail:
            command_handlers.run_execution(execution)

        fail.assert_called_once()
        execution.refresh_from_db()
        assert "ExecutionFailed" not in event_names(execution)

    @mock.patch(
        "netbox_rpc.jobs._call_backend",
        side_effect=RPCExecutionError(
            "Backend unreachable.", code="RPC_BACKEND_UNREACHABLE"
        ),
    )
    @mock.patch.object(
        command_handlers, "normalize_execution_params", return_value=_NORMALIZED
    )
    @mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET)
    def test_dispatch_error_is_reraised_when_the_failure_write_is_rejected(
        self, _resolve, _normalize, _call
    ):
        enable_rpc_integration()
        execution = _queued()

        with mock.patch.object(
            RPCExecutionAggregate,
            "fail",
            side_effect=RPCExecutionAggregateError("already terminal"),
        ):
            with self.assertRaises(RPCExecutionError) as caught:
                command_handlers.run_execution(execution)

        assert caught.exception.code == "RPC_BACKEND_UNREACHABLE"

    # The protected-claim approval gate has its own tests. Here it is stubbed to
    # pass, so the test reaches the backend binding check it is about.
    @mock.patch.object(
        command_handlers, "_reject_invalid_protected_claim", return_value=False
    )
    @mock.patch.object(
        command_handlers,
        "_resolve_validated_protected_backend_target",
        side_effect=drf_serializers.ValidationError("binding changed"),
    )
    @mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET)
    def test_protected_target_validation_error_fails_with_the_binding_code(
        self, _resolve, _validated, _claim_gate
    ):
        enable_rpc_integration()
        procedure = make_procedure(NETBOX_STAGING_ROTATE_BACKEND_TOKEN)
        procedure.enabled = True
        procedure.save()
        backend = make_backend()
        execution = make_execution(procedure=procedure)
        execution.backend = backend.pk
        execution.save()
        RPCExecutionAggregate(execution).queue()

        with self.assertRaises(RPCExecutionError) as caught:
            command_handlers.run_execution(execution)

        assert caught.exception.code == "RPC_BACKEND_BINDING_INVALID"
        execution.refresh_from_db()
        assert execution.status == RPCExecution.STATUS_FAILED
        assert execution.error_code == "RPC_BACKEND_BINDING_INVALID"
