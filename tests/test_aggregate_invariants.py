from __future__ import annotations

import sys
import types
from dataclasses import dataclass

import pytest


def _install_netbox_stub() -> None:
    if "netbox.plugins" in sys.modules:
        return
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig
    sys.modules["netbox"] = netbox
    sys.modules["netbox.plugins"] = netbox_plugins


_install_netbox_stub()

from netbox_rpc.domain.aggregate import (  # noqa: E402
    RPCExecutionAggregate,
    RPCExecutionAggregateError,
)


@dataclass
class FakeExecution:
    status: str
    events: object | None = None


class ExistingEvents:
    def exists(self) -> bool:
        return True


def test_cannot_start_unless_queued() -> None:
    aggregate = RPCExecutionAggregate(FakeExecution(status="running"))

    with pytest.raises(RPCExecutionAggregateError, match="queued execution can start"):
        aggregate.start()


@pytest.mark.parametrize("status", ["succeeded", "failed", "cancelled"])
def test_cannot_transition_from_terminal_status(status: str) -> None:
    aggregate = RPCExecutionAggregate(FakeExecution(status=status))

    with pytest.raises(RPCExecutionAggregateError, match="terminal status"):
        aggregate.fail("boom", "RPC_BOOM")


def test_cancel_only_when_queued_or_pending_approval() -> None:
    # A running execution can no longer be cancelled; queued and (since #164)
    # pending-approval executions can.
    aggregate = RPCExecutionAggregate(FakeExecution(status="running"))

    with pytest.raises(
        RPCExecutionAggregateError,
        match="queued or pending-approval execution can be cancelled",
    ):
        aggregate.cancel()


def test_queue_event_must_be_first_in_stream() -> None:
    aggregate = RPCExecutionAggregate(
        FakeExecution(status="queued", events=ExistingEvents())
    )

    with pytest.raises(RPCExecutionAggregateError, match="first event"):
        aggregate.queue()
