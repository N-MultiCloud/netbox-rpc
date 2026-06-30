"""Pure tests for the CQRS query-side helpers (no Django/DB)."""

from __future__ import annotations

import sys
import types


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

from netbox_rpc.application.queries import (  # noqa: E402
    execution_events,
    ordered_execution_events,
)


class _FakeQuerySet:
    def __init__(self, items):
        self.items = items
        self.order_by_args = None

    def all(self):
        return self

    def order_by(self, *args):
        self.order_by_args = args
        return self


class _FakeExecution:
    def __init__(self, items):
        self.events = _FakeQuerySet(items)


def test_execution_events_returns_all_events() -> None:
    ex = _FakeExecution(["e1", "e2"])
    assert execution_events(ex) is ex.events


def test_ordered_execution_events_orders_by_sequence() -> None:
    ex = _FakeExecution(["e1"])
    result = ordered_execution_events(ex)
    assert result is ex.events
    assert ex.events.order_by_args == ("sequence", "created")
