from __future__ import annotations

import sys
import types
from datetime import datetime, timezone


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

from netbox_rpc.domain.events import (  # noqa: E402
    EVENT_TYPES,
    BackendEventRecorded,
    ExecutionCancelled,
    ExecutionEnqueueFailed,
    ExecutionFailed,
    ExecutionQueued,
    ExecutionStarted,
    ExecutionSucceeded,
    JobEnqueued,
    ParametersNormalized,
    from_record,
)


NOW = datetime(2026, 2, 3, 4, 5, 6, tzinfo=timezone.utc)


def test_event_registry_contains_every_transition_type() -> None:
    assert set(EVENT_TYPES) == {
        # Approval workflow (issue #164).
        "ExecutionRequested",
        "ApprovalRequested",
        "ExecutionApproved",
        "ExecutionRejected",
        "ExecutionExpired",
        # Existing execution lifecycle.
        "ExecutionQueued",
        "ExecutionStarted",
        "ParametersNormalized",
        "JobEnqueued",
        "BackendEventRecorded",
        "ExecutionSucceeded",
        "ExecutionFailed",
        "ExecutionEnqueueFailed",
        "ExecutionCancelled",
    }


def test_typed_events_round_trip_through_record_data() -> None:
    events = [
        ExecutionQueued(requested_by_id=1),
        ExecutionStarted(started_at=NOW),
        ParametersNormalized({"target": "edge-01"}, "hash"),
        JobEnqueued(job_id=12),
        ExecutionSucceeded({"value": 1}, NOW),
        ExecutionFailed("boom", "RPC_BOOM", NOW),
        ExecutionEnqueueFailed("queue down", "RPC_ENQUEUE_FAILED", NOW),
        ExecutionCancelled(NOW, cancelled_by_id=1, reason="operator cancelled"),
    ]

    for event in events:
        reconstructed = from_record(event.event_name, event.data)
        assert reconstructed.event_name == event.event_name
        assert reconstructed.data == event.data
        assert reconstructed.level == event.level
        assert reconstructed.message == event.message


def test_backend_event_preserves_backend_event_name_and_data() -> None:
    event = BackendEventRecorded(
        backend_event="BackendProgress",
        backend_data={"step": "normalize"},
        event_level="debug",
        event_message="progress",
    )

    reconstructed = from_record(event.event_name, event.data)

    assert reconstructed.event_name == "BackendProgress"
    assert reconstructed.data == {"step": "normalize"}
