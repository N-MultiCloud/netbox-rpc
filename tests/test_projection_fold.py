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
    BackendEventRecorded,
    ExecutionCancelled,
    ExecutionEnqueueFailed,
    ExecutionFailed,
    ExecutionQueued,
    ExecutionStarted,
    ExecutionSucceeded,
    JobEnqueued,
    ParametersNormalized,
)
from netbox_rpc.domain.projection import ProjectionState, apply, rebuild  # noqa: E402


STARTED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
FINISHED_AT = datetime(2026, 1, 2, 3, 5, 5, tzinfo=timezone.utc)


def _fold(events):
    state = ProjectionState.initial()
    for event in events:
        state = apply(state, event)
    return state


def test_rebuild_success_path_matches_folded_projection() -> None:
    normalized = {
        "target": "edge-01",
        "rpc_ssh_credential_pk": 42,
        "command_fingerprint": {"handler_id": "handler"},
    }
    events = [
        ExecutionQueued(requested_by_id=7),
        ExecutionStarted(started_at=STARTED_AT),
        ParametersNormalized(normalized, "abc123"),
        JobEnqueued(job_id=99),
        BackendEventRecorded(
            backend_event="BackendProgress",
            backend_data={"step": "called"},
        ),
        ExecutionSucceeded({"ok": True}, FINISHED_AT),
    ]

    expected = ProjectionState(
        status="succeeded",
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
        result={"ok": True},
        normalized_params=normalized,
        resolved_command_hash="abc123",
        job_id=99,
    )

    assert _fold(events) == expected
    assert rebuild(events) == expected


def test_rebuild_failed_path_sets_canonical_error_defaults() -> None:
    events = [
        ExecutionQueued(),
        ExecutionStarted(started_at=STARTED_AT),
        ExecutionFailed("", "", FINISHED_AT),
    ]

    expected = ProjectionState(
        status="failed",
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
        error_code="RPC_EXECUTION_FAILED",
        error_message="RPC execution failed.",
    )

    assert rebuild(events) == expected


def test_rebuild_enqueue_failed_path() -> None:
    events = [
        ExecutionQueued(),
        ExecutionEnqueueFailed(
            "Failed to enqueue RPC job. Check RQ/Redis connectivity.",
            "RPC_ENQUEUE_FAILED",
            FINISHED_AT,
        ),
    ]

    assert rebuild(events) == ProjectionState(
        status="failed",
        finished_at=FINISHED_AT,
        error_code="RPC_ENQUEUE_FAILED",
        error_message="Failed to enqueue RPC job. Check RQ/Redis connectivity.",
    )


def test_rebuild_cancelled_path() -> None:
    events = [
        ExecutionQueued(),
        JobEnqueued(job_id=101),
        ExecutionCancelled(finished_at=FINISHED_AT, cancelled_by_id=7),
    ]

    assert rebuild(events) == ProjectionState(
        status="cancelled",
        finished_at=FINISHED_AT,
        job_id=101,
    )


def test_backend_events_do_not_change_projection() -> None:
    state = ProjectionState(
        status="running",
        started_at=STARTED_AT,
        normalized_params={"target": "edge-01"},
        resolved_command_hash="hash",
    )

    assert (
        apply(
            state,
            BackendEventRecorded(
                backend_event="BackendProgress",
                backend_data={"line": "bounded"},
                event_level="debug",
                event_message="backend emitted progress",
            ),
        )
        == state
    )
