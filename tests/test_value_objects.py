"""Pure tests for the domain value objects (no Django/DB)."""

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

from pathlib import Path  # noqa: E402

from netbox_rpc.domain.value_objects import (  # noqa: E402
    Effect,
    ExecutionMode,
    ExecutionStatus,
)


def test_execution_status_values() -> None:
    assert ExecutionStatus.QUEUED.value == "queued"
    assert ExecutionStatus.RUNNING.value == "running"
    assert ExecutionStatus.SUCCEEDED.value == "succeeded"
    assert ExecutionStatus.FAILED.value == "failed"
    assert ExecutionStatus.CANCELLED.value == "cancelled"


def test_effect_values() -> None:
    assert Effect.READ.value == "read"
    assert Effect.WRITE.value == "write"
    assert Effect.DESTRUCTIVE.value == "destructive"


def test_execution_mode_values() -> None:
    assert ExecutionMode.SEQUENTIAL.value == "sequential"
    assert ExecutionMode.PARALLEL.value == "parallel"


def test_model_constants_are_single_sourced_from_value_objects() -> None:
    # The model must derive its STATUS_*/EFFECT_*/MODE_* constants from the domain
    # value objects so there is exactly one source of truth.
    src = Path(__file__).resolve().parent.parent.joinpath("netbox_rpc/models.py").read_text()
    assert (
        "from .domain.value_objects import Effect, ExecutionMode, ExecutionStatus"
        in src
    )
    assert "STATUS_QUEUED = ExecutionStatus.QUEUED.value" in src
    assert "STATUS_CANCELLED = ExecutionStatus.CANCELLED.value" in src
    assert "EFFECT_READ = Effect.READ.value" in src
    assert "EFFECT_DESTRUCTIVE = Effect.DESTRUCTIVE.value" in src
    assert "MODE_SEQUENTIAL = ExecutionMode.SEQUENTIAL.value" in src
    assert "MODE_PARALLEL = ExecutionMode.PARALLEL.value" in src
