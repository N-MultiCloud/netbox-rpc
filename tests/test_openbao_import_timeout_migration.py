"""Contracts for migration 0100's OpenBao importer timeout-only update."""

from __future__ import annotations

import importlib.util
import sys
import types
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "netbox_rpc/migrations/0100_extend_openbao_import_timeout_budget.py"
CONTRACT_PATH = ROOT / "netbox_rpc/openbao_import_contract.py"
DRY_RUN = "service.netbox.openbao_import.dry_run"
APPLY = "service.netbox.openbao_import.apply"


class _Row:
    def __init__(self, fields: dict[str, object]) -> None:
        self.__dict__.update(deepcopy(fields))
        self.saved_fields: list[list[str]] = []

    def save(self, *, update_fields: list[str]) -> None:
        self.saved_fields.append(update_fields)


class _QuerySet:
    def __init__(self, row: _Row | None) -> None:
        self.row = row

    def first(self) -> _Row | None:
        return self.row


class _Manager:
    def __init__(self, rows: dict[str, _Row]) -> None:
        self.rows = rows

    def filter(self, *, name: str) -> _QuerySet:
        return _QuerySet(self.rows.get(name))


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.migrations = SimpleNamespace(
        Migration=object,
        RunPython=lambda *args, **kwargs: None,
    )
    django.db = django_db
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    spec = importlib.util.spec_from_file_location("openbao_timeout_migration", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fields(timeout_seconds: int, *, destructive: bool) -> dict[str, object]:
    return {
        "timeout_seconds": timeout_seconds,
        "handler_id": APPLY if destructive else DRY_RUN,
        "version": 1,
        "enabled": True,
        "target_models": ["dcim.device"],
        "effect": "destructive" if destructive else "read",
        "approval_required": destructive,
        "params_schema": {"closed": "params"},
        "result_schema": {"closed": "result"},
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "description": "unchanged",
    }


def _apps(rows: dict[str, _Row]):
    model = type("RPCProcedure", (), {"objects": _Manager(rows)})
    return SimpleNamespace(get_model=lambda app, name: model)


def test_forward_and_reverse_change_only_timeout_and_are_reentrant(migration) -> None:
    rows = {
        DRY_RUN: _Row(_fields(300, destructive=False)),
        APPLY: _Row(_fields(900, destructive=True)),
    }
    expected_dry_run = deepcopy(rows[DRY_RUN].__dict__)
    expected_apply = deepcopy(rows[APPLY].__dict__)
    apps = _apps(rows)

    migration.forwards(apps, None)
    migration.forwards(apps, None)

    assert migration._BACKEND_ROUTE_BUDGET_SECONDS == 1050
    assert migration._REQUEST_CANCELLATION_RESULT_MARGIN_SECONDS == 150
    assert migration._TIMEOUT_SECONDS == 1200
    expected_dry_run["timeout_seconds"] = 1200
    expected_dry_run["saved_fields"] = [["timeout_seconds"]]
    expected_apply["timeout_seconds"] = 1200
    expected_apply["saved_fields"] = [["timeout_seconds"]]
    assert rows[DRY_RUN].__dict__ == expected_dry_run
    assert rows[APPLY].__dict__ == expected_apply

    migration.backwards(apps, None)
    migration.backwards(apps, None)

    assert rows[DRY_RUN].timeout_seconds == 300
    assert rows[APPLY].timeout_seconds == 900
    assert rows[DRY_RUN].saved_fields == [["timeout_seconds"], ["timeout_seconds"]]
    assert rows[APPLY].saved_fields == [["timeout_seconds"], ["timeout_seconds"]]


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ({APPLY: _Row(_fields(900, destructive=True))}, "required procedure row is missing"),
        (
            {
                DRY_RUN: _Row(_fields(301, destructive=False)),
                APPLY: _Row(_fields(900, destructive=True)),
            },
            "timeout_seconds was modified",
        ),
    ],
)
def test_forward_refuses_missing_or_drifted_catalog_rows(migration, rows, message) -> None:
    before = {name: deepcopy(row.__dict__) for name, row in rows.items()}

    with pytest.raises(RuntimeError, match=message):
        migration.forwards(_apps(rows), None)

    assert {name: row.__dict__ for name, row in rows.items()} == before


@pytest.mark.parametrize(
    ("direction", "rows", "message"),
    [
        (
            "forwards",
            {DRY_RUN: _Row(_fields(300, destructive=False))},
            "required procedure row is missing",
        ),
        (
            "forwards",
            {
                DRY_RUN: _Row(_fields(300, destructive=False)),
                APPLY: _Row(_fields(901, destructive=True)),
            },
            "timeout_seconds was modified",
        ),
        (
            "backwards",
            {DRY_RUN: _Row(_fields(1200, destructive=False))},
            "required procedure row is missing",
        ),
        (
            "backwards",
            {
                DRY_RUN: _Row(_fields(1200, destructive=False)),
                APPLY: _Row(_fields(1199, destructive=True)),
            },
            "timeout_seconds was modified",
        ),
    ],
)
def test_second_row_failure_never_partially_updates_first_row(
    migration, direction, rows, message
) -> None:
    before = {name: deepcopy(row.__dict__) for name, row in rows.items()}

    with pytest.raises(RuntimeError, match=message):
        getattr(migration, direction)(_apps(rows), None)

    assert {name: row.__dict__ for name, row in rows.items()} == before


@pytest.mark.parametrize(
    ("direction", "dry_start", "apply_start", "dry_end", "apply_end", "saved_name"),
    [
        ("forwards", 1200, 900, 1200, 1200, APPLY),
        ("forwards", 300, 1200, 1200, 1200, DRY_RUN),
        ("backwards", 300, 1200, 300, 900, APPLY),
        ("backwards", 1200, 900, 300, 900, DRY_RUN),
    ],
)
def test_mixed_reentry_states_update_only_the_expected_row(
    migration,
    direction,
    dry_start,
    apply_start,
    dry_end,
    apply_end,
    saved_name,
) -> None:
    rows = {
        DRY_RUN: _Row(_fields(dry_start, destructive=False)),
        APPLY: _Row(_fields(apply_start, destructive=True)),
    }

    getattr(migration, direction)(_apps(rows), None)

    assert rows[DRY_RUN].timeout_seconds == dry_end
    assert rows[APPLY].timeout_seconds == apply_end
    assert rows[saved_name].saved_fields == [["timeout_seconds"]]
    unchanged_name = APPLY if saved_name == DRY_RUN else DRY_RUN
    assert rows[unchanged_name].saved_fields == []


def test_runtime_apply_policy_matches_the_extended_catalog_budget() -> None:
    spec = importlib.util.spec_from_file_location("openbao_import_contract", CONTRACT_PATH)
    assert spec is not None and spec.loader is not None
    openbao_import_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(openbao_import_contract)

    assert openbao_import_contract.BACKEND_ROUTE_BUDGET_SECONDS == 1050
    assert openbao_import_contract.REQUEST_CANCELLATION_RESULT_MARGIN_SECONDS == 150
    assert openbao_import_contract.TIMEOUT_SECONDS == 1200
    assert openbao_import_contract.PROCEDURE_POLICY["timeout_seconds"] == 1200
