"""Exercise the reversible migration suffix and the historical 0068 reverse.

Run only against a disposable database after a complete forward migration. The
published migrations through 0089 contain deliberate reverse barriers, and
some later seeds cannot reapply after their non-destructive reverses, so this
check never crosses them. A new leaf or an unavailable suffix is an error.
"""

from __future__ import annotations

import importlib

import django
from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

APP = "netbox_rpc"
EXPECTED_LEAF = "0112_seed_iam_ui_control"
ROLLBACK_TARGET = "0103_seed_ubuntu_26_samba_ad_dc_procedures"
HISTORICAL_SEED = "0068_seed_staging_backend_token_rotation"
HISTORICAL_PROCEDURE = "service.netbox.staging.rotate_backend_token"
EXPECTED_ROLLBACK_PLAN = frozenset(
    (APP, name)
    for name in (
        "0112_seed_iam_ui_control",
        "0111_seed_pbs_procedures",
        "0110_seed_netbox_production_rq_worker_procedures",
        "0109_merge_enabled_publication_adoption",
        "0108_merge_publication_drift_report",
        "0107_merge_publication_provenance_normalization",
        "0106_merge_unmarked_publication_adoption",
        "0105_merge_protected_publication_predecessor",
        "0104_seed_protected_publication_pair",
        "0103_adopt_protected_publication_predecessor",
        "0103_adopt_unmarked_protected_publication_pair",
        "0103_normalize_protected_publication_provenance",
        "0103_report_protected_publication_drift",
        "0103_adopt_enabled_unmarked_publication_pair",
    )
)


def _executor() -> MigrationExecutor:
    return MigrationExecutor(connection)


def _check_current_leaf(executor: MigrationExecutor) -> None:
    leaves = executor.loader.graph.leaf_nodes(APP)
    if leaves != [(APP, EXPECTED_LEAF)]:
        raise RuntimeError(f"Rollback gate needs review for migration leaves {leaves!r}")
    applied = executor.loader.applied_migrations
    if (APP, EXPECTED_LEAF) not in applied:
        raise RuntimeError("Rollback gate requires a fully forward-migrated database")


def _seed_snapshot() -> tuple[set[str], set[int], set[int]]:
    latest = importlib.import_module(f"{APP}.migrations.{EXPECTED_LEAF}")
    pbs = importlib.import_module(f"{APP}.migrations.0111_seed_pbs_procedures")
    worker = importlib.import_module(
        f"{APP}.migrations.0110_seed_netbox_production_rq_worker_procedures"
    )
    procedure = apps.get_model(APP, "RPCProcedure")
    names = set(latest.HANDLER_IDS) | {row[0] for row in pbs._PROCEDURES}
    names |= {worker._STATUS_NAME, worker._RESTART_NAME}
    rows = procedure.objects.filter(name__in=names)
    row_ids = set(rows.values_list("pk", flat=True))
    command = apps.get_model(APP, "RPCProcedureCommand")
    commands = command.objects.filter(procedure__name__in=names)
    command_ids = set(commands.values_list("pk", flat=True))
    command_names = set(commands.values_list("procedure__name", flat=True))
    if len(row_ids) != len(names) or command_names != names:
        raise RuntimeError("Rollback suffix seed rows or inbound commands are missing")
    if not rows.filter(enabled=True).exists():
        raise RuntimeError("Rollback suffix has no enabled seed to exercise")
    return names, row_ids, command_ids


def _assert_seed_ids(
    names: set[str], row_ids: set[int], command_ids: set[int], phase: str
) -> None:
    procedure = apps.get_model(APP, "RPCProcedure")
    command = apps.get_model(APP, "RPCProcedureCommand")
    actual_rows = set(
        procedure.objects.filter(name__in=names).values_list("pk", flat=True)
    )
    actual_commands = set(
        command.objects.filter(procedure__name__in=names).values_list("pk", flat=True)
    )
    if actual_rows != row_ids or actual_commands != command_ids:
        raise RuntimeError(f"{phase} deleted or replaced seeded procedures or commands")


def _assert_leaf_applied(expected: bool) -> None:
    applied = (APP, EXPECTED_LEAF) in _executor().loader.applied_migrations
    if applied != expected:
        raise RuntimeError(f"Latest seed applied={applied}, expected={expected}")


def _rollback_plan(executor: MigrationExecutor) -> list:
    plan = executor.migration_plan([(APP, ROLLBACK_TARGET)])
    if not plan or not all(backwards for _migration, backwards in plan):
        raise RuntimeError("Rollback gate cannot construct a backward migration plan")
    nodes = {(migration.app_label, migration.name) for migration, _backwards in plan}
    if nodes != EXPECTED_ROLLBACK_PLAN or len(plan) != len(EXPECTED_ROLLBACK_PLAN):
        raise RuntimeError("Rollback plan changed; review its migration scope")
    return plan


def _check_historical_reverse(executor: MigrationExecutor) -> None:
    """Use the real reverse callable with a historical model and inbound FK."""

    procedure = apps.get_model(APP, "RPCProcedure")
    command = apps.get_model(APP, "RPCProcedureCommand")
    row = procedure.objects.get(name=HISTORICAL_PROCEDURE)
    inbound_count = command.objects.filter(procedure=row).count()
    if not inbound_count:
        raise RuntimeError("Historical reverse has no inbound command FK to test")
    migration = executor.loader.disk_migrations[(APP, HISTORICAL_SEED)]
    reverse_code = migration.operations[0].reverse_code
    historical_apps = executor.loader.project_state([(APP, HISTORICAL_SEED)]).apps
    reverse_code(historical_apps, None)
    row.refresh_from_db()
    if row.enabled or command.objects.filter(procedure=row).count() != inbound_count:
        raise RuntimeError("Historical reverse deleted or failed to disable seeded data")
    print(f"HISTORICAL_REVERSE_OK {HISTORICAL_SEED} inbound_commands={inbound_count}")


def _check_suffix_rollback(executor: MigrationExecutor) -> None:
    names, row_ids, command_ids = _seed_snapshot()
    target = (APP, ROLLBACK_TARGET)
    plan = _rollback_plan(executor)
    print(f"ROLLBACK_PLAN target={ROLLBACK_TARGET} migrations={len(plan)}")
    executor.migrate([target])
    _assert_leaf_applied(False)
    _assert_seed_ids(names, row_ids, command_ids, "Rollback")
    procedure = apps.get_model(APP, "RPCProcedure")
    if procedure.objects.filter(name__in=names, enabled=True).exists():
        raise RuntimeError("Rollback failed to disable an enabled seeded procedure")
    _executor().migrate([(APP, EXPECTED_LEAF)])
    _assert_leaf_applied(True)
    _assert_seed_ids(names, row_ids, command_ids, "Reapply")
    print(f"ROLLBACK_REAPPLY_OK {ROLLBACK_TARGET}..{EXPECTED_LEAF}")


def main() -> None:
    django.setup()
    executor = _executor()
    _check_current_leaf(executor)
    _check_historical_reverse(executor)
    _check_suffix_rollback(_executor())


if __name__ == "__main__":
    main()
