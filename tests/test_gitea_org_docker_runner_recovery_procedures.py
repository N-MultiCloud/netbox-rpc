from __future__ import annotations

import importlib
import json
import runpy
import sys
import types
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = "netbox_rpc.migrations.0092_seed_gitea_org_docker_network_recovery"
DIAGNOSE = "service.gitea.actions_runner.diagnose_org_ci_runner"
RECOVER = "service.gitea.actions_runner.recover_org_ci_runner"
EXPECTED_HASHES = {
    DIAGNOSE: "2d98c0b205623df33114a623de8ec24a328c9ae1f86add08cfd9876395ce2abc",
    RECOVER: "e7ff9405ed45f0eff23260fc111af93afddd06a11c852ed03ccab729fce3dd7b",
}
CONTRACT = runpy.run_path(
    str(ROOT / "netbox_rpc/gitea_org_docker_runner_recovery_contract.py")
)


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    django.db = django_db
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_exact_schema_and_capability_hashes_match_backend() -> None:
    assert CONTRACT["PARAMS_SCHEMA_SHA256"] == (
        "f59454b0027f98b98b7c7e0ce1cc767fb8bd7c33aecbfb9a0910e6d21a46de34"
    )
    assert CONTRACT["DIAGNOSE_RESULT_SCHEMA_SHA256"] == (
        "f254cbde523602b2eb1849f6806417f64703e876832232f28350d27f12717a90"
    )
    assert CONTRACT["RECOVER_RESULT_SCHEMA_SHA256"] == (
        "07cd0990dcfb84c0dd28f20a88ff3912b3bf8f883ebe9dc50979edc160e160b4"
    )
    assert CONTRACT["CAPABILITY_CONTRACT_SHA256"] == EXPECTED_HASHES


def test_closed_schemas_reject_caller_selectors_and_network_near_misses() -> None:
    validate({}, CONTRACT["PARAMS_SCHEMA"])
    with pytest.raises(ValidationError):
        validate({"network": "attacker-selected"}, CONTRACT["PARAMS_SCHEMA"])

    valid = _diagnose_result()
    validate(valid, CONTRACT["DIAGNOSE_RESULT_SCHEMA"])
    for key, near_miss in (
        ("procedure", DIAGNOSE.replace("diagnose", "inspect")),
        ("target_object_id", 416),
        ("lane", "user-ubuntu"),
    ):
        mutated = deepcopy(valid)
        mutated[key] = near_miss
        with pytest.raises(ValidationError):
            validate(mutated, CONTRACT["DIAGNOSE_RESULT_SCHEMA"])

    recovery = _recovery_result()
    validate(recovery, CONTRACT["RECOVER_RESULT_SCHEMA"])
    recovery["removed_network_ids"] = ["../not-a-network-id"]
    with pytest.raises(ValidationError):
        validate(recovery, CONTRACT["RECOVER_RESULT_SCHEMA"])


def test_semantic_contract_forbids_adjacent_mutations() -> None:
    recovery = CONTRACT["SEMANTIC_CONTRACTS"][RECOVER]
    assert recovery["active_job_policy"] == (
        "authenticated-gitea-and-docker-idle-before-every-removal"
    )
    assert recovery["network_removal_policy"] == (
        "matching-prefix-and-zero-attached-containers-only"
    )
    assert recovery["default_address_pools_policy"] == "diagnostic-only"
    assert recovery["runner_lifecycle_policy"] == "no-pause-or-restart"
    assert recovery["resolver_policy"] == "no-change"


def test_migration_seeds_disabled_exact_rows_and_commands(migration) -> None:
    procedures = _ProcedureManager()
    commands = _CommandManager()
    migration.seed_gitea_org_docker_network_recovery(_apps(procedures, commands), None)

    assert set(procedures.rows) == {DIAGNOSE, RECOVER}
    assert procedures.rows[DIAGNOSE]["enabled"] is False
    assert procedures.rows[DIAGNOSE]["effect"] == "read"
    assert procedures.rows[DIAGNOSE]["timeout_seconds"] == 120
    assert procedures.rows[DIAGNOSE]["approval_required"] is False
    assert procedures.rows[RECOVER]["enabled"] is False
    assert procedures.rows[RECOVER]["effect"] == "write"
    assert procedures.rows[RECOVER]["timeout_seconds"] == 180
    assert procedures.rows[RECOVER]["approval_required"] is True
    assert procedures.rows[DIAGNOSE]["params_schema"] == CONTRACT["PARAMS_SCHEMA"]
    assert (
        procedures.rows[DIAGNOSE]["result_schema"]
        == (CONTRACT["DIAGNOSE_RESULT_SCHEMA"])
    )
    assert (
        procedures.rows[RECOVER]["result_schema"] == (CONTRACT["RECOVER_RESULT_SCHEMA"])
    )
    assert commands.rows[(DIAGNOSE, 1)]["argv"] == [
        "backend-orchestrated",
        "gitea-org-ci-runner-diagnose",
    ]
    assert commands.rows[(RECOVER, 1)]["argv"] == [
        "backend-orchestrated",
        "gitea-org-ci-runner-recover",
    ]


def test_reverse_disables_without_deleting_history(migration) -> None:
    procedures = _ProcedureManager()
    commands = _CommandManager()
    migration.seed_gitea_org_docker_network_recovery(_apps(procedures, commands), None)
    procedures.rows["unrelated"] = {"enabled": True}

    migration.disable_gitea_org_docker_network_recovery(
        _apps(procedures, commands), None
    )

    assert procedures.rows[DIAGNOSE]["enabled"] is False
    assert procedures.rows[RECOVER]["enabled"] is False
    assert procedures.rows["unrelated"]["enabled"] is True
    assert procedures.deleted == []


def test_catalog_wiring_is_explicit() -> None:
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))
    assert {DIAGNOSE, RECOVER} <= constants[
        "GITEA_ORG_CI_RUNNER_RECOVERY_PROCEDURE_NAMES"
    ]
    assert {DIAGNOSE, RECOVER} <= constants[
        "EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES"
    ]
    assert RECOVER in constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    assert DIAGNOSE not in constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    command_contract = runpy.run_path(str(ROOT / "netbox_rpc/command_contract.py"))
    assert {DIAGNOSE, RECOVER} <= command_contract["EXEMPT_HANDLER_IDS"]
    serialized = json.dumps(CONTRACT["SEMANTIC_CONTRACTS"], sort_keys=True)
    assert "rpc_ssh_host" not in serialized
    assert "restart_performed" not in serialized
    assert "resolver_reconciled" not in serialized


def _snapshot(*, active_job: bool = False) -> dict[str, object]:
    return {
        "docker_active": True,
        "runner_container_name": "ci-ubuntu-nmulticloud-org-241",
        "runner_container_id": "a" * 12,
        "runner_state": "running",
        "active_job": active_job,
        "default_address_pools": ["base=172.30.0.0/16,size=24"],
        "networks": [
            {
                "id": "b" * 12,
                "name": "GITEA-ACTIONS-TASK-1",
                "attached_containers": 0,
                "disposition": "stale",
            }
        ],
        "address_pool_exhausted": True,
        "last_log_activity": None,
        "truncated": False,
    }


def _diagnose_result() -> dict[str, object]:
    return {
        **_snapshot(),
        "ok": True,
        "procedure": DIAGNOSE,
        "target": "Gitea-Runner",
        "target_object_id": 604,
        "lane": "general-ubuntu",
        "stage": "complete",
    }


def _recovery_result() -> dict[str, object]:
    return {
        "ok": False,
        "procedure": RECOVER,
        "target": "Gitea-Runner",
        "target_object_id": 604,
        "lane": "general-ubuntu",
        "stage": "refused_active_job",
        "before": _snapshot(active_job=True),
        "after": None,
        "removed_network_ids": [],
        "refused_active_job": True,
    }


def _apps(procedures, commands):
    def get_model(app_label: str, model_name: str):
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure"):
            return SimpleNamespace(objects=procedures)
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedureCommand"):
            return SimpleNamespace(objects=commands)
        raise AssertionError((app_label, model_name))

    return SimpleNamespace(get_model=get_model)


class _Query:
    def __init__(self, manager: _ProcedureManager, names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def exists(self) -> bool:
        return any(name in self.manager.rows for name in self.names)

    def update(self, **fields: object) -> int:
        matches = [name for name in self.names if name in self.manager.rows]
        for name in matches:
            self.manager.rows[name].update(fields)
        return len(matches)


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.deleted: list[str] = []

    def filter(self, *, name=None, name__in=None):
        names = {name} if name is not None else set(name__in or ())
        return _Query(self, names)

    def create(self, *, name: str, **fields: object):
        self.rows[name] = dict(fields)
        return SimpleNamespace(name=name, handler_id=fields["handler_id"])


class _CommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def create(self, *, procedure, sequence: int, **fields: object):
        self.rows[(procedure.name, sequence)] = dict(fields)
        return SimpleNamespace()
