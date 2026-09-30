"""Contract tests for proxbox-api offline-image diagnosis and preload."""

from __future__ import annotations

import importlib
import runpy
import sys
import types
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = (
    "netbox_rpc.migrations.0102_seed_proxbox_offline_image_recovery"
)
DIAGNOSE = "service.nmulticloud.deploy.diagnose_proxbox_api_images"
PRELOAD = "service.nmulticloud.deploy.preload_proxbox_api_images"
CONTRACT = runpy.run_path(
    str(ROOT / "netbox_rpc/proxbox_offline_images_contract.py")
)


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type(
        "PluginConfig", (), {"ready": lambda self: None}
    )
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    django_db.transaction = SimpleNamespace(atomic=nullcontext)
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


def test_params_schema_accepts_only_one_lowercase_manifest_digest() -> None:
    digest = "a" * 64
    validate({"manifest_sha256": digest}, CONTRACT["PARAMS_SCHEMA"])
    for invalid in (
        {},
        {"manifest_sha256": "A" * 64},
        {"manifest_sha256": "a" * 63},
        {"manifest_sha256": digest, "image": "attacker/image:latest"},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, CONTRACT["PARAMS_SCHEMA"])


def test_result_schemas_are_closed_and_enforce_image_identity() -> None:
    digest = "b" * 64
    result = {
        "ok": True,
        "procedure": DIAGNOSE,
        "target": "nmc-prod-207",
        "manifest_sha256": digest,
        "stage": "complete",
        "images": [
            {
                "image": f"registry.example/image@sha256:{'c' * 64}",
                "present": False,
                "image_id": None,
            }
        ],
    }
    validate(result, CONTRACT["DIAGNOSE_RESULT_SCHEMA"])

    inconsistent = deepcopy(result)
    inconsistent["images"][0]["present"] = True
    with pytest.raises(ValidationError):
        validate(inconsistent, CONTRACT["DIAGNOSE_RESULT_SCHEMA"])

    hostile = deepcopy(result)
    hostile["images"][0]["image"] = "$(attacker)"
    with pytest.raises(ValidationError):
        validate(hostile, CONTRACT["DIAGNOSE_RESULT_SCHEMA"])

    for mutable_image in (
        "registry.example/image:latest",
        "registry.example/image",
    ):
        mutable = deepcopy(result)
        mutable["images"][0]["image"] = mutable_image
        with pytest.raises(ValidationError):
            validate(mutable, CONTRACT["DIAGNOSE_RESULT_SCHEMA"])

    tagged = deepcopy(result)
    tagged["images"][0]["image"] = (
        f"registry.example:5000/team/image:v1.2@sha256:{'d' * 64}"
    )
    validate(tagged, CONTRACT["DIAGNOSE_RESULT_SCHEMA"])

    preload_failure = {
        "ok": False,
        "procedure": PRELOAD,
        "target": "nmc-prod-207",
        "manifest_sha256": digest,
        "stage": "indeterminate",
        "images": None,
    }
    validate(preload_failure, CONTRACT["PRELOAD_RESULT_SCHEMA"])


def test_contract_pins_commands_budgets_and_outcome_policy() -> None:
    assert CONTRACT["COMMAND_CONTRACTS"][DIAGNOSE][0]["argv"] == [
        "diagnose-proxbox-api-images",
        "{manifest_sha256}",
    ]
    assert CONTRACT["COMMAND_CONTRACTS"][PRELOAD][0]["argv"] == [
        "preload-proxbox-api-images",
        "{manifest_sha256}",
    ]
    assert CONTRACT["DIAGNOSE_TIMEOUT_SECONDS"] == 120
    assert CONTRACT["PRELOAD_TIMEOUT_SECONDS"] == 2100
    assert CONTRACT["PRELOAD_ROUTE_BUDGET_SECONDS"] == 1950
    assert CONTRACT["PRELOAD_SSH_BUDGET_SECONDS"] == 1920
    assert CONTRACT["SEMANTIC_CONTRACTS"][PRELOAD]["outcome_policy"] == (
        "post-process-non-clean-is-indeterminate-no-auto-retry"
    )


def test_migration_seeds_exact_rows_and_disables_without_delete(migration) -> None:
    procedures = _ProcedureManager()
    commands = _CommandManager()
    apps = _apps(procedures, commands)

    migration.seed_proxbox_offline_image_recovery(apps, None)

    assert procedures.rows[DIAGNOSE]["effect"] == "read"
    assert procedures.rows[DIAGNOSE]["approval_required"] is False
    assert procedures.rows[DIAGNOSE]["timeout_seconds"] == 120
    assert procedures.rows[PRELOAD]["effect"] == "write"
    assert procedures.rows[PRELOAD]["approval_required"] is True
    assert procedures.rows[PRELOAD]["timeout_seconds"] == 2100
    assert procedures.rows[PRELOAD]["params_schema"] == CONTRACT["PARAMS_SCHEMA"]
    assert procedures.rows[DIAGNOSE]["result_schema"] == CONTRACT[
        "DIAGNOSE_RESULT_SCHEMA"
    ]
    assert procedures.rows[PRELOAD]["result_schema"] == CONTRACT[
        "PRELOAD_RESULT_SCHEMA"
    ]
    assert commands.rows[(DIAGNOSE, 1)]["argv"] == [
        "diagnose-proxbox-api-images",
        "{manifest_sha256}",
    ]
    assert commands.rows[(PRELOAD, 1)]["argv"] == [
        "preload-proxbox-api-images",
        "{manifest_sha256}",
    ]

    migration.disable_proxbox_offline_image_recovery(apps, None)
    assert procedures.rows[DIAGNOSE]["enabled"] is False
    assert procedures.rows[PRELOAD]["enabled"] is False
    assert procedures.deleted == []


def test_migration_refuses_preexisting_rows_and_reapplication(migration) -> None:
    procedures = _ProcedureManager()
    commands = _CommandManager()
    apps = _apps(procedures, commands)
    procedures.rows[DIAGNOSE] = {"enabled": True}

    with pytest.raises(RuntimeError, match="refuses to adopt"):
        migration.seed_proxbox_offline_image_recovery(apps, None)
    assert PRELOAD not in procedures.rows
    assert commands.rows == {}

    procedures.rows.clear()
    migration.seed_proxbox_offline_image_recovery(apps, None)
    with pytest.raises(RuntimeError, match="refuses to adopt"):
        migration.seed_proxbox_offline_image_recovery(apps, None)
    assert set(procedures.rows) == {DIAGNOSE, PRELOAD}
    assert set(commands.rows) == {(DIAGNOSE, 1), (PRELOAD, 1)}


def test_migration_seed_is_atomic_when_command_creation_fails(
    migration, monkeypatch: pytest.MonkeyPatch
) -> None:
    procedures = _ProcedureManager()
    commands = _CommandManager(fail_for=PRELOAD)
    apps = _apps(procedures, commands)

    class _RollbackAtomic:
        def __enter__(self):
            self.procedure_snapshot = deepcopy(procedures.rows)
            self.command_snapshot = deepcopy(commands.rows)

        def __exit__(self, exc_type, exc_value, traceback):
            if exc_type is not None:
                procedures.rows = self.procedure_snapshot
                commands.rows = self.command_snapshot
            return False

    monkeypatch.setattr(migration.transaction, "atomic", _RollbackAtomic)
    with pytest.raises(RuntimeError, match="simulated command creation failure"):
        migration.seed_proxbox_offline_image_recovery(apps, None)

    assert procedures.rows == {}
    assert commands.rows == {}


def test_catalog_wiring_is_explicit_and_preload_is_protected() -> None:
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))
    assert constants["NMULTICLOUD_DEPLOY_PROXBOX_IMAGES_PROCEDURE_NAMES"] == {
        DIAGNOSE,
        PRELOAD,
    }
    assert {DIAGNOSE, PRELOAD} <= constants[
        "EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES"
    ]
    assert PRELOAD in constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    assert DIAGNOSE not in constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    capabilities_source = (ROOT / "netbox_rpc/capabilities.py").read_text()
    for procedure_name in (DIAGNOSE, PRELOAD):
        assert procedure_name in capabilities_source


def test_capability_hashes_are_pinned_for_backend_parity() -> None:
    assert CONTRACT["CAPABILITY_CONTRACT_SHA256"] == {
        DIAGNOSE: "71e42d76abf0bc72e3782cef7c09c20007f363cf695f1a1fe31d90ce80baeaf7",
        PRELOAD: "ef7feef5ff142c8a2632076e02024a7c96b00387035eff578f974d4523729935",
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
    def __init__(self, *, fail_for: str | None = None) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}
        self.fail_for = fail_for

    def create(self, *, procedure, sequence: int, **fields: object):
        if procedure.name == self.fail_for:
            raise RuntimeError("simulated command creation failure")
        self.rows[(procedure.name, sequence)] = dict(fields)
        return SimpleNamespace()
