from __future__ import annotations

import importlib
import runpy
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

MIGRATION_MODULE = "netbox_rpc.migrations.0068_widen_ubuntu_restart_service_targets"
MERGE_MIGRATION_MODULE = "netbox_rpc.migrations.0101_widen_ubuntu_restart_service_targets"
PROCEDURE_NAME = "os.linux.ubuntu.24.restart_service"
ORIGINAL_TARGET_MODELS = ["dcim.device"]
WIDENED_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type(
        "PluginConfig",
        (),
        {"ready": lambda self: None},
    )
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


def test_forward_widens_target_models_and_is_idempotent(migration) -> None:
    procedure = _FakeProcedure(ORIGINAL_TARGET_MODELS)
    apps = _fake_apps(procedure)

    migration.widen_ubuntu_restart_service_targets(apps, None)
    migration.widen_ubuntu_restart_service_targets(apps, None)

    assert procedure.target_models == WIDENED_TARGET_MODELS
    assert procedure.saved_update_fields == [["target_models"]]


def test_reverse_restores_target_models_and_is_idempotent(migration) -> None:
    procedure = _FakeProcedure(WIDENED_TARGET_MODELS)
    apps = _fake_apps(procedure)

    migration.revert_ubuntu_restart_service_targets(apps, None)
    migration.revert_ubuntu_restart_service_targets(apps, None)

    assert procedure.target_models == ORIGINAL_TARGET_MODELS
    assert procedure.saved_update_fields == [["target_models"]]


def test_forward_and_reverse_preserve_unexpected_or_missing_rows(migration) -> None:
    custom_targets = ["dcim.device", "custom.host"]
    procedure = _FakeProcedure(custom_targets)

    migration.widen_ubuntu_restart_service_targets(_fake_apps(procedure), None)
    migration.revert_ubuntu_restart_service_targets(_fake_apps(procedure), None)
    migration.widen_ubuntu_restart_service_targets(_fake_apps(None), None)
    migration.revert_ubuntu_restart_service_targets(_fake_apps(None), None)

    assert procedure.target_models == custom_targets
    assert procedure.saved_update_fields == []


def test_migration_depends_on_current_leaf(migration) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0067_merge_huawei_bgp_and_upgrade_result_limits")
    ]


def test_merge_migration_preserves_applied_0068_and_converges_graph(migration) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0067_merge_huawei_bgp_and_upgrade_result_limits")
    ]
    sys.modules.pop(MERGE_MIGRATION_MODULE, None)
    merge_migration = importlib.import_module(MERGE_MIGRATION_MODULE)

    assert merge_migration.Migration.dependencies == [
        ("netbox_rpc", "0100_extend_openbao_import_timeout_budget"),
        ("netbox_rpc", "0068_widen_ubuntu_restart_service_targets"),
    ]
    assert merge_migration.Migration.operations == []
    sys.modules.pop(MERGE_MIGRATION_MODULE, None)


def test_constants_match_widened_migration_state() -> None:
    root = Path(__file__).resolve().parents[1]
    constants = runpy.run_path(str(root / "netbox_rpc/constants.py"))
    procedure = next(
        row
        for row in constants["INITIAL_PROCEDURES"]
        if row["name"] == constants["UBUNTU_24_RESTART_SERVICE"]
    )

    assert procedure["target_models"] == WIDENED_TARGET_MODELS


class _FakeProcedure:
    class DoesNotExist(Exception):
        pass

    def __init__(self, target_models: list[str]) -> None:
        self.target_models = list(target_models)
        self.saved_update_fields: list[list[str]] = []

    def save(self, *, update_fields: list[str]) -> None:
        self.saved_update_fields.append(update_fields)


class _FakeManager:
    def __init__(self, procedure: _FakeProcedure | None) -> None:
        self.procedure = procedure

    def get(self, *, name: str) -> _FakeProcedure:
        assert name == PROCEDURE_NAME
        if self.procedure is None:
            raise _FakeProcedure.DoesNotExist
        return self.procedure


def _fake_apps(procedure: _FakeProcedure | None) -> SimpleNamespace:
    model = type(
        "RPCProcedure",
        (),
        {"DoesNotExist": _FakeProcedure.DoesNotExist, "objects": _FakeManager(procedure)},
    )
    return SimpleNamespace(
        get_model=lambda app_label, model_name: model
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure")
        else None
    )
