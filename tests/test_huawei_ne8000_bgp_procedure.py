from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate

MIGRATION_MODULE = "netbox_rpc.migrations.0066_seed_huawei_ne8000_bgp_procedures"
MERGE_MIGRATION_MODULE = (
    "netbox_rpc.migrations.0067_merge_huawei_bgp_and_upgrade_result_limits"
)
PROCEDURE_NAME = "network.device.huawei.router.ne8000.f1a.show_bgp_peer"
HANDLER_ID = "network.huawei_ne8000_f1a.show_bgp_peer"


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_huawei_ne8000_bgp_procedure_contract(migration) -> None:
    [procedure] = migration.HUAWEI_NE8000_BGP_PROCEDURES

    assert procedure["name"] == PROCEDURE_NAME
    assert procedure["handler_id"] == HANDLER_ID
    assert procedure["target_models"] == ["dcim.device"]
    assert procedure["effect"] == "read"
    assert procedure["approval_required"] is False
    assert procedure["timeout_seconds"] == 45
    # The normalizer is present, but the live netbox-rpc-backend handler and
    # coordinated rollout approval are still prerequisites. RPCProcedure.enabled
    # defaults to True, so this gate must be explicit rather than merely omitted.
    assert procedure["enabled"] is False
    assert procedure["params_schema"]["additionalProperties"] is False
    assert procedure["params_schema"]["properties"] == {
        "vrf": {
            "type": "string",
            "default": "",
            "maxLength": 31,
            "pattern": "^[A-Za-z0-9_.:-]{0,31}(?![\\s\\S])",
        }
    }
    assert procedure["result_schema"] == migration._RESULT_SCHEMA

    Draft202012Validator.check_schema(procedure["params_schema"])
    Draft202012Validator.check_schema(procedure["result_schema"])
    validate({}, procedure["params_schema"])
    validate(
        {"vrf": "customer-a"},
        procedure["params_schema"],
    )
    for invalid in (
        {"vrf": "customer vrf"},
        {"vrf": " customer-a"},
        {"vrf": "customer-a "},
        {"vrf": "customer-a\n"},
        {"vrf": "customer-a\x00"},
        {"vrf": "x" * 32},
    ):
        with pytest.raises(ValidationError):
            validate(invalid, procedure["params_schema"])


def test_huawei_ne8000_bgp_migration_seeds_and_unseeds(migration) -> None:
    manager = _FakeProcedureManager()
    command_manager = _FakeCommandManager()
    _FakeRPCProcedure.objects = manager
    _FakeRPCProcedureCommand.objects = command_manager
    apps = SimpleNamespace(
        get_model=lambda app_label, model_name: {
            ("netbox_rpc", "RPCProcedure"): _FakeRPCProcedure,
            ("netbox_rpc", "RPCProcedureCommand"): _FakeRPCProcedureCommand,
        }.get((app_label, model_name))
    )

    migration.seed_huawei_ne8000_bgp_procedures(apps, None)

    assert manager.rows == {
        PROCEDURE_NAME: {
            key: value
            for key, value in migration.HUAWEI_NE8000_BGP_PROCEDURES[0].items()
            if key != "name"
        }
    }
    assert command_manager.rows == {
        (PROCEDURE_NAME, 1): migration._REPRESENTATIVE_COMMAND
    }

    migration.unseed_huawei_ne8000_bgp_procedures(apps, None)

    assert manager.rows == {}


def test_huawei_ne8000_bgp_migration_depends_on_current_leaf(migration) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0065_seed_ubuntu_upgrade_26_intent")
    ]


def test_huawei_ne8000_bgp_and_upgrade_migration_leaves_are_merged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MERGE_MIGRATION_MODULE, None)
    merge_migration = importlib.import_module(MERGE_MIGRATION_MODULE)

    assert merge_migration.Migration.dependencies == [
        ("netbox_rpc", "0066_fix_ubuntu_upgrade_26_result_schema_limits"),
        ("netbox_rpc", "0066_seed_huawei_ne8000_bgp_procedures"),
    ]
    assert merge_migration.Migration.operations == []

    sys.modules.pop(MERGE_MIGRATION_MODULE, None)


class _FakeQuerySet:
    def __init__(self, manager: _FakeProcedureManager, names: list[str]) -> None:
        self.manager = manager
        self.names = names

    def delete(self) -> None:
        for name in self.names:
            self.manager.rows.pop(name, None)


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.rows[name] = dict(defaults)
        return SimpleNamespace(name=name, **defaults), True

    def filter(self, *, name__in: list[str]) -> _FakeQuerySet:
        return _FakeQuerySet(self, name__in)


class _FakeRPCProcedure:
    objects: _FakeProcedureManager


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def update_or_create(self, *, procedure, sequence: int, defaults):
        self.rows[(procedure.name, sequence)] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence), True


class _FakeRPCProcedureCommand:
    objects: _FakeCommandManager


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type(
        "PluginConfig",
        (),
        {"ready": lambda self: None},
    )

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db_models = types.ModuleType("django.db.models")
    django_db_deletion = types.ModuleType("django.db.models.deletion")
    django_db_deletion.ProtectedError = type("ProtectedError", (Exception,), {})
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    django_db.models = django_db_models
    django_db_models.deletion = django_db_deletion
    django.db = django_db

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.models", django_db_models)
    monkeypatch.setitem(sys.modules, "django.db.models.deletion", django_db_deletion)
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)
