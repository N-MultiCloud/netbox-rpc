from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, validate

MIGRATION_MODULE = (
    "netbox_rpc.migrations.0066_seed_huawei_ne8000_bgp_procedures"
)
PROCEDURE_NAME = "Show BGP Peer (Huawei NE8000-F1A)"
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
    assert procedure["params_schema"]["additionalProperties"] is False
    assert procedure["params_schema"]["properties"]["vrf"] == {
        "type": "string",
        "default": "",
    }
    assert procedure["params_schema"]["properties"][
        "rpc_ssh_credential_pk"
    ] == migration._CREDENTIAL_REF
    assert procedure["result_schema"] == migration._RESULT_SCHEMA

    Draft202012Validator.check_schema(procedure["params_schema"])
    Draft202012Validator.check_schema(procedure["result_schema"])
    validate({}, procedure["params_schema"])
    validate(
        {"vrf": "customer-a", "rpc_ssh_credential_pk": 7},
        procedure["params_schema"],
    )


def test_huawei_ne8000_bgp_migration_seeds_and_unseeds(migration) -> None:
    manager = _FakeProcedureManager()
    _FakeRPCProcedure.objects = manager
    apps = SimpleNamespace(
        get_model=lambda app_label, model_name: _FakeRPCProcedure
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure")
        else None
    )

    migration.seed_huawei_ne8000_bgp_procedures(apps, None)

    assert manager.rows == {
        PROCEDURE_NAME: {
            key: value
            for key, value in migration.HUAWEI_NE8000_BGP_PROCEDURES[0].items()
            if key != "name"
        }
    }

    migration.unseed_huawei_ne8000_bgp_procedures(apps, None)

    assert manager.rows == {}


def test_huawei_ne8000_bgp_migration_depends_on_current_leaf(migration) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0065_seed_ubuntu_upgrade_26_intent")
    ]


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
