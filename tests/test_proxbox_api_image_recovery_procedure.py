"""Contracts and migration behavior for retained proxbox-api image recovery."""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_NAME = "netbox_rpc.migrations.0102_seed_proxbox_api_image_recovery"
INSPECT = "service.proxbox_api.release_images.inspect"
RECOVER = "service.proxbox_api.release_images.recover"


class _Query:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows

    def first(self):
        return self.rows[0] if self.rows else None

    def order_by(self, _field: str):
        return self

    def __iter__(self):
        return iter(self.rows)

    def update(self, **values: object) -> int:
        for row in self.rows:
            for key, value in values.items():
                setattr(row, key, value)
        return len(self.rows)


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: list[object] = []

    def filter(self, **values: object) -> _Query:
        if "name__in" in values:
            names = values["name__in"]
            return _Query([row for row in self.rows if row.name in names])
        return _Query([row for row in self.rows if row.name == values["name"]])

    def create(self, **values: object):
        row = SimpleNamespace(pk=len(self.rows) + 1, **values)
        self.rows.append(row)
        return row


class _CommandManager:
    def __init__(self) -> None:
        self.rows: list[object] = []

    def filter(self, **values: object) -> _Query:
        return _Query(
            [row for row in self.rows if row.procedure is values["procedure"]]
        )

    def create(self, **values: object):
        row = SimpleNamespace(**values)
        self.rows.append(row)
        return row


def _migration(monkeypatch: pytest.MonkeyPatch):
    module = _load_migration()
    monkeypatch.setattr(module.transaction, "atomic", nullcontext)
    procedures = _ProcedureManager()
    commands = _CommandManager()

    class Apps:
        @staticmethod
        def get_model(_app: str, model: str):
            manager = procedures if model == "RPCProcedure" else commands
            return SimpleNamespace(objects=manager)

    return module, Apps(), procedures, commands


def test_seed_is_disabled_idempotent_and_reverse_retains_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration, apps, procedures, commands = _migration(monkeypatch)

    migration.seed(apps, None)
    migration.seed(apps, None)

    assert len(procedures.rows) == 2
    assert len(commands.rows) == 2
    assert all(row.enabled is False for row in procedures.rows)
    procedures.rows[1].enabled = True
    migration.seed(apps, None)
    assert procedures.rows[1].enabled is True
    migration.reverse(apps, None)
    assert len(procedures.rows) == 2
    assert all(row.enabled is False for row in procedures.rows)


def test_seed_refuses_an_existing_contract_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration, apps, procedures, _commands = _migration(monkeypatch)
    migration.seed(apps, None)
    procedures.rows[0].timeout_seconds = 1

    with pytest.raises(
        RuntimeError, match="immutable procedure or command fields differ"
    ):
        migration.seed(apps, None)


def test_approval_and_fixed_gateway_contracts() -> None:
    migration = _load_migration()
    constants = _load_file("proxbox_constants", ROOT / "netbox_rpc/constants.py")
    contract = _load_file(
        "proxbox_recovery_contract",
        ROOT / "netbox_rpc/proxbox_api_release_images_contract.py",
    )

    assert migration._INSPECT_DEFAULTS["approval_required"] is False
    assert migration._RECOVER_DEFAULTS["approval_required"] is True
    assert migration._RECOVER_DEFAULTS["effect"] == "destructive"
    assert RECOVER in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert INSPECT not in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert contract.COMMAND_CONTRACT[0]["argv"] == [
        "recover-proxbox-api-release-images"
    ]
    assert migration._RECOVER_DEFAULTS["params_schema"] == contract.PARAMS_SCHEMA
    assert migration._RECOVER_DEFAULTS["result_schema"] == contract.RESULT_SCHEMA
    assert migration._command("recover-proxbox-api-release-images") == {
        key: value
        for key, value in contract.COMMAND_CONTRACT[0].items()
        if key != "sequence"
    }
    assert migration._command("inspect-proxbox-api-release-images")["argv"] == [
        "inspect-proxbox-api-release-images"
    ]


def test_result_schemas_are_procedure_specific_and_recovery_is_complete() -> None:
    migration = _load_migration()
    inspect_schema = migration._INSPECT_DEFAULTS["result_schema"]
    recover_schema = migration._RECOVER_DEFAULTS["result_schema"]
    image = "docker.io/library/python@sha256:" + "a" * 64
    image_id = "sha256:" + "b" * 64

    jsonschema.validate(
        {
            "ok": True,
            "procedure": INSPECT,
            "target": "nmc-prod-207",
            "mode": "inspect",
            "images": [{"image": image, "present": False, "image_id": None}],
            "ready": False,
        },
        inspect_schema,
    )
    jsonschema.validate(
        {
            "ok": True,
            "procedure": RECOVER,
            "target": "nmc-prod-207",
            "mode": "recover",
            "images": [{"image": image, "present": True, "image_id": image_id}],
            "ready": True,
        },
        recover_schema,
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "ok": True,
                "procedure": RECOVER,
                "target": "nmc-prod-207",
                "mode": "inspect",
                "images": [{"image": image, "present": False, "image_id": None}],
                "ready": False,
            },
            recover_schema,
        )


def test_gateway_identifiers_match_the_reviewed_cross_repository_contract() -> None:
    migration = _load_migration()
    commands = {
        migration._command("inspect-proxbox-api-release-images")["argv"][0],
        migration._command("recover-proxbox-api-release-images")["argv"][0],
    }

    assert commands == {
        "inspect-proxbox-api-release-images",
        "recover-proxbox-api-release-images",
    }


def _load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_migration():
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")

    class Migration:
        pass

    django_db.migrations = SimpleNamespace(
        Migration=Migration, RunPython=lambda *args, **kwargs: None
    )
    django_db.transaction = SimpleNamespace(atomic=nullcontext)
    sys.modules.setdefault("django", django)
    sys.modules.setdefault("django.db", django_db)
    return _load_file(
        "proxbox_image_recovery_migration",
        ROOT / "netbox_rpc/migrations/0102_seed_proxbox_api_image_recovery.py",
    )
