"""Forward/backward/forward re-application tests for migration 0098 (#605).

Round-3 review found the forward function refused to re-apply after a
reverse: the reverse only disables rows (documented, non-destructive, the
same pattern every other seed migration in this catalogue uses), but the
forward unconditionally raised on any existing same-name row -- including its
own -- so a `migrate netbox_rpc 0097` (reverse past 0098) followed by
`migrate netbox_rpc` (forward again) raised `RuntimeError` instead of
recognizing and re-enabling its own rows. This is a real operational path:
Django migration testing, `manage.py migrate <app> <earlier>` during
development, and squash/rebase workflows all exercise it.

Django-free, matching the sibling migration/catalogue tests
(`tests/test_openbao_netbox_approle_procedure.py`) -- fake in-memory
managers stand in for the ORM so this runs with no database.
"""

from __future__ import annotations

import contextlib
import importlib
import sys
import types
from types import SimpleNamespace

import pytest

MIGRATION_MODULE = "netbox_rpc.migrations.0098_seed_release_marker_procedures"
CHECK_NAME = "service.nmulticloud.deploy.release_marker_check"
RECONCILE_NAME = "service.nmulticloud.deploy.release_marker_reconcile"


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


class _FakeProcedureRecord:
    """A live attribute view over ``manager.rows[name]``.

    ``getattr``/``setattr`` read and write straight through to the backing
    dict, so a caller's ``existing.enabled = True`` (as the migration does)
    is immediately visible to every other holder of the same name -- the
    same single-row-of-truth behavior a real ORM instance backed by one DB
    row has.
    """

    def __init__(self, manager: _FakeProcedureManager, name: str) -> None:
        object.__setattr__(self, "_manager", manager)
        object.__setattr__(self, "_name", name)

    def __getattr__(self, item: str):
        if item == "name":
            return self._name
        # `.get()`, not `[...]`: an unrelated operator-created row (see
        # test_forward_still_refuses_a_genuinely_unrelated_row) legitimately
        # lacks most of the seed's fields, and a missing immutable field must
        # compare as a mismatch, not raise KeyError out of the migration.
        return self._manager.rows[self._name].get(item)

    def __setattr__(self, key: str, value: object) -> None:
        if key == "name":
            raise AttributeError("name is immutable")
        self._manager.rows[self._name][key] = value

    def save(self, update_fields: list[str] | None = None) -> None:
        # __setattr__ already wrote through; nothing further to persist.
        pass


class _FakeProcedureQuerySet:
    def __init__(self, manager: _FakeProcedureManager, name: str) -> None:
        self.manager = manager
        self.name = name

    def exists(self) -> bool:
        return self.name in self.manager.rows

    def first(self) -> _FakeProcedureRecord | None:
        if self.name not in self.manager.rows:
            return None
        return _FakeProcedureRecord(self.manager, self.name)

    def update(self, **kwargs: object) -> int:
        if self.name not in self.manager.rows:
            return 0
        self.manager.rows[self.name].update(kwargs)
        return 1


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def filter(self, *, name: str | None = None, name__in: list[str] | None = None):
        if name__in is not None:
            return _FakeProcedureBulkQuerySet(self, name__in)
        return _FakeProcedureQuerySet(self, name)

    def create(self, *, name: str, **defaults: object) -> _FakeProcedureRecord:
        row = dict(defaults)
        row.setdefault("enabled", True)
        self.rows[name] = row
        return _FakeProcedureRecord(self, name)


class _FakeProcedureBulkQuerySet:
    """Backs the reverse migration's ``filter(name__in=[...]).update(...)``."""

    def __init__(self, manager: _FakeProcedureManager, names: list[str]) -> None:
        self.manager = manager
        self.names = names

    def update(self, **kwargs: object) -> int:
        updated = 0
        for name in self.names:
            if name in self.manager.rows:
                self.manager.rows[name].update(kwargs)
                updated += 1
        return updated


class _FakeCommandQuerySet:
    def __init__(self, items: list[SimpleNamespace]) -> None:
        self.items = items

    def order_by(self, field: str) -> list[SimpleNamespace]:
        return sorted(self.items, key=lambda item: getattr(item, field))


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def create(
        self, *, procedure: _FakeProcedureRecord, sequence: int, **defaults: object
    ) -> SimpleNamespace:
        self.rows[(procedure.name, sequence)] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence, **defaults)

    def filter(self, *, procedure: _FakeProcedureRecord) -> _FakeCommandQuerySet:
        matching = [
            SimpleNamespace(sequence=sequence, **fields)
            for (name, sequence), fields in self.rows.items()
            if name == procedure.name
        ]
        return _FakeCommandQuerySet(matching)


class _FakeRPCProcedure:
    objects: _FakeProcedureManager


class _FakeRPCProcedureCommand:
    objects: _FakeCommandManager


def _model_lookup(app_label: str, model_name: str):
    return {
        ("netbox_rpc", "RPCProcedure"): _FakeRPCProcedure,
        ("netbox_rpc", "RPCProcedureCommand"): _FakeRPCProcedureCommand,
    }[(app_label, model_name)]


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")

    class RunPython:
        noop = staticmethod(lambda apps, schema_editor: None)

        def __init__(self, code, reverse_code=None) -> None:
            self.code = code
            self.reverse_code = reverse_code

    @contextlib.contextmanager
    def _fake_atomic():
        yield

    django_db.migrations = SimpleNamespace(Migration=object, RunPython=RunPython)
    django_db.transaction = SimpleNamespace(atomic=_fake_atomic)
    django.db = django_db
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)


def _reset_fakes() -> None:
    _FakeRPCProcedure.objects = _FakeProcedureManager()
    _FakeRPCProcedureCommand.objects = _FakeCommandManager()


def test_forward_backward_forward_reenables_its_own_rows(migration) -> None:
    _reset_fakes()
    apps = SimpleNamespace(get_model=_model_lookup)

    migration.seed_release_marker_procedures(apps, None)
    assert _FakeRPCProcedure.objects.rows[CHECK_NAME]["enabled"] is True
    assert _FakeRPCProcedure.objects.rows[RECONCILE_NAME]["enabled"] is True
    # Exactly one command row was created per procedure.
    assert len(_FakeRPCProcedureCommand.objects.rows) == 2

    migration.unseed_release_marker_procedures(apps, None)
    assert _FakeRPCProcedure.objects.rows[CHECK_NAME]["enabled"] is False
    assert _FakeRPCProcedure.objects.rows[RECONCILE_NAME]["enabled"] is False
    # Reverse never deletes -- both procedure and command rows survive.
    assert set(_FakeRPCProcedure.objects.rows) == {CHECK_NAME, RECONCILE_NAME}
    assert len(_FakeRPCProcedureCommand.objects.rows) == 2

    # This must NOT raise: forward again recognizes its own exact rows and
    # re-enables them, rather than refusing an "already exists" collision.
    migration.seed_release_marker_procedures(apps, None)
    assert _FakeRPCProcedure.objects.rows[CHECK_NAME]["enabled"] is True
    assert _FakeRPCProcedure.objects.rows[RECONCILE_NAME]["enabled"] is True
    # No duplicate command rows were created on the re-apply.
    assert len(_FakeRPCProcedureCommand.objects.rows) == 2


def test_forward_still_refuses_a_drifted_immutable_field(migration) -> None:
    _reset_fakes()
    apps = SimpleNamespace(get_model=_model_lookup)
    migration.seed_release_marker_procedures(apps, None)
    migration.unseed_release_marker_procedures(apps, None)

    # Simulate an operator (or a later migration) having changed an
    # immutable field on the disabled row -- e.g. its timeout -- between the
    # reverse and this forward re-run.
    _FakeRPCProcedure.objects.rows[CHECK_NAME]["timeout_seconds"] = 999

    with pytest.raises(RuntimeError, match="differ from this migration's seed"):
        migration.seed_release_marker_procedures(apps, None)


def test_forward_still_refuses_a_drifted_command_row(migration) -> None:
    _reset_fakes()
    apps = SimpleNamespace(get_model=_model_lookup)
    migration.seed_release_marker_procedures(apps, None)
    migration.unseed_release_marker_procedures(apps, None)

    # Simulate the single command row's argv having been hand-edited.
    key = (CHECK_NAME, 1)
    _FakeRPCProcedureCommand.objects.rows[key]["argv"] = ["/bin/echo", "tampered"]

    with pytest.raises(RuntimeError, match="differ from this migration's seed"):
        migration.seed_release_marker_procedures(apps, None)


def test_forward_still_refuses_a_genuinely_unrelated_row(migration) -> None:
    """An operator-created row with the canonical name but a wholly
    different policy (not merely disabled by our own reverse) must still be
    refused, exactly as before this fix -- the recognition path only ever
    matches this migration's own exact seed.
    """
    _reset_fakes()
    apps = SimpleNamespace(get_model=_model_lookup)
    _FakeRPCProcedure.objects.rows[CHECK_NAME] = {
        "enabled": True,
        "handler_id": "not.the.real.handler",
    }

    with pytest.raises(RuntimeError, match="differ from this migration's seed"):
        migration.seed_release_marker_procedures(apps, None)
