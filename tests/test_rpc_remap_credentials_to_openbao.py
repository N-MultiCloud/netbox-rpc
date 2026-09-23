"""Pure-domain tests for rpc_remap_credentials_to_openbao.

The command module is loaded with minimal Django stubs and exercised against
fake models and querysets -- no app registry, no database. The DB-backed
behaviour lives in netbox_rpc/tests/test_openbao_credential_reference.py.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

_MODULE_PATH = (
    Path(__file__).resolve().parent.parent
    / "netbox_rpc"
    / "management"
    / "commands"
    / "rpc_remap_credentials_to_openbao.py"
)


class _CommandError(Exception):
    pass


class _Apps:
    installed = True
    models: dict = {}

    def is_installed(self, _label: str) -> bool:
        return self.installed

    def get_model(self, app_label: str, model_name: str):
        return self.models[(app_label, model_name)]


_APPS = _Apps()


def _load_module():
    stubs = {
        "django": types.ModuleType("django"),
        "django.apps": types.ModuleType("django.apps"),
        "django.core": types.ModuleType("django.core"),
        "django.core.management": types.ModuleType("django.core.management"),
        "django.core.management.base": types.ModuleType("django.core.management.base"),
    }
    stubs["django.apps"].apps = _APPS
    stubs["django.core.management.base"].CommandError = _CommandError
    stubs["django.core.management.base"].BaseCommand = type("BaseCommand", (), {})
    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location("_remap_under_test", _MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        # dataclasses resolve annotations through sys.modules[cls.__module__].
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


remap = _load_module()


class _Query:
    def __init__(self, rows: list[dict]):
        self._rows = rows

    def values_list(self, *fields: str, flat: bool = False):
        if flat:
            return [row[fields[0]] for row in self._rows]
        return [tuple(row[f] for f in fields) for row in self._rows]


class _Manager:
    def __init__(self, rows: list[dict]):
        self.rows = rows

    def filter(self, **kwargs):
        return _Query(
            [r for r in self.rows if all(r.get(k) == v for k, v in kwargs.items())]
        )


class _Credential:
    objects = _Manager([])


class _Assignment:
    objects = _Manager([])
    saved: list = []

    def __init__(self, **fields):
        self.fields = fields
        self.cleaned = False
        self.pk = None

    def full_clean(self):
        self.cleaned = True

    def save(self):
        assert self.cleaned, "full_clean() must run before save()"
        self.pk = 900 + len(_Assignment.saved)
        _Assignment.saved.append(self)


class _Row:
    _meta = types.SimpleNamespace(model_name="rpclinuxserviceallowlist")

    def __init__(self, *, pk=1, legacy=7, assignment=None):
        self.pk = pk
        self.ssh_credential_override = legacy
        self.openbao_assignment_id = assignment
        self.saved_fields = None

    def save(self, update_fields):
        self.saved_fields = update_fields


@pytest.fixture(autouse=True)
def _reset():
    _Credential.objects = _Manager(
        [{"pk": 50, "import_source": "netbox_nms.DeviceCredential:7"}]
    )
    _Assignment.objects = _Manager([])
    _Assignment.saved = []
    _APPS.installed = True
    _APPS.models = {
        ("netbox_openbao", "Credential"): _Credential,
        ("netbox_openbao", "CredentialAssignment"): _Assignment,
    }


def test_require_models_fails_when_openbao_absent():
    _APPS.installed = False
    with pytest.raises(_CommandError):
        remap._require_openbao_models()


def test_require_models_returns_both_models():
    assert remap._require_openbao_models() == (_Credential, _Assignment)


def test_existing_login_assignment_is_reused():
    _Assignment.objects = _Manager(
        [{"pk": 11, "credential_id": 50, "purpose": "login", "enabled": True}]
    )
    row = _Row()
    outcome = remap._remap_row(row, _Credential, _Assignment, dry_run=False)
    assert outcome.updated == 1
    assert row.openbao_assignment_id == 11
    assert row.saved_fields == ["openbao_assignment_id"]
    assert _Assignment.saved == []


def test_ambiguous_login_assignments_need_manual_assignment():
    _Assignment.objects = _Manager(
        [
            {"pk": 11, "credential_id": 50, "purpose": "login", "enabled": True},
            {"pk": 12, "credential_id": 50, "purpose": "login", "enabled": True},
        ]
    )
    row = _Row()
    outcome = remap._remap_row(row, _Credential, _Assignment, dry_run=False)
    assert outcome.needs_manual_assignment and outcome.updated == 0
    assert row.openbao_assignment_id is None


def test_single_other_assignment_is_adopted_and_validated():
    _Assignment.objects = _Manager(
        [
            {
                "pk": 20,
                "credential_id": 50,
                "purpose": "api",
                "enabled": True,
                "assigned_object_type_id": 3,
                "assigned_object_id": 44,
            }
        ]
    )
    row = _Row()
    outcome = remap._remap_row(row, _Credential, _Assignment, dry_run=False)
    assert outcome.updated == 1
    (created,) = _Assignment.saved
    assert created.cleaned
    assert created.fields["assigned_object_id"] == 44
    assert created.fields["purpose"] == "login"
    assert row.openbao_assignment_id == created.pk


def test_dry_run_never_writes():
    _Assignment.objects = _Manager(
        [
            {
                "pk": 20,
                "credential_id": 50,
                "purpose": "api",
                "enabled": True,
                "assigned_object_type_id": 3,
                "assigned_object_id": 44,
            }
        ]
    )
    row = _Row()
    outcome = remap._remap_row(row, _Credential, _Assignment, dry_run=True)
    assert outcome.updated == 1
    assert _Assignment.saved == []
    assert row.openbao_assignment_id is None and row.saved_fields is None


def test_unmatched_and_already_set_and_missing_legacy_rows():
    assert remap._remap_row(
        _Row(legacy=99), _Credential, _Assignment, dry_run=False
    ).unmatched_credential
    assert (
        remap._remap_row(
            _Row(assignment=5), _Credential, _Assignment, dry_run=False
        ).already_set
        == 1
    )
    assert (
        remap._remap_row(
            _Row(legacy=None), _Credential, _Assignment, dry_run=False
        ).no_legacy_value
        == 1
    )


def test_duplicate_imported_credentials_are_unmatched():
    _Credential.objects = _Manager(
        [
            {"pk": 50, "import_source": "netbox_nms.DeviceCredential:7"},
            {"pk": 51, "import_source": "netbox_nms.DeviceCredential:7"},
        ]
    )
    assert remap._remap_row(
        _Row(), _Credential, _Assignment, dry_run=False
    ).unmatched_credential
