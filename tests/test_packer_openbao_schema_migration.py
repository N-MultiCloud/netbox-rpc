"""Pure tests for migration 0095's structural params_schema transform.

The migration must never abort startup on an operator-customised schema: it
adds the netbox-openbao reference, preserves every unrelated key, skips unsafe
shapes, and its reverse removes only what it added.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import types
from pathlib import Path

_PATH = (
    Path(__file__).resolve().parent.parent
    / "netbox_rpc"
    / "migrations"
    / "0095_packer_openbao_assignment_id_param.py"
)


def _load():
    db = types.ModuleType("django.db")
    db.migrations = types.SimpleNamespace(
        Migration=object, RunPython=lambda *a, **k: (a, k)
    )
    saved = {name: sys.modules.get(name) for name in ("django", "django.db")}
    sys.modules.setdefault("django", types.ModuleType("django"))
    sys.modules["django.db"] = db
    try:
        spec = importlib.util.spec_from_file_location("_mig0095", _PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


mig = _load()

CUSTOMISED = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk", "operator_note"],
    "additionalProperties": False,
    "properties": {
        "rpc_ssh_credential_pk": {"type": "integer", "minimum": 1},
        "ssh_host": {"type": "string"},
        "operator_note": {"type": "string", "maxLength": 40},
    },
}


class _Procedure:
    def __init__(self, name, schema):
        self.name = name
        self.params_schema = schema
        self.saves = 0

    def save(self, update_fields):
        assert update_fields == ["params_schema"]
        self.saves += 1


class _Apps:
    def __init__(self, procedures):
        self.procedures = procedures

    def get_model(self, *_args):
        procedures = self.procedures

        class _Model:
            class objects:  # noqa: N801 - mimic a Django manager
                @staticmethod
                def filter(name__in):
                    return [p for p in procedures if p.name in name__in]

        return _Model


def test_forward_preserves_custom_keys_and_adds_reference():
    updated = mig._forward_schema(copy.deepcopy(CUSTOMISED))
    assert (
        updated["properties"]["operator_note"]
        == CUSTOMISED["properties"]["operator_note"]
    )
    assert updated["properties"]["openbao_assignment_id"] == mig._OPENBAO_ASSIGNMENT_REF
    assert updated["required"] == ["operator_note"]
    assert updated["oneOf"] == mig._ONE_OF_CREDENTIAL
    assert updated["additionalProperties"] is False


def test_reverse_restores_the_customised_schema():
    forward = mig._forward_schema(copy.deepcopy(CUSTOMISED))
    assert mig._reverse_schema(forward) == CUSTOMISED


def test_apply_is_idempotent_and_never_raises_on_unsafe_shapes():
    good = _Procedure("packer.vm.collect_info", copy.deepcopy(CUSTOMISED))
    conflict_schema = copy.deepcopy(CUSTOMISED)
    conflict_schema["properties"]["openbao_assignment_id"] = {"type": "string"}
    conflict = _Procedure("packer.vm.verify_services", conflict_schema)
    not_object = _Procedure("packer.vm.check_agent_running", ["unexpected"])
    apps = _Apps([good, conflict, not_object])

    mig._apply(apps, None)
    mig._apply(apps, None)

    assert good.saves == 1 and mig._is_applied(good.params_schema)
    assert conflict.saves == 0 and conflict.params_schema == conflict_schema
    assert not_object.saves == 0 and not_object.params_schema == ["unexpected"]


def test_reverse_touches_only_schemas_this_migration_changed():
    applied = _Procedure(
        "packer.vm.collect_info", mig._forward_schema(copy.deepcopy(CUSTOMISED))
    )
    untouched = _Procedure("packer.vm.verify_services", copy.deepcopy(CUSTOMISED))
    mig._reverse(_Apps([applied, untouched]), None)
    assert applied.params_schema == CUSTOMISED
    assert untouched.saves == 0
