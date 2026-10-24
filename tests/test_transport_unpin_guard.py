"""Un-pinning a transport-pinned procedure needs the approve permission (#246)."""

from __future__ import annotations

import ast
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _transport_symbol(name: str):
    # transport.py is pure, so it loads without NetBox or Django.
    return runpy.run_path(str(ROOT / "netbox_rpc" / "transport.py"))[name]


@pytest.mark.parametrize(
    ("previously", "requested", "may_approve", "refused"),
    [
        pytest.param(True, False, False, True, id="unpin-without-approve-refused"),
        pytest.param(True, False, True, False, id="unpin-with-approve-allowed"),
        pytest.param(True, True, False, False, id="keep-the-pin"),
        pytest.param(True, None, False, False, id="omitted-field-allowed"),
        pytest.param(False, False, False, False, id="already-unpinned"),
        pytest.param(None, False, False, False, id="create-unpinned"),
        pytest.param(True, 0, False, True, id="falsy-int-fails-closed"),
        pytest.param(True, "", False, True, id="empty-string-fails-closed"),
        pytest.param(True, 0, True, False, id="falsy-int-with-approve-allowed"),
        pytest.param(True, 1, False, False, id="truthy-non-bool-keeps-pin"),
    ],
)
def test_unpin_is_refused_only_when_a_pin_is_dropped_without_approval(
    previously, requested, may_approve, refused
) -> None:
    unpin_is_refused = _transport_symbol("unpin_is_refused")

    assert (
        unpin_is_refused(
            previously_pinned=previously,
            requested_pinned=requested,
            may_approve=may_approve,
        )
        is refused
    )


class _ScopedApprover:
    """Stands in for a NetBox user: an unscoped check passes, a scoped one must match."""

    def __init__(self, allowed: str) -> None:
        self.allowed = allowed

    def has_perm(self, perm: str, obj: object = None) -> bool:
        return obj is None or getattr(obj, "name", None) == self.allowed


@pytest.mark.parametrize(
    ("user", "procedure", "expected"),
    [
        pytest.param(
            _ScopedApprover("a"), SimpleNamespace(name="a"), True, id="scoped-to-this"
        ),
        pytest.param(
            _ScopedApprover("a"),
            SimpleNamespace(name="b"),
            False,
            id="scoped-to-another-procedure",
        ),
        pytest.param(None, SimpleNamespace(name="a"), False, id="no-user"),
        pytest.param(_ScopedApprover("a"), None, False, id="no-procedure"),
    ],
)
def test_approval_is_checked_against_the_stored_procedure(
    user, procedure, expected
) -> None:
    may_approve_procedure = _transport_symbol("may_approve_procedure")

    assert may_approve_procedure(user, procedure) is expected


def test_form_shares_the_unpin_rule() -> None:
    forms = _read("netbox_rpc/forms.py")

    assert "from .transport import (" in forms
    assert "protected_field_refusals," in forms
    assert "protected_field_snapshot," in forms
    assert "cleaned_data = self.cleaned_data" in forms
    assert "protected_field_snapshot(self.instance)," in forms
    assert "may_approve_procedure(user, self.instance)," in forms
    assert "raise forms.ValidationError(refused)" in forms
    assert "def save(self, commit: bool = True):" in forms
    assert "self._refuse_unpin_under_lock()" in forms
    assert "def _refuse_unpin_under_lock(self) -> frozenset[object]:" in forms
    assert "select_for_update()" in forms
    assert "may_approve = may_approve_procedure(user, stored)" in forms
    assert "user = reload_requesting_user(_request_user(self.instance))" in forms
    assert "    reload_requesting_user,\n)" in forms


def test_shared_table_applies_the_unpin_rule_and_message() -> None:
    rule, message = _transport_symbol("PROTECTED_PROCEDURE_FIELD_RULES")["transport_pinned"]
    assert message == _transport_symbol("UNPIN_DENIED_MESSAGE")
    assert rule(True, False, False) is True
    assert rule(True, False, True) is False


def test_serializer_shares_the_unpin_rule() -> None:
    serializers = _read("netbox_rpc/api/serializers.py")

    assert "from ..transport import (" in serializers
    assert "protected_field_refusals," in serializers
    block = serializers.split(
        "class RPCProcedureSerializer(NetBoxModelSerializer):", 1
    )[1].split("\nclass ", 1)[0]
    assert "def validate(self, attrs):" in block
    assert "may_approve = may_approve_procedure(" in block
    assert "_requested_protected_values(stored_flags, attrs), may_approve" in block
    assert "def update(self, instance, validated_data):" in block
    assert "select_for_update()" in block
    assert "setattr(instance, field, getattr(stored, field))" in block
    assert "may_approve = may_approve_procedure(user, stored)" in block
    assert "user = reload_requesting_user(request_user)" in block
    assert "    reload_requesting_user,\n)" in serializers


def test_update_decides_the_pin_rule_after_taking_the_row_lock() -> None:
    # A decision made before the lock would read the pin the request was prepared
    # against, and a concurrent write could commit in between.
    serializers = _read("netbox_rpc/api/serializers.py")
    block = serializers.split(
        "class RPCProcedureSerializer(NetBoxModelSerializer):", 1
    )[1].split("\nclass ", 1)[0]
    update = block.split("    def update(self, instance, validated_data):", 1)[1]
    assert update.index("select_for_update()") < update.index("protected_field_refusals(")
    assert update.index("select_for_update()") < update.index("reload_requesting_user(")


def test_serializer_reads_the_stored_state_before_the_parent_validator_runs() -> None:
    # NetBox's parent validate() writes the submitted values onto self.instance.
    # A stored-state read, or the approve check, made after it would see the
    # requested values, and the approve check would then apply to a new name.
    tree = ast.parse(_read("netbox_rpc/api/serializers.py"))
    serializer = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RPCProcedureSerializer"
    )
    validate = next(
        node
        for node in serializer.body
        if isinstance(node, ast.FunctionDef) and node.name == "validate"
    )
    parent_call = min(
        node.lineno
        for node in ast.walk(validate)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "validate"
        and isinstance(node.func.value, ast.Call)
        and getattr(node.func.value.func, "id", "") == "super"
    )
    for name in ("stored_flags", "may_approve"):
        capture = min(
            node.lineno
            for node in ast.walk(validate)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets
            )
        )
        assert capture < parent_call, name
