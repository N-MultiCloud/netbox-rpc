"""Lowering approval_required needs the approve permission (#406)."""

from __future__ import annotations

import ast
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _transport_namespace() -> dict:
    # transport.py is pure, so it loads without NetBox or Django.
    return runpy.run_path(str(ROOT / "netbox_rpc" / "transport.py"))


def _serializer_block() -> str:
    serializers = _read("netbox_rpc/api/serializers.py")
    return serializers.split("class RPCProcedureSerializer(NetBoxModelSerializer):", 1)[
        1
    ].split("\nclass ", 1)[0]


def _serializer_method(name: str) -> ast.FunctionDef:
    tree = ast.parse(_read("netbox_rpc/api/serializers.py"))
    serializer = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RPCProcedureSerializer"
    )
    return next(
        node
        for node in serializer.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


@pytest.mark.parametrize(
    ("previously", "requested", "may_approve", "refused"),
    [
        pytest.param(True, False, False, True, id="lower-without-approve-refused"),
        pytest.param(True, False, True, False, id="lower-with-approve-allowed"),
        pytest.param(True, True, False, False, id="keep-required"),
        pytest.param(True, None, False, False, id="omitted-field-allowed"),
        pytest.param(False, False, False, False, id="already-disabled"),
        pytest.param(None, False, False, False, id="create-disabled"),
        pytest.param(True, 0, False, True, id="falsy-int-fails-closed"),
        pytest.param(True, "", False, True, id="empty-string-fails-closed"),
        pytest.param(True, 0, True, False, id="falsy-int-with-approve-allowed"),
        pytest.param(True, 1, False, False, id="truthy-non-bool-keeps-required"),
    ],
)
def test_lowering_is_refused_only_when_a_required_flag_is_dropped_without_approval(
    previously, requested, may_approve, refused
) -> None:
    lowering_is_refused = _transport_namespace()["lowering_is_refused"]

    assert (
        lowering_is_refused(
            previously_set=previously,
            requested=requested,
            may_approve=may_approve,
        )
        is refused
    )


def test_pin_entry_point_delegates_to_the_shared_rule() -> None:
    namespace = _transport_namespace()
    unpin_is_refused = namespace["unpin_is_refused"]
    lowering_is_refused = namespace["lowering_is_refused"]
    values = (True, False, None, 0, 1, "")
    for previously in values:
        for requested in values:
            for may_approve in (True, False):
                assert unpin_is_refused(
                    previously_pinned=previously,
                    requested_pinned=requested,
                    may_approve=may_approve,
                ) is lowering_is_refused(
                    previously_set=previously,
                    requested=requested,
                    may_approve=may_approve,
                )


def test_form_and_transport_carry_the_same_approval_message() -> None:
    # The form keeps its own constant because a static contract test reads forms.py.
    # Compare the parsed literals, so implicit string concatenation is folded.
    forms = ast.parse(_read("netbox_rpc/forms.py"))
    form_message = next(
        ast.literal_eval(node.value)
        for node in forms.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "APPROVAL_DENIED_MESSAGE"
            for target in node.targets
        )
    )

    assert form_message == _transport_namespace()["APPROVAL_DENIED_MESSAGE"]


def test_serializer_imports_and_checks_the_approval_rule() -> None:
    serializers = _read("netbox_rpc/api/serializers.py")
    block = _serializer_block()

    assert (
        "from ..transport import APPROVAL_DENIED_MESSAGE, lowering_is_refused"
        in serializers
    )
    assert 'previously_required = getattr(self.instance, "approval_required", None)' in block
    assert 'requested=attrs.get("approval_required")' in block
    assert 'refused["approval_required"] = APPROVAL_DENIED_MESSAGE' in block
    assert "requested=requested_required" in block
    assert "instance.approval_required = stored.approval_required" in block


def _is_parent_validate_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "validate"
        and isinstance(node.func.value, ast.Call)
        and getattr(node.func.value.func, "id", "") == "super"
    )


def _assigned_line(function: ast.FunctionDef, name: str) -> int:
    return min(
        node.lineno
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        )
    )


def test_serializer_reads_the_stored_approval_before_the_parent_validator_runs() -> None:
    # NetBox's parent validate() writes the submitted values onto self.instance.
    # The stored approval requirement must be captured before that call.
    validate = _serializer_method("validate")
    parent_call = min(
        node.lineno for node in ast.walk(validate) if _is_parent_validate_call(node)
    )
    for name in ("previously_pinned", "previously_required", "may_approve"):
        assert _assigned_line(validate, name) < parent_call, name


def test_update_checks_the_approval_rule_after_taking_the_row_lock() -> None:
    # A decision made before the lock would read the approval requirement the
    # request was prepared against, and a concurrent write could commit in between.
    update = _serializer_block().split("    def update(self, instance, validated_data):", 1)[1]

    lock = update.index("select_for_update()")
    assert lock < update.index("if lowering_is_refused(")


def test_form_lock_path_uses_the_shared_rule() -> None:
    forms = _read("netbox_rpc/forms.py")
    lock_block = forms.split("    def _refuse_unpin_under_lock(self) -> None:", 1)[1].split(
        "    def _refuse_transport_unpin", 1
    )[0]

    assert "from .transport import lowering_is_refused" in forms
    assert "if lowering_is_refused(" in lock_block
    assert "previously_set=stored.approval_required" in lock_block
    assert 'requested=self.cleaned_data.get("approval_required")' in lock_block
    assert "raise AbortRequest(APPROVAL_DENIED_MESSAGE)" in lock_block
