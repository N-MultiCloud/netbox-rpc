"""Pure rules for the protected RPC procedure fields (issue 424)."""

from __future__ import annotations

import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _transport():
    # transport.py is pure, so it loads without NetBox or Django.
    return runpy.run_path(str(ROOT / "netbox_rpc" / "transport.py"))


@pytest.mark.parametrize(
    ("previous", "requested", "may_approve", "refused"),
    [
        pytest.param("destructive", "write", False, True, id="destructive-to-write"),
        pytest.param("destructive", "read", False, True, id="destructive-to-read"),
        pytest.param("write", "read", False, True, id="write-to-read"),
        pytest.param("destructive", "write", True, False, id="lower-with-approve"),
        pytest.param("read", "destructive", False, False, id="raise-allowed"),
        pytest.param("write", "destructive", False, False, id="raise-to-destructive"),
        pytest.param("destructive", "destructive", False, False, id="keep"),
        pytest.param("destructive", None, False, False, id="omitted"),
        pytest.param(None, "read", False, False, id="create"),
        pytest.param("destructive", "unknown", False, True, id="unknown-requested-fails-closed"),
        pytest.param("unknown", "destructive", False, True, id="unknown-stored-fails-closed"),
        pytest.param("unknown", "destructive", True, False, id="unknown-stored-with-approve"),
    ],
)
def test_effect_lowering_rule(previous, requested, may_approve, refused) -> None:
    rule = _transport()["effect_lowering_is_refused"]
    assert rule(previous=previous, requested=requested, may_approve=may_approve) is refused


@pytest.mark.parametrize(
    ("previous", "requested", "may_approve", "refused"),
    [
        pytest.param(False, True, False, True, id="enable-without-approve"),
        pytest.param(False, True, True, False, id="enable-with-approve"),
        pytest.param(False, 1, False, True, id="truthy-non-bool-fails-closed"),
        pytest.param(False, "yes", False, True, id="string-fails-closed"),
        pytest.param(False, False, False, False, id="stays-disabled"),
        pytest.param(False, None, False, False, id="omitted"),
        pytest.param(True, False, False, False, id="disable-allowed"),
        pytest.param(True, True, False, False, id="stays-enabled"),
        pytest.param(None, True, False, False, id="create-enabled"),
    ],
)
def test_enabling_rule(previous, requested, may_approve, refused) -> None:
    rule = _transport()["enabling_is_refused"]
    assert (
        rule(previously_enabled=previous, requested=requested, may_approve=may_approve)
        is refused
    )


@pytest.mark.parametrize(
    ("previous", "requested", "may_approve", "refused"),
    [
        pytest.param("asyncssh", "ansible", False, True, id="driver-change"),
        pytest.param("asyncssh", "ansible", True, False, id="driver-change-with-approve"),
        pytest.param("asyncssh", "asyncssh", False, False, id="driver-kept"),
        pytest.param("asyncssh", None, False, False, id="driver-omitted"),
        pytest.param(None, "ansible", False, False, id="create"),
        pytest.param([], ["ansible"], False, True, id="chain-added"),
        pytest.param(["ansible", "asyncssh"], ["asyncssh", "ansible"], False, True, id="chain-reordered"),
        pytest.param(["ansible"], [], False, True, id="chain-cleared"),
        pytest.param(["ansible"], ("ansible",), False, False, id="chain-tuple-equal"),
        pytest.param(["ansible"], ["ansible"], False, False, id="chain-kept"),
        pytest.param([1], ["1"], False, True, id="item-types-matter"),
        pytest.param({"a": True}, {"a": 1}, False, True, id="bool-is-not-int"),
        pytest.param({"a": 1}, {"a": 1.0}, False, True, id="int-is-not-float"),
        pytest.param(0, False, False, True, id="zero-is-not-false"),
        pytest.param({1: "a"}, {True: "a"}, False, True, id="key-types-matter"),
        pytest.param({"a": True}, {"a": 1}, True, False, id="type-change-with-approve"),
        pytest.param(["a", 1], ("a", 1), False, False, id="tuple-and-list-same-items"),
        pytest.param({"a": [1]}, {"a": (1,)}, False, False, id="nested-tuple-equal"),
        pytest.param({"a": 1}, {"a": 2}, False, True, id="schema-change"),
        pytest.param([], [], False, False, id="empty-chain-kept"),
    ],
)
def test_change_rule(previous, requested, may_approve, refused) -> None:
    rule = _transport()["change_is_refused"]
    assert rule(previous=previous, requested=requested, may_approve=may_approve) is refused


def test_every_issue_field_has_a_rule_and_a_message() -> None:
    namespace = _transport()
    rules = namespace["PROTECTED_PROCEDURE_FIELD_RULES"]
    assert set(rules) == {
        "transport_pinned",
        "approval_required",
        "effect",
        "enabled",
        "transport_driver",
        "transport_driver_chain",
        "handler_id",
        "name",
        "version",
        "target_models",
        "params_schema",
        "timeout_seconds",
        "result_schema",
        "output_parser",
        "output_schema",
        "tags",
        "custom_field_data",
    }
    for field, (_rule, message) in rules.items():
        assert "netbox_rpc.approve_rpcprocedure" in message, field


def test_only_documentation_fields_stay_open_to_the_change_permission() -> None:
    # Every RPCProcedure field the REST serializer writes is protected, except these.
    import ast

    serializers = (ROOT / "netbox_rpc" / "api" / "serializers.py").read_text(encoding="utf-8")
    block = serializers.split("class RPCProcedureSerializer(NetBoxModelSerializer):", 1)[1]
    fields_node = next(
        node
        for node in ast.walk(ast.parse("class _M:\n" + block.split("\n    def ", 1)[0]))
        if isinstance(node, ast.Assign)
        and any(getattr(t, "id", "") == "fields" for t in node.targets)
    )
    fields = set(ast.literal_eval(fields_node.value))
    read_only = {"id", "url", "display", "commands", "created", "last_updated"}
    documentation = {"description", "comments"}
    # The serializer's custom_fields field writes the model's custom_field_data.
    protected = set(_transport()["PROTECTED_PROCEDURE_FIELDS"]) - {"custom_field_data"}
    assert fields - read_only - documentation == protected | {"custom_fields"}


def _procedure(**overrides):
    values = {
        "pk": 7,
        "transport_pinned": True,
        "approval_required": True,
        "effect": "destructive",
        "enabled": False,
        "transport_driver": "asyncssh",
        "transport_driver_chain": ("asyncssh",),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_snapshot_is_none_for_a_new_procedure() -> None:
    snapshot = _transport()["protected_field_snapshot"]
    assert snapshot(None) is None
    assert snapshot(_procedure(pk=None)) is None
    stored = snapshot(_procedure())
    assert stored["transport_driver_chain"] == ("asyncssh",)
    assert _transport()["change_is_refused"](
        previous=stored["transport_driver_chain"], requested=["asyncssh"], may_approve=False
    ) is False


def test_refusals_report_every_lowered_field_and_nothing_else() -> None:
    namespace = _transport()
    stored = namespace["protected_field_snapshot"](_procedure())
    refusals = namespace["protected_field_refusals"]
    requested = {
        "transport_pinned": False,
        "approval_required": False,
        "effect": "read",
        "enabled": True,
        "transport_driver": "ansible",
        "transport_driver_chain": ["ansible"],
        "description": "changed",
    }

    refused = refusals(stored, requested, False)
    assert set(refused) == set(requested) - {"description"}
    assert refusals(stored, requested, True) == {}
    assert refusals(stored, {"description": "changed"}, False) == {}
    assert refusals(None, requested, False) == {}
    # Raising the effect, disabling, and keeping every value are allowed.
    assert refusals(
        namespace["protected_field_snapshot"](_procedure(effect="read", enabled=True)),
        {"effect": "destructive", "enabled": False, "transport_driver": "asyncssh"},
        False,
    ) == {}


def test_every_editable_form_field_is_protected_or_documentation() -> None:
    import ast

    tree = ast.parse((ROOT / "netbox_rpc" / "forms.py").read_text(encoding="utf-8"))
    form = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RPCProcedureForm"
    )
    meta = next(n for n in form.body if isinstance(n, ast.ClassDef) and n.name == "Meta")
    fields_node = next(
        n
        for n in meta.body
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "fields" for t in n.targets)
    )
    fields = set(ast.literal_eval(fields_node.value))
    documentation = {"description", "comments"}
    # Custom fields reach the form as cf_* fields, outside Meta.fields.
    protected = set(_transport()["PROTECTED_PROCEDURE_FIELDS"]) - {"custom_field_data"}
    assert fields - documentation == protected


def test_tag_keys_normalize_managers_iterables_and_absence() -> None:
    tag_keys = _transport()["tag_keys"]
    manager = SimpleNamespace(all=lambda: [SimpleNamespace(pk=3), SimpleNamespace(pk=1)])
    assert tag_keys(manager) == (1, 3)
    assert tag_keys([SimpleNamespace(pk=2)]) == (2,)
    assert tag_keys([]) == ()
    assert tag_keys(None) is None
    refusals = _transport()["protected_field_refusals"]
    assert refusals({"tags": (1,)}, {"tags": [SimpleNamespace(pk=1)]}, False) == {}
    assert set(refusals({"tags": ()}, {"tags": [SimpleNamespace(pk=1)]}, False)) == {"tags"}
