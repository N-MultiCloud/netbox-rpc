"""Static permission-surface checks for RPCTargetBinding (#326 round 4).

The DB-backed integration tier (``netbox_rpc/tests/``) is the place to prove
end to end that a user holding only ``dcim.change_device`` cannot write an
``RPCTargetBinding`` row and that a user holding
``netbox_rpc.change_rpctargetbinding`` can -- it needs a real NetBox +
PostgreSQL database and is out of scope for this pure-domain suite (see
AGENTS.md's CI/Testing "Two tiers" section). This module instead proves, from
source, that nothing in the plugin widens access beyond NetBox's ordinary
per-model permission machinery, which is what makes that DB-backed proof
possible: ``RPCTargetBindingViewSet`` must subclass ``NetBoxModelViewSet``
(the class that wires in ``NetBoxObjectPermission``, keyed off the model's
own ``add_``/``change_``/``delete_``/``view_rpctargetbinding`` Django
permissions) and must declare no custom ``permission_classes`` that could
relax that -- in particular, ``dcim.change_device`` must never appear
anywhere in this plugin's permission-checking code path for this model.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_VIEWS = ROOT / "netbox_rpc" / "api" / "views.py"


def _class_def(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError(f"Missing class definition: {name}")


def test_target_binding_viewset_uses_the_standard_netbox_model_viewset() -> None:
    tree = ast.parse(API_VIEWS.read_text())
    viewset = _class_def(tree, "RPCTargetBindingViewSet")

    base_names = {
        base.id if isinstance(base, ast.Name) else ast.dump(base) for base in viewset.bases
    }
    assert base_names == {"NetBoxModelViewSet"}, (
        "RPCTargetBindingViewSet must subclass NetBoxModelViewSet only -- that is "
        "what wires in NetBoxObjectPermission, requiring the caller to hold the "
        "model's own add_/change_/delete_/view_rpctargetbinding Django permission "
        "for every write/read. A different or additional base could bypass that."
    )


def test_target_binding_viewset_declares_no_custom_permission_classes() -> None:
    tree = ast.parse(API_VIEWS.read_text())
    viewset = _class_def(tree, "RPCTargetBindingViewSet")

    assigned_names = {
        target.id
        for node in viewset.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    assert "permission_classes" not in assigned_names, (
        "RPCTargetBindingViewSet must not override permission_classes -- doing so "
        "could relax NetBoxModelViewSet's default NetBoxObjectPermission "
        "enforcement and let a broader (or unrelated) permission authorize writes."
    )


def test_target_binding_write_path_never_checks_a_dcim_device_permission() -> None:
    """A caller must never be authorized to write RPCTargetBinding merely by
    holding dcim.change_device -- that was the round-3 tag design's actual
    flaw (a generic device-edit permission, not a binding-specific one)."""
    source = API_VIEWS.read_text()
    tree = ast.parse(source)
    viewset = _class_def(tree, "RPCTargetBindingViewSet")
    # Skip the leading docstring (an Expr(Constant(str)) statement), which
    # legitimately discusses dcim.change_device as the *wrong* permission --
    # only the executable body must never reference it.
    body_nodes = [
        node
        for node in viewset.body
        if not (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        )
    ]
    body_source = "\n".join(
        ast.get_source_segment(source, node) or "" for node in body_nodes
    )

    assert "change_device" not in body_source
    assert "dcim" not in body_source
