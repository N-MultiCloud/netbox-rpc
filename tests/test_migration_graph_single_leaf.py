"""Reject a migration graph Django cannot plan, before it can be released.

`netbox.service` runs `manage.py migrate` as `ExecStartPre`, so a graph with two
leaves does not degrade the service — it stops it from starting at all. That is
not hypothetical: it took production down for roughly fifteen hours across 1256
failed starts, and #218 was the same defect a release earlier.

Two branches each numbering a migration from the same parent is the ordinary
outcome of parallel work. The graph only conflicts once both land, which is
precisely when no single pull request looks wrong — so the check has to run on
the merged tree, which is what this test does.

Deliberately Django-free: it reads `dependencies` out of the files with `ast`, so
it runs in the ordinary suite on every pull request rather than needing a
settings module or a database.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "netbox_rpc" / "migrations"
APP_LABEL = "netbox_rpc"

#: `0087_extend_gitea_org_ci_runner_contract` -> the leading number is the only
#: part Django orders by, and the only part a rename has to change.
MIGRATION_NAME = re.compile(r"^\d{4}_\w+$")


def _migration_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.glob("*.py") if MIGRATION_NAME.match(p.stem))


def _intra_app_dependencies(path: Path) -> set[str]:
    """Return the names this migration depends on **within this app**.

    A dependency on another app, such as `("extras", "0134_owner")`, orders this
    migration against that app's graph and says nothing about this one's leaves.
    Counting it would make every migration that touches `extras` look like a
    child of nothing.

    Entries are evaluated one at a time, never as a whole list. A real migration
    mixes literals with calls — `migrations.swappable_dependency(AUTH_USER_MODEL)`
    sits beside them — and evaluating the list would fail on the call and silently
    discard the literal dependencies next to it, turning a perfectly ordinary
    parent into a phantom leaf.
    """
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assignment = _dependencies_assignment(module)
    if assignment is None or not isinstance(assignment, (ast.List, ast.Tuple)):
        return set()
    return {name for name in map(_intra_app_name, assignment.elts) if name is not None}


def _dependencies_assignment(module: ast.Module) -> ast.expr | None:
    """Return the right-hand side of the module's `dependencies = ...` assignment."""
    for node in ast.walk(module):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "dependencies"
            for target in node.targets
        ):
            return node.value
    return None


def _intra_app_name(element: ast.expr) -> str | None:
    """Return the migration name if this entry is an intra-app dependency."""
    try:
        pair = ast.literal_eval(element)
    except ValueError:
        return None  # a call such as swappable_dependency(); never intra-app
    if isinstance(pair, tuple) and len(pair) == 2 and pair[0] == APP_LABEL:
        return pair[1]
    return None


def _leaves(directory: Path) -> set[str]:
    """Names no other migration in the same app depends on."""
    files = _migration_files(directory)
    names = {path.stem for path in files}
    depended_on: set[str] = set()
    for path in files:
        depended_on |= _intra_app_dependencies(path)
    return names - depended_on


def test_the_migration_graph_has_exactly_one_leaf() -> None:
    leaves = _leaves(MIGRATIONS_DIR)
    assert leaves, "no migrations found; the guard would pass vacuously"
    assert len(leaves) == 1, (
        "Django refuses to plan a migration graph with more than one leaf, and "
        "`netbox.service` runs `migrate` before it starts, so this stops NetBox "
        f"from booting. Leaves: {sorted(leaves)}. Renumber the newer one onto the "
        "other and depend it on that migration."
    )


def test_the_guard_actually_fails_on_a_two_leaf_graph(tmp_path: Path) -> None:
    """Prove the check can fail, so a vacuous pass is not mistaken for a green graph.

    This reproduces the exact shape that took production down: a second
    migration numbered from the same parent as an existing one.
    """
    (tmp_path / "0001_initial.py").write_text("dependencies = []\n", encoding="utf-8")
    (tmp_path / "0002_first_branch.py").write_text(
        'dependencies = [("netbox_rpc", "0001_initial")]\n', encoding="utf-8"
    )
    (tmp_path / "0002_second_branch.py").write_text(
        'dependencies = [("netbox_rpc", "0001_initial")]\n', encoding="utf-8"
    )

    assert _leaves(tmp_path) == {"0002_first_branch", "0002_second_branch"}


def test_a_cross_app_dependency_does_not_create_a_leaf(tmp_path: Path) -> None:
    """`("extras", "0134_owner")` orders against another app, not against this one."""
    (tmp_path / "0001_initial.py").write_text("dependencies = []\n", encoding="utf-8")
    (tmp_path / "0002_next.py").write_text(
        'dependencies = [("extras", "0134_owner"), ("netbox_rpc", "0001_initial")]\n',
        encoding="utf-8",
    )

    assert _leaves(tmp_path) == {"0002_next"}


@pytest.mark.parametrize("name", ["__init__", "conftest", "0001_initial_backup"])
def test_only_numbered_migration_modules_are_considered(name: str) -> None:
    """A helper or a backup left beside the migrations must not become a phantom leaf."""
    assert bool(MIGRATION_NAME.match(name)) == name.startswith("0001_initial_backup")


def test_a_swappable_dependency_does_not_hide_its_literal_siblings(
    tmp_path: Path,
) -> None:
    """The real shape that made the first version of this guard report a phantom leaf.

    `0069_rpcexecution_approved_by` mixes `swappable_dependency(AUTH_USER_MODEL)`
    with a literal parent. Evaluating the list as a whole raises on the call and
    loses the parent, so `0068` looked like a leaf when nothing was wrong.
    """
    (tmp_path / "0068_parent.py").write_text("dependencies = []\n", encoding="utf-8")
    (tmp_path / "0069_child.py").write_text(
        "dependencies = [\n"
        "    migrations.swappable_dependency(settings.AUTH_USER_MODEL),\n"
        '    ("netbox_rpc", "0068_parent"),\n'
        "]\n",
        encoding="utf-8",
    )

    assert _leaves(tmp_path) == {"0069_child"}
