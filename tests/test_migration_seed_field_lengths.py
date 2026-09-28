"""Seed migrations must fit the model's CharField limits.

The pure-domain CI never runs migrations against PostgreSQL, so a seeded
``description`` longer than the 255-character column only fails at deploy
time (migration 0098 did exactly that). This scans every migration's literal
``"description"`` values and fails early instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

_MIGRATIONS = Path(__file__).resolve().parents[1] / "netbox_rpc" / "migrations"
_DESCRIPTION_MAX = 255


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return None
    return None


def _descriptions(path: Path) -> list[tuple[int, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if _literal_string(key) != "description":
                continue
            text = _literal_string(value)
            if text is not None:
                found.append((value.lineno, len(text)))
    return found


def test_seeded_descriptions_fit_the_column() -> None:
    too_long = [
        f"{path.name}:{line} ({length} characters)"
        for path in sorted(_MIGRATIONS.glob("0*.py"))
        for line, length in _descriptions(path)
        if length > _DESCRIPTION_MAX
    ]
    assert not too_long, too_long
