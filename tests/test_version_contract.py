import ast
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _plugin_version() -> str:
    module = ast.parse((ROOT / "netbox_rpc/__init__.py").read_text(encoding="utf-8"))
    for node in module.body:
        if not isinstance(node, ast.ClassDef) or node.name != "NetBoxRPCConfig":
            continue
        for statement in node.body:
            if not isinstance(statement, ast.Assign):
                continue
            if any(
                isinstance(target, ast.Name) and target.id == "version"
                for target in statement.targets
            ):
                value = ast.literal_eval(statement.value)
                assert isinstance(value, str)
                return value
    raise AssertionError("NetBoxRPCConfig.version must be a literal string")


def test_package_and_plugin_versions_match() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert _plugin_version() == project["version"]
