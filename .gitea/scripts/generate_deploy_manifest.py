#!/usr/bin/env python3
"""Generate and validate the package-embedded production deploy contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = ROOT / "pyproject.toml"
MODULE_ROOT = ROOT / "netbox_rpc"
MANIFEST_PATH = MODULE_ROOT / "_nmulticloud_deploy.json"
MIGRATION_POLICY_PATH = ROOT / ".gitea" / "deploy" / "migration-compatibility.json"
BUILD_LOCK_PATH = ROOT / ".gitea" / "deploy" / "python-build.lock.json"
PACKAGE_NAME = "netbox-rpc"
REPOSITORY = "N-MultiCloud/netbox-rpc"
RUNTIME_TARGET = {
    "abi": "cp312",
    "implementation": "cp",
    "platform": "manylinux_2_17_x86_64",
    "python_version": "3.12",
}
BUILD_PYTHON_VERSION = "3.12.13"
BUILD_FRONTEND = {"name": "uv", "version": "0.12.5"}
BUILD_WHEELS = {
    "setuptools==83.0.0": [
        "29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3"
    ]
}


class ManifestError(ValueError):
    """A generated deployment manifest is invalid."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _write_canonical_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_json(value) + b"\n")


def _project() -> dict[str, Any]:
    project = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8")).get("project")
    if not isinstance(project, dict):
        raise ManifestError("pyproject.toml must contain a [project] table")
    if project.get("name") != PACKAGE_NAME:
        raise ManifestError(f"project name must be {PACKAGE_NAME}")
    if not isinstance(project.get("version"), str):
        raise ManifestError("project version must be a literal string")
    return project


def _requires_dist(project: dict[str, Any]) -> list[str]:
    values = project.get("dependencies", [])
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ManifestError("project dependencies must be strings")
    requirements = list(values)
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise ManifestError("project optional-dependencies must be a table")
    for extra, extra_requirements in optional.items():
        if not isinstance(extra, str) or not isinstance(extra_requirements, list):
            raise ManifestError(
                "optional dependency groups must contain requirement lists"
            )
        for requirement in extra_requirements:
            if not isinstance(requirement, str):
                raise ManifestError("optional dependency requirements must be strings")
            requirements.append(f'{requirement}; extra == "{extra}"')
    try:
        return sorted(str(Requirement(requirement)) for requirement in requirements)
    except InvalidRequirement as exc:
        raise ManifestError(f"invalid project requirement: {exc}") from exc


def _regular_files(root: Path, pattern: str) -> list[Path]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise ManifestError(f"{root.relative_to(ROOT)} must be a regular directory")
    files: list[Path] = []
    for path in root.glob(pattern):
        relative_parts = path.relative_to(root).parts
        if path.is_symlink():
            raise ManifestError(
                f"{path.relative_to(ROOT)} must be a regular non-symlink file"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise ManifestError(f"{path.relative_to(ROOT)} must be a regular file")
        if any(
            (root.joinpath(*relative_parts[:index])).is_symlink()
            for index in range(1, len(relative_parts))
        ):
            raise ManifestError(f"{path.relative_to(ROOT)} has a symlink parent")
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def _content_row(path: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _validate_reviewed_migrations(
    migrations: list[dict[str, Any]], policy: object
) -> None:
    if not isinstance(policy, dict) or set(policy) != {
        "migration_count",
        "reviewed_migrations_sha256",
        "schema",
    }:
        raise ManifestError("migration compatibility policy has invalid keys")
    count = policy["migration_count"]
    digest = policy["reviewed_migrations_sha256"]
    if (
        policy["schema"] != 1
        or isinstance(policy["schema"], bool)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ManifestError("migration compatibility policy is invalid")
    if any(row.get("rollback_compatible") is not True for row in migrations):
        raise ManifestError("every reviewed migration must be rollback compatible")
    actual_digest = hashlib.sha256(_canonical_json(migrations)).hexdigest()
    if count != len(migrations) or digest != actual_digest:
        raise ManifestError(
            "migration compatibility policy is stale; review every migration and "
            "renew its count and canonical digest deliberately"
        )


def _validate_migration_policy(migrations: list[dict[str, Any]]) -> None:
    if not MIGRATION_POLICY_PATH.is_file() or MIGRATION_POLICY_PATH.is_symlink():
        raise ManifestError(
            "migration compatibility policy must be a regular non-symlink file"
        )
    try:
        policy = json.loads(MIGRATION_POLICY_PATH.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(
            "migration compatibility policy must be valid JSON"
        ) from exc
    _validate_reviewed_migrations(migrations, policy)


def _migration_rows() -> list[dict[str, Any]]:
    migrations: list[dict[str, Any]] = []
    for path in _regular_files(MODULE_ROOT / "migrations", "*.py"):
        if path.name == "__init__.py":
            continue
        migrations.append({**_content_row(path), "rollback_compatible": True})
    return migrations


def migration_policy_candidate() -> dict[str, Any]:
    migrations = _migration_rows()
    return {
        "migration_count": len(migrations),
        "reviewed_migrations_sha256": hashlib.sha256(
            _canonical_json(migrations)
        ).hexdigest(),
        "schema": 1,
    }


def generate_build_lock() -> dict[str, Any]:
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    build_system = pyproject.get("build-system")
    if (
        not isinstance(build_system, dict)
        or build_system.get("build-backend") != "setuptools.build_meta"
    ):
        raise ManifestError("build backend must be exactly setuptools.build_meta")
    raw_requirements = build_system.get("requires")
    if not isinstance(raw_requirements, list) or not raw_requirements:
        raise ManifestError("build-system.requires must be a nonempty list")
    requirements: list[str] = []
    for raw in raw_requirements:
        if not isinstance(raw, str):
            raise ManifestError("build requirements must be strings")
        try:
            requirement = Requirement(raw)
        except InvalidRequirement as exc:
            raise ManifestError("build requirement is invalid") from exc
        canonical = str(requirement)
        specifiers = list(requirement.specifier)
        if (
            canonical != raw
            or requirement.url is not None
            or requirement.extras
            or requirement.marker is not None
            or len(specifiers) != 1
            or specifiers[0].operator != "=="
            or "*" in specifiers[0].version
        ):
            raise ManifestError("build requirements must be canonical exact pins")
        requirements.append(canonical)
    if requirements != sorted(
        set(requirements), key=lambda item: canonicalize_name(Requirement(item).name)
    ):
        raise ManifestError("build requirements must be unique and canonically ordered")
    if set(requirements) != set(BUILD_WHEELS):
        raise ManifestError(
            "audited build-wheel closure does not match build requirements"
        )
    dependencies = [
        {
            "hashes": sorted(BUILD_WHEELS[requirement]),
            "requirement": requirement,
        }
        for requirement in requirements
    ]
    return {
        "dependencies": dependencies,
        "frontend": BUILD_FRONTEND,
        "python_version": BUILD_PYTHON_VERSION,
        "schema": 1,
    }


def generate_manifest() -> dict[str, Any]:
    project = _project()
    migrations = _migration_rows()
    _validate_migration_policy(migrations)
    static_files = [
        _content_row(path) for path in _regular_files(MODULE_ROOT / "static", "**/*")
    ]
    requires_dist = _requires_dist(project)
    return {
        "database_strategy": "expand-only-rollback-compatible",
        "dependencies": [],
        "dependency_mode": "host-provided-no-install",
        "migrations": migrations,
        "package_name": PACKAGE_NAME,
        "package_version": project["version"],
        "repository": REPOSITORY,
        "requires_dist_sha256": hashlib.sha256(
            _canonical_json(requires_dist)
        ).hexdigest(),
        "runtime_target": RUNTIME_TARGET,
        "schema": 1,
        "static_files": static_files,
        "static_strategy": "append-only-hashed",
    }


def write() -> None:
    _write_canonical_json(BUILD_LOCK_PATH, generate_build_lock())
    _write_canonical_json(MANIFEST_PATH, generate_manifest())


def _check_file(path: Path, expected: dict[str, Any], label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ManifestError(f"{label} must be a regular non-symlink file")
    if path.read_bytes() != _canonical_json(expected) + b"\n":
        raise ManifestError(
            f"{label} is stale or not canonical; run this script with --write"
        )


def check() -> None:
    _check_file(BUILD_LOCK_PATH, generate_build_lock(), "Python build lock")
    _check_file(MANIFEST_PATH, generate_manifest(), "deployment manifest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write", action="store_true", help="rewrite generated artifacts"
    )
    parser.add_argument(
        "--show-migration-attestation",
        action="store_true",
        help="print the candidate policy after manual rollback review; never write it",
    )
    args = parser.parse_args(argv)
    try:
        if args.write and args.show_migration_attestation:
            raise ManifestError("choose only one generator action")
        if args.show_migration_attestation:
            print(_canonical_json(migration_policy_candidate()).decode("ascii"))
        elif args.write:
            write()
        else:
            check()
    except (InvalidRequirement, ManifestError, OSError, ValueError) as exc:
        print(f"deploy manifest error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
