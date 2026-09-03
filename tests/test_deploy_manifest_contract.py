import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "netbox_rpc/_nmulticloud_deploy.json"


def _archive_content(
    archive: zipfile.ZipFile, prefix: str, *, exclude_init: bool = False
) -> dict[str, str]:
    content: dict[str, str] = {}
    for name in archive.namelist():
        if not name.startswith(prefix) or name.endswith("/"):
            continue
        if exclude_init and Path(name).name == "__init__.py":
            continue
        content[name] = hashlib.sha256(archive.read(name)).hexdigest()
    return content


def _declared_content(manifest: dict, key: str) -> dict[str, str]:
    rows = manifest[key]
    assert isinstance(rows, list)
    declared = {row["path"]: row["sha256"] for row in rows}
    assert len(declared) == len(rows)
    return declared


def _assert_wheel_content_matches_manifest(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        assert archive.namelist().count(MANIFEST_NAME) == 1
        manifest = json.loads(archive.read(MANIFEST_NAME))
        assert _declared_content(manifest, "migrations") == _archive_content(
            archive,
            "netbox_rpc/migrations/",
            exclude_init=True,
        )
        assert _declared_content(manifest, "static_files") == _archive_content(
            archive,
            "netbox_rpc/static/",
        )


def _build_wheel(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    shutil.copytree(ROOT / "netbox_rpc", source / "netbox_rpc")
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / name, source / name)

    environment = {
        "PATH": os.defpath,
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
    }
    command = (
        "from pathlib import Path; "
        "from setuptools.build_meta import build_wheel; "
        "Path('dist').mkdir(); "
        "build_wheel('dist')"
    )
    subprocess.run(
        [sys.executable, "-I", "-c", command],
        cwd=source,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list((source / "dist").glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _rewrite_manifest_without_last_migration(wheel: Path, output: Path) -> None:
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(output, "w") as target:
        for entry in source.infolist():
            payload = source.read(entry.filename)
            if entry.filename == MANIFEST_NAME:
                manifest = json.loads(payload)
                manifest["migrations"] = manifest["migrations"][:-1]
                payload = (
                    json.dumps(
                        manifest,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                    + b"\n"
                )
            target.writestr(entry, payload)


def test_generated_deploy_contract_is_current() -> None:
    subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / ".gitea/scripts/generate_deploy_manifest.py"),
        ],
        cwd=ROOT,
        env={
            "PATH": os.defpath,
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        },
        check=True,
        capture_output=True,
        text=True,
    )


def test_migration_attestation_candidate_preserves_reviewed_decisions() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / ".gitea/scripts/generate_deploy_manifest.py"),
            "--show-migration-attestation",
        ],
        cwd=ROOT,
        env={
            "PATH": os.defpath,
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        },
        check=True,
        capture_output=True,
        text=True,
    )
    policy = json.loads(
        (ROOT / ".gitea/deploy/migration-compatibility.json").read_text(
            encoding="utf-8"
        )
    )
    assert json.loads(result.stdout) == policy


def test_built_wheel_manifest_covers_exact_migration_and_static_content(
    tmp_path: Path,
) -> None:
    _assert_wheel_content_matches_manifest(_build_wheel(tmp_path))


def test_wheel_parity_rejects_a_stale_embedded_manifest(tmp_path: Path) -> None:
    wheel = _build_wheel(tmp_path)
    stale_wheel = tmp_path / "stale.whl"
    _rewrite_manifest_without_last_migration(wheel, stale_wheel)
    with pytest.raises(AssertionError):
        _assert_wheel_content_matches_manifest(stale_wheel)
