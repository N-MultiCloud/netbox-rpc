"""Executable tests for the held NetBox 4.7 release boundary."""

from __future__ import annotations

import importlib.util
import sys
import types
from collections import Counter
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "netbox_rpc"
GUARD = PACKAGE / "release_guard.py"


class IncompatiblePluginError(Exception):
    """Test double for NetBox's plugin compatibility exception."""


class HeldConfig:
    """Minimal configuration double consumed by the package-local guard."""

    approved_netbox_version = "4.7.0"
    approved_netbox_designation = "beta2"


def load_guard(monkeypatch: pytest.MonkeyPatch, release_base: Path):
    core = types.ModuleType("core")
    core_exceptions = types.ModuleType("core.exceptions")
    core_exceptions.IncompatiblePluginError = IncompatiblePluginError
    core.exceptions = core_exceptions

    utilities = types.ModuleType("utilities")
    utilities_release = types.ModuleType("utilities.release")
    utilities_release.RELEASE_PATH = "release.yaml"
    utilities_release.LOCAL_RELEASE_PATH = "local/release.yaml"
    utilities_release._find_release_base_path = lambda: release_base
    utilities.release = utilities_release

    for name, module in {
        "core": core,
        "core.exceptions": core_exceptions,
        "utilities": utilities,
        "utilities.release": utilities_release,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    module_name = f"{PACKAGE.name}_release_guard_under_test"
    spec = importlib.util.spec_from_file_location(module_name, GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_netbox_release


def write_release(
    release_base: Path,
    *,
    version: str = "4.7.0",
    designation: str | None = "beta2",
    local: object = None,
) -> None:
    release_data = {"version": version, "edition": "Community"}
    if designation is not None:
        release_data["designation"] = designation
    release_base.joinpath("release.yaml").write_text(
        yaml.safe_dump(release_data),
        encoding="utf-8",
    )
    if local is not None:
        local_path = release_base / "local/release.yaml"
        local_path.parent.mkdir()
        local_path.write_text(yaml.safe_dump(local), encoding="utf-8")


def test_exact_beta_with_build_overlay_reads_each_release_file_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_release(tmp_path, local={"build": "Docker-ci"})
    validate_release = load_guard(monkeypatch, tmp_path)
    original_read_text = Path.read_text
    reads: Counter[Path] = Counter()

    def counted_read_text(path: Path, *args, **kwargs) -> str:
        reads[path] += 1
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read_text)
    validate_release(HeldConfig, "4.7.0")

    assert reads[tmp_path / "release.yaml"] == 1
    assert reads[tmp_path / "local/release.yaml"] == 1


@pytest.mark.parametrize("loader_version", ["4.7", "4.7.0", "4.7b2", "4.7.0-beta2"])
def test_equivalent_beta2_loader_versions_are_admitted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    loader_version: str,
) -> None:
    write_release(tmp_path)
    validate_release = load_guard(monkeypatch, tmp_path)

    validate_release(HeldConfig, loader_version)


@pytest.mark.parametrize(
    "loader_version",
    ["4.7b1", "4.7rc1", "4.7.dev1", "4.7.0-beta1", "4.7.0.post1"],
)
def test_conflicting_47_loader_identity_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    loader_version: str,
) -> None:
    write_release(tmp_path)
    validate_release = load_guard(monkeypatch, tmp_path)

    with pytest.raises(IncompatiblePluginError, match="approved only"):
        validate_release(HeldConfig, loader_version)


@pytest.mark.parametrize("loader_version", ["4.7.0-beta2", "4.7.0b2", "4.7.0rc1"])
def test_prerelease_loader_versions_cannot_bypass_identity_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    loader_version: str,
) -> None:
    write_release(tmp_path, designation="beta1")
    validate_release = load_guard(monkeypatch, tmp_path)

    with pytest.raises(IncompatiblePluginError, match="approved only"):
        validate_release(HeldConfig, loader_version)


def test_malformed_47_loader_version_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    validate_release = load_guard(monkeypatch, tmp_path)

    with pytest.raises(IncompatiblePluginError, match="malformed NetBox 4.7"):
        validate_release(HeldConfig, "4.7-not-a-version")


@pytest.mark.parametrize("designation", [None, "beta1", "beta3", "rc1"])
def test_unreviewed_47_designations_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    designation: str | None,
) -> None:
    write_release(tmp_path, designation=designation)
    validate_release = load_guard(monkeypatch, tmp_path)

    with pytest.raises(IncompatiblePluginError, match="approved only"):
        validate_release(HeldConfig, "4.7.0")


def test_unreviewed_canonical_version_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_release(tmp_path, version="4.7.1")
    validate_release = load_guard(monkeypatch, tmp_path)

    with pytest.raises(IncompatiblePluginError, match="approved only"):
        validate_release(HeldConfig, "4.7.0")


@pytest.mark.parametrize(
    "local_release",
    [
        {"version": "4.7.0", "designation": "beta2"},
        {"build": "Docker-ci", "designation": "beta2"},
        ["build", "Docker-ci"],
    ],
)
def test_local_release_identity_spoofing_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    local_release: object,
) -> None:
    write_release(tmp_path, local=local_release)
    validate_release = load_guard(monkeypatch, tmp_path)

    with pytest.raises(IncompatiblePluginError, match="permits only the build key"):
        validate_release(HeldConfig, "4.7.0")


@pytest.mark.parametrize("contents", ["[not-a-mapping]", "version: [unterminated"])
def test_invalid_canonical_metadata_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    contents: str,
) -> None:
    tmp_path.joinpath("release.yaml").write_text(contents, encoding="utf-8")
    validate_release = load_guard(monkeypatch, tmp_path)

    with pytest.raises(IncompatiblePluginError, match="release.yaml"):
        validate_release(HeldConfig, "4.7.0")


def test_unreadable_local_metadata_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_release(tmp_path)
    validate_release = load_guard(monkeypatch, tmp_path)
    original_read_text = Path.read_text

    def failing_read_text(path: Path, *args, **kwargs) -> str:
        if path == tmp_path / "local/release.yaml":
            raise PermissionError("denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)

    with pytest.raises(IncompatiblePluginError, match="could not verify local/release.yaml"):
        validate_release(HeldConfig, "4.7.0")


def test_stable_release_returns_without_reading_47_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    validate_release = load_guard(monkeypatch, tmp_path)

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("stable validation must not read 4.7 release metadata")

    monkeypatch.setattr(Path, "read_text", unexpected_read)
    validate_release(HeldConfig, "4.6.6")
