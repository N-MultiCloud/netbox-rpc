"""Executable tests for the fail-closed NetBox 4.7.0 GA boundary."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "netbox_rpc" / "release_guard.py"


class IncompatiblePluginError(Exception):
    """Test double for NetBox's plugin compatibility exception."""


class ApprovedConfig:
    """Minimal configuration double consumed by the package-local guard."""

    approved_netbox_version = "4.7.0"
    approved_netbox_designation = None


def _load_guard(monkeypatch: pytest.MonkeyPatch, release_base: Path):
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

    spec = importlib.util.spec_from_file_location("release_guard_under_test", GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_netbox_release


def _write_release(
    release_base: Path,
    *,
    version: str = "4.7.0",
    designation: str | None = None,
    local: object = None,
) -> None:
    release_data = {"version": version, "edition": "Community"}
    if designation is not None:
        release_data["designation"] = designation
    release_base.joinpath("release.yaml").write_text(
        yaml.safe_dump(release_data), encoding="utf-8"
    )
    if local is not None:
        local_path = release_base / "local/release.yaml"
        local_path.parent.mkdir()
        local_path.write_text(yaml.safe_dump(local), encoding="utf-8")


@pytest.mark.parametrize("loader_version", ["4.7", "4.7.0"])
def test_ga_loader_versions_are_admitted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    loader_version: str,
) -> None:
    _write_release(tmp_path, local={"build": "Docker-ci"})
    _load_guard(monkeypatch, tmp_path)(ApprovedConfig, loader_version)


@pytest.mark.parametrize(
    "loader_version",
    ["4.7.0-beta2", "4.7.1", "4.7.0.post1", "4.7-not-a-version"],
)
def test_unreviewed_ga_loader_versions_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    loader_version: str,
) -> None:
    _write_release(tmp_path)
    validate_release = _load_guard(monkeypatch, tmp_path)
    with pytest.raises(IncompatiblePluginError, match="approved only|malformed"):
        validate_release(ApprovedConfig, loader_version)


@pytest.mark.parametrize("designation", ["beta2", "rc1", ""])
def test_non_ga_canonical_designations_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    designation: str,
) -> None:
    _write_release(tmp_path, designation=designation)
    validate_release = _load_guard(monkeypatch, tmp_path)
    with pytest.raises(IncompatiblePluginError, match="approved only"):
        validate_release(ApprovedConfig, "4.7.0")


def test_canonical_ga_without_designation_is_admitted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_release(tmp_path)
    _load_guard(monkeypatch, tmp_path)(ApprovedConfig, "4.7.0")


def test_local_release_identity_spoofing_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_release(tmp_path, local={"build": "Docker-ci", "designation": "beta2"})
    validate_release = _load_guard(monkeypatch, tmp_path)
    with pytest.raises(IncompatiblePluginError, match="permits only the build key"):
        validate_release(ApprovedConfig, "4.7.0")


def test_stable_non_47_release_does_not_read_47_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    validate_release = _load_guard(monkeypatch, tmp_path)

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("non-4.7 validation must not read 4.7 metadata")

    monkeypatch.setattr(Path, "read_text", unexpected_read)
    validate_release(ApprovedConfig, "4.6.5")
