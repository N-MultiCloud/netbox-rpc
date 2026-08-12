"""Pure tests for the secret-safe dispatch-lease issuer key-file fallback."""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)


def _install_netbox_stub() -> None:
    if "netbox.plugins" in sys.modules:
        return
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig
    sys.modules["netbox"] = netbox
    sys.modules["netbox.plugins"] = netbox_plugins


_install_netbox_stub()

from netbox_rpc import dispatch_lease as dl  # noqa: E402


def _pem() -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("51" * 32))
    return private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode("ascii")


def _write_key(directory: Path, *, mode: int = 0o600) -> Path:
    path = directory / "issuer.pem"
    path.write_text(_pem(), encoding="utf-8")
    path.chmod(mode)
    return path


def _configure_environment(monkeypatch, path: Path) -> None:
    monkeypatch.setenv(dl._SIGNING_KEY_FILE_ENV, str(path))
    monkeypatch.setenv(dl._SIGNING_KEY_ID_ENV, "staging-issuer")
    monkeypatch.setenv(dl._SIGNING_KEY_VERSION_ENV, "4")


def _plugin_setting_absent(_name, default=None):
    return default


def test_environment_file_loads_when_plugin_setting_is_absent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = _write_key(tmp_path)
    _configure_environment(monkeypatch, path)
    monkeypatch.setattr(dl, "_plugin_setting", _plugin_setting_absent)

    signing_key = dl.load_active_signing_key()
    public_keys = dl.load_verifier_public_keys()

    assert signing_key is not None
    assert (signing_key.key_id, signing_key.key_version) == ("staging-issuer", 4)
    assert ("staging-issuer", 4) in public_keys


def test_explicit_plugin_setting_never_falls_through_to_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = _write_key(tmp_path)
    _configure_environment(monkeypatch, path)
    monkeypatch.setattr(dl, "_plugin_setting", lambda _name, default=None: [])

    assert dl.load_active_signing_key() is None


def test_file_fallback_rejects_symlink_hardlink_loose_mode_and_oversize(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(dl, "_plugin_setting", _plugin_setting_absent)
    target = _write_key(tmp_path)

    symlink = tmp_path / "symlink.pem"
    symlink.symlink_to(target)
    _configure_environment(monkeypatch, symlink)
    assert dl.load_active_signing_key() is None

    hardlink = tmp_path / "hardlink.pem"
    os.link(target, hardlink)
    _configure_environment(monkeypatch, target)
    assert dl.load_active_signing_key() is None
    hardlink.unlink()

    target.chmod(0o644)
    assert dl.load_active_signing_key() is None

    target.write_bytes(b"x" * (dl._MAX_SIGNING_KEY_FILE_BYTES + 1))
    target.chmod(0o600)
    assert dl.load_active_signing_key() is None


def test_file_fallback_rejects_fifo_without_opening_it(
    tmp_path: Path,
    monkeypatch,
) -> None:
    fifo = tmp_path / "issuer.fifo"
    os.mkfifo(fifo, mode=0o600)
    _configure_environment(monkeypatch, fifo)
    monkeypatch.setattr(dl, "_plugin_setting", _plugin_setting_absent)

    assert dl.load_active_signing_key() is None


def test_file_fallback_handles_short_reads_and_missing_os_support(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = _write_key(tmp_path)
    _configure_environment(monkeypatch, path)
    monkeypatch.setattr(dl, "_plugin_setting", _plugin_setting_absent)
    original_read = os.read

    def short_read(fd: int, length: int) -> bytes:
        return original_read(fd, min(length, 5))

    monkeypatch.setattr(dl.os, "read", short_read)
    assert dl.load_active_signing_key() is not None

    monkeypatch.setattr(dl.os, "supports_dir_fd", set())
    assert dl.load_active_signing_key() is None


def test_file_fallback_rejects_premature_eof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = _write_key(tmp_path)
    original_read = os.read
    calls = 0

    def premature_eof(fd: int, length: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_read(fd, min(length, 32))
        return b""

    monkeypatch.setattr(dl.os, "read", premature_eof)

    assert dl._secure_read_signing_key_file(str(path)) is None


def test_file_reader_rejects_unencodable_or_control_paths() -> None:
    assert dl._secure_read_signing_key_file("/tmp/\ud800") is None
    assert dl._secure_read_signing_key_file("/tmp/key\n.pem") is None
