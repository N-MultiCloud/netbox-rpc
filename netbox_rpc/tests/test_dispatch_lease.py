"""One-time signed dispatch lease tests (issue #168).

Covers the reference sign/verify contract (accept-once, reject
replay/tamper/wrong-audience/expiry/unknown-lineage/downgrade/stream-drift), the
checked-in cross-repo determinism fixture, and the ``run_execution`` issuance
seam (mint + audit when a key is configured; graceful ID-only otherwise).
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from django.test import TestCase

from netbox_rpc import dispatch_lease as dl
from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.domain.aggregate import RPCExecutionAggregate

from ._common import enable_rpc_integration, event_names, make_execution, make_procedure

NOW = datetime(2026, 7, 23, 12, 0, 0, tzinfo=timezone.utc)
FIXTURE = Path(__file__).parent / "fixtures" / "dispatch_lease" / "contract.json"


def _pem_for(seed_hex: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(
        "ascii"
    )


def _configure_key(seed_hex: str, *, key_id="rpc-sign", key_version=3):
    """Patch the plugin setting so a real signing key is 'configured'."""
    entries = [
        {
            "key_id": key_id,
            "key_version": key_version,
            "private_key_pem": _pem_for(seed_hex),
            "active": True,
        }
    ]

    def _setting(name, default=None):
        return {
            dl._SIGNING_KEYS_SETTING: entries,
            dl._AUDIENCE_SETTING: "netbox-rpc-backend",
            dl._TTL_SETTING: 120,
        }.get(name, default)

    return mock.patch.object(dl, "_plugin_setting", side_effect=_setting)


def _absent_setting(_name, default=None):
    return default


class CrossRepoFixtureTests(TestCase):
    """The checked-in fixture is the hard cross-repo contract with #583."""

    def setUp(self):
        self.fx = json.loads(FIXTURE.read_text())
        self.claims = dl.LeaseClaims.model_validate(self.fx["claims"])
        self.lease = dl.SignedDispatchLease(
            algorithm=self.fx["algorithm"],
            claims=self.claims,
            signature=self.fx["signature_b64"],
        )
        seed = bytes.fromhex(self.fx["test_private_seed_hex"])
        self.priv = Ed25519PrivateKey.from_private_bytes(seed)
        lineage = (
            self.fx["key_lineage"]["key_id"],
            self.fx["key_lineage"]["key_version"],
        )
        self.pubs = {lineage: self.priv.public_key()}
        self.now = datetime.fromisoformat(self.fx["verify_now_iso"])

    def test_signature_is_deterministic(self):
        # RFC 8032: re-signing the canonical bytes reproduces the fixture sig.
        resigned = base64.b64encode(
            self.priv.sign(self.claims.canonical_bytes())
        ).decode("ascii")
        assert resigned == self.fx["signature_b64"]
        assert self.claims.canonical_bytes() == base64.b64decode(
            self.fx["canonical_message_b64"]
        )

    def test_accepts_valid_lease(self):
        v = dl.verify_dispatch_lease(
            self.lease,
            public_keys=self.pubs,
            audience=self.fx["audience"],
            now=self.now,
            expected_execution_id=self.claims.execution_id,
            expected_stream_version=self.claims.stream_version,
            expected_contract_hash=self.claims.contract_hash,
        )
        assert v.is_valid, v.reason

    def test_rejects_replayed_nonce(self):
        v = dl.verify_dispatch_lease(
            self.lease,
            public_keys=self.pubs,
            audience=self.fx["audience"],
            now=self.now,
            seen_nonces={self.fx["negatives"]["replay"]["seen_nonce"]},
        )
        assert not v.is_valid and v.reason == "nonce replay"

    def test_rejects_tamper(self):
        override = self.fx["negatives"]["tamper"]["claims_override"]
        tampered = dl.SignedDispatchLease(
            algorithm="ed25519",
            claims=self.claims.model_copy(update=override),
            signature=self.lease.signature,
        )
        v = dl.verify_dispatch_lease(
            tampered, public_keys=self.pubs, audience=self.fx["audience"], now=self.now
        )
        assert not v.is_valid and v.reason == "signature verification failed"

    def test_rejects_wrong_audience(self):
        v = dl.verify_dispatch_lease(
            self.lease,
            public_keys=self.pubs,
            audience=self.fx["negatives"]["wrong_audience"]["verify_audience"],
            now=self.now,
        )
        assert not v.is_valid and v.reason == "wrong audience"

    def test_rejects_unknown_lineage(self):
        override = self.fx["negatives"]["unknown_lineage"]["claims_override"]
        bad_claims = self.claims.model_copy(update=override)
        bad = dl.SignedDispatchLease(
            algorithm="ed25519",
            claims=bad_claims,
            signature=base64.b64encode(
                self.priv.sign(bad_claims.canonical_bytes())
            ).decode("ascii"),
        )
        v = dl.verify_dispatch_lease(
            bad, public_keys=self.pubs, audience=self.fx["audience"], now=self.now
        )
        assert not v.is_valid and v.reason == "unknown signing key lineage"

    def test_rejects_expired(self):
        v = dl.verify_dispatch_lease(
            self.lease,
            public_keys=self.pubs,
            audience=self.fx["audience"],
            now=datetime.fromisoformat(self.fx["expired_now_iso"]),
        )
        assert not v.is_valid and v.reason == "lease expired"

    def test_rejects_stream_drift(self):
        v = dl.verify_dispatch_lease(
            self.lease,
            public_keys=self.pubs,
            audience=self.fx["audience"],
            now=self.now,
            expected_stream_version=self.claims.stream_version + 1,
        )
        assert not v.is_valid and v.reason == "stream version mismatch"

    def test_rejects_downgrade_envelope(self):
        down = self.claims.model_copy(update={"envelope_version": 999})
        lease = dl.SignedDispatchLease(
            algorithm="ed25519",
            claims=down,
            signature=base64.b64encode(self.priv.sign(down.canonical_bytes())).decode(
                "ascii"
            ),
        )
        v = dl.verify_dispatch_lease(
            lease, public_keys=self.pubs, audience=self.fx["audience"], now=self.now
        )
        assert not v.is_valid and v.reason == "unsupported envelope version"


class KeyLoadingTests(TestCase):
    def _environment(self, path: Path, *, key_id="env-sign", key_version="7"):
        return mock.patch.dict(
            os.environ,
            {
                dl._SIGNING_KEY_FILE_ENV: str(path),
                dl._SIGNING_KEY_ID_ENV: key_id,
                dl._SIGNING_KEY_VERSION_ENV: key_version,
            },
            clear=False,
        )

    @staticmethod
    def _write_key(directory: str, *, mode: int = 0o600) -> Path:
        path = Path(directory) / "dispatch-lease.pem"
        path.write_text(_pem_for("12" * 32), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_no_config_returns_none(self):
        with mock.patch.object(dl, "_plugin_setting", return_value=None):
            assert dl.load_active_signing_key() is None
            assert dl.load_verifier_public_keys() == {}

    def test_secure_environment_file_fallback_loads_private_and_public_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_key(directory)
            with (
                mock.patch.object(
                    dl,
                    "_plugin_setting",
                    side_effect=lambda _name, default=None: default,
                ),
                self._environment(path),
            ):
                signing_key = dl.load_active_signing_key()
                public_keys = dl.load_verifier_public_keys()

        assert signing_key is not None
        assert signing_key.key_id == "env-sign"
        assert signing_key.key_version == 7
        assert ("env-sign", 7) in public_keys

    def test_explicit_plugin_setting_is_primary_over_environment_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_key(directory)
            with (
                mock.patch.object(dl, "_plugin_setting", return_value=[]),
                self._environment(path),
            ):
                assert dl.load_active_signing_key() is None
                assert dl.load_verifier_public_keys() == {}

    def test_environment_file_rejects_partial_or_invalid_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_key(directory)
            absent_setting = mock.patch.object(
                dl,
                "_plugin_setting",
                side_effect=_absent_setting,
            )
            with (
                absent_setting,
                mock.patch.dict(
                    os.environ,
                    {dl._SIGNING_KEY_FILE_ENV: str(path)},
                    clear=True,
                ),
            ):
                assert dl.load_active_signing_key() is None
            for key_id, version in (("bad id", "1"), ("key", "0"), ("key", "x")):
                with (
                    mock.patch.object(
                        dl,
                        "_plugin_setting",
                        side_effect=_absent_setting,
                    ),
                    self._environment(path, key_id=key_id, key_version=version),
                ):
                    assert dl.load_active_signing_key() is None

    def test_environment_file_rejects_symlinks_and_loose_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._write_key(directory)
            symlink = Path(directory) / "linked.pem"
            symlink.symlink_to(target)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                self._environment(symlink),
            ):
                assert dl.load_active_signing_key() is None

            target.chmod(0o644)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                self._environment(target),
            ):
                assert dl.load_active_signing_key() is None

    def test_environment_file_rejects_symlinked_directory_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            real_dir = Path(directory) / "real"
            real_dir.mkdir(mode=0o700)
            target = self._write_key(str(real_dir))
            linked_dir = Path(directory) / "linked"
            linked_dir.symlink_to(real_dir, target_is_directory=True)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                self._environment(linked_dir / target.name),
            ):
                assert dl.load_active_signing_key() is None

            target.write_bytes(b"x" * (dl._MAX_SIGNING_KEY_FILE_BYTES + 1))
            target.chmod(0o600)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                self._environment(target),
            ):
                assert dl.load_active_signing_key() is None

    def test_environment_file_rejects_hardlinks_unsafe_directory_and_device(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._write_key(directory)
            hardlink = Path(directory) / "hardlinked.pem"
            os.link(target, hardlink)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                self._environment(target),
            ):
                assert dl.load_active_signing_key() is None

        with tempfile.TemporaryDirectory() as directory:
            unsafe_dir = Path(directory) / "unsafe"
            unsafe_dir.mkdir(mode=0o700)
            target = self._write_key(str(unsafe_dir))
            unsafe_dir.chmod(0o777)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                self._environment(target),
            ):
                assert dl.load_active_signing_key() is None

        with (
            mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
            self._environment(Path("/dev/null")),
        ):
            assert dl.load_active_signing_key() is None

    def test_environment_file_rejects_fifo_without_blocking_and_missing_primitives(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "dispatch-lease.fifo"
            os.mkfifo(fifo, mode=0o600)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                self._environment(fifo),
            ):
                assert dl.load_active_signing_key() is None

            path = self._write_key(directory)
            with (
                mock.patch.object(dl, "_plugin_setting", side_effect=_absent_setting),
                mock.patch.object(dl.os, "supports_dir_fd", set()),
                self._environment(path),
            ):
                assert dl.load_active_signing_key() is None

    def test_environment_file_handles_short_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_key(directory)
            original_read = os.read

            def short_read(fd, length):
                return original_read(fd, min(length, 7))

            with (
                mock.patch.object(
                    dl,
                    "_plugin_setting",
                    side_effect=_absent_setting,
                ),
                mock.patch.object(dl.os, "read", side_effect=short_read),
                self._environment(path),
            ):
                assert dl.load_active_signing_key() is not None

    def test_malformed_key_is_skipped(self):
        entries = [{"key_id": "", "active": True, "private_key_pem": "nope"}]
        with mock.patch.object(dl, "_plugin_setting", return_value=entries):
            assert dl.load_active_signing_key() is None

    def test_inactive_key_is_not_used_for_signing(self):
        seed = "11" * 32
        entries = [
            {
                "key_id": "k",
                "key_version": 1,
                "private_key_pem": _pem_for(seed),
                "active": False,
            }
        ]
        with mock.patch.object(dl, "_plugin_setting", return_value=entries):
            assert dl.load_active_signing_key() is None
            # ...but its public key is still resolvable for verification.
            assert ("k", 1) in dl.load_verifier_public_keys()


class RunExecutionIssuanceTests(TestCase):
    """The ``run_execution`` seam mints + audits a lease behind the atomic claim."""

    def _queued_execution(self):
        proc = make_procedure("os.linux.test.echo", handler_id="h.echo", effect="read")
        ex = make_execution(procedure=proc)
        RPCExecutionAggregate(ex).queue()
        return ex

    @mock.patch("netbox_rpc.jobs._call_backend")
    @mock.patch.object(command_handlers, "normalize_execution_params")
    @mock.patch.object(command_handlers, "resolve_backend")
    def test_issues_and_audits_lease_when_key_configured(self, resolve, norm, call):
        resolve.return_value = BackendTarget(
            url="http://backend.example", headers={}, verify_ssl=True
        )
        norm.return_value = {"command_fingerprint": {"handler_id": "h.echo"}}
        call.return_value = {"ok": True, "result": {"stdout": "ok"}}
        enable_rpc_integration()
        ex = self._queued_execution()

        with _configure_key("22" * 32):
            command_handlers.run_execution(ex)

        # A lease reached the backend call...
        assert call.call_args.kwargs.get("lease") is not None
        lease = call.call_args.kwargs["lease"]
        assert lease.claims.execution_id == ex.pk
        assert lease.claims.key_id == "rpc-sign"
        # ...and the audit event is on the append-only ledger.
        assert "DispatchLeaseIssued" in event_names(ex)
        ex.refresh_from_db()
        assert ex.status == ex.STATUS_SUCCEEDED

    @mock.patch("netbox_rpc.jobs._call_backend")
    @mock.patch.object(command_handlers, "normalize_execution_params")
    @mock.patch.object(command_handlers, "resolve_backend")
    def test_graceful_id_only_when_no_key(self, resolve, norm, call):
        resolve.return_value = BackendTarget(
            url="http://backend.example", headers={}, verify_ssl=True
        )
        norm.return_value = {"command_fingerprint": {"handler_id": "h.echo"}}
        call.return_value = {"ok": True, "result": {"stdout": "ok"}}
        enable_rpc_integration()
        ex = self._queued_execution()

        with mock.patch.object(dl, "_plugin_setting", return_value=None):
            command_handlers.run_execution(ex)

        assert call.call_args.kwargs.get("lease") is None
        assert "DispatchLeaseIssued" not in event_names(ex)
        ex.refresh_from_db()
        assert ex.status == ex.STATUS_SUCCEEDED
