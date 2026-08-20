"""One-time signed RPC dispatch leases (issue #168).

After authorization, normalization, approval, capability verification, and the
atomic *queued → claimed* transition, ``netbox-rpc`` (the **issuer**) mints a
short-lived, ed25519-signed *dispatch lease* and hands it to the paired
``netbox-rpc-backend`` (the **verifier**, N-MultiCloud/nms-backend#583) inside
the ``/rpc/executions/{id}/run`` body. The lease binds the dispatch to the exact
execution, event-stream version, handler contract, effect, target snapshot,
normalized-parameter fingerprint, credential policy, requester/approver,
audience, a one-time nonce, and an expiry, so the backend can prove — before it
touches a managed host — that *this* request is the one that was authorized and
that it has not been replayed, tampered with, downgraded, or misdirected.

Trust boundary / non-goals:

* The lease carries **references and hashes only** — never a secret, private-key
  byte, credential value, or raw exception chain. It is signed data, not command
  input; the backend still re-derives every command from the audited procedure.
* **Nonce ownership:** the issuer *generates* the one-time nonce and records it
  on the append-only ledger (``DispatchLeaseIssued``). The verifier *owns the
  consumed-nonce store* (accept-once / replay rejection) — a nonce is single-use
  on the backend side. "At most one valid envelope per claim" is guaranteed here
  because issuance sits behind the atomic ``start()`` (queued → running)
  transition: a cancelled / terminal / expired / unclaimed stream never reaches
  issuance.
* **Prod-safe graceful degradation:** when no signing key is configured (the
  current production state), ``issue_dispatch_lease`` returns ``None`` and
  ordinary procedures dispatch ID-only exactly as before. Staging backend-token
  rotation is the explicit fail-closed exception in the application handler and
  does not contact the backend without a signed lease. Leases become active once
  an operator configures a key *and* the paired backend advertises verification
  — mirroring the capability-handshake (#167) rollout posture.

Key rotation: keys are identified by ``(key_id, key_version)``. Several keys may
be configured for overlap during rotation, but exactly one is ``active`` and
signs. The verifier resolves the signer by ``(key_id, key_version)`` and MUST
reject unknown lineage — a signature from a retired or unrecognised key id/
version is not accepted just because the bytes verify against some key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .capabilities import derive_command_contract_hash

# Envelope versions this issuer/verifier pair understands. A lease advertising a
# version outside this set is a downgrade/upgrade mismatch and is rejected — the
# version is never silently accepted.
LEASE_ENVELOPE_VERSION = 1
SUPPORTED_ENVELOPE_VERSIONS: frozenset[int] = frozenset({1})

# ed25519 is the only signing algorithm; pinning it defeats algorithm-downgrade
# attempts ("alg=none" / weaker-primitive substitution).
SIGNING_ALGORITHM = "ed25519"

DEFAULT_AUDIENCE = "netbox-rpc-backend"
DEFAULT_TTL_SECONDS = 120
_MAX_TTL_SECONDS = 900

_PLUGIN_NAME = "netbox_rpc"
_SIGNING_KEYS_SETTING = "dispatch_lease_signing_keys"
_AUDIENCE_SETTING = "dispatch_lease_audience"
_TTL_SETTING = "dispatch_lease_ttl_seconds"
_SIGNING_KEY_FILE_ENV = "NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_FILE"
_SIGNING_KEY_ID_ENV = "NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_ID"
_SIGNING_KEY_VERSION_ENV = "NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_VERSION"
_MAX_SIGNING_KEY_FILE_BYTES = 16 * 1024
_MAX_SIGNING_KEY_PATH_BYTES = 4096
_MAX_ENV_KEY_VERSION = 2_147_483_647
_ENV_KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}\Z")
_SETTING_ABSENT = object()

# Bounds — every field is length-capped so a hostile/oversized value can neither
# bloat the ledger nor the signed body.
_MAX_ID_LEN = 255
_MAX_HASH_LEN = 128
_MAX_NONCE_LEN = 128
_MAX_SIG_LEN = 512
_MAX_REF_LEN = 255


class LeaseClaims(BaseModel):
    """The signed, bounded claim set. Serialised canonically to form the message
    over which the ed25519 signature is computed. References/hashes only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    envelope_version: int = Field(ge=0)
    execution_id: int = Field(ge=0)
    stream_version: int = Field(ge=0)
    nonce: str = Field(min_length=1, max_length=_MAX_NONCE_LEN)
    audience: str = Field(min_length=1, max_length=_MAX_REF_LEN)
    handler_id: str = Field(max_length=_MAX_ID_LEN)
    handler_version: int = Field(ge=0)
    effect: str = Field(max_length=20)
    contract_hash: str = Field(max_length=_MAX_HASH_LEN)
    target_snapshot_hash: str = Field(default="", max_length=_MAX_HASH_LEN)
    params_fingerprint: str = Field(default="", max_length=_MAX_HASH_LEN)
    credential_policy: str = Field(default="", max_length=_MAX_REF_LEN)
    requested_by_id: int | None = Field(default=None, ge=0)
    approved_by_id: int | None = Field(default=None, ge=0)
    issued_at: str = Field(max_length=64)
    expires_at: str = Field(max_length=64)
    trace_id: str = Field(default="", max_length=_MAX_ID_LEN)
    key_id: str = Field(min_length=1, max_length=_MAX_ID_LEN)
    key_version: int = Field(ge=0)

    def canonical_bytes(self) -> bytes:
        """Deterministic message bytes both sides sign/verify (sorted keys,
        compact separators). The signature is *not* part of this payload."""
        return json.dumps(
            self.model_dump(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")


class SignedDispatchLease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: str = Field(default=SIGNING_ALGORITHM, max_length=32)
    claims: LeaseClaims
    signature: str = Field(min_length=1, max_length=_MAX_SIG_LEN)

    def to_body(self) -> dict[str, Any]:
        return self.model_dump()


class LeaseStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    # No key configured / lease not issued → the caller proceeds ID-only.
    NOT_ISSUED = "not_issued"


class LeaseVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: LeaseStatus
    reason: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status is LeaseStatus.VALID


# --------------------------------------------------------------------------- #
# Key material                                                                #
# --------------------------------------------------------------------------- #


class _SigningKey:
    __slots__ = ("key_id", "key_version", "_private_key")

    def __init__(self, key_id: str, key_version: int, private_key: Any) -> None:
        self.key_id = key_id
        self.key_version = key_version
        self._private_key = private_key

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self._private_key.sign(message)).decode("ascii")

    def public_key(self) -> Any:
        return self._private_key.public_key()


def _load_ed25519_private_key(pem: str) -> Any | None:
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        key = load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception:
        return None
    return key if isinstance(key, Ed25519PrivateKey) else None


def _load_ed25519_public_key(material: str) -> Any | None:
    """Load a public key from PEM text or base64 raw 32-byte form."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        text = material.strip()
        if "BEGIN" in text:
            key = load_pem_public_key(text.encode("utf-8"))
            return key if isinstance(key, Ed25519PublicKey) else None
        raw = base64.b64decode(text, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def _plugin_setting(name: str, default: Any = None) -> Any:
    try:
        from django.conf import settings

        return settings.PLUGINS_CONFIG.get(_PLUGIN_NAME, {}).get(name, default)
    except Exception:
        return default


def _metadata_is_trusted_directory(metadata: os.stat_result) -> bool:
    """Accept only root/current-euid owned, non-writable path components."""
    if not stat.S_ISDIR(metadata.st_mode):
        return False
    if metadata.st_uid not in {0, os.geteuid()}:
        return False
    writable_by_others = bool(stat.S_IMODE(metadata.st_mode) & 0o022)
    root_sticky = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
    return not writable_by_others or root_sticky


def _metadata_is_trusted_key_file(metadata: os.stat_result) -> bool:
    """Validate a small root/current-euid owned, non-shareable regular file."""
    mode = stat.S_IMODE(metadata.st_mode)
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid in {0, os.geteuid()}
        and metadata.st_nlink == 1
        and bool(mode & 0o440)
        and not bool(mode & ~0o640)
        and 0 < metadata.st_size <= _MAX_SIGNING_KEY_FILE_BYTES
    )


def _secure_read_signing_key_file(path: str) -> str | None:
    """Read one PEM without symlink/special-file/race or unbounded-read hazards."""
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    required_functions = (
        "close",
        "fstat",
        "fsencode",
        "geteuid",
        "open",
        "read",
        "stat",
    )
    if any(not hasattr(os, flag) for flag in required_flags) or any(
        not callable(getattr(os, name, None)) for name in required_functions
    ):
        return None
    supports_dir_fd = getattr(os, "supports_dir_fd", ())
    supports_follow_symlinks = getattr(os, "supports_follow_symlinks", ())
    if (
        os.open not in supports_dir_fd
        or os.stat not in supports_dir_fd
        or os.stat not in supports_follow_symlinks
    ):
        return None
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    try:
        encoded_path = os.fsencode(path)
    except (UnicodeError, ValueError, TypeError):
        return None
    if len(encoded_path) > _MAX_SIGNING_KEY_PATH_BYTES or any(
        ord(character) < 32 or ord(character) == 127 for character in path
    ):
        return None
    components = path.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        return None

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open("/", directory_flags)
        if not _metadata_is_trusted_directory(os.fstat(directory_fd)):
            return None
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            try:
                next_metadata = os.fstat(next_fd)
            except Exception:
                os.close(next_fd)
                raise
            if not _metadata_is_trusted_directory(next_metadata):
                os.close(next_fd)
                return None
            os.close(directory_fd)
            directory_fd = next_fd

        filename = components[-1]
        before = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if not _metadata_is_trusted_key_file(before):
            return None
        file_fd = os.open(filename, file_flags, dir_fd=directory_fd)
        opened = os.fstat(file_fd)
        if not _metadata_is_trusted_key_file(opened) or (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            return None

        chunks: list[bytes] = []
        remaining = _MAX_SIGNING_KEY_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        material = b"".join(chunks)
        after = os.fstat(file_fd)
        if (
            len(material) > _MAX_SIGNING_KEY_FILE_BYTES
            or len(material) != opened.st_size
            or not _metadata_is_trusted_key_file(after)
            or (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_uid,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
        ):
            return None
        return material.decode("utf-8")
    except (OSError, UnicodeError, ValueError, TypeError, NotImplementedError):
        return None
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass


def _load_environment_signing_key() -> _SigningKey | None:
    """Load the opt-in file fallback; partial/malformed environment fails closed."""
    path = os.environ.get(_SIGNING_KEY_FILE_ENV)
    key_id = os.environ.get(_SIGNING_KEY_ID_ENV)
    raw_version = os.environ.get(_SIGNING_KEY_VERSION_ENV)
    if not path and not key_id and not raw_version:
        return None
    if (
        not path
        or not key_id
        or not raw_version
        or not _ENV_KEY_ID_RE.fullmatch(key_id)
    ):
        return None
    try:
        key_version = int(raw_version)
    except (TypeError, ValueError):
        return None
    if not 1 <= key_version <= _MAX_ENV_KEY_VERSION:
        return None
    pem = _secure_read_signing_key_file(path)
    if pem is None:
        return None
    private_key = _load_ed25519_private_key(pem)
    if private_key is None:
        return None
    return _SigningKey(key_id, key_version, private_key)


def load_active_signing_key() -> _SigningKey | None:
    """Return the single active signing key, or ``None`` (graceful ID-only).

    Config shape (``PLUGINS_CONFIG['netbox_rpc']['dispatch_lease_signing_keys']``)
    is a list of ``{key_id, key_version, private_key_pem, active}`` dicts. Exactly
    one entry should be ``active``; the first active, well-formed ed25519 key
    wins. When that setting is absent (not merely empty or malformed), the
    three ``NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_*`` environment variables may
    select a strictly validated private-key file and bounded lineage. Any
    malformed source degrades to no lease, never a traceback in the worker.
    """
    entries = _plugin_setting(_SIGNING_KEYS_SETTING, _SETTING_ABSENT)
    if entries is _SETTING_ABSENT:
        return _load_environment_signing_key()
    if not isinstance(entries, (list, tuple)):
        return None
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("active"):
            continue
        key_id = str(entry.get("key_id") or "").strip()
        pem = entry.get("private_key_pem")
        if not key_id or not isinstance(pem, str) or not pem.strip():
            continue
        try:
            key_version = int(entry.get("key_version", 1))
        except (TypeError, ValueError):
            continue
        if key_version < 0 or len(key_id) > _MAX_ID_LEN:
            continue
        private_key = _load_ed25519_private_key(pem)
        if private_key is None:
            continue
        return _SigningKey(key_id, key_version, private_key)
    return None


def load_verifier_public_keys() -> dict[tuple[str, int], Any]:
    """Resolve the ``(key_id, key_version) → ed25519 public key`` lineage map for
    verification. Public material may be a ``public_key_pem`` / ``public_key_b64``
    field or derived from a configured ``private_key_pem``. Unknown lineage is
    simply absent from the map, so the verifier rejects it (never a wildcard)."""
    entries = _plugin_setting(_SIGNING_KEYS_SETTING, _SETTING_ABSENT)
    out: dict[tuple[str, int], Any] = {}
    if entries is _SETTING_ABSENT:
        signing_key = _load_environment_signing_key()
        if signing_key is not None:
            out[(signing_key.key_id, signing_key.key_version)] = (
                signing_key.public_key()
            )
        return out
    if not isinstance(entries, (list, tuple)):
        return out
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key_id = str(entry.get("key_id") or "").strip()
        if not key_id:
            continue
        try:
            key_version = int(entry.get("key_version", 1))
        except (TypeError, ValueError):
            continue
        public: Any | None = None
        material = entry.get("public_key_pem") or entry.get("public_key_b64")
        if isinstance(material, str) and material.strip():
            public = _load_ed25519_public_key(material)
        if public is None and isinstance(entry.get("private_key_pem"), str):
            private = _load_ed25519_private_key(entry["private_key_pem"])
            if private is not None:
                public = private.public_key()
        if public is not None:
            out[(key_id, key_version)] = public
    return out


# --------------------------------------------------------------------------- #
# Issue                                                                       #
# --------------------------------------------------------------------------- #


def generate_nonce() -> str:
    return secrets.token_hex(16)


def _hash_json(value: Any) -> str:
    if value is None:
        return ""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def issue_dispatch_lease(
    execution: Any,
    *,
    stream_version: int,
    normalized_params: dict[str, Any] | None,
    now: Any,
    credential_policy: str = "",
    trace_id: str = "",
    audience: str | None = None,
    ttl_seconds: int | None = None,
) -> SignedDispatchLease | None:
    """Mint a signed lease for a just-claimed execution, or ``None`` (ID-only).

    Returns ``None`` when no signing key is configured (graceful) or when the
    execution/procedure is missing required identity — never raises into the
    worker dispatch path. The ``contract_hash`` is the same value the capability
    handshake (#167) verifies, so a lease and a capability manifest agree by
    construction on *what will run*.
    """
    signing_key = load_active_signing_key()
    if signing_key is None:
        return None

    procedure = getattr(execution, "procedure", None)
    execution_id = getattr(execution, "pk", None)
    if procedure is None or execution_id is None:
        return None

    resolved_audience = (
        audience or _plugin_setting(_AUDIENCE_SETTING) or DEFAULT_AUDIENCE
    )
    resolved_audience = str(resolved_audience)[:_MAX_REF_LEN]

    ttl = ttl_seconds if ttl_seconds is not None else _plugin_setting(_TTL_SETTING)
    try:
        ttl = int(ttl) if ttl is not None else DEFAULT_TTL_SECONDS
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL_SECONDS
    ttl = max(1, min(ttl, _MAX_TTL_SECONDS))

    fingerprint_source = (normalized_params or {}).get("command_fingerprint")
    target_hash = ""
    if isinstance(fingerprint_source, dict):
        target_hash = str(fingerprint_source.get("target_object_sha256") or "")[
            :_MAX_HASH_LEN
        ]

    try:
        from datetime import timedelta

        expires = now + timedelta(seconds=ttl)
        claims = LeaseClaims(
            envelope_version=LEASE_ENVELOPE_VERSION,
            execution_id=int(execution_id),
            stream_version=int(stream_version),
            nonce=generate_nonce(),
            audience=resolved_audience,
            handler_id=str(getattr(procedure, "handler_id", "") or "")[:_MAX_ID_LEN],
            handler_version=int(getattr(procedure, "version", 1) or 1),
            effect=str(getattr(procedure, "effect", "") or "")[:20],
            contract_hash=derive_command_contract_hash(procedure),
            target_snapshot_hash=target_hash,
            params_fingerprint=_hash_json(fingerprint_source),
            credential_policy=str(credential_policy or "")[:_MAX_REF_LEN],
            requested_by_id=_maybe_int(getattr(execution, "requested_by_id", None)),
            approved_by_id=_maybe_int(getattr(execution, "approved_by_id", None)),
            issued_at=_isoformat(now),
            expires_at=_isoformat(expires),
            trace_id=str(trace_id or "")[:_MAX_ID_LEN],
            key_id=signing_key.key_id,
            key_version=signing_key.key_version,
        )
        signature = signing_key.sign(claims.canonical_bytes())
    except (ValidationError, ValueError, TypeError):
        return None

    return SignedDispatchLease(
        algorithm=SIGNING_ALGORITHM, claims=claims, signature=signature
    )


# --------------------------------------------------------------------------- #
# Verify (shared reference implementation for the paired backend, #583)        #
# --------------------------------------------------------------------------- #


def verify_dispatch_lease(
    lease: SignedDispatchLease,
    *,
    public_keys: dict[tuple[str, int], Any],
    audience: str,
    now: Any,
    expected_execution_id: int | None = None,
    expected_stream_version: int | None = None,
    expected_contract_hash: str | None = None,
    expected_handler_id: str | None = None,
    expected_handler_version: int | None = None,
    expected_effect: str | None = None,
    expected_target_snapshot_hash: str | None = None,
    expected_params_fingerprint: str | None = None,
    expected_credential_policy: str | None = None,
    expected_requested_by_id: int | None = None,
    expected_approved_by_id: int | None = None,
    seen_nonces: set[str] | frozenset[str] | None = None,
) -> LeaseVerification:
    """Reference verifier: fail-closed on every mismatch.

    Rejects (in order) unsupported envelope/algorithm (downgrade), unknown key
    lineage (retired/unrecognised ``key_id``/``key_version``), bad signature
    (tamper), wrong audience (confused deputy), expiry, execution/stream/contract
    binding drift (TOCTOU / wrong-version), and a replayed nonce. Never trusts
    any field as command input; returns a bounded reason string with no secret
    or exception chain.
    """
    claims = lease.claims
    if claims.envelope_version not in SUPPORTED_ENVELOPE_VERSIONS:
        return _invalid("unsupported envelope version")
    if lease.algorithm != SIGNING_ALGORITHM:
        return _invalid("unsupported signing algorithm")

    public_key = public_keys.get((claims.key_id, claims.key_version))
    if public_key is None:
        return _invalid("unknown signing key lineage")

    try:
        signature = base64.b64decode(lease.signature, validate=True)
    except (binascii.Error, ValueError):
        return _invalid("malformed signature encoding")
    try:
        public_key.verify(signature, claims.canonical_bytes())
    except Exception:
        return _invalid("signature verification failed")

    if claims.audience != audience:
        return _invalid("wrong audience")

    expires = _parse_iso(claims.expires_at)
    if expires is None or _parse_iso(claims.issued_at) is None:
        return _invalid("malformed lease timestamps")
    if now > expires:
        return _invalid("lease expired")

    if (
        expected_execution_id is not None
        and claims.execution_id != expected_execution_id
    ):
        return _invalid("execution id mismatch")
    if (
        expected_stream_version is not None
        and claims.stream_version != expected_stream_version
    ):
        return _invalid("stream version mismatch")
    if (
        expected_contract_hash is not None
        and claims.contract_hash != expected_contract_hash
    ):
        return _invalid("contract hash mismatch")
    semantic_expectations = (
        (expected_handler_id, claims.handler_id, "handler id mismatch"),
        (expected_handler_version, claims.handler_version, "handler version mismatch"),
        (expected_effect, claims.effect, "effect mismatch"),
        (
            expected_target_snapshot_hash,
            claims.target_snapshot_hash,
            "target snapshot mismatch",
        ),
        (
            expected_params_fingerprint,
            claims.params_fingerprint,
            "params fingerprint mismatch",
        ),
        (
            expected_credential_policy,
            claims.credential_policy,
            "credential policy mismatch",
        ),
        (expected_requested_by_id, claims.requested_by_id, "requester mismatch"),
        (expected_approved_by_id, claims.approved_by_id, "approver mismatch"),
    )
    for expected, actual, mismatch_reason in semantic_expectations:
        if expected is not None and actual != expected:
            return _invalid(mismatch_reason)
    if seen_nonces is not None and claims.nonce in seen_nonces:
        return _invalid("nonce replay")

    return LeaseVerification(status=LeaseStatus.VALID)


def _invalid(reason: str) -> LeaseVerification:
    return LeaseVerification(status=LeaseStatus.INVALID, reason=reason[:255])


def _maybe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _isoformat(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _parse_iso(value: str) -> Any | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        from datetime import datetime

        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
