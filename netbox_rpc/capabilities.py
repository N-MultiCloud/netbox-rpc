"""Versioned backend capability handshake (issue #167).

netbox-rpc is the *consumer* of a capability manifest that the paired
``netbox-rpc-backend`` service advertises at ``GET {backend_url}/capabilities``.
The manifest declares, per handler: ``handler_id`` / ``version`` / ``effect`` /
a ``contract_hash`` over the procedure's command contract, plus a top-level
``envelope_version``. This module fetches it (bounded, authenticated, cached,
Pydantic-v2-validated, *never* trusted as command input) and verifies a
procedure against it.

Prod-safe rollout / graceful degradation: when the backend advertises **nothing**
(no ``/capabilities`` route, unreachable, or a malformed/oversized body), the
fetch returns ``None`` and legacy callers proceed as before. Procedures listed
in ``EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES`` fail closed on that unknown
state at advertisement, admission, and worker claim. When the backend **does**
advertise, a missing/mismatched handler/version/effect/contract-hash/envelope is
failed closed before enqueue. The ``contract_hash`` is derived here from the
shared command contract so both sides compute the same value.
"""

from __future__ import annotations

import hashlib
import json
import time
from enum import StrEnum
from typing import Any

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError

# The envelope versions this consumer understands. A manifest advertising an
# envelope outside this set is treated as an incompatibility (fail closed) when
# present — never silently trusted.
SUPPORTED_ENVELOPE_VERSIONS: frozenset[int] = frozenset({1})

CAPABILITIES_PATH = "/capabilities"
# Hard bound on the manifest body we will read/parse (defence against an
# oversized/hostile response). 512 KiB is generous for a handler list.
_MAX_MANIFEST_BYTES = 512 * 1024
_MAX_HANDLERS = 2000
# Cache the parsed manifest per backend URL for a short TTL to avoid a fetch on
# every create/claim while still reflecting drift promptly.
_CACHE_TTL_SECONDS = 30.0
_MANIFEST_CACHE: dict[str, tuple[float, "BackendCapabilityManifest | None"]] = {}
_SEMANTIC_CAPABILITY_HANDLER_IDS = frozenset(
    {
        "service.gitea.production.upgrade_1_27_1",
        "service.gitea.runner.register",
        "service.gitea.actions_runner.provision_org_ci_runner",
        "service.netbox.staging.deploy_dns_pair",
    }
)


class CapabilityStatus(StrEnum):
    COMPATIBLE = "compatible"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"  # backend advertised nothing → graceful proceed


class HandlerCapability(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    handler_id: str = Field(max_length=255)
    version: int = Field(ge=0)
    effect: str = Field(max_length=20)
    contract_hash: str = Field(max_length=128)
    compatible_contract_hashes: list[str] = Field(default_factory=list, max_length=8)


class BackendCapabilityManifest(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    envelope_version: int = Field(ge=0)
    handlers: list[HandlerCapability] = Field(
        default_factory=list, max_length=_MAX_HANDLERS
    )

    def handler(self, handler_id: str) -> HandlerCapability | None:
        for cap in self.handlers:
            if cap.handler_id == handler_id:
                return cap
        return None


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _base_command_contract_payload(procedure: Any) -> dict[str, Any]:
    commands = []
    command_qs = getattr(procedure, "commands", None)
    iterable = command_qs.all() if hasattr(command_qs, "all") else (command_qs or [])
    for cmd in sorted(iterable, key=lambda c: getattr(c, "sequence", 0)):
        commands.append(
            {
                "sequence": getattr(cmd, "sequence", 0),
                "step_type": getattr(cmd, "step_type", ""),
                "device_cli_mode": getattr(cmd, "device_cli_mode", None),
                "argv": list(getattr(cmd, "argv", []) or []),
                "render_mode": getattr(cmd, "render_mode", ""),
                "produces_var": getattr(cmd, "produces_var", ""),
                "capture_kind": getattr(cmd, "capture_kind", ""),
                "capture_expression": getattr(cmd, "capture_expression", ""),
                "condition_param": getattr(cmd, "condition_param", ""),
                "condition_negate": bool(getattr(cmd, "condition_negate", False)),
                "for_each_param": getattr(cmd, "for_each_param", ""),
                "continue_on_error": bool(getattr(cmd, "continue_on_error", False)),
            }
        )
    return {
        "handler_id": str(getattr(procedure, "handler_id", "")),
        "version": int(getattr(procedure, "version", 1) or 1),
        "effect": str(getattr(procedure, "effect", "")),
        "commands": commands,
    }
def derive_legacy_command_contract_hash(procedure: Any) -> str:
    """Derive the pre-semantic command-only hash for bounded rollout support."""
    payload = _base_command_contract_payload(procedure)
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def derive_command_contract_hash(procedure: Any) -> str:
    """Derive the shared policy, schema, command, and runtime contract hash."""
    payload = _base_command_contract_payload(procedure)
    handler_id = payload["handler_id"]
    if handler_id in _SEMANTIC_CAPABILITY_HANDLER_IDS:
        from .gitea_org_ci_runner_contract import (
            SEMANTIC_CAPABILITY_EXTENSION as org_ci_runner_contract,
        )
        from .gitea_runner_contract import (
            SEMANTIC_CAPABILITY_EXTENSION as runner_contract,
        )
        from .gitea_upgrade_contract import (
            SEMANTIC_CAPABILITY_EXTENSION as upgrade_contract,
        )
        from .dns_staging_deploy_contract import (
            SEMANTIC_CAPABILITY_EXTENSION as dns_staging_contract,
        )

        payload["semantic_contract"] = {
            "service.gitea.production.upgrade_1_27_1": upgrade_contract,
            "service.gitea.runner.register": runner_contract,
            "service.gitea.actions_runner.provision_org_ci_runner": (
                org_ci_runner_contract
            ),
            "service.netbox.staging.deploy_dns_pair": dns_staging_contract,
        }[handler_id]
    else:
        from .akvorado_bootstrap_contract import (
            AKVORADO_BOOTSTRAP_HANDLER_IDS,
            AKVORADO_LIFECYCLE_HANDLER_IDS,
            lifecycle_semantic_capability_extension,
            semantic_capability_extension,
        )

        if handler_id in AKVORADO_BOOTSTRAP_HANDLER_IDS:
            payload["semantic_contract"] = semantic_capability_extension(procedure)
        elif handler_id in AKVORADO_LIFECYCLE_HANDLER_IDS:
            payload["semantic_contract"] = lifecycle_semantic_capability_extension(
                procedure
            )
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def fetch_backend_capabilities(
    target: Any, *, timeout: float = 5.0, use_cache: bool = True
) -> "BackendCapabilityManifest | None":
    """Fetch + validate the backend capability manifest, or ``None`` (graceful).

    Returns ``None`` — meaning "the backend advertises no capabilities" — for
    an absent route, unreachable backend, non-200, oversized body, or a body
    that fails Pydantic validation. Callers decide whether the procedure is
    legacy-graceful or explicitly capability-gated. Never raises and never
    trusts the response as command input.
    """
    base = (
        str(getattr(target, "url", "") or "").rstrip("/") if target is not None else ""
    )
    if not base:
        return None

    now = time.monotonic()
    if use_cache:
        cached = _MANIFEST_CACHE.get(base)
        if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
            return cached[1]

    manifest = _fetch_uncached(base, target, timeout)
    _MANIFEST_CACHE[base] = (now, manifest)
    return manifest


def _fetch_uncached(
    base: str, target: Any, timeout: float
) -> "BackendCapabilityManifest | None":
    headers = dict(getattr(target, "headers", {}) or {})
    verify = bool(getattr(target, "verify_ssl", True))
    try:
        response = requests.get(
            f"{base}{CAPABILITIES_PATH}",
            headers=headers,
            verify=verify,
            timeout=timeout,
            stream=True,
            # A capability manifest is authoritative only for the configured
            # backend origin.  Never accept compatibility through a redirect.
            allow_redirects=False,
        )
    except requests.RequestException:
        return None
    try:
        if response.status_code != 200:
            return None
        try:
            content = response.raw.read(
                _MAX_MANIFEST_BYTES + 1,
                decode_content=True,
            )
        except Exception:  # noqa: BLE001 - capability absence degrades to UNKNOWN
            return None
        if content is None or len(content) > _MAX_MANIFEST_BYTES:
            return None
        try:
            data = json.loads(content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        try:
            return BackendCapabilityManifest.model_validate(data)
        except ValidationError:
            return None
    finally:
        response.close()


def verify_procedure_capability(
    procedure: Any, manifest: "BackendCapabilityManifest | None"
) -> CapabilityStatus:
    """Verify a procedure against a manifest.

    ``UNKNOWN`` when no manifest is advertised (graceful proceed). ``MISMATCH``
    when the envelope is unsupported, the handler is absent, or version / effect
    / contract-hash disagree. ``COMPATIBLE`` otherwise.
    """
    if manifest is None:
        return CapabilityStatus.UNKNOWN
    if manifest.envelope_version not in SUPPORTED_ENVELOPE_VERSIONS:
        return CapabilityStatus.MISMATCH

    cap = manifest.handler(str(getattr(procedure, "handler_id", "")))
    if cap is None:
        return CapabilityStatus.MISMATCH
    if cap.version != int(getattr(procedure, "version", 1) or 1):
        return CapabilityStatus.MISMATCH
    if cap.effect != str(getattr(procedure, "effect", "")):
        return CapabilityStatus.MISMATCH
    expected_hash = derive_command_contract_hash(procedure)
    advertised_hashes = {cap.contract_hash, *cap.compatible_contract_hashes}
    if expected_hash in advertised_hashes:
        return CapabilityStatus.COMPATIBLE

    from .akvorado_bootstrap_contract import (
        AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES,
        AKVORADO_LIFECYCLE_HANDLER_IDS,
    )

    handler_id = str(getattr(procedure, "handler_id", ""))
    if (
        handler_id in AKVORADO_LIFECYCLE_HANDLER_IDS
        and expected_hash
        == AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES.get(handler_id)
        and cap.contract_hash == derive_legacy_command_contract_hash(procedure)
    ):
        # Bounded mixed-version window: a reviewed current catalog may talk to
        # the immediately preceding command-only backend. Any policy/schema
        # drift changes expected_hash and fails closed instead of using this path.
        return CapabilityStatus.COMPATIBLE
    return CapabilityStatus.MISMATCH


def clear_capability_cache() -> None:
    _MANIFEST_CACHE.clear()
