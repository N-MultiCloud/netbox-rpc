"""Bounded, secret-free projections of the authoritative capability handshake."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from . import capabilities

MAX_CATALOG_PROCEDURES = 200
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Version = Annotated[StrictInt, Field(ge=0, le=2147483647)]


class HandlerIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    handler_id: str = Field(max_length=255, pattern=r"^[A-Za-z0-9_.:-]+$")
    version: Version
    effect: Literal["read", "write", "destructive"]
    contract_hash: Digest
    compatible_contract_hashes: list[Digest] = Field(default_factory=list, max_length=8)


def _identity(procedure: Any) -> HandlerIdentity:
    return HandlerIdentity(
        handler_id=procedure.handler_id,
        version=int(procedure.version or 1),
        effect=procedure.effect,
        contract_hash=capabilities.derive_command_contract_hash(procedure),
    )


def _reason(procedure: Any, manifest: Any, result: capabilities.CapabilityStatus) -> str:
    if manifest is None:
        return "unknown_manifest"
    if result is capabilities.CapabilityStatus.COMPATIBLE:
        return "compatible"
    if manifest.envelope_version not in capabilities.SUPPORTED_ENVELOPE_VERSIONS:
        return "envelope_mismatch"
    advertised = manifest.handler(procedure.handler_id)
    if advertised is None:
        return "missing_handler"
    if advertised.version != int(procedure.version or 1):
        return "version_mismatch"
    if advertised.effect != procedure.effect:
        return "effect_mismatch"
    return "contract_mismatch"


def _catalog_entry(procedure: Any, manifest: Any) -> dict[str, Any]:
    expected = _identity(procedure)
    result = capabilities.verify_procedure_capability(procedure, manifest)
    advertised = manifest.handler(procedure.handler_id) if manifest else None
    projected = None
    if advertised is not None:
        try:
            projected = HandlerIdentity.model_validate(advertised.model_dump()).model_dump()
        except ValidationError:
            pass
    return {
        "procedure_id": int(procedure.pk),
        "expected": expected.model_dump(),
        "advertised": projected,
        "advertised_projection_valid": advertised is None or projected is not None,
        "status": result.value,
        "reason": _reason(procedure, manifest, result),
    }


def project_capabilities(backend_id: int, procedures: list[Any], manifest: Any) -> dict[str, Any]:
    """Expose only identities corresponding to the caller's visible catalog."""
    envelope = manifest.envelope_version if manifest is not None else None
    valid_envelope = envelope is None or 0 <= envelope <= 2147483647
    return {
        "backend_id": backend_id,
        "manifest_available": manifest is not None,
        "supported_envelope_versions": sorted(capabilities.SUPPORTED_ENVELOPE_VERSIONS),
        "advertised_envelope_version": envelope if valid_envelope else None,
        "advertised_envelope_projection_valid": valid_envelope,
        "catalog_limit": MAX_CATALOG_PROCEDURES,
        "catalog_truncated": len(procedures) > MAX_CATALOG_PROCEDURES,
        "procedures": [
            _catalog_entry(procedure, manifest)
            for procedure in procedures[:MAX_CATALOG_PROCEDURES]
        ],
    }
