"""Semantic capability attestation for the Ubuntu 26.04 Samba AD DC handlers.

The base capability hash covers only the handler id, version, effect and the
representative command rows. For these three handlers it is extended with the
``semantic_contract`` built here, which pins the exact reviewed installer program
and the wire protocol in addition to the catalog policy and both schemas. The
backend reproduces the same payload byte for byte; ``tests/fixtures/
samba_ad_dc_capability_contract.json`` holds the expected values both repositories
assert.

Updating the installer
----------------------
The installer digest is NOT stored in the database, so a new installer needs no
migration. Change ``INSTALLER_SHA256`` (and ``STDIN_PROTOCOL_VERSION`` / the modes
if the protocol changed) here, regenerate the fixture with
``python tests/test_samba_ad_dc_capability_contract.py --write-fixture``, and pin
the same digest in ``netbox_rpc_backend/rpc/samba_ad_dc.py``. Until both sides agree
the backend's advertised hash differs and dispatch fails closed with a capability
mismatch.

Semantic payload (canonical JSON: ``sort_keys``, separators ``(",", ":")``,
``default=str``; every hash is the lowercase hex SHA-256 of that encoding)::

    {
      "contract_version": 1,
      "installer_sha256": INSTALLER_SHA256,
      "protocol": {
        "stdin_version": STDIN_PROTOCOL_VERSION,
        "modes": sorted(INSTALLER_MODES),
        "firewall_proof": FIREWALL_PROOF_PROTOCOL,
        "result": RESULT_PROTOCOL,
      },
      "procedure_policy": {
        "name", "target_models" (sorted), "effect", "timeout_seconds",
        "approval_required", "transport_driver", "transport_pinned",
        "transport_driver_chain", "output_parser",
        "output_schema_sha256", "params_schema_sha256", "result_schema_sha256"
      }
    }

The final contract hash is ``sha256(canonical({"handler_id", "version", "effect",
"commands": [...], "semantic_contract": <payload above>}))`` exactly as
``netbox_rpc.capabilities.derive_command_contract_hash`` computes it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

CONTRACT_VERSION = 1
# Pinned to netbox-rpc-backend ``netbox_rpc_backend/rpc/samba_ad_dc.py``.
INSTALLER_SHA256 = "df7a5fc827c56418e3b3b10320ed76c31395b87aa20a6bc5808ff2f0398caa0a"
STDIN_PROTOCOL_VERSION = 1
INSTALLER_MODES = (
    "confirm_firewall",
    "preflight",
    "provision",
    "provision_continue",
    "rollback_firewall",
    "verify",
)
FIREWALL_PROOF_PROTOCOL = "fresh-ssh-connection-confirm-v1"
RESULT_PROTOCOL = "samba-ad-dc-result-v1"

HANDLER_IDS = frozenset(
    {
        "os.linux.ubuntu.26.samba_ad_dc.preflight",
        "os.linux.ubuntu.26.samba_ad_dc.provision",
        "os.linux.ubuntu.26.samba_ad_dc.verify",
    }
)
FIXTURE_NAME = "samba_ad_dc_capability_contract.json"


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def protocol_contract() -> dict[str, Any]:
    return {
        "stdin_version": STDIN_PROTOCOL_VERSION,
        "modes": sorted(INSTALLER_MODES),
        "firewall_proof": FIREWALL_PROOF_PROTOCOL,
        "result": RESULT_PROTOCOL,
    }


def semantic_capability_extension(procedure: Any) -> dict[str, Any]:
    """Return the semantic contract for one catalog row (attribute access only)."""
    return {
        "contract_version": CONTRACT_VERSION,
        "installer_sha256": INSTALLER_SHA256,
        "protocol": protocol_contract(),
        "procedure_policy": {
            "name": str(getattr(procedure, "name", "")),
            "target_models": sorted(getattr(procedure, "target_models", []) or []),
            "effect": str(getattr(procedure, "effect", "")),
            "timeout_seconds": int(getattr(procedure, "timeout_seconds", 0) or 0),
            "approval_required": bool(getattr(procedure, "approval_required", False)),
            "transport_driver": str(getattr(procedure, "transport_driver", "")),
            "transport_pinned": bool(getattr(procedure, "transport_pinned", False)),
            "transport_driver_chain": list(
                getattr(procedure, "transport_driver_chain", []) or []
            ),
            "output_parser": str(getattr(procedure, "output_parser", "")),
            "output_schema_sha256": canonical_sha256(
                getattr(procedure, "output_schema", {}) or {}
            ),
            "params_schema_sha256": canonical_sha256(
                getattr(procedure, "params_schema", {}) or {}
            ),
            "result_schema_sha256": canonical_sha256(
                getattr(procedure, "result_schema", {}) or {}
            ),
        },
    }
