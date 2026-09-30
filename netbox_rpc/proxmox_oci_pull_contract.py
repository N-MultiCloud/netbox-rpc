"""Immutable protected contract for the Proxmox OCI registry pull."""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "os.linux.proxmox.oci_registry_pull"
HANDLER_ID = "os.linux_proxmox.oci_registry_pull"
VERSION = 1
TARGET_MODELS = ["netbox_proxbox.proxmoxendpoint"]
EFFECT = "write"
TIMEOUT_SECONDS = 3720
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_DRIVER_CHAIN: list[str] = []
TRANSPORT_PINNED = True
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}

COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "proxmox-oci-registry-pull"],
        "description": (
            "Backend runs one fixed pvesh OCI registry pull with fallback disabled."
        ),
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
        "render_mode": "literal",
        "produces_var": "",
        "capture_kind": "",
        "capture_expression": "",
    }
]

PARAMS_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "proxmox_endpoint_id": {"minimum": 1, "type": "integer"},
        "node": {
            "maxLength": 64,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
            "type": "string",
        },
        "storage": {
            "maxLength": 64,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
            "type": "string",
        },
        "reference": {
            "description": (
                "Explicitly tagged public Docker Hub netbox-proxbox appliance reference."
            ),
            "maxLength": 179,
            "pattern": (
                "^(?:docker[.]io/)?emersonfelipesp/netbox-proxbox:"
                "[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
            ),
            "type": "string",
        },
        "filename": {
            "maxLength": 255,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$",
            "type": "string",
        },
    },
    "required": ["proxmox_endpoint_id", "node", "storage", "reference"],
    "type": "object",
}

RESULT_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID, "type": "string"},
        "target": {"type": "string"},
        "node": {"type": "string"},
        "storage": {"type": "string"},
        "reference": {"type": "string"},
        "filename": {"type": ["string", "null"]},
        "upid": {"type": ["string", "null"]},
        "exit_code": {"type": "integer"},
        "stderr": {"type": "string"},
        "stage": {
            "enum": ["complete", "execute", "indeterminate"],
            "type": "string",
        },
    },
    "required": [
        "ok",
        "procedure",
        "target",
        "node",
        "storage",
        "reference",
        "filename",
        "upid",
        "exit_code",
        "stderr",
        "stage",
    ],
    "type": "object",
}


def canonical_sha256(value: Any) -> str:
    """Return a stable SHA-256 fingerprint for a JSON-compatible value."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


PROCEDURE_POLICY = {
    "name": PROCEDURE_NAME,
    "handler_id": HANDLER_ID,
    "version": VERSION,
    "enabled": True,
    "target_models": TARGET_MODELS,
    "effect": EFFECT,
    "timeout_seconds": TIMEOUT_SECONDS,
    "approval_required": APPROVAL_REQUIRED,
    "transport_driver": TRANSPORT_DRIVER,
    "transport_driver_chain": TRANSPORT_DRIVER_CHAIN,
    "output_parser": OUTPUT_PARSER,
    "output_schema": OUTPUT_SCHEMA,
    "command_contract_sha256": canonical_sha256(COMMAND_CONTRACT),
    "transport_pinned": TRANSPORT_PINNED,
}

PROCEDURE_POLICY_SHA256 = canonical_sha256(PROCEDURE_POLICY)
COMMAND_CONTRACT_SHA256 = canonical_sha256(COMMAND_CONTRACT)
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
RESULT_SCHEMA_SHA256 = canonical_sha256(RESULT_SCHEMA)
