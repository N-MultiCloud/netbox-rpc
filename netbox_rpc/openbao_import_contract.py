"""Immutable runtime contract for the netbox-openbao credential importer apply.

Migration 0096 keeps its own inline copy so historical migrations remain
deterministic. Tests require that copy and this runtime policy to stay exactly
aligned. Only ``apply`` needs a protected contract: ``dry_run`` is
``approval_required=False`` and never reaches the two-person approval path
this module backs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "service.netbox.openbao_import.apply"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
TARGET_MODELS = ["dcim.device"]
EFFECT = "destructive"
TIMEOUT_SECONDS = 900
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_DRIVER_CHAIN: list[str] = []
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}

COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "netbox-openbao-import", "{environment}"],
        "description": (
            "Backend maps environment to a fixed NetBox root/venv for "
            f"{PROCEDURE_NAME} and parses only the importer's bounded "
            "summary counts."
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
    "type": "object",
    "additionalProperties": False,
    "required": ["environment"],
    "properties": {
        "environment": {
            "type": "string",
            "enum": ["staging", "production"],
        },
    },
}

_SOURCE_MODEL_KEYS = [
    "device_credential",
    "device_service",
    "user_ssh_key",
    "proxmox_binding",
    "cloud_vm_credential",
    "observability_secret",
]

_SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": _SOURCE_MODEL_KEYS,
    "properties": {
        key: {"type": "integer", "minimum": 0, "maximum": 1000000}
        for key in _SOURCE_MODEL_KEYS
    },
}

RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "environment", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"type": "string", "maxLength": 255},
        "environment": {"type": "string", "enum": ["staging", "production"]},
        "summary": {"type": ["object", "null"], **_SUMMARY_SCHEMA},
        "stage": {
            "type": "string",
            "enum": ["execute", "complete", "indeterminate"],
        },
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "stage": {"const": "complete"},
                "summary": _SUMMARY_SCHEMA,
            },
            "required": ["summary"],
        },
        {
            "properties": {
                "ok": {"const": False},
                "stage": {"const": "execute"},
                "summary": {"const": None},
            },
        },
        {
            "properties": {
                "ok": {"const": False},
                "stage": {"const": "indeterminate"},
                "summary": {"const": None},
            },
        },
    ],
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
}


PROCEDURE_POLICY_SHA256 = canonical_sha256(PROCEDURE_POLICY)
COMMAND_CONTRACT_SHA256 = canonical_sha256(COMMAND_CONTRACT)
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
RESULT_SCHEMA_SHA256 = canonical_sha256(RESULT_SCHEMA)
