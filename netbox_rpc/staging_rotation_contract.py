"""Immutable runtime contract for staging backend-token rotation.

Migration 0068 keeps its own inline copy so historical migrations remain
deterministic. Tests require that copy and this runtime policy to stay exactly
aligned.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "service.netbox.staging.rotate_backend_token"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
TARGET_MODELS = ["dcim.device"]
EFFECT = "destructive"
TIMEOUT_SECONDS = 1800
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
        "argv": ["backend-orchestrated", "netbox-staging-rotate-backend-token"],
        "description": (
            "Backend invokes the fixed root-owned staging-token provisioner; "
            "no token value is accepted as argv, persisted, or returned."
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
    "properties": {},
}

RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "rotated", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"const": "nms-front-door"},
        "rotated": {"type": ["boolean", "null"]},
        "stage": {
            "type": "string",
            "enum": ["execute", "complete", "indeterminate"],
        },
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "rotated": {"const": True},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "rotated": {"const": False},
                "stage": {"const": "execute"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "rotated": {"const": True},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "rotated": {"const": None},
                "stage": {"const": "indeterminate"},
            }
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
