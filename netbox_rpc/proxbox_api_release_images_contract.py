"""Immutable protected contract for retained proxbox-api image recovery."""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "service.proxbox_api.release_images.recover"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
TARGET_MODELS = ["dcim.device"]
EFFECT = "destructive"
TIMEOUT_SECONDS = 1200
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_PINNED = True
TRANSPORT_DRIVER_CHAIN: list[str] = []
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}
PARAMS_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["recover-proxbox-api-release-images"],
        "description": (
            "Inspect or recover only the immutable images bound to the retained "
            "proxbox-api pre-activation transaction."
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

IMAGE_SCHEMA = {
    "type": "object",
    "required": ["image", "present", "image_id"],
    "additionalProperties": False,
    "properties": {
        "image": {
            "type": "string",
            "pattern": r"^[^\s]+@sha256:[a-f0-9]{64}$",
            "maxLength": 512,
        },
        "present": {"const": True},
        "image_id": {"type": "string", "pattern": r"^sha256:[a-f0-9]{64}$"},
    },
}
RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "mode", "images", "ready"],
    "additionalProperties": False,
    "properties": {
        "ok": {"const": True},
        "procedure": {"const": PROCEDURE_NAME},
        "target": {"const": "nmc-prod-207"},
        "mode": {"const": "recover"},
        "images": {
            "type": "array",
            "items": IMAGE_SCHEMA,
            "minItems": 1,
            "maxItems": 16,
        },
        "ready": {"const": True},
    },
}


def canonical_sha256(value: Any) -> str:
    """Return a stable SHA-256 fingerprint for a JSON-compatible value."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
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
