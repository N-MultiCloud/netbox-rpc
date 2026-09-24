"""Immutable runtime contract for the issue-#605 release-marker reconcile apply.

Migration 0098 keeps its own inline copy so historical migrations remain
deterministic. Tests require that copy and this runtime policy to stay
exactly aligned. Only ``reconcile`` needs a protected contract: ``check`` is
``approval_required=False`` and never reaches the two-person approval path
this module backs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "service.nmulticloud.deploy.release_marker_reconcile"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
TARGET_MODELS = ["dcim.device"]
EFFECT = "destructive"
TIMEOUT_SECONDS = 300
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
        "argv": [
            "/opt/nmulticloud/deploy/bin/reconcile-release-marker",
            "{app}",
            "--apply",
        ],
        "description": (
            "Rewrite the active release marker to the running container's "
            "image ref, but only when the marker's own image is missing and "
            "the running image exists with a full 40-hex tag. Backend "
            "parses only the closed key=value report."
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
    "required": ["app"],
    "properties": {
        "app": {
            "type": "string",
            "enum": ["nms-backend-staging", "nms-backend"],
        },
    },
}

RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "app", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"type": "string", "maxLength": 255},
        "app": {"type": "string", "enum": ["nms-backend-staging", "nms-backend"]},
        "before_ref": {
            "type": ["string", "null"],
            "pattern": "^([0-9a-f]{40}|none)$",
        },
        "after_ref": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
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
                "before_ref": {"type": "string"},
                "after_ref": {"type": "string"},
            },
            "required": ["before_ref", "after_ref"],
        },
        {
            "properties": {
                "ok": {"const": False},
                "stage": {"const": "execute"},
                "before_ref": {"const": None},
                "after_ref": {"const": None},
            },
        },
        {
            "properties": {
                "ok": {"const": False},
                "stage": {"const": "indeterminate"},
                "before_ref": {"const": None},
                "after_ref": {"const": None},
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
