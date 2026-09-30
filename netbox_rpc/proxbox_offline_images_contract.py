"""Immutable catalog contract for proxbox-api offline-image recovery."""

from __future__ import annotations

import hashlib
import json
from typing import Any

DIAGNOSE_PROCEDURE_NAME = "service.nmulticloud.deploy.diagnose_proxbox_api_images"
PRELOAD_PROCEDURE_NAME = "service.nmulticloud.deploy.preload_proxbox_api_images"
PROCEDURE_NAMES = frozenset({DIAGNOSE_PROCEDURE_NAME, PRELOAD_PROCEDURE_NAME})
VERSION = 1
TARGET_MODELS = ["dcim.device"]
DIAGNOSE_EFFECT = "read"
PRELOAD_EFFECT = "write"
DIAGNOSE_TIMEOUT_SECONDS = 120
PRELOAD_TIMEOUT_SECONDS = 2100
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_DRIVER_CHAIN: list[str] = []
TRANSPORT_PINNED = True
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}
TARGET_BINDING_SLUG = "nmulticloud-deploy-host"
MANIFEST_SHA256_PATTERN = "^[a-f0-9]{64}$"
IMAGE_REFERENCE_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,439}@sha256:[a-f0-9]{64}$"
)
IMAGE_ID_PATTERN = "^sha256:[a-f0-9]{64}$"
MAX_IMAGES = 8
BACKEND_RESPONSE_MAX_BYTES = 8192
PRELOAD_ROUTE_BUDGET_SECONDS = 1950
PRELOAD_SSH_BUDGET_SECONDS = 1920

PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["manifest_sha256"],
    "properties": {
        "manifest_sha256": {
            "type": "string",
            "pattern": MANIFEST_SHA256_PATTERN,
        }
    },
}

IMAGE_STATUS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["image", "present", "image_id"],
    "properties": {
        "image": {
            "type": "string",
            "minLength": 3,
            "maxLength": 512,
            "pattern": IMAGE_REFERENCE_PATTERN,
        },
        "present": {"type": "boolean"},
        "image_id": {
            "type": ["string", "null"],
            "pattern": IMAGE_ID_PATTERN,
        },
    },
    "oneOf": [
        {
            "properties": {
                "present": {"const": True},
                "image_id": {"type": "string", "pattern": IMAGE_ID_PATTERN},
            }
        },
        {
            "properties": {
                "present": {"const": False},
                "image_id": {"const": None},
            }
        },
    ],
}


def _result_schema(procedure: str, stages: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "ok",
            "procedure",
            "target",
            "manifest_sha256",
            "stage",
            "images",
        ],
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"type": "string", "const": procedure},
            "target": {"type": "string", "minLength": 1, "maxLength": 255},
            "manifest_sha256": {
                "type": "string",
                "pattern": MANIFEST_SHA256_PATTERN,
            },
            "stage": {"type": "string", "enum": stages},
            "images": {
                "type": ["array", "null"],
                "items": IMAGE_STATUS_SCHEMA,
                "minItems": 1,
                "maxItems": MAX_IMAGES,
            },
        },
        "oneOf": [
            {
                "properties": {
                    "ok": {"const": True},
                    "stage": {"const": "complete"},
                    "images": {"type": "array"},
                }
            },
            {
                "properties": {
                    "ok": {"const": False},
                    "stage": {"enum": [stage for stage in stages if stage != "complete"]},
                    "images": {"const": None},
                }
            },
        ],
    }


DIAGNOSE_RESULT_SCHEMA = _result_schema(
    DIAGNOSE_PROCEDURE_NAME,
    ["complete", "execute"],
)
PRELOAD_RESULT_SCHEMA = _result_schema(
    PRELOAD_PROCEDURE_NAME,
    ["complete", "execute", "indeterminate"],
)


def _command(action: str) -> list[dict[str, Any]]:
    return [
        {
            "sequence": 1,
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": [action, "{manifest_sha256}"],
            "description": (
                "Invoke the fixed deploy-host gateway action for the exact "
                "approved proxbox-api release manifest."
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


COMMAND_CONTRACTS = {
    DIAGNOSE_PROCEDURE_NAME: _command("diagnose-proxbox-api-images"),
    PRELOAD_PROCEDURE_NAME: _command("preload-proxbox-api-images"),
}

SEMANTIC_CONTRACTS = {
    DIAGNOSE_PROCEDURE_NAME: {
        "target_binding_slug": TARGET_BINDING_SLUG,
        "params_schema": PARAMS_SCHEMA,
        "result_schema": DIAGNOSE_RESULT_SCHEMA,
        "runtime": {"response_max_bytes": BACKEND_RESPONSE_MAX_BYTES},
    },
    PRELOAD_PROCEDURE_NAME: {
        "target_binding_slug": TARGET_BINDING_SLUG,
        "params_schema": PARAMS_SCHEMA,
        "result_schema": PRELOAD_RESULT_SCHEMA,
        "outcome_policy": "post-process-non-clean-is-indeterminate-no-auto-retry",
        "runtime": {
            "route_budget_seconds": PRELOAD_ROUTE_BUDGET_SECONDS,
            "ssh_budget_seconds": PRELOAD_SSH_BUDGET_SECONDS,
            "response_max_bytes": BACKEND_RESPONSE_MAX_BYTES,
        },
    },
}


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_CAPABILITY_COMMAND_KEYS = (
    "sequence",
    "step_type",
    "device_cli_mode",
    "argv",
    "render_mode",
    "produces_var",
    "capture_kind",
    "capture_expression",
    "condition_param",
    "condition_negate",
    "for_each_param",
    "continue_on_error",
)


def capability_contract(procedure_name: str, effect: str) -> dict[str, Any]:
    return {
        "handler_id": procedure_name,
        "version": VERSION,
        "effect": effect,
        "commands": [
            {key: command[key] for key in _CAPABILITY_COMMAND_KEYS}
            for command in COMMAND_CONTRACTS[procedure_name]
        ],
        "semantic_contract": SEMANTIC_CONTRACTS[procedure_name],
    }


CAPABILITY_CONTRACT_SHA256 = {
    DIAGNOSE_PROCEDURE_NAME: canonical_sha256(
        capability_contract(DIAGNOSE_PROCEDURE_NAME, DIAGNOSE_EFFECT)
    ),
    PRELOAD_PROCEDURE_NAME: canonical_sha256(
        capability_contract(PRELOAD_PROCEDURE_NAME, PRELOAD_EFFECT)
    ),
}
EXPECTED_CAPABILITY_CONTRACT_SHA256 = {
    DIAGNOSE_PROCEDURE_NAME: (
        "71e42d76abf0bc72e3782cef7c09c20007f363cf695f1a1fe31d90ce80baeaf7"
    ),
    PRELOAD_PROCEDURE_NAME: (
        "ef7feef5ff142c8a2632076e02024a7c96b00387035eff578f974d4523729935"
    ),
}
if CAPABILITY_CONTRACT_SHA256 != EXPECTED_CAPABILITY_CONTRACT_SHA256:
    raise RuntimeError("proxbox offline-image capability contract hash drifted")
SEMANTIC_CAPABILITY_SHA256 = {
    procedure_name: canonical_sha256(semantic_contract)
    for procedure_name, semantic_contract in SEMANTIC_CONTRACTS.items()
}

RESULT_SCHEMAS = {
    DIAGNOSE_PROCEDURE_NAME: DIAGNOSE_RESULT_SCHEMA,
    PRELOAD_PROCEDURE_NAME: PRELOAD_RESULT_SCHEMA,
}

PROCEDURE_POLICY = {
    "name": PRELOAD_PROCEDURE_NAME,
    "handler_id": PRELOAD_PROCEDURE_NAME,
    "version": VERSION,
    "enabled": True,
    "target_models": TARGET_MODELS,
    "effect": PRELOAD_EFFECT,
    "timeout_seconds": PRELOAD_TIMEOUT_SECONDS,
    "approval_required": True,
    "transport_driver": TRANSPORT_DRIVER,
    "transport_pinned": TRANSPORT_PINNED,
    "transport_driver_chain": TRANSPORT_DRIVER_CHAIN,
    "output_parser": OUTPUT_PARSER,
    "output_schema": OUTPUT_SCHEMA,
    "command_contract_sha256": canonical_sha256(
        COMMAND_CONTRACTS[PRELOAD_PROCEDURE_NAME]
    ),
    "semantic_contract_sha256": canonical_sha256(
        SEMANTIC_CONTRACTS[PRELOAD_PROCEDURE_NAME]
    ),
}
