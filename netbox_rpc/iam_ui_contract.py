"""Immutable catalog and runtime contract for fixed IAM UI operations."""

from __future__ import annotations

import hashlib
import json
from typing import Any

PREFIX = "service.keycloak.iam_ui."
MODES = ("inspect", "configure", "certificate", "activate")
HANDLER_IDS = frozenset(PREFIX + mode for mode in MODES)
WRITE_HANDLER_IDS = HANDLER_IDS - {PREFIX + "inspect"}
TARGET_NAME = "nmc-prod-207"
TARGET_MODEL = "dcim.device"
TARGET_OBJECT_ID = 44
HELPER = "/opt/nmulticloud/deploy/keycloak/bin/iam-ui-control"
TIMEOUTS = dict(zip(MODES, (60, 180, 240, 60), strict=True))
MAX_OUTPUT_BYTES = 2048
TRANSPORT_PINNED = True
PARAMS_SCHEMA = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
TARGET_OBJECT_SCHEMA = {
    "type": "object",
    "required": ["content_type", "object_id"],
    "additionalProperties": False,
    "properties": {
        "content_type": {"const": TARGET_MODEL},
        "object_id": {"const": TARGET_OBJECT_ID},
    },
}
RESPONSE_KEYS = (
    "ok",
    "operation",
    "admin_ready",
    "bootstrap_available",
    "certificate_present",
    "tls_active",
)
DESCRIPTIONS = {
    "inspect": "Report only fixed IAM UI readiness without changing the host.",
    "configure": "Configure only the dedicated IAM client and fixed NMS integration.",
    "certificate": "Issue only the dedicated IAM UI certificate through HTTP-01.",
    "activate": "Activate only the reviewed IAM UI TLS virtual host.",
}


def canonical_sha256(value: object) -> str:
    """Hash the shared compact canonical JSON representation."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def command(mode: str) -> dict[str, Any]:
    """Return the exact representative command row."""
    return {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "keycloak-iam-ui-" + mode],
        "description": DESCRIPTIONS[mode],
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
        "render_mode": "literal",
        "produces_var": "",
        "capture_kind": "",
        "capture_expression": "",
    }


def fingerprint_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["handler_id", "procedure", "target_object", "argv_sha256"],
        "additionalProperties": False,
        "properties": {
            "handler_id": {"const": handler_id},
            "procedure": {"const": handler_id},
            "target_object": TARGET_OBJECT_SCHEMA,
            "argv_sha256": {
                "const": canonical_sha256(["sudo", "-n", HELPER, handler_id.removeprefix(PREFIX)])
            },
        },
    }


def normalized_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["target", "target_object", "command_fingerprint"],
        "additionalProperties": False,
        "properties": {
            "target": {"const": TARGET_NAME},
            "target_object": TARGET_OBJECT_SCHEMA,
            "command_fingerprint": fingerprint_schema(handler_id),
        },
    }


def result_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "ok",
            "procedure",
            "target",
            "operation",
            "status",
            "retry_requires_inspect",
            "readiness",
        ],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"const": handler_id},
            "target": {"const": TARGET_NAME},
            "operation": {"const": handler_id.removeprefix(PREFIX)},
            "status": {"enum": ["succeeded", "failed", "indeterminate"]},
            "retry_requires_inspect": {"type": "boolean"},
            "readiness": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "required": list(RESPONSE_KEYS),
                        "additionalProperties": False,
                        "properties": {
                            **{
                                key: {"type": "boolean"}
                                for key in RESPONSE_KEYS
                                if key != "operation"
                            },
                            "ok": {"const": True},
                            "operation": {"const": handler_id.removeprefix(PREFIX)},
                        },
                    },
                ],
            },
        },
    }


NORMALIZED_PARAMS_SCHEMAS = {name: normalized_schema(name) for name in HANDLER_IDS}
COMMAND_FINGERPRINT_SCHEMAS = {name: fingerprint_schema(name) for name in HANDLER_IDS}
RESULT_SCHEMAS = {name: result_schema(name) for name in HANDLER_IDS}
PROCEDURE_POLICIES = {
    PREFIX + mode: {
        "name": PREFIX + mode,
        "handler_id": PREFIX + mode,
        "version": 1,
        "enabled": True,
        "description": DESCRIPTIONS[mode],
        "effect": "read" if mode == "inspect" else "write",
        "timeout_seconds": TIMEOUTS[mode],
        "approval_required": mode != "inspect",
        "target_models": [TARGET_MODEL],
        "params_schema": PARAMS_SCHEMA,
        "result_schema": RESULT_SCHEMAS[PREFIX + mode],
        "transport_driver": "asyncssh",
        "transport_pinned": True,
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
    }
    for mode in MODES
}
RUNTIME_CONTRACT = {
    "target": {"name": TARGET_NAME, "content_type": TARGET_MODEL, "object_id": TARGET_OBJECT_ID},
    "helper": HELPER,
    "argv": ["sudo", "-n", HELPER, "<fixed-operation>"],
    "host_timeouts": TIMEOUTS,
    "transport": {"driver": "asyncssh", "strict_auth": True, "allow_fallback": False},
    "capture_max_bytes": MAX_OUTPUT_BYTES,
    "result_keys": list(RESPONSE_KEYS),
    "credentials": "current-strict-target-owned-no-overrides",
    "indeterminate_requires_inspect": True,
    "automatic_retry": False,
}


def _field(procedure: object, key: str) -> Any:
    return procedure[key] if isinstance(procedure, dict) else getattr(procedure, key)


def semantic_capability_extension(procedure: object) -> dict[str, Any]:
    """Derive semantic policy from actual catalog fields, including drift."""
    name = _field(procedure, "name")
    policy = {
        key: _field(procedure, key)
        for key in (
            "name",
            "description",
            "target_models",
            "timeout_seconds",
            "approval_required",
            "transport_driver",
            "transport_pinned",
            "transport_driver_chain",
            "output_parser",
        )
    }
    for field in ("output_schema", "params_schema", "result_schema"):
        policy[field + "_sha256"] = canonical_sha256(_field(procedure, field))
    policy["normalized_params_schema_sha256"] = canonical_sha256(NORMALIZED_PARAMS_SCHEMAS[name])
    policy["command_fingerprint_schema_sha256"] = canonical_sha256(
        COMMAND_FINGERPRINT_SCHEMAS[name]
    )
    return {"procedure_policy": policy, "runtime": RUNTIME_CONTRACT}


SEMANTIC_CAPABILITY_EXTENSIONS = {
    name: semantic_capability_extension(policy) for name, policy in PROCEDURE_POLICIES.items()
}
SEMANTIC_CAPABILITY_SHA256 = {
    name: canonical_sha256(value) for name, value in SEMANTIC_CAPABILITY_EXTENSIONS.items()
}
PROTECTED_PROCEDURE_POLICIES = {
    name: {
        **{
            key: policy[key]
            for key in (
                "name",
                "handler_id",
                "version",
                "enabled",
                "target_models",
                "effect",
                "timeout_seconds",
                "approval_required",
                "transport_driver",
                "transport_pinned",
                "transport_driver_chain",
                "output_parser",
                "output_schema",
            )
        },
        "command_contract_sha256": canonical_sha256([command(name.removeprefix(PREFIX))]),
        "semantic_contract_sha256": SEMANTIC_CAPABILITY_SHA256[name],
    }
    for name, policy in PROCEDURE_POLICIES.items()
    if name in WRITE_HANDLER_IDS
}
PROCEDURE_POLICY = PROTECTED_PROCEDURE_POLICIES[PREFIX + "configure"]
