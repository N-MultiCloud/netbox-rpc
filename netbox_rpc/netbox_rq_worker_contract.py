"""Semantic capability contract for the production NetBox RQ worker."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .constants import (
    NETBOX_PRODUCTION_RESTART_RQ_WORKER,
    NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES,
    NETBOX_PRODUCTION_STATUS_RQ_WORKER,
)

TARGET_NAME = "nmc-prod-207"
TARGET_MODEL = "dcim.device"
TARGET_OBJECT_ID = 44
COMPOSE_PROJECT = "nmc-netbox"
COMPOSE_FILE = "/opt/nmulticloud/deploy/compose/netbox.compose.yaml"
COMPOSE_ENV_FILE = "/opt/nmulticloud/deploy/env/netbox.compose.env"
COMPOSE_SERVICE = "netbox-rq"
STATUS_TIMEOUT_SECONDS = 45
RESTART_TIMEOUT_SECONDS = 150
WAIT_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 8192
CONTROL_QUEUE_NAME = "netbox_rpc.control"
CONTROL_QUEUE_MAX_AGE_SECONDS = 600
CONTROL_WORKER_HEARTBEAT_MAX_AGE_SECONDS = 120
# RQ sleeps for worker_ttl - 15 seconds while idle. Keep the dedicated worker's
# cadence inside the admission window; RQ's 420-second default is too slow.
CONTROL_WORKER_TTL_SECONDS = 90
EXPIRY_SWEEP_INTERVAL_MINUTES = 1
EXPIRY_SWEEP_QUEUE_NAME = "default"
BACKEND_RESPONSE_MAX_BYTES = 16384
BACKEND_ROUTE_BUDGET_SECONDS = {
    NETBOX_PRODUCTION_STATUS_RQ_WORKER: 55,
    NETBOX_PRODUCTION_RESTART_RQ_WORKER: 160,
}
TRANSPORT_PINNED = True

PARAMS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}

_TARGET_OBJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["content_type", "object_id"],
    "additionalProperties": False,
    "properties": {
        "content_type": {"const": TARGET_MODEL},
        "object_id": {"const": TARGET_OBJECT_ID},
    },
}


def _fingerprint(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _command_fingerprint_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["handler_id", "procedure", "target_object"],
        "additionalProperties": False,
        "properties": {
            "handler_id": {"const": handler_id},
            "procedure": {"const": handler_id},
            "target_object": _TARGET_OBJECT_SCHEMA,
        },
    }


def _normalized_params_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["target", "target_object", "command_fingerprint"],
        "additionalProperties": False,
        "properties": {
            "target": {"const": TARGET_NAME},
            "target_object": _TARGET_OBJECT_SCHEMA,
            "command_fingerprint": _command_fingerprint_schema(handler_id),
        },
    }


def _result_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "ok",
            "procedure",
            "target",
            "project",
            "service",
            "status",
            "phase",
            "retry_requires_status_check",
            "state",
            "health",
            "container",
            "exit_code",
            "output",
        ],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"const": handler_id},
            "target": {"const": TARGET_NAME},
            "project": {"const": COMPOSE_PROJECT},
            "service": {"const": COMPOSE_SERVICE},
            "status": {
                "enum": [
                    "running",
                    "stopped",
                    "degraded",
                    "missing",
                    "status_failed",
                    "restart_failed",
                    "timeout",
                    "indeterminate",
                ]
            },
            "phase": {"enum": ["status", "restart", "readiness"]},
            "retry_requires_status_check": {"type": "boolean"},
            "state": {"type": "string", "maxLength": 64},
            "health": {"type": "string", "maxLength": 64},
            "container": {"type": "string", "maxLength": 255},
            "exit_code": {"type": "integer"},
            "output": {"type": "string", "maxLength": MAX_OUTPUT_BYTES},
        },
    }


NORMALIZED_PARAMS_SCHEMAS = {
    handler_id: _normalized_params_schema(handler_id)
    for handler_id in NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES
}
COMMAND_FINGERPRINT_SCHEMAS = {
    handler_id: _command_fingerprint_schema(handler_id)
    for handler_id in NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES
}
RESULT_SCHEMAS = {
    handler_id: _result_schema(handler_id)
    for handler_id in NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES
}

PROCEDURE_POLICIES: dict[str, dict[str, Any]] = {
    NETBOX_PRODUCTION_STATUS_RQ_WORKER: {
        "name": NETBOX_PRODUCTION_STATUS_RQ_WORKER,
        "description": (
            "Report the production NetBox Compose RQ worker status without changing it."
        ),
        "target_models": [TARGET_MODEL],
        "timeout_seconds": STATUS_TIMEOUT_SECONDS,
        "approval_required": False,
        "transport_driver": "asyncssh",
        "transport_pinned": True,
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "params_schema": PARAMS_SCHEMA,
        "result_schema": RESULT_SCHEMAS[NETBOX_PRODUCTION_STATUS_RQ_WORKER],
    },
    NETBOX_PRODUCTION_RESTART_RQ_WORKER: {
        "name": NETBOX_PRODUCTION_RESTART_RQ_WORKER,
        "description": (
            "Restart only the production NetBox Compose RQ worker and wait until it is running."
        ),
        "target_models": [TARGET_MODEL],
        "timeout_seconds": RESTART_TIMEOUT_SECONDS,
        "approval_required": True,
        "transport_driver": "asyncssh",
        "transport_pinned": True,
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "params_schema": PARAMS_SCHEMA,
        "result_schema": RESULT_SCHEMAS[NETBOX_PRODUCTION_RESTART_RQ_WORKER],
    },
}

RUNTIME_CONTRACT: dict[str, Any] = {
    "target": {
        "name": TARGET_NAME,
        "content_type": TARGET_MODEL,
        "object_id": TARGET_OBJECT_ID,
    },
    "compose": {
        "binary": "/usr/bin/docker",
        "file": COMPOSE_FILE,
        "environment_file": COMPOSE_ENV_FILE,
        "project": COMPOSE_PROJECT,
        "service": COMPOSE_SERVICE,
        "restart_scope": "single-service",
        "status_format": "json",
    },
    "restart_readiness": {
        "required_state": "running",
        "wait_timeout_seconds": WAIT_TIMEOUT_SECONDS,
    },
    "transport": {
        "driver": "asyncssh",
        "strict_auth": True,
        "allow_fallback": False,
        "stream_capture_max_bytes": MAX_OUTPUT_BYTES,
        "capture_overflow": "indeterminate",
    },
    "indeterminate_outcome": {
        "phases": ["status", "restart", "readiness"],
        "status_check_required_before_retry": True,
    },
    "control_queue": {
        "name": CONTROL_QUEUE_NAME,
        "procedure_names": sorted(NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES),
        "worker_heartbeat_max_age_seconds": CONTROL_WORKER_HEARTBEAT_MAX_AGE_SECONDS,
        "restart_queue_max_age_seconds": CONTROL_QUEUE_MAX_AGE_SECONDS,
        "expiry_sweep_interval_minutes": EXPIRY_SWEEP_INTERVAL_MINUTES,
        "expiry_sweep_queue": EXPIRY_SWEEP_QUEUE_NAME,
    },
    "http_transport": {
        "route_budget_seconds": BACKEND_ROUTE_BUDGET_SECONDS,
        "stream_response": True,
        "response_max_bytes": BACKEND_RESPONSE_MAX_BYTES,
        "allow_redirects": False,
        "ambiguous_failure": "reconciliation_required",
    },
    "reconciliation": {
        "restart_launch_ambiguity_requires_status_check": True,
        "post_restart_readiness_failure_requires_status_check": True,
    },
    "result_output_max_bytes": MAX_OUTPUT_BYTES,
}


def canonical_sha256(value: object) -> str:
    """Return the shared compact canonical JSON digest."""
    return _fingerprint(value)


def _semantic_capability_contract(handler_id: str) -> dict[str, Any]:
    """Build the immutable semantic extension for one catalog procedure."""
    policy = PROCEDURE_POLICIES[handler_id]
    return {
        "procedure_policy": {
            "name": handler_id,
            "description": policy["description"],
            "target_models": sorted(policy["target_models"]),
            "timeout_seconds": policy["timeout_seconds"],
            "approval_required": policy["approval_required"],
            "transport_driver": policy["transport_driver"],
            "transport_pinned": policy["transport_pinned"],
            "transport_driver_chain": policy["transport_driver_chain"],
            "output_parser": policy["output_parser"],
            "output_schema_sha256": _fingerprint(policy["output_schema"]),
            "params_schema_sha256": _fingerprint(policy["params_schema"]),
            "result_schema_sha256": _fingerprint(policy["result_schema"]),
            "normalized_params_schema_sha256": _fingerprint(
                NORMALIZED_PARAMS_SCHEMAS[handler_id]
            ),
            "command_fingerprint_schema_sha256": _fingerprint(
                COMMAND_FINGERPRINT_SCHEMAS[handler_id]
            ),
        },
        "runtime": RUNTIME_CONTRACT,
    }


SEMANTIC_CAPABILITY_SHA256 = {
    handler_id: canonical_sha256(_semantic_capability_contract(handler_id))
    for handler_id in NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES
}


PROCEDURE_POLICY = {
    "name": NETBOX_PRODUCTION_RESTART_RQ_WORKER,
    "handler_id": NETBOX_PRODUCTION_RESTART_RQ_WORKER,
    "version": 1,
    "enabled": True,
    "target_models": [TARGET_MODEL],
    "effect": "write",
    "timeout_seconds": RESTART_TIMEOUT_SECONDS,
    "approval_required": True,
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "command_contract_sha256": canonical_sha256(
        [
            {
                "sequence": 1,
                "step_type": "shell_argv",
                "device_cli_mode": "",
                "argv": ["backend-orchestrated", "netbox-production-restart-rq-worker"],
                "description": (
                    "Restart only the production NetBox Compose RQ worker and wait until it is running."
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
    ),
    "semantic_contract_sha256": SEMANTIC_CAPABILITY_SHA256[
        NETBOX_PRODUCTION_RESTART_RQ_WORKER
    ],
    "transport_pinned": True,
}
PROTECTED_PROCEDURE_POLICIES = {
    NETBOX_PRODUCTION_RESTART_RQ_WORKER: PROCEDURE_POLICY,
}


def semantic_capability_extension(procedure: Any) -> dict[str, Any]:
    """Bind the advertised handler to catalog policy and Compose semantics."""
    procedure_name = str(getattr(procedure, "name", ""))
    return {
        "procedure_policy": {
            "name": procedure_name,
            "description": str(getattr(procedure, "description", "")),
            "target_models": sorted(getattr(procedure, "target_models", []) or []),
            "timeout_seconds": int(getattr(procedure, "timeout_seconds", 0) or 0),
            "approval_required": bool(
                getattr(procedure, "approval_required", False)
            ),
            "transport_driver": str(getattr(procedure, "transport_driver", "")),
            "transport_pinned": bool(
                getattr(procedure, "transport_pinned", False)
            ),
            "transport_driver_chain": list(
                getattr(procedure, "transport_driver_chain", []) or []
            ),
            "output_parser": str(getattr(procedure, "output_parser", "")),
            "output_schema_sha256": _fingerprint(
                getattr(procedure, "output_schema", {}) or {}
            ),
            "params_schema_sha256": _fingerprint(
                getattr(procedure, "params_schema", {}) or {}
            ),
            "result_schema_sha256": _fingerprint(
                getattr(procedure, "result_schema", {}) or {}
            ),
            "normalized_params_schema_sha256": _fingerprint(
                NORMALIZED_PARAMS_SCHEMAS[procedure_name]
            ),
            "command_fingerprint_schema_sha256": _fingerprint(
                COMMAND_FINGERPRINT_SCHEMAS[procedure_name]
            ),
        },
        "runtime": RUNTIME_CONTRACT,
    }


__all__ = [
    "BACKEND_RESPONSE_MAX_BYTES",
    "BACKEND_ROUTE_BUDGET_SECONDS",
    "COMMAND_FINGERPRINT_SCHEMAS",
    "COMPOSE_ENV_FILE",
    "COMPOSE_FILE",
    "COMPOSE_PROJECT",
    "COMPOSE_SERVICE",
    "CONTROL_QUEUE_MAX_AGE_SECONDS",
    "CONTROL_QUEUE_NAME",
    "CONTROL_WORKER_HEARTBEAT_MAX_AGE_SECONDS",
    "EXPIRY_SWEEP_INTERVAL_MINUTES",
    "EXPIRY_SWEEP_QUEUE_NAME",
    "MAX_OUTPUT_BYTES",
    "NORMALIZED_PARAMS_SCHEMAS",
    "PARAMS_SCHEMA",
    "PROCEDURE_POLICIES",
    "PROCEDURE_POLICY",
    "PROTECTED_PROCEDURE_POLICIES",
    "RESTART_TIMEOUT_SECONDS",
    "RESULT_SCHEMAS",
    "RUNTIME_CONTRACT",
    "SEMANTIC_CAPABILITY_SHA256",
    "STATUS_TIMEOUT_SECONDS",
    "TARGET_MODEL",
    "TARGET_NAME",
    "TARGET_OBJECT_ID",
    "TRANSPORT_PINNED",
    "WAIT_TIMEOUT_SECONDS",
    "canonical_sha256",
    "semantic_capability_extension",
]
