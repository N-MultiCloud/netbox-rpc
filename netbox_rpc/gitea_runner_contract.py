"""Immutable catalog contract for composite Gitea runner registration.

The backend obtains the reusable Gitea bootstrap token on the fixed Gitea VM
and immediately consumes it on the fixed isolated-runner VM.  The token is not
accepted from a caller and is never part of the RPC result or event stream.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "service.gitea.runner.register"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
ROUTE_BUDGET_SECONDS = 300
HANDLER_BUDGET_SECONDS = 270
PREFLIGHT_TIMEOUT_SECONDS = 30
TOKEN_TIMEOUT_SECONDS = 30
REGISTER_TIMEOUT_SECONDS = 150
RESET_TIMEOUT_SECONDS = 30
CAPTURE_MAX_BYTES = 512
BACKEND_RESPONSE_MAX_BYTES = 4096
RECONCILIATION_QUIESCENCE_SECONDS = 360
TARGET_MODELS = ["virtualization.virtualmachine"]
EFFECT = "destructive"
TIMEOUT_SECONDS = 360
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_DRIVER_CHAIN: list[str] = []
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}

BACKEND_ID = 1
BACKEND_BASE_URL = "http://127.0.0.1:16005"
BACKEND_VERIFY_SSL = False

RUNNER_TARGET_NAME = "nmultifibra-ci-untrusted-01"
RUNNER_TARGET_ID = 399
RUNNER_TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": RUNNER_TARGET_ID,
}
RUNNER_CLUSTER_ID = 8
RUNNER_CLUSTER_NAME = "CLUSTER01-DC01"
RUNNER_NODE_ID = 34
RUNNER_NODE_NAME = "node01"
RUNNER_PROXMOX_VMID = 10_040
RUNNER_TENANT_ID = 14
RUNNER_TENANT_NAME = "N-MultiFibra"
RUNNER_ROLE_ID = 5
RUNNER_ROLE_NAME = "Virtual Machine (QEMU)"
RUNNER_VCPUS = 8.0
RUNNER_MEMORY_MIB = 16_384
RUNNER_DISK_MIB = 122_880
RUNNER_SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:399"

GITEA_TARGET_NAME = "Gitea"
GITEA_TARGET_ID = 170
GITEA_TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": GITEA_TARGET_ID,
}
GITEA_IPV4_ADDRESS = "10.0.30.96"
GITEA_SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:170"
GITEA_BINARY = "/usr/local/bin/gitea"
GITEA_CONFIG = "/etc/gitea/app.ini"
GITEA_TOKEN_COMMAND_PREFIX = (
    "/usr/bin/sudo",
    "-n",
    "-u",
    "git",
    GITEA_BINARY,
    "--config",
    GITEA_CONFIG,
    "actions",
    "generate-runner-token",
    "--scope",
)
GITEA_TOKEN_RESET_HELPER = "/usr/local/libexec/nms/gitea-runner-token-reset"
GITEA_TOKEN_RESET_HELPER_SHA256 = (
    "67562056a5c00c1f667383b98d83ff43a136ea10079ab041079680a511614c78"
)
GITEA_TOKEN_RESET_COMMAND_PREFIX = (
    "/usr/bin/sudo",
    "-n",
    "-u",
    "git",
    GITEA_TOKEN_RESET_HELPER,
)

RUNNER_REGISTER_HELPER = "/usr/local/libexec/gitea-runner/register-runner"
RUNNER_REGISTER_HELPER_SHA256 = (
    "15b72776c546ff433dc585bb8bab0645524adada7151aa9038d7b7e2711a49ed"
)
RUNNER_REGISTER_COMMAND_PREFIX = (
    "/usr/bin/sudo",
    "-n",
    "-u",
)
RUNNER_REGISTER_COMMAND_SUFFIX = (
    "--",
    RUNNER_REGISTER_HELPER,
    "nmc-register",
    "--scope",
)

SCOPE_TO_GITEA_SCOPE = {
    "netbox-proxbox": "emersonfelipesp/netbox-proxbox",
    "nmulticloud-org": "N-MultiCloud",
    "nmulticloud-org-root": "N-MultiCloud",
    "proxbox-api": "emersonfelipesp/proxbox-api",
    "release-netbox-proxbox-validation": "emersonfelipesp/netbox-proxbox",
    "release-netbox-proxbox-build": "emersonfelipesp/netbox-proxbox",
    "release-proxbox-api-validation": "emersonfelipesp/proxbox-api",
    "release-proxbox-api-build": "emersonfelipesp/proxbox-api",
}
SCOPES = tuple(sorted(SCOPE_TO_GITEA_SCOPE))
SCOPE_TO_RUNNER_USER = {scope: f"gitea-runner-{scope}" for scope in SCOPES}
RUNNER_REGISTER_COMMANDS = {
    scope: [
        *RUNNER_REGISTER_COMMAND_PREFIX,
        service_user,
        *RUNNER_REGISTER_COMMAND_SUFFIX,
        scope,
    ]
    for scope, service_user in SCOPE_TO_RUNNER_USER.items()
}
OPERATIONS = ("reconcile", "register")
FENCE_UNKNOWN_SHA256 = "0" * 64

COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "gitea-runner-lifecycle-composite"],
        "description": (
            "Backend registers or reconciles one fixed runner scope, always "
            "invalidating the reusable Gitea token before completion."
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
    "required": ["operation", "scope"],
    "properties": {
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "scope": {"type": "string", "enum": list(SCOPES)},
    },
}

RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "ok",
        "procedure",
        "target",
        "operation",
        "scope",
        "registered",
        "reconciled",
        "token_invalidated",
        "token_reset_required",
        "token_sha256",
        "reset_state",
        "prior_token_id",
        "prior_active_sha256",
        "replacement_token_id",
        "stage",
    ],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"const": RUNNER_TARGET_NAME},
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "scope": {"type": "string", "enum": list(SCOPES)},
        "registered": {"type": ["boolean", "null"]},
        "reconciled": {"type": ["boolean", "null"]},
        "token_invalidated": {"type": "boolean"},
        "token_reset_required": {"type": "boolean"},
        "token_sha256": {
            "type": ["string", "null"],
            "pattern": r"^[0-9a-f]{64}$",
        },
        "reset_state": {
            "type": "string",
            "enum": [
                "not_started",
                "rotated",
                "already_inactive",
                "reconciled_expected_active",
                "reconciled_expected_inactive",
                "reconciled_no_active",
                "failed",
                "indeterminate",
            ],
        },
        "prior_token_id": {"type": ["integer", "null"], "minimum": 1},
        "prior_active_sha256": {
            "type": ["string", "null"],
            "pattern": r"^[0-9a-f]{64}$",
        },
        "replacement_token_id": {
            "type": ["integer", "null"],
            "minimum": 1,
        },
        "stage": {
            "type": "string",
            "enum": [
                "generate_token",
                "register",
                "reset",
                "reconcile",
                "complete",
                "indeterminate",
            ],
        },
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "operation": {"const": "register"},
                "registered": {"const": True},
                "reconciled": {"const": None},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
                "reset_state": {"enum": ["rotated", "already_inactive"]},
                "prior_token_id": {"type": "integer", "minimum": 1},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {"type": "integer", "minimum": 1},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "register"},
                "registered": {"const": False},
                "reconciled": {"const": None},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": False},
                "token_sha256": {"const": None},
                "reset_state": {"const": "not_started"},
                "prior_token_id": {"const": None},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {"const": None},
                "stage": {"const": "generate_token"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "register"},
                "registered": {"type": ["boolean", "null"]},
                "reconciled": {"const": None},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
                "reset_state": {"enum": ["rotated", "already_inactive"]},
                "prior_token_id": {"type": "integer", "minimum": 1},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {"type": "integer", "minimum": 1},
                "stage": {"enum": ["register", "indeterminate"]},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "register"},
                "registered": {"type": ["boolean", "null"]},
                "reconciled": {"const": None},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": True},
                "token_sha256": {
                    "type": ["string", "null"],
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "reset_state": {"enum": ["failed", "indeterminate"]},
                "prior_token_id": {"type": ["integer", "null"], "minimum": 1},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "stage": {"enum": ["register", "reset", "indeterminate"]},
            }
        },
        {
            "properties": {
                "ok": {"const": True},
                "operation": {"const": "reconcile"},
                "registered": {"const": None},
                "reconciled": {"const": True},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
                "reset_state": {
                    "enum": [
                        "reconciled_expected_active",
                        "reconciled_expected_inactive",
                        "reconciled_no_active",
                    ]
                },
                "prior_token_id": {"type": ["integer", "null"], "minimum": 1},
                "prior_active_sha256": {
                    "type": ["string", "null"],
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "replacement_token_id": {"type": "integer", "minimum": 1},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "reconcile"},
                "registered": {"const": None},
                "reconciled": {"type": ["boolean", "null"]},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": True},
                "token_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
                "reset_state": {"enum": ["failed", "indeterminate"]},
                "prior_token_id": {"type": ["integer", "null"], "minimum": 1},
                "prior_active_sha256": {
                    "type": ["string", "null"],
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "replacement_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "stage": {"enum": ["reconcile", "indeterminate"]},
            }
        },
    ],
}

_REVISION_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _ssh_snapshot_properties(
    prefix: str,
    *,
    host: str | None,
    policy_ref: str,
    principal: str,
) -> dict[str, Any]:
    host_schema: dict[str, Any] = {"type": "string", "format": "ipv4"}
    if host is not None:
        host_schema = {"const": host}
    return {
        f"{prefix}_ssh_service_id": {"type": "integer", "minimum": 1},
        f"{prefix}_ssh_service_revision": {
            "type": "string",
            "maxLength": 64,
            "pattern": _REVISION_PATTERN,
        },
        f"{prefix}_ssh_identity_id": {"type": "integer", "minimum": 1},
        f"{prefix}_ssh_identity_revision": {
            "type": "string",
            "maxLength": 64,
            "pattern": _REVISION_PATTERN,
        },
        f"{prefix}_ssh_storage_backend": {"const": "local"},
        f"{prefix}_ssh_principal": {"const": principal},
        f"{prefix}_ssh_method": {"enum": ["key", "key_with_passphrase", "password"]},
        f"{prefix}_ssh_host": host_schema,
        f"{prefix}_ssh_port": {"const": 22},
        f"{prefix}_ssh_known_hosts_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
        f"{prefix}_ssh_policy_ref": {"const": policy_ref},
    }


_NORMALIZED_PROPERTIES: dict[str, Any] = {
    "target": {"const": RUNNER_TARGET_NAME},
    "target_object": {"const": RUNNER_TARGET_OBJECT},
    "runner_cluster_id": {"const": RUNNER_CLUSTER_ID},
    "runner_node_id": {"const": RUNNER_NODE_ID},
    "runner_node": {"const": RUNNER_NODE_NAME},
    "runner_proxmox_vmid": {"const": RUNNER_PROXMOX_VMID},
    "runner_tenant_id": {"const": RUNNER_TENANT_ID},
    "runner_role_id": {"const": RUNNER_ROLE_ID},
    "runner_vcpus": {"const": RUNNER_VCPUS},
    "runner_memory_mib": {"const": RUNNER_MEMORY_MIB},
    "runner_disk_mib": {"const": RUNNER_DISK_MIB},
    "runner_ipv4": {"type": "string", "format": "ipv4"},
    "operation": {"type": "string", "enum": list(OPERATIONS)},
    "scope": {"type": "string", "enum": list(SCOPES)},
    "gitea_scope": {
        "type": "string",
        "enum": sorted(set(SCOPE_TO_GITEA_SCOPE.values())),
    },
    "gitea_target": {"const": GITEA_TARGET_NAME},
    "gitea_target_object": {"const": GITEA_TARGET_OBJECT},
    "gitea_ipv4": {"const": GITEA_IPV4_ADDRESS},
    "fence_state": {"type": "string", "enum": ["blocked", "clear", "pending"]},
    "fence_expected_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
    "fence_execution_id": {"type": ["integer", "null"], "minimum": 1},
    "register_helper_sha256": {"const": RUNNER_REGISTER_HELPER_SHA256},
    "token_reset_helper_sha256": {"const": GITEA_TOKEN_RESET_HELPER_SHA256},
    **_ssh_snapshot_properties(
        "runner",
        host=None,
        policy_ref=RUNNER_SSH_POLICY_REF,
        principal="nms-runner-bootstrap",
    ),
    **_ssh_snapshot_properties(
        "gitea",
        host=GITEA_IPV4_ADDRESS,
        policy_ref=GITEA_SSH_POLICY_REF,
        principal="nms-gitea-runner-control",
    ),
}
_FINGERPRINT_PROPERTIES: dict[str, Any] = {
    "handler_id": {"const": HANDLER_ID},
    "assigned_object_id": {"const": RUNNER_TARGET_ID},
    "target_object_sha256": {
        "const": "88df1357034bcc700bdf62f9c1c8a04322562c6b33bc38546d8520e818785704"
    },
    "runner_target_object_sha256": {
        "const": "88df1357034bcc700bdf62f9c1c8a04322562c6b33bc38546d8520e818785704"
    },
    "gitea_target_object_sha256": {
        "const": "3bd33992a1cb7401c9dd60ac0cb7eacd874a6e2f2a87c3374096e269e18cd916"
    },
    **_NORMALIZED_PROPERTIES,
}
COMMAND_FINGERPRINT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": list(_FINGERPRINT_PROPERTIES),
    "properties": _FINGERPRINT_PROPERTIES,
}
NORMALIZED_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [*list(_NORMALIZED_PROPERTIES), "command_fingerprint"],
    "properties": {
        **_NORMALIZED_PROPERTIES,
        "command_fingerprint": COMMAND_FINGERPRINT_SCHEMA,
    },
}


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


RUNNER_TARGET_OBJECT_SHA256 = canonical_sha256(RUNNER_TARGET_OBJECT)
GITEA_TARGET_OBJECT_SHA256 = canonical_sha256(GITEA_TARGET_OBJECT)

SEMANTIC_CAPABILITY_EXTENSION = {
    "version": VERSION,
    "runtime": {
        "route_budget_seconds": ROUTE_BUDGET_SECONDS,
        "handler_budget_seconds": HANDLER_BUDGET_SECONDS,
        "preflight_timeout_seconds": PREFLIGHT_TIMEOUT_SECONDS,
        "token_timeout_seconds": TOKEN_TIMEOUT_SECONDS,
        "register_timeout_seconds": REGISTER_TIMEOUT_SECONDS,
        "reset_timeout_seconds": RESET_TIMEOUT_SECONDS,
        "capture_max_bytes": CAPTURE_MAX_BYTES,
        "backend_response_max_bytes": BACKEND_RESPONSE_MAX_BYTES,
        "reconciliation_quiescence_seconds": RECONCILIATION_QUIESCENCE_SECONDS,
    },
    "runner_target": {
        "object": RUNNER_TARGET_OBJECT,
        "name": RUNNER_TARGET_NAME,
        "cluster_id": RUNNER_CLUSTER_ID,
        "node_id": RUNNER_NODE_ID,
        "proxmox_vmid": RUNNER_PROXMOX_VMID,
        "tenant_id": RUNNER_TENANT_ID,
        "role_id": RUNNER_ROLE_ID,
        "vcpus": RUNNER_VCPUS,
        "memory_mib": RUNNER_MEMORY_MIB,
        "disk_mib": RUNNER_DISK_MIB,
        "ssh_policy_ref": RUNNER_SSH_POLICY_REF,
    },
    "gitea_target": {
        "object": GITEA_TARGET_OBJECT,
        "name": GITEA_TARGET_NAME,
        "ipv4": GITEA_IPV4_ADDRESS,
        "ssh_policy_ref": GITEA_SSH_POLICY_REF,
        "token_command_prefix": list(GITEA_TOKEN_COMMAND_PREFIX),
        "token_reset_helper": GITEA_TOKEN_RESET_HELPER,
        "token_reset_helper_sha256": GITEA_TOKEN_RESET_HELPER_SHA256,
        "token_reset_command_prefix": list(GITEA_TOKEN_RESET_COMMAND_PREFIX),
    },
    "registration": {
        "scope_to_gitea_scope": SCOPE_TO_GITEA_SCOPE,
        "helper": RUNNER_REGISTER_HELPER,
        "helper_sha256": RUNNER_REGISTER_HELPER_SHA256,
        "scope_to_command": RUNNER_REGISTER_COMMANDS,
        "scope_to_runner_user": SCOPE_TO_RUNNER_USER,
        "token_transport": "stdin-only",
        "fence_unknown_sha256": FENCE_UNKNOWN_SHA256,
    },
    "params_schema": PARAMS_SCHEMA,
    "normalized_params_schema": NORMALIZED_PARAMS_SCHEMA,
    "command_fingerprint_schema": COMMAND_FINGERPRINT_SCHEMA,
    "result_schema": RESULT_SCHEMA,
}
SEMANTIC_CAPABILITY_SHA256 = canonical_sha256(SEMANTIC_CAPABILITY_EXTENSION)

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
    "semantic_contract_sha256": SEMANTIC_CAPABILITY_SHA256,
}

PROCEDURE_POLICY_SHA256 = canonical_sha256(PROCEDURE_POLICY)
COMMAND_CONTRACT_SHA256 = canonical_sha256(COMMAND_CONTRACT)
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
RESULT_SCHEMA_SHA256 = canonical_sha256(RESULT_SCHEMA)
