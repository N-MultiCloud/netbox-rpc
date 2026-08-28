"""Immutable catalog contract for exact-SHA staging DNS-pair deployment."""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "service.netbox.staging.deploy_dns_pair"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
TARGET = "nms-front-door"
TARGET_MODEL = "dcim.device"
TARGET_MODELS = [TARGET_MODEL]
RPC_CONTRACT_GENERATION = "nmc-dns-staging-rpc-v1"
RPC_PRINCIPAL = "nms-proxy"
RPC_WRAPPER = "/opt/nmulticloud/deploy/bin/deploy-netbox-dns-staging-rpc"
RPC_WRAPPER_SHA256 = "54b0274d80a42f50e6ccfab6eac932d055c894fee4e6a998297e7d2fa995f144"
RPC_SUDOERS_PATH = "/etc/sudoers.d/nms-proxy-dns-staging"
RPC_SUDOERS_SHA256 = "b6901f84190e3098ddd85e44c934aeecd62014cc13421a91390f308c5d77e807"
RUNTIME_ARTIFACT_SHA256 = {
    "/opt/nmulticloud/deploy/bin/deploy-netbox-plugin-staging": (
        "6f68953c6e928ba0d301557c9ee082660c56a4519a0bc093b7677015d5a6239a"
    ),
    "/opt/nmulticloud/deploy/bin/deploy-netbox-dns-api-staging": (
        "2ead48ff20e72b62ab8facc5df1ea67820e889d8f2ed929cf34fa1f19c124e8e"
    ),
    "/opt/nmulticloud/deploy/bin/validate-netbox-dns-api-source": (
        "b28532c228c7c25045c6b2f4ff9a7c03f1dc4a96bf4981fb3b7f3fd9695dfa5c"
    ),
    "/opt/nmulticloud/deploy/bin/netbox-dns-api-staging-state": (
        "f5c5d76654edb38b1b4f605f267699752dd8d339328ddd37fd4434d697729c55"
    ),
    "/opt/nmulticloud/deploy/bin/python-package-deploy": (
        "d2150dd55a4695434882b9bdd8ce63924516d22ebe980b0c5ca84894fcb28bd2"
    ),
    "/opt/nmulticloud/deploy/bin/run-bounded-tree-command": (
        "1568d35aa77375e7e7be5980a6e83163ff00f2c35bc7870854eeba19e9b0fd50"
    ),
    "/opt/nmulticloud/deploy/bin/nmc-deploy-lib": (
        "72e241ddf072b64218eb3abc3d1285e154177f38eacb0a428aa22ace8a5592de"
    ),
    "/opt/nmulticloud/deploy/systemd/netbox-dns-api-staging.service": (
        "d9c25b54bc41ab036f8d00d34ce96e807095d5fd84968e851a6e0087a50008a9"
    ),
}
EFFECT = "destructive"
TIMEOUT_SECONDS = 2700
ROUTE_BUDGET_SECONDS = 2640
HANDLER_BUDGET_SECONDS = 2580
PROCESS_TIMEOUT_SECONDS = 2550
HANDLER_DEADLINE_MARGIN_SECONDS = ROUTE_BUDGET_SECONDS - HANDLER_BUDGET_SECONDS
PROCESS_DEADLINE_MARGIN_SECONDS = ROUTE_BUDGET_SECONDS - PROCESS_TIMEOUT_SECONDS
BACKEND_RESPONSE_MAX_BYTES = 4096
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_DRIVER_CHAIN: list[str] = []
TRANSPORT_PINNED = True
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}
COMMAND_PREFIX = (
    "/usr/bin/sudo",
    "-n",
    RPC_WRAPPER,
    RPC_WRAPPER_SHA256,
)

_REVISION_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z(?![\s\S])"
)
SSH_POLICY_PATTERN = r"^target-owned-ssh:dcim[.]device:[1-9][0-9]*(?![\s\S])"
SSH_SNAPSHOT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "ssh_service_id",
        "ssh_service_revision",
        "ssh_identity_id",
        "ssh_identity_revision",
        "ssh_storage_backend",
        "ssh_principal",
        "ssh_method",
        "ssh_host",
        "ssh_port",
        "ssh_known_hosts_sha256",
        "ssh_policy_ref",
    ],
    "properties": {
        "ssh_service_id": {"type": "integer", "minimum": 1},
        "ssh_service_revision": {"type": "string", "pattern": _REVISION_PATTERN},
        "ssh_identity_id": {"type": "integer", "minimum": 1},
        "ssh_identity_revision": {"type": "string", "pattern": _REVISION_PATTERN},
        "ssh_storage_backend": {"const": "local"},
        "ssh_principal": {"const": RPC_PRINCIPAL},
        "ssh_method": {
            "type": "string",
            "enum": ["key", "key_with_passphrase", "password"],
        },
        "ssh_host": {"type": "string", "minLength": 7, "maxLength": 15},
        "ssh_port": {"const": 22},
        "ssh_known_hosts_sha256": {
            "type": "string",
            "pattern": r"^[0-9a-f]{64}(?![\s\S])",
        },
        "ssh_policy_ref": {"type": "string", "pattern": SSH_POLICY_PATTERN},
    },
}

COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "netbox-staging-deploy-dns-pair"],
        "description": (
            "Backend invokes the fixed root-owned staging DNS-pair deployer "
            "for one approved exact commit SHA without capturing output."
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
    "required": ["commit_sha"],
    "properties": {
        "commit_sha": {
            "type": "string",
            "pattern": r"^[0-9a-f]{40}(?![\s\S])",
        }
    },
}

RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "commit_sha", "deployed", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"const": TARGET},
        "commit_sha": {"type": "string", "pattern": r"^[0-9a-f]{40}(?![\s\S])"},
        "deployed": {"type": ["boolean", "null"]},
        "stage": {"type": "string", "enum": ["execute", "complete", "indeterminate"]},
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "deployed": {"const": True},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "deployed": {"const": False},
                "stage": {"const": "execute"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "deployed": {"const": None},
                "stage": {"const": "indeterminate"},
            }
        },
    ],
}

NORMALIZED_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "target",
        "commit_sha",
        "target_object",
        "ssh_snapshot",
        "ssh_policy_ref",
        "command_fingerprint",
    ],
    "properties": {
        "target": {"const": TARGET},
        "commit_sha": PARAMS_SCHEMA["properties"]["commit_sha"],
        "target_object": {
            "type": "object",
            "additionalProperties": False,
            "required": ["content_type", "object_id"],
            "properties": {
                "content_type": {"const": TARGET_MODEL},
                "object_id": {"type": "integer", "minimum": 1},
            },
        },
        "ssh_snapshot": SSH_SNAPSHOT_SCHEMA,
        "ssh_policy_ref": {"type": "string", "pattern": SSH_POLICY_PATTERN},
        "command_fingerprint": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "handler_id",
                "target",
                "commit_sha",
                "assigned_object_id",
                "target_object_sha256",
                "ssh_snapshot_sha256",
                "ssh_policy_ref",
            ],
            "properties": {
                "handler_id": {"const": HANDLER_ID},
                "target": {"const": TARGET},
                "commit_sha": PARAMS_SCHEMA["properties"]["commit_sha"],
                "assigned_object_id": {"type": "integer", "minimum": 1},
                "target_object_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}(?![\s\S])",
                },
                "ssh_snapshot_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}(?![\s\S])",
                },
                "ssh_policy_ref": {"type": "string", "pattern": SSH_POLICY_PATTERN},
            },
        },
    },
}

SEMANTIC_CAPABILITY_EXTENSION = {
    "schema_version": 1,
    "target": TARGET,
    "target_model": TARGET_MODEL,
    "transport": {
        "driver": TRANSPORT_DRIVER,
        "pinned": TRANSPORT_PINNED,
        "strict_auth": True,
        "fallback": False,
        "capture_output": False,
        "required_principal": RPC_PRINCIPAL,
    },
    "runtime": {
        "contract_generation": RPC_CONTRACT_GENERATION,
        "command_prefix": list(COMMAND_PREFIX),
        "wrapper_sha256": RPC_WRAPPER_SHA256,
        "sudoers_path": RPC_SUDOERS_PATH,
        "sudoers_sha256": RPC_SUDOERS_SHA256,
        "artifact_sha256": RUNTIME_ARTIFACT_SHA256,
        "route_budget_seconds": ROUTE_BUDGET_SECONDS,
        "handler_budget_seconds": HANDLER_BUDGET_SECONDS,
        "process_timeout_seconds": PROCESS_TIMEOUT_SECONDS,
        "handler_deadline_margin_seconds": HANDLER_DEADLINE_MARGIN_SECONDS,
        "process_deadline_margin_seconds": PROCESS_DEADLINE_MARGIN_SECONDS,
        "backend_response_max_bytes": BACKEND_RESPONSE_MAX_BYTES,
    },
    "params_schema": PARAMS_SCHEMA,
    "normalized_params_schema": NORMALIZED_PARAMS_SCHEMA,
    "result_schema": RESULT_SCHEMA,
}


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


SEMANTIC_CAPABILITY_SHA256 = canonical_sha256(SEMANTIC_CAPABILITY_EXTENSION)
COMMAND_CONTRACT_SHA256 = canonical_sha256(COMMAND_CONTRACT)
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
RESULT_SCHEMA_SHA256 = canonical_sha256(RESULT_SCHEMA)

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
    "transport_pinned": TRANSPORT_PINNED,
    "output_parser": OUTPUT_PARSER,
    "output_schema": OUTPUT_SCHEMA,
    "command_contract_sha256": COMMAND_CONTRACT_SHA256,
    "semantic_contract_sha256": SEMANTIC_CAPABILITY_SHA256,
}
