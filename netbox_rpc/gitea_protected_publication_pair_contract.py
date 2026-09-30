"""Immutable contract for the protected publication runner pair."""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROVE_PROCEDURE = "service.gitea.actions_runner.protected_pair.prove"
PROVISION_PROCEDURE = "service.gitea.actions_runner.protected_pair.provision"
PROVE_PROCEDURE_NAME = PROVE_PROCEDURE
PROVISION_PROCEDURE_NAME = PROVISION_PROCEDURE
PROCEDURE_NAME = PROVISION_PROCEDURE
PROCEDURE_NAMES = frozenset({PROVE_PROCEDURE, PROVISION_PROCEDURE})
VERSION = 1
TARGET_OBJECT_ID = 416
TARGET_NAME = "Gitea-Runner"
TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": TARGET_OBJECT_ID,
}
TARGET_IPV4_ADDRESS = "10.0.30.241"
TARGET_SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:416"
TARGET_SSH_PRINCIPAL = "nms-runner-bootstrap"
BACKEND_ID = 1
BACKEND_BASE_URL = "http://127.0.0.1:16005"
BACKEND_VERIFY_SSL = False
SCOPE_OWNER = "N-MultiCloud"
SCOPE_TYPE = "organization"
HOST_GENERATION_SHA256 = "11fc017aff23a9572db7b4a2d38cba895dcba50bfd600a2127dfad7bfcb778b5"
RUNTIME_INVENTORY_SHA256 = "0398104f4485b623c10a9e236a53b4e950c9b03ba4101aa6cc5d33b7679ebd4e"
PROVE_HELPER = "/usr/local/libexec/nms/prove-protected-publication-pair"
PROVISION_HELPER = "/usr/local/libexec/nms/provision-protected-publication-pair"
PROVE_HELPER_SHA256 = "43e47fe535e4497624cc423097bf7a386aedbbd10fde2ae90c72c280005aa0a7"
PROVISION_HELPER_SHA256 = "a977c99a33ab26ae4beb0b8c71848d3ed116daf821a4088caa29a31ea8979216"
BUILD_SANDBOX = "/usr/local/bin/nmulticloud-release-build-sandbox"
BUILD_SANDBOX_PATH = BUILD_SANDBOX
PROVE_HELPER_PATH = PROVE_HELPER
PROVISION_HELPER_PATH = PROVISION_HELPER
BUILD_SANDBOX_SHA256 = "2e644e715af33b73a91e517f6b5b59f76e0c0c2461576a9f87f522a3603f18ec"
PUBLICATION_BROKER_SHA256 = "452b1a3b61413509e9f2de07a0d603961dfb06e3564f28eb7c9029b8d1fee153"
PUBLICATION_POLICY_SHA256 = "75844eb1293ae8ebc06d2d2ef76c16604901a1b6825a8cea30ea664273ecac40"
ACTIVATION_ELIGIBLE = True
BACKEND_RESPONSE_MAX_BYTES = 32_768
ROUTE_BUDGET_SECONDS = {
    PROVE_PROCEDURE: 300,
    PROVISION_PROCEDURE: 1740,
}

PARAMS_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
_SHA256 = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
_POSITIVE_ID = {
    "type": "integer",
    "minimum": 1,
    "maximum": 9_007_199_254_740_991,
}
_REVISION_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z$"

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
        "ssh_service_id": _POSITIVE_ID,
        "ssh_service_revision": {
            "type": "string",
            "maxLength": 64,
            "pattern": _REVISION_PATTERN,
        },
        "ssh_identity_id": _POSITIVE_ID,
        "ssh_identity_revision": {
            "type": "string",
            "maxLength": 64,
            "pattern": _REVISION_PATTERN,
        },
        "ssh_storage_backend": {"const": "local"},
        "ssh_principal": {"const": TARGET_SSH_PRINCIPAL},
        "ssh_method": {"enum": ["key", "key_with_passphrase", "password"]},
        "ssh_host": {"const": TARGET_IPV4_ADDRESS},
        "ssh_port": {"const": 22},
        "ssh_known_hosts_sha256": _SHA256,
        "ssh_policy_ref": {"const": TARGET_SSH_POLICY_REF},
    },
}


def _role_schema(
    role: str,
) -> dict[str, Any]:
    service_user = f"nmc-rpc-release-{role}"
    runner_name = f"ci-release-{role}-netbox-rpc-backend"
    properties: dict[str, Any] = {
        "runner_id": _POSITIVE_ID,
        "runner_name": {"const": runner_name},
        "labels": {"const": [f"release-{role}"]},
        "online": {"const": True},
        "busy": {"const": False},
        "service_active": {"const": True},
        "service_user": {"const": service_user},
        "service_name": {"const": f"{service_user}.service"},
        "process_identity": {"type": "string", "minLength": 1, "maxLength": 128},
        "workspace_root": {"const": f"/var/lib/{service_user}/work"},
        "state_root": {"const": f"/var/lib/{service_user}"},
        "cache_root": {"const": f"/var/cache/{service_user}"},
        "config_path": {"const": f"/etc/nmc-protected-publication/{role}.yaml"},
        "launcher_sha256": {
            "const": "7cc722a0de44af661d299c0b86eeee03231f993effa517718e48a45c2c188ef1"
        },
        "scope_owner": {"const": SCOPE_OWNER},
        "scope_type": {"const": SCOPE_TYPE},
        "scope_sha256": _SHA256,
        "runtime_inventory_sha256": {"const": RUNTIME_INVENTORY_SHA256},
        "accepts_pull_requests": {"const": False},
        "control_plane_https": {"const": "same-origin-gitea-only"},
        "candidate_build_network": {"const": "none"},
        "package_write_credential_present": {"const": False},
        "package_mutation": {
            "const": "broker-socket-only" if role == "publisher" else "none"
        },
    }
    return {
        "type": "object",
        "required": list(properties),
        "additionalProperties": False,
        "properties": properties,
    }


_PAIR_SCHEMA = {
    "type": "object",
    "required": [
        "distinct_runner_ids",
        "distinct_service_users",
        "distinct_processes",
        "distinct_workspaces",
        "distinct_state_roots",
        "distinct_cache_roots",
        "crossover_absent",
    ],
    "additionalProperties": False,
    "properties": {
        "distinct_runner_ids": {"const": True},
        "distinct_service_users": {"const": True},
        "distinct_processes": {"const": True},
        "distinct_workspaces": {"const": True},
        "distinct_state_roots": {"const": True},
        "distinct_cache_roots": {"const": True},
        "crossover_absent": {"const": True},
    },
}
_SET_FIELDS = (
    "all_cache_roots_distinct",
    "all_processes_distinct",
    "all_runner_ids_distinct",
    "all_service_users_distinct",
    "all_state_roots_distinct",
    "all_workspaces_distinct",
    "crossover_absent",
    "validator_build_authority_absent",
    "validator_publisher_socket_absent",
)
_SET_SCHEMA = {
    "type": "object",
    "required": list(_SET_FIELDS),
    "additionalProperties": False,
    "properties": {field: {"const": True} for field in _SET_FIELDS},
}
_ISOLATION_FIELDS = (
    "fresh_unprivileged_execution",
    "candidate_network_blocked",
    "candidate_credentials_hidden",
    "source_read_only",
    "output_scoped",
    "authority_paths_hidden",
    "sibling_paths_hidden",
    "runner_control_paths_hidden",
    "environment_cleared",
    "resources_bounded",
    "processes_reaped",
    "writable_layer_absent",
    "persistence_absent",
)
_ISOLATION_SCHEMA = {
    "type": "object",
    "required": list(_ISOLATION_FIELDS),
    "additionalProperties": False,
    "properties": {field: {"const": True} for field in _ISOLATION_FIELDS},
}
_PUBLICATION_BROKER_SCHEMA = {
    "type": "object",
    "required": [
        "socket_path",
        "service_template",
        "credential_scope",
        "broker_sha256",
        "policy_sha256",
        "credential_exposed_to_runner",
        "credential_exposed_to_candidate",
        "canonical_main_reauthorized",
        "active_run_reauthorized",
        "workflow_digest_reauthorized",
        "same_origin_https_only",
        "redirects_denied",
        "mutations_scoped",
    ],
    "additionalProperties": False,
    "properties": {
        "socket_path": {"const": "/run/nmc-release-control/publish.sock"},
        "service_template": {"const": "nmc-release-publish@.service"},
        "credential_scope": {"const": "netbox-rpc-backend-package-write-only"},
        "broker_sha256": {"const": PUBLICATION_BROKER_SHA256},
        "policy_sha256": {"const": PUBLICATION_POLICY_SHA256},
        "credential_exposed_to_runner": {"const": False},
        "credential_exposed_to_candidate": {"const": False},
        "canonical_main_reauthorized": {"const": True},
        "active_run_reauthorized": {"const": True},
        "workflow_digest_reauthorized": {"const": True},
        "same_origin_https_only": {"const": True},
        "redirects_denied": {"const": True},
        "mutations_scoped": {"const": True},
    },
}


def _result_schema(procedure: str, operation: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "ok",
            "schema_version",
            "procedure",
            "operation",
            "stage",
            "target",
            "target_object",
            "scope",
            "host_generation_sha256",
            "runtime_inventory_sha256",
            "helper_sha256",
            "sandbox_path",
            "sandbox_owner",
            "sandbox_mode",
            "sandbox_sha256",
            "roles",
            "pair",
            "set",
            "isolation",
            "publication_broker",
        ],
        "additionalProperties": False,
        "properties": {
            "ok": {"const": True},
            "schema_version": {"const": 1},
            "procedure": {"const": procedure},
            "operation": {"const": operation},
            "stage": {"const": "complete"},
            "target": {"const": TARGET_NAME},
            "target_object": {"const": TARGET_OBJECT},
            "scope": {"const": {"owner": SCOPE_OWNER, "type": SCOPE_TYPE}},
            "host_generation_sha256": {"const": HOST_GENERATION_SHA256},
            "runtime_inventory_sha256": {"const": RUNTIME_INVENTORY_SHA256},
            "helper_sha256": {
                "const": (
                    PROVE_HELPER_SHA256
                    if operation == "prove"
                    else PROVISION_HELPER_SHA256
                )
            },
            "sandbox_path": {"const": BUILD_SANDBOX},
            "sandbox_owner": {"const": "root"},
            "sandbox_mode": {"const": "0755"},
            "sandbox_sha256": {"const": BUILD_SANDBOX_SHA256},
            "roles": {
                "type": "object",
                "required": ["builder", "publisher", "validator"],
                "additionalProperties": False,
                "properties": {
                    "builder": _role_schema("builder"),
                    "publisher": _role_schema("publisher"),
                    "validator": _role_schema("validator"),
                },
            },
            "pair": _PAIR_SCHEMA,
            "set": _SET_SCHEMA,
            "isolation": _ISOLATION_SCHEMA,
            "publication_broker": _PUBLICATION_BROKER_SCHEMA,
        },
    }


RESULT_SCHEMAS = {
    PROVE_PROCEDURE: _result_schema(PROVE_PROCEDURE, "prove"),
    PROVISION_PROCEDURE: _result_schema(PROVISION_PROCEDURE, "provision"),
}
COMMAND_CONTRACTS = {
    PROVE_PROCEDURE: [
        {
            "sequence": 1,
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": ["backend-orchestrated", "gitea-protected-publication-pair-prove"],
            "description": (
                "Prove or provision the fixed, distinct release-validator, "
                "release-builder, and release-publisher set without accepting "
                "caller-selected host operations."
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
    ],
    PROVISION_PROCEDURE: [
        {
            "sequence": 1,
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": [
                "backend-orchestrated",
                "gitea-protected-publication-pair-provision",
            ],
            "description": (
                "Prove or provision the fixed, distinct release-validator, "
                "release-builder, and release-publisher set without accepting "
                "caller-selected host operations."
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
    ],
}


def canonical_sha256(value: Any) -> str:
    """Return a stable SHA-256 fingerprint for a JSON-compatible value."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _roles_have_distinct_values(role_values: list[dict[str, Any]]) -> bool:
    distinct_fields = (
        "runner_id",
        "service_user",
        "process_identity",
        "workspace_root",
        "state_root",
        "cache_root",
    )
    return all(
        len({role.get(field) for role in role_values}) == 3
        for field in distinct_fields
    )


def result_semantics_are_valid(result: object) -> bool:
    """Verify cross-role invariants that JSON Schema cannot express."""
    if not isinstance(result, dict):
        return False
    roles = result.get("roles")
    pair = result.get("pair")
    role_set = result.get("set")
    if not all(isinstance(value, dict) for value in (roles, pair, role_set)):
        return False
    if set(roles) != {"builder", "publisher", "validator"}:
        return False
    role_values = list(roles.values())
    if not _roles_have_distinct_values(role_values):
        return False
    builder = roles["builder"]
    publisher = roles["publisher"]
    validator = roles["validator"]
    return all(
        (
            builder.get("package_mutation") == "none",
            validator.get("package_mutation") == "none",
            publisher.get("package_mutation") == "broker-socket-only",
            pair.get("crossover_absent") is True,
            role_set.get("crossover_absent") is True,
            role_set.get("validator_build_authority_absent") is True,
            role_set.get("validator_publisher_socket_absent") is True,
        )
    )


TARGET_OBJECT_SHA256 = canonical_sha256(TARGET_OBJECT)
PAIR_CONTRACT = {
    "schema_version": 1,
    "target": {
        "name": TARGET_NAME,
        "model": TARGET_OBJECT["content_type"],
        "object_id": TARGET_OBJECT_ID,
        "object_sha256": TARGET_OBJECT_SHA256,
        "ssh_principal": TARGET_SSH_PRINCIPAL,
        "ssh_policy_ref": TARGET_SSH_POLICY_REF,
        "ssh_host": TARGET_IPV4_ADDRESS,
    },
    "scope": {"type": SCOPE_TYPE, "owner": SCOPE_OWNER},
    "helpers": {
        "prove": {"path": PROVE_HELPER, "sha256": PROVE_HELPER_SHA256},
        "provision": {
            "path": PROVISION_HELPER,
            "sha256": PROVISION_HELPER_SHA256,
        },
        "build_sandbox": {"path": BUILD_SANDBOX, "sha256": BUILD_SANDBOX_SHA256},
    },
    "host_generation_sha256": HOST_GENERATION_SHA256,
    "runtime_inventory_sha256": RUNTIME_INVENTORY_SHA256,
    "runner_binary_sha256": (
        "7cc722a0de44af661d299c0b86eeee03231f993effa517718e48a45c2c188ef1"
    ),
    "roles": {
        role: {
            "runner_name": f"ci-release-{role}-netbox-rpc-backend",
            "label": f"release-{role}",
            "service_user": f"nmc-rpc-release-{role}",
            "service_name": f"nmc-rpc-release-{role}.service",
            "workspace_root": f"/var/lib/nmc-rpc-release-{role}/work",
            "state_root": f"/var/lib/nmc-rpc-release-{role}",
            "cache_root": f"/var/cache/nmc-rpc-release-{role}",
            "config_path": f"/etc/nmc-protected-publication/{role}.yaml",
            "package_mutation": (
                "broker-socket-only" if role == "publisher" else "none"
            ),
        }
        for role in ("builder", "publisher", "validator")
    },
    "separation": {
        "all_identities_distinct": True,
        "validator_build_authority_absent": True,
        "validator_publisher_socket_absent": True,
    },
    "publication_broker": {
        "path": "/run/nmc-release-control/publish.sock",
        "sha256": PUBLICATION_BROKER_SHA256,
        "policy_sha256": PUBLICATION_POLICY_SHA256,
    },
    "activation_policy": "default-dark-explicit-operator-enable",
    "publication_credential_boundary": "root-broker-only",
    "publication_activation_policy": "never-edit-publication-runner-json",
}
PAIR_CONTRACT_SHA256 = canonical_sha256(PAIR_CONTRACT)

COMMAND_FINGERPRINT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "handler_id",
        "procedure",
        "assigned_object_id",
        "target_object_sha256",
        "ssh_snapshot_sha256",
        "ssh_policy_ref",
        "pair_contract_sha256",
        "host_generation_sha256",
        "provision_helper_sha256",
        "prove_helper_sha256",
        "build_sandbox_sha256",
    ],
    "properties": {
        "handler_id": {"enum": sorted(PROCEDURE_NAMES)},
        "procedure": {"enum": sorted(PROCEDURE_NAMES)},
        "assigned_object_id": {"const": TARGET_OBJECT_ID},
        "target_object_sha256": {"const": TARGET_OBJECT_SHA256},
        "ssh_snapshot_sha256": _SHA256,
        "ssh_policy_ref": {"const": TARGET_SSH_POLICY_REF},
        "pair_contract_sha256": {"const": PAIR_CONTRACT_SHA256},
        "host_generation_sha256": {"const": HOST_GENERATION_SHA256},
        "provision_helper_sha256": {"const": PROVISION_HELPER_SHA256},
        "prove_helper_sha256": {"const": PROVE_HELPER_SHA256},
        "build_sandbox_sha256": {"const": BUILD_SANDBOX_SHA256},
    },
    "oneOf": [
        {
            "properties": {
                "handler_id": {"const": procedure},
                "procedure": {"const": procedure},
            }
        }
        for procedure in sorted(PROCEDURE_NAMES)
    ],
}
NORMALIZED_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "target",
        "target_object",
        "ssh_snapshot",
        "ssh_policy_ref",
        "command_fingerprint",
    ],
    "properties": {
        "target": {"const": TARGET_NAME},
        "target_object": {"const": TARGET_OBJECT},
        "ssh_snapshot": SSH_SNAPSHOT_SCHEMA,
        "ssh_policy_ref": {"const": TARGET_SSH_POLICY_REF},
        "command_fingerprint": COMMAND_FINGERPRINT_SCHEMA,
    },
}


SEMANTIC_CAPABILITY_EXTENSIONS = {
    procedure: {
        "activation_eligible": ACTIVATION_ELIGIBLE,
        "target_object": TARGET_OBJECT,
        "target_name": TARGET_NAME,
        "scope_owner": SCOPE_OWNER,
        "scope_type": SCOPE_TYPE,
        "host_generation_sha256": HOST_GENERATION_SHA256,
        "prove_helper": PROVE_HELPER,
        "prove_helper_sha256": PROVE_HELPER_SHA256,
        "provision_helper": PROVISION_HELPER,
        "provision_helper_sha256": PROVISION_HELPER_SHA256,
        "build_sandbox": BUILD_SANDBOX,
        "build_sandbox_sha256": BUILD_SANDBOX_SHA256,
        "runtime_inventory_sha256": RUNTIME_INVENTORY_SHA256,
        "params_schema": PARAMS_SCHEMA,
        "normalized_params_schema": NORMALIZED_PARAMS_SCHEMA,
        "command_fingerprint_schema": COMMAND_FINGERPRINT_SCHEMA,
        "result_schema": RESULT_SCHEMAS[procedure],
    }
    for procedure in PROCEDURE_NAMES
}


def _procedure_policy(procedure: str) -> dict[str, Any]:
    provision = procedure == PROVISION_PROCEDURE
    return {
        "name": procedure,
        "handler_id": procedure,
        "version": VERSION,
        "enabled": False,
        "target_models": ["virtualization.virtualmachine"],
        "effect": "destructive" if provision else "read",
        "timeout_seconds": 1800 if provision else 300,
        "approval_required": provision,
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "command_contract_sha256": canonical_sha256(COMMAND_CONTRACTS[procedure]),
        "semantic_contract_sha256": canonical_sha256(
            SEMANTIC_CAPABILITY_EXTENSIONS[procedure]
        ),
        "transport_pinned": True,
    }


PROCEDURE_POLICIES = {
    procedure: _procedure_policy(procedure) for procedure in PROCEDURE_NAMES
}
SEMANTIC_CAPABILITY_SHA256 = {
    procedure: canonical_sha256(extension)
    for procedure, extension in SEMANTIC_CAPABILITY_EXTENSIONS.items()
}
SEMANTIC_CONTRACTS = SEMANTIC_CAPABILITY_EXTENSIONS

# Single-contract aliases used by the shared protected-policy machinery.
PROCEDURE_POLICY = PROCEDURE_POLICIES[PROVISION_PROCEDURE]
RESULT_SCHEMA = RESULT_SCHEMAS[PROVISION_PROCEDURE]
TRANSPORT_PINNED = True
