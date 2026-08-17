"""Immutable runtime contract for the production Gitea 1.27.1 upgrade.

Migration 0071 keeps an inline copy so historical migration behavior remains
deterministic. Tests require the migration seed and this runtime policy to stay
exactly aligned.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "service.gitea.production.upgrade_1_27_1"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
# The reviewed *active* runtime policy requires enabled=True. Migration 0071
# deliberately seeds the row disabled; ordered activation is backend gate +
# capability first, then an operator enables this catalog row. This distinction
# keeps activation possible without weakening the exact policy enforced at run
# time.
ENABLED = True
TARGET_MODELS = ["virtualization.virtualmachine"]
EFFECT = "destructive"
TIMEOUT_SECONDS = 1800
HANDLER_BUDGET_SECONDS = 1725
PROCESS_TIMEOUT_SECONDS = 1690
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_DRIVER_CHAIN: list[str] = []
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}

TARGET_NAME = "Gitea"
TARGET_OBJECT_ID = 170
TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": TARGET_OBJECT_ID,
}
TARGET_OBJECT_SHA256 = hashlib.sha256(
    json.dumps(
        TARGET_OBJECT,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
).hexdigest()
PROXMOX_VMID = 222
CLUSTER_ID = 6
CLUSTER_NAME = "PVE-CLUSTER-02"
NODE_ID = 27
NODE_NAME = "pve03"
IPV4_ADDRESS = "10.0.30.96"
EXPECTED_SOURCE_VERSION = "1.26.2"
TARGET_VERSION = "1.27.1"
ARTIFACT_SHA256 = (
    "86a7ac26e7f9c9cca0f56c4fac07fff205d5fc3bca0e54af23a204f07b833bc9"
)
SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:170"
ARTIFACT_URL = "https://dl.gitea.com/gitea/1.27.1/gitea-1.27.1-linux-amd64"
BINARY_PATH = "/usr/local/bin/gitea"
SYSTEMD_UNIT = "gitea.service"
SYSTEMD_UNIT_PATH = "/etc/systemd/system/gitea.service"
SYSTEMD_UNIT_SHA256 = (
    "557ad3478e463075b1f6dd3a459207631ca6114371a9db670458e76515d4b7f6"
)
SERVICE_USER = "git"
SERVICE_GROUP = "git"
CONFIG_PATH = "/etc/gitea/app.ini"
WORK_PATH = "/var/lib/gitea"
DATA_PATH = "/var/lib/gitea/data"
BACKUP_ROOT = "/var/lib/netbox-rpc-gitea-upgrade-1.27.1-backups"
STATE_PATH = f"{BACKUP_ROOT}/transaction-state.json"
LOCAL_HEALTH_URL = "http://127.0.0.1:3000/api/healthz"
LOCAL_VERSION_URL = "http://127.0.0.1:3000/api/v1/version"
EXTERNAL_VERSION_URL = "https://git.nmulti.cloud/api/v1/version"
BACKEND_ID = 1
BACKEND_BASE_URL = "http://127.0.0.1:16005"
BACKEND_VERIFY_SSL = False
SUPPORTED_SSH_METHODS = frozenset({"password", "key", "key_with_passphrase"})
SSH_HOST_KEY_ALGORITHM = "ssh-ed25519"
SSH_HOST_KEY_ENCODED_MAX_LENGTH = 256
SSH_HOST_KEY_BYTES = 32
SUPPORTED_SSH_HOST_KEY_ALGORITHMS = frozenset({SSH_HOST_KEY_ALGORITHM})

# Cross-repository executable identity. The backend derives these values from
# the exact production script and complete fixed argv; the catalog binds them
# into capability compatibility without carrying executable bytes or secrets.
EXECUTABLE_CONTRACT_VERSION = 1
EXECUTABLE_CANONICALIZATION = "json-sort-keys-compact-utf8"
EXECUTABLE_SCRIPT_LENGTH_BYTES = 59_952
EXECUTABLE_SCRIPT_SHA256 = (
    "8cb74c96ebbc278eaa1e23f0f22d0c4a19fa044a00e15503be95ac54a5d80f93"
)
EXECUTABLE_ARGV_LENGTH_BYTES = 63_492
EXECUTABLE_ARGV_SHA256 = (
    "c8ba17a10783f0ebe6823026571ac388fbcf75fc4d5443c9c7d309792f4a3631"
)

COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "gitea-production-upgrade-1-27-1"],
        "description": (
            "Backend verifies, backs up, upgrades, health-checks, and safely rolls "
            "back the exact production Gitea target without caller-controlled input."
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
    "required": ["ok", "procedure", "target", "changed", "healthy", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"const": TARGET_NAME},
        "changed": {"type": ["boolean", "null"]},
        "healthy": {"type": ["boolean", "null"]},
        "stage": {
            "type": "string",
            "enum": ["execute", "rolled_back", "complete", "indeterminate"],
        },
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "changed": {"const": True},
                "healthy": {"const": True},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": True},
                "changed": {"const": False},
                "healthy": {"const": True},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "changed": {"const": False},
                "healthy": {"const": False},
                "stage": {"const": "execute"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "changed": {"const": False},
                "healthy": {"const": True},
                "stage": {"const": "rolled_back"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "changed": {"const": True},
                "healthy": {"const": False},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "changed": {"const": None},
                "healthy": {"const": None},
                "stage": {"const": "indeterminate"},
            }
        },
    ],
}

SSH_PUBLIC_SNAPSHOT_SCHEMA_PROPERTIES = {
    "ssh_service_id": {"type": "integer", "minimum": 1},
    "ssh_service_revision": {
        "type": "string",
        "maxLength": 64,
        "pattern": (
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,6})?Z$"
        ),
    },
    "ssh_identity_id": {"type": "integer", "minimum": 1},
    "ssh_identity_revision": {
        "type": "string",
        "maxLength": 64,
        "pattern": (
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,6})?Z$"
        ),
    },
    "ssh_principal": {
        "type": "string",
        "minLength": 1,
        "maxLength": 200,
        "pattern": r"^[^\u0000-\u001f\u007f]+$",
    },
    "ssh_method": {"enum": sorted(SUPPORTED_SSH_METHODS)},
    "ssh_host": {"const": IPV4_ADDRESS},
    "ssh_port": {"const": 22},
    "ssh_known_hosts_sha256": {
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    },
    "ssh_policy_ref": {"const": SSH_POLICY_REF},
}
SSH_PUBLIC_SNAPSHOT_FIELDS = list(SSH_PUBLIC_SNAPSHOT_SCHEMA_PROPERTIES)

COMMAND_FINGERPRINT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "handler_id",
        "target",
        "assigned_object_id",
        "target_object_sha256",
        "vmid",
        "cluster_id",
        "node",
        "ipv4",
        "expected_source_version",
        "target_version",
        "artifact_sha256",
        *SSH_PUBLIC_SNAPSHOT_FIELDS,
    ],
    "properties": {
        "handler_id": {"const": HANDLER_ID},
        "target": {"const": TARGET_NAME},
        "assigned_object_id": {"const": TARGET_OBJECT_ID},
        "target_object_sha256": {"const": TARGET_OBJECT_SHA256},
        "vmid": {"const": PROXMOX_VMID},
        "cluster_id": {"const": CLUSTER_ID},
        "node": {"const": NODE_NAME},
        "ipv4": {"const": IPV4_ADDRESS},
        "expected_source_version": {"const": EXPECTED_SOURCE_VERSION},
        "target_version": {"const": TARGET_VERSION},
        "artifact_sha256": {"const": ARTIFACT_SHA256},
        **SSH_PUBLIC_SNAPSHOT_SCHEMA_PROPERTIES,
    },
}

NORMALIZED_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "target",
        "target_object",
        "vmid",
        "cluster_id",
        "node",
        "ipv4",
        "expected_source_version",
        "target_version",
        "artifact_sha256",
        *SSH_PUBLIC_SNAPSHOT_FIELDS,
        "command_fingerprint",
    ],
    "properties": {
        "target": {"const": TARGET_NAME},
        "target_object": {"const": TARGET_OBJECT},
        "vmid": {"const": PROXMOX_VMID},
        "cluster_id": {"const": CLUSTER_ID},
        "node": {"const": NODE_NAME},
        "ipv4": {"const": IPV4_ADDRESS},
        "expected_source_version": {"const": EXPECTED_SOURCE_VERSION},
        "target_version": {"const": TARGET_VERSION},
        "artifact_sha256": {"const": ARTIFACT_SHA256},
        **SSH_PUBLIC_SNAPSHOT_SCHEMA_PROPERTIES,
        "command_fingerprint": COMMAND_FINGERPRINT_SCHEMA,
    },
}

RESULT_STATE_TUPLES = [
    {"ok": True, "changed": True, "healthy": True, "stage": "complete"},
    {"ok": True, "changed": False, "healthy": True, "stage": "complete"},
    {"ok": False, "changed": False, "healthy": False, "stage": "execute"},
    {
        "ok": False,
        "changed": False,
        "healthy": True,
        "stage": "rolled_back",
    },
    {"ok": False, "changed": True, "healthy": False, "stage": "complete"},
    {
        "ok": False,
        "changed": None,
        "healthy": None,
        "stage": "indeterminate",
    },
]

# Backend diagnostics are deliberately outside the durable contract.  The raw
# nms-backend wrapper is validated and discarded at the transport boundary;
# only this catalog-owned mapping may populate ExecutionFailed diagnostics.
# Keys contain the complete closed result state so a backend cannot select a
# message independently from the result which passed RESULT_SCHEMA.
RESULT_DIAGNOSTICS = {
    (True, True, True, "complete"): ("", ""),
    (True, False, True, "complete"): ("", ""),
    (False, False, False, "execute"): (
        "RPC_GITEA_UPGRADE_PRE_MUTATION_FAILURE",
        "Production Gitea upgrade failed before guest mutation.",
    ),
    (False, False, True, "rolled_back"): (
        "RPC_GITEA_UPGRADE_ROLLED_BACK",
        "Production Gitea upgrade failed and was rolled back safely.",
    ),
    (False, True, False, "complete"): (
        "RPC_GITEA_UPGRADE_COMMITTED_FAILURE",
        "Production Gitea upgrade committed but did not become healthy.",
    ),
    (False, None, None, "indeterminate"): (
        "RPC_BACKEND_INDETERMINATE",
        "Backend dispatch outcome is indeterminate; reconcile before retry.",
    ),
}


def result_diagnostics(result: dict[str, Any]) -> tuple[str, str]:
    """Return catalog-owned diagnostics for one already-validated result tuple."""

    state = (
        result.get("ok"),
        result.get("changed"),
        result.get("healthy"),
        result.get("stage"),
    )
    return RESULT_DIAGNOSTICS.get(state, ("", ""))

SEMANTIC_CAPABILITY_EXTENSION = {
    "backend": {
        "backend_id": BACKEND_ID,
        "base_url": BACKEND_BASE_URL,
        "verify_ssl": BACKEND_VERIFY_SSL,
    },
    "executable": {
        "version": EXECUTABLE_CONTRACT_VERSION,
        "canonicalization": EXECUTABLE_CANONICALIZATION,
        "script_length_bytes": EXECUTABLE_SCRIPT_LENGTH_BYTES,
        "script_sha256": EXECUTABLE_SCRIPT_SHA256,
        "argv_length_bytes": EXECUTABLE_ARGV_LENGTH_BYTES,
        "argv_sha256": EXECUTABLE_ARGV_SHA256,
    },
    "procedure": {
        "effect": EFFECT,
        "timeout_seconds": TIMEOUT_SECONDS,
        "handler_budget_seconds": HANDLER_BUDGET_SECONDS,
        "process_timeout_seconds": PROCESS_TIMEOUT_SECONDS,
        "approval_required": APPROVAL_REQUIRED,
    },
    "target": {
        "name": TARGET_NAME,
        "object": TARGET_OBJECT,
        "vmid": PROXMOX_VMID,
        "cluster_id": CLUSTER_ID,
        "cluster_name": CLUSTER_NAME,
        "node_id": NODE_ID,
        "node_name": NODE_NAME,
        "ipv4": IPV4_ADDRESS,
    },
    "upgrade": {
        "expected_source_version": EXPECTED_SOURCE_VERSION,
        "target_version": TARGET_VERSION,
        "artifact_url": ARTIFACT_URL,
        "artifact_sha256": ARTIFACT_SHA256,
    },
    "guest": {
        "binary_path": BINARY_PATH,
        "systemd_unit": SYSTEMD_UNIT,
        "systemd_unit_path": SYSTEMD_UNIT_PATH,
        "systemd_unit_sha256": SYSTEMD_UNIT_SHA256,
        "service_user": SERVICE_USER,
        "service_group": SERVICE_GROUP,
        "config_path": CONFIG_PATH,
        "work_path": WORK_PATH,
        "data_path": DATA_PATH,
        "backup_root": BACKUP_ROOT,
        "state_path": STATE_PATH,
        "local_health_url": LOCAL_HEALTH_URL,
        "local_version_url": LOCAL_VERSION_URL,
        "external_version_url": EXTERNAL_VERSION_URL,
    },
    "ssh_policy_ref": SSH_POLICY_REF,
    "ssh_host_identity": {
        "host": IPV4_ADDRESS,
        "algorithm": SSH_HOST_KEY_ALGORITHM,
        "encoded_token_max_length": SSH_HOST_KEY_ENCODED_MAX_LENGTH,
        "base64_encoding": "standard-strict-with-valid-optional-padding",
        "wire_algorithm": SSH_HOST_KEY_ALGORITHM,
        "wire_key_bytes": SSH_HOST_KEY_BYTES,
    },
    "raw_params_schema": PARAMS_SCHEMA,
    "normalized_params_schema": NORMALIZED_PARAMS_SCHEMA,
    "command_fingerprint_schema": COMMAND_FINGERPRINT_SCHEMA,
    "result_schema": RESULT_SCHEMA,
    "result_states": RESULT_STATE_TUPLES,
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


COMMAND_CONTRACT_SHA256 = canonical_sha256(COMMAND_CONTRACT)
SEMANTIC_CAPABILITY_SHA256 = canonical_sha256(SEMANTIC_CAPABILITY_EXTENSION)

PROCEDURE_POLICY = {
    "name": PROCEDURE_NAME,
    "handler_id": HANDLER_ID,
    "version": VERSION,
    "enabled": ENABLED,
    "target_models": TARGET_MODELS,
    "effect": EFFECT,
    "timeout_seconds": TIMEOUT_SECONDS,
    "approval_required": APPROVAL_REQUIRED,
    "transport_driver": TRANSPORT_DRIVER,
    "transport_driver_chain": TRANSPORT_DRIVER_CHAIN,
    "output_parser": OUTPUT_PARSER,
    "output_schema": OUTPUT_SCHEMA,
    "command_contract_sha256": COMMAND_CONTRACT_SHA256,
    # Gitea-only approval binding. Capability compatibility and the signed
    # lease already carry the full contract hash; including the semantic digest
    # here also invalidates a pending or queued approval when exact backend,
    # executable, rollback, schema, or result semantics change.
    "semantic_contract_sha256": SEMANTIC_CAPABILITY_SHA256,
}

PROCEDURE_POLICY_SHA256 = canonical_sha256(PROCEDURE_POLICY)
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
RESULT_SCHEMA_SHA256 = canonical_sha256(RESULT_SCHEMA)
CAPABILITY_COMMAND_CONTRACT = [
    {
        key: row[key]
        for key in (
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
    }
    for row in COMMAND_CONTRACT
]
CAPABILITY_CONTRACT_PAYLOAD = {
    "handler_id": HANDLER_ID,
    "version": VERSION,
    "effect": EFFECT,
    "commands": CAPABILITY_COMMAND_CONTRACT,
    "semantic_contract": SEMANTIC_CAPABILITY_EXTENSION,
}
CAPABILITY_CONTRACT_CANONICAL_JSON = json.dumps(
    CAPABILITY_CONTRACT_PAYLOAD,
    sort_keys=True,
    separators=(",", ":"),
    default=str,
)
CAPABILITY_CONTRACT_SHA256 = hashlib.sha256(
    CAPABILITY_CONTRACT_CANONICAL_JSON.encode("utf-8")
).hexdigest()
