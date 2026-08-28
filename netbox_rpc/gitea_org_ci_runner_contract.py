"""Immutable contract for the dedicated Gitea organization CI runner host.

The catalog row, code gate, and paired backend handler remain disabled.  This
module defines the exact policy that admission, approval, worker claim,
capability verification, the durable token-scope fence, and signed dispatch
leases must agree on before a separately reviewed activation can proceed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


PROCEDURE_NAME = "service.gitea.actions_runner.provision_org_ci_runner"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
JS_SAFE_INTEGER_MAX = 9_007_199_254_740_991
TIMEOUT_SECONDS = 1800
ROUTE_BUDGET_SECONDS = 1740
HANDLER_BUDGET_SECONDS = 1680
BACKEND_RESPONSE_MAX_BYTES = 8192
RECONCILIATION_QUIESCENCE_SECONDS = TIMEOUT_SECONDS
SHARED_FENCE_PROTOCOL = {
    "canonical_scope": "N-MultiCloud",
    "participants": [
        "service.gitea.actions_runner.provision_org_ci_runner",
        "service.gitea.runner.register",
    ],
    "takeover_generation_minimum": 1,
    "takeover_generation_maximum": JS_SAFE_INTEGER_MAX,
    "reconciliation_quiescence_seconds": RECONCILIATION_QUIESCENCE_SECONDS,
    "late_response_policy": "reject-generation-mismatch",
}
TARGET_MODELS = ["virtualization.virtualmachine"]
EFFECT = "write"
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_PINNED = True
TRANSPORT_DRIVER_CHAIN: list[str] = []
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}

BACKEND_ID = 1
BACKEND_BASE_URL = "http://127.0.0.1:16005"
BACKEND_VERIFY_SSL = False

TARGET_NAME = "Gitea-Runner"
TARGET_OBJECT_ID = 416
TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": TARGET_OBJECT_ID,
}
TARGET_IPV4_ADDRESS = "10.0.30.241"
TARGET_SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:416"
TARGET_SSH_PRINCIPAL = "nms-runner-bootstrap"

GITEA_TARGET_NAME = "Gitea"
GITEA_TARGET_ID = 170
GITEA_TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": GITEA_TARGET_ID,
}
TARGET_OBJECT_SHA256 = canonical_sha256(TARGET_OBJECT)
GITEA_TARGET_OBJECT_SHA256 = canonical_sha256(GITEA_TARGET_OBJECT)
GITEA_IPV4_ADDRESS = "10.0.30.96"
GITEA_SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:170"
GITEA_SSH_PRINCIPAL = "nms-gitea-runner-control"
DEFAULT_GITEA_INSTANCE_URL = "http://10.0.30.96:3000"
DEFAULT_ORGANIZATION = "N-MultiCloud"

RUNNER_REGISTER_HELPER = "/usr/local/libexec/gitea-runner/register-runner"
RUNNER_REGISTER_HELPER_SHA256 = (
    "15b72776c546ff433dc585bb8bab0645524adada7151aa9038d7b7e2711a49ed"
)
GITEA_TOKEN_RESET_HELPER = "/usr/local/libexec/nms/gitea-runner-token-reset"
GITEA_TOKEN_RESET_HELPER_SHA256 = (
    "67562056a5c00c1f667383b98d83ff43a136ea10079ab041079680a511614c78"
)
NATIVE_RUNNER_VERSION = "0.2.13+nmc.9"
NATIVE_RUNNER_SHA256 = (
    "9536fab4c686389b4c99d1846576bdb30cb4f4c197c0e156384b3ca5ce55deb2"
)
NATIVE_RUNNER_OVERLAY_SHA256 = (
    "df56855731b0cbf8da887258a6e9a815a283a18f3b4bc991861098e8bae8b7a9"
)
NATIVE_TOKEN_RESET_SHA256 = (
    "6d3e51f94512c19563543a719b245ed6fa731d7499cbdacdeec55b4619a46b87"
)

HOST_GENERATION_DEPENDENCY = "N-MultiCloud/nmulticloud-context#411"
HOST_GENERATION_ACTIVATION_ELIGIBLE = False
HOST_GENERATION_PROVISION_HELPER_PATH = None
HOST_GENERATION_PROVISION_HELPER_SHA256 = None
HOST_GENERATION_PROVE_HELPER_PATH = None
HOST_GENERATION_PROVE_HELPER_SHA256 = None

ROOT_BASE_IMAGE = (
    "ghcr.io/astral-sh/uv:0.12.5-python3.12-trixie-slim@"
    "sha256:0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f"
)
ROOT_BASE_IMAGE_DIGEST = (
    "0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f"
)
ROOT_PYTHON_VERSION = "3.12.14"
ROOT_PYTHON_SOURCE_SHA256 = (
    "5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a"
)
ROOT_UV_VERSION = "0.12.5"
ROOT_UV_ARCHIVE_SHA256 = (
    "68a509da24b06b4223a1c0175fb5eb5bc79342b76cbeff0cfe51ac3f5b17b6b2"
)

FUTURE_LANE_DESIGNS = {
    "untrusted-python312": {
        "compose_project_dir": "/opt/nmc-ci-untrusted-org-241",
        "runner_name": "ci-untrusted-nmulticloud-org-241",
        "runner_image": "nmc/ci-untrusted-runner:python312-241",
        "runner_labels": ["ci-untrusted-python312:host"],
        "executor": "host",
        "runner_mounts_docker_socket": False,
        "jobs_mount_docker_socket": False,
        "runner_cap_drop_all": True,
        "runner_no_new_privileges": True,
        "job_user": "cirunner",
    },
    "general-ubuntu": {
        "compose_project_dir": "/opt/nmc-ci-ubuntu-241",
        "runner_name": "ci-ubuntu-nmulticloud-org-241",
        "runner_image": "nmulti/gitea-act-ubuntu:22.04-actions",
        "runner_labels": [
            "ubuntu-latest:docker://nmulti/gitea-act-ubuntu:22.04-actions",
            "ubuntu-24.04:docker://nmulti/gitea-act-ubuntu:22.04-actions",
            "ubuntu-22.04:docker://nmulti/gitea-act-ubuntu:22.04-actions",
        ],
        "executor": "docker",
        "runner_mounts_docker_socket": True,
        "jobs_mount_docker_socket": False,
        "runner_cap_drop_all": False,
        "runner_no_new_privileges": False,
        "job_user": None,
    },
}

# Version 1 is deliberately root-only.  The two designs above remain inert
# source material for a future separately named/reviewed procedure; they are
# excluded from every caller-admissible schema and capability byte below.
LANES = {
    "root-python312": {
        "compose_project_dir": "/opt/nmc-ci-untrusted-root-org-241",
        "runner_name": "ci-untrusted-root-nmulticloud-org-241",
        # nmulticloud-context#411 must publish the content-addressed job image
        # and host-generation boundary before this lane can be activated.
        "runner_image": None,
        "runner_labels": ["ci-untrusted-root-python312"],
        "runner_label": "ci-untrusted-root-python312",
        "executor": "docker",
        "runner_mounts_docker_socket": True,
        "jobs_mount_docker_socket": False,
        "runner_cap_drop_all": True,
        "runner_no_new_privileges": True,
        "job_user": "0:0",
        "service_user": "gitea-runner-nmulticloud-org-root",
        "service_user_login": False,
        "state_dir": "/var/lib/gitea-runner-nmulticloud-org-root",
        "config_path": "/etc/gitea-runner/nmulticloud-org-root.yaml",
        "capacity": 1,
        "fresh_container_per_job": True,
        "rootless_user_namespace": True,
        "container_uid0_maps_to_host_root": False,
        "container_privileged": False,
        "container_host_network": False,
        "container_host_pid": False,
        "container_host_ipc": False,
        "container_host_uts": False,
        "container_bind_workdir": False,
        "container_valid_volumes": [],
        "container_devices": [],
        "container_host_effective_capabilities": [],
        "container_host_ambient_capabilities": [],
        "job_cap_drop_all": True,
        "job_no_new_privileges": True,
        "container_cap_add": [
            "CHOWN",
            "SETUID",
            "SETGID",
            "FOWNER",
            "DAC_OVERRIDE",
        ],
        "container_daemon_socket_in_job": False,
        "job_network_policy": {
            "default_action": "deny",
            "build": {
                "network_mode": "none",
                "dns_resolvers": [],
                "egress": [],
            },
            "publisher": {
                "network_mode": "filtered",
                "dns_required": False,
                "dns_resolvers": [],
                "host_bindings": [
                    {"hostname": "git.nmulti.cloud", "ipv4": "10.0.30.96"}
                ],
                "https_origins": ["https://git.nmulti.cloud:443"],
                "ipv4_destinations": ["10.0.30.96/32"],
                "tcp_ports": [443],
                "tls_server_names": ["git.nmulti.cloud"],
                "tls_verify": True,
                "redirects": False,
            },
            "other_egress": "deny",
        },
        "job_resource_limits": {
            "cgroup_version": 2,
            "cpu_period_us": 100_000,
            "cpu_quota_us": 200_000,
            "cpu_weight": 100,
            "memory_max_bytes": 4_294_967_296,
            "memory_swap_max_bytes": 0,
            "pids_max": 512,
            "root_filesystem_read_only": True,
            "writable_paths": ["/workspace", "/tmp", "/run"],
            "workspace": {
                "path": "/workspace",
                "kind": "ephemeral-volume",
                "host_bind": False,
                "disk_quota_bytes": 8_589_934_592,
            },
            "tmpfs": [
                {
                    "path": "/tmp",
                    "size_bytes": 1_073_741_824,
                    "options": ["nodev", "nosuid", "noexec"],
                },
                {
                    "path": "/run",
                    "size_bytes": 67_108_864,
                    "options": ["nodev", "nosuid", "noexec"],
                },
            ],
            "ulimits": {
                "core": {"soft": 0, "hard": 0},
                "fsize": {"soft": 8_589_934_592, "hard": 8_589_934_592},
                "nofile": {"soft": 1024, "hard": 1024},
                "nproc": {"soft": 512, "hard": 512},
            },
            "wall_clock_timeout_seconds": 1800,
            "kill_grace_seconds": 10,
        },
        "management_egress_policy": "deny-except-gitea-publisher",
        "production_egress_policy": "deny-except-gitea-publisher",
        "cross_scope_state": False,
        "activation_eligible": HOST_GENERATION_ACTIVATION_ELIGIBLE,
        "activation_blocker": HOST_GENERATION_DEPENDENCY,
        "base_image_reference": ROOT_BASE_IMAGE,
        "base_image_digest": ROOT_BASE_IMAGE_DIGEST,
        "provision_helper_path": HOST_GENERATION_PROVISION_HELPER_PATH,
        "provision_helper_sha256": HOST_GENERATION_PROVISION_HELPER_SHA256,
        "prove_helper_path": HOST_GENERATION_PROVE_HELPER_PATH,
        "prove_helper_sha256": HOST_GENERATION_PROVE_HELPER_SHA256,
        "python_version": ROOT_PYTHON_VERSION,
        "python_source_sha256": ROOT_PYTHON_SOURCE_SHA256,
        "uv_version": ROOT_UV_VERSION,
        "uv_archive_sha256": ROOT_UV_ARCHIVE_SHA256,
    },
}
LANE_CONTRACT_SHA256 = {
    lane: canonical_sha256(lane_contract) for lane, lane_contract in LANES.items()
}
SCOPE_BY_LANE = {
    "root-python312": "nmulticloud-org-root",
}
GITEA_SCOPE_BY_SCOPE = {
    "nmulticloud-org-root": DEFAULT_ORGANIZATION,
}
OPERATIONS = ("provision", "reconcile")
FENCE_UNKNOWN_SHA256 = "0" * 64
BOOLEAN_PARAM_DEFAULTS = {
    "install_docker": True,
    "build_runner_image": True,
    "load_prebuilt_runner_image": False,
    "force_recreate": False,
}


def activation_unavailable_reason(params: object) -> str | None:
    """Return the source prerequisite blocking one schema-valid lane request."""
    if not isinstance(params, dict):
        return None
    lane = params.get("lane")
    lane_contract = LANES.get(lane) if isinstance(lane, str) else None
    if not isinstance(lane_contract, dict):
        return None
    if lane_contract.get("activation_eligible") is not False:
        return None
    return (
        f"{lane} host generation is unavailable until "
        f"{HOST_GENERATION_DEPENDENCY} publishes a reviewed "
        "content-addressed provision-and-prove boundary."
    )


_LANE_NAMES = sorted(LANES)
_SCOPES = sorted(set(SCOPE_BY_LANE.values()))
_ALL_RUNNER_NAMES = sorted(lane["runner_name"] for lane in LANES.values())
_ALL_RUNNER_IMAGES = sorted(
    lane["runner_image"]
    for lane in LANES.values()
    if isinstance(lane["runner_image"], str)
)
_ALL_COMPOSE_DIRS = sorted(lane["compose_project_dir"] for lane in LANES.values())
_NMS_SECRET_REF_PATTERN = (
    r"^nms-secret:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?![\s\S])"
)
_SHA256_PATTERN = r"^[0-9a-f]{64}(?![\s\S])"
_REVISION_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)


def _lane_binding(lane_name: str) -> dict[str, Any]:
    lane = LANES[lane_name]
    scope = SCOPE_BY_LANE[lane_name]
    return {
        "if": {"properties": {"lane": {"const": lane_name}}, "required": ["lane"]},
        "then": {
            "required": list(lane),
            "properties": {
                "scope": {"const": scope},
                **{key: {"const": value} for key, value in lane.items()},
            },
        },
    }


def _secret_reference_operation_bindings() -> list[dict[str, Any]]:
    return [
        {
            "if": {
                "properties": {"operation": {"const": "provision"}},
                "required": ["operation"],
            },
            "then": {"required": ["registration_token_secret_ref"]},
        },
        {
            "if": {
                "properties": {"operation": {"const": "reconcile"}},
                "required": ["operation"],
            },
            "then": {"not": {"required": ["registration_token_secret_ref"]}},
        },
    ]


def _lane_fingerprint_binding(lane_name: str) -> dict[str, Any]:
    return {
        "if": {
            "properties": {"lane": {"const": lane_name}},
            "required": ["lane"],
        },
        "then": {
            "properties": {
                "scope": {"const": SCOPE_BY_LANE[lane_name]},
                "lane_contract_sha256": {"const": LANE_CONTRACT_SHA256[lane_name]},
            }
        },
    }


PARAMS_SCHEMA = {
    "type": "object",
    "required": ["operation", "lane"],
    "additionalProperties": False,
    "properties": {
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "registration_token_secret_ref": {
            "type": "string",
            "minLength": 47,
            "maxLength": 47,
            "pattern": _NMS_SECRET_REF_PATTERN,
            "description": "Reference to the vaulted one-time Gitea runner token.",
        },
        "lane": {
            "type": "string",
            "enum": _LANE_NAMES,
            "description": "Selects one complete frozen runner trust domain.",
        },
        "install_docker": {"type": "boolean", "default": True},
        "build_runner_image": {"type": "boolean", "default": True},
        "load_prebuilt_runner_image": {"type": "boolean", "default": False},
        "force_recreate": {"type": "boolean", "default": False},
    },
    "not": {
        "required": ["build_runner_image", "load_prebuilt_runner_image"],
        "properties": {
            "build_runner_image": {"const": True},
            "load_prebuilt_runner_image": {"const": True},
        },
    },
    "allOf": _secret_reference_operation_bindings(),
}

_LANE_RESULT_PROPERTIES: dict[str, Any] = {
    "compose_project_dir": {"enum": _ALL_COMPOSE_DIRS},
    "runner_name": {"enum": _ALL_RUNNER_NAMES},
    "runner_image": {"enum": [*_ALL_RUNNER_IMAGES, None]},
    "runner_labels": {
        "type": "array",
        "items": {"type": "string", "maxLength": 512},
        "minItems": 1,
        "maxItems": 8,
        "uniqueItems": True,
    },
    "executor": {"type": "string", "enum": ["host", "docker"]},
    "runner_mounts_docker_socket": {"type": "boolean"},
    "jobs_mount_docker_socket": {"type": "boolean"},
    "runner_cap_drop_all": {"type": "boolean"},
    "runner_no_new_privileges": {"type": "boolean"},
    "job_user": {"type": ["string", "null"], "maxLength": 64},
    "runner_label": {"const": "ci-untrusted-root-python312"},
    "service_user": {"const": "gitea-runner-nmulticloud-org-root"},
    "service_user_login": {"const": False},
    "state_dir": {"const": "/var/lib/gitea-runner-nmulticloud-org-root"},
    "config_path": {"const": "/etc/gitea-runner/nmulticloud-org-root.yaml"},
    "capacity": {"const": 1},
    "fresh_container_per_job": {"const": True},
    "rootless_user_namespace": {"const": True},
    "container_uid0_maps_to_host_root": {"const": False},
    "container_privileged": {"const": False},
    "container_host_network": {"const": False},
    "container_host_pid": {"const": False},
    "container_host_ipc": {"const": False},
    "container_host_uts": {"const": False},
    "container_bind_workdir": {"const": False},
    "container_valid_volumes": {"const": []},
    "container_devices": {"const": []},
    "container_host_effective_capabilities": {"const": []},
    "container_host_ambient_capabilities": {"const": []},
    "job_cap_drop_all": {"const": True},
    "job_no_new_privileges": {"const": True},
    "container_cap_add": {
        "const": ["CHOWN", "SETUID", "SETGID", "FOWNER", "DAC_OVERRIDE"]
    },
    "container_daemon_socket_in_job": {"const": False},
    "job_network_policy": {"const": LANES["root-python312"]["job_network_policy"]},
    "job_resource_limits": {"const": LANES["root-python312"]["job_resource_limits"]},
    "management_egress_policy": {"const": "deny-except-gitea-publisher"},
    "production_egress_policy": {"const": "deny-except-gitea-publisher"},
    "cross_scope_state": {"const": False},
    "activation_eligible": {"const": False},
    "activation_blocker": {"const": HOST_GENERATION_DEPENDENCY},
    "base_image_reference": {"const": ROOT_BASE_IMAGE},
    "base_image_digest": {"const": ROOT_BASE_IMAGE_DIGEST},
    "provision_helper_path": {"const": None},
    "provision_helper_sha256": {"const": None},
    "prove_helper_path": {"const": None},
    "prove_helper_sha256": {"const": None},
    "python_version": {"const": ROOT_PYTHON_VERSION},
    "python_source_sha256": {"const": ROOT_PYTHON_SOURCE_SHA256},
    "uv_version": {"const": ROOT_UV_VERSION},
    "uv_archive_sha256": {"const": ROOT_UV_ARCHIVE_SHA256},
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
        "lane",
        "fence_execution_id",
        "fence_generation",
        "provisioned",
        "registered",
        "reconciled",
        "stage",
        "organization",
        "gitea_instance_url",
        "token_invalidated",
        "token_reset_required",
        "token_sha256",
        "reset_state",
        "prior_token_id",
        "prior_active_sha256",
        "replacement_token_id",
        "runner_name",
        "runner_labels",
        "runner_image",
        "compose_project_dir",
        "executor",
        "runner_mounts_docker_socket",
        "jobs_mount_docker_socket",
        "runner_cap_drop_all",
        "runner_no_new_privileges",
        "job_user",
    ],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"const": TARGET_NAME},
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "scope": {"type": "string", "enum": _SCOPES},
        "lane": {"type": "string", "enum": _LANE_NAMES},
        "fence_execution_id": {
            "type": ["integer", "null"],
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        "fence_generation": {
            "type": "integer",
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        "provisioned": {"type": ["boolean", "null"]},
        "registered": {"type": ["boolean", "null"]},
        "reconciled": {"type": ["boolean", "null"]},
        "stage": {
            "type": "string",
            "enum": [
                "preconditions",
                "docker",
                "image",
                "config",
                "register",
                "start",
                "verify",
                "reset",
                "reconcile",
                "complete",
                "indeterminate",
            ],
        },
        "organization": {"const": DEFAULT_ORGANIZATION},
        "gitea_instance_url": {"const": DEFAULT_GITEA_INSTANCE_URL},
        "token_invalidated": {"type": "boolean"},
        "token_reset_required": {"type": "boolean"},
        "token_sha256": {"type": ["string", "null"], "pattern": _SHA256_PATTERN},
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
        "prior_token_id": {
            "type": ["integer", "null"],
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        "prior_active_sha256": {
            "type": ["string", "null"],
            "pattern": _SHA256_PATTERN,
        },
        "replacement_token_id": {
            "type": ["integer", "null"],
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        **_LANE_RESULT_PROPERTIES,
    },
    "allOf": [_lane_binding(lane) for lane in _LANE_NAMES],
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "operation": {"const": "provision"},
                "provisioned": {"const": True},
                "registered": {"const": True},
                "reconciled": {"const": None},
                "stage": {"const": "complete"},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
                "reset_state": {"enum": ["rotated", "already_inactive"]},
                "prior_token_id": {"type": "integer", "minimum": 1},
                "replacement_token_id": {"type": "integer", "minimum": 1},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "provision"},
                "provisioned": {"const": False},
                "registered": {"const": False},
                "reconciled": {"const": None},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": False},
                "token_sha256": {"const": None},
                "reset_state": {"const": "not_started"},
                "prior_token_id": {"const": None},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {"const": None},
                "stage": {"enum": ["preconditions", "docker", "image", "config"]},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "provision"},
                "provisioned": {"type": ["boolean", "null"]},
                "registered": {"type": ["boolean", "null"]},
                "reconciled": {"const": None},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
                "reset_state": {"enum": ["rotated", "already_inactive"]},
                "prior_token_id": {"type": "integer", "minimum": 1},
                "replacement_token_id": {"type": "integer", "minimum": 1},
                "stage": {
                    "enum": [
                        "register",
                        "start",
                        "verify",
                        "indeterminate",
                    ]
                },
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "provision"},
                "provisioned": {"type": ["boolean", "null"]},
                "registered": {"type": ["boolean", "null"]},
                "reconciled": {"const": None},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": True},
                "reset_state": {"enum": ["failed", "indeterminate"]},
                "stage": {
                    "enum": ["register", "start", "verify", "reset", "indeterminate"]
                },
            }
        },
        {
            "properties": {
                "ok": {"const": True},
                "operation": {"const": "reconcile"},
                "provisioned": {"const": None},
                "registered": {"const": None},
                "reconciled": {"const": True},
                "stage": {"const": "complete"},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
                "reset_state": {
                    "enum": [
                        "reconciled_expected_active",
                        "reconciled_expected_inactive",
                        "reconciled_no_active",
                    ]
                },
                "replacement_token_id": {"type": "integer", "minimum": 1},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "reconcile"},
                "provisioned": {"const": None},
                "registered": {"const": None},
                "reconciled": {"type": ["boolean", "null"]},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": True},
                "token_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
                "reset_state": {"enum": ["failed", "indeterminate"]},
                "replacement_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "stage": {"enum": ["reconcile", "indeterminate"]},
            }
        },
    ],
}


def _ssh_snapshot_schema(
    *, host: str, policy_ref: str, principal: str
) -> dict[str, Any]:
    return {
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
            "ssh_service_id": {
                "type": "integer",
                "minimum": 1,
                "maximum": JS_SAFE_INTEGER_MAX,
            },
            "ssh_service_revision": {
                "type": "string",
                "maxLength": 64,
                "pattern": _REVISION_PATTERN,
            },
            "ssh_identity_id": {
                "type": "integer",
                "minimum": 1,
                "maximum": JS_SAFE_INTEGER_MAX,
            },
            "ssh_identity_revision": {
                "type": "string",
                "maxLength": 64,
                "pattern": _REVISION_PATTERN,
            },
            "ssh_storage_backend": {"const": "local"},
            "ssh_principal": {"const": principal},
            "ssh_method": {"enum": ["key", "key_with_passphrase", "password"]},
            "ssh_host": {"const": host},
            "ssh_port": {"const": 22},
            "ssh_known_hosts_sha256": {
                "type": "string",
                "pattern": _SHA256_PATTERN,
            },
            "ssh_policy_ref": {"const": policy_ref},
        },
    }


RUNNER_SSH_SNAPSHOT_SCHEMA = _ssh_snapshot_schema(
    host=TARGET_IPV4_ADDRESS,
    policy_ref=TARGET_SSH_POLICY_REF,
    principal=TARGET_SSH_PRINCIPAL,
)
GITEA_SSH_SNAPSHOT_SCHEMA = _ssh_snapshot_schema(
    host=GITEA_IPV4_ADDRESS,
    policy_ref=GITEA_SSH_POLICY_REF,
    principal=GITEA_SSH_PRINCIPAL,
)

COMMAND_FINGERPRINT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "handler_id",
        "procedure",
        "assigned_object_id",
        "target_object_sha256",
        "gitea_target_object_sha256",
        "operation",
        "scope",
        "gitea_scope",
        "fence_state",
        "fence_expected_sha256",
        "fence_execution_id",
        "fence_generation",
        "lane",
        "lane_contract_sha256",
        "gitea_instance_url",
        "organization",
        "runner_ssh_snapshot_sha256",
        "gitea_ssh_snapshot_sha256",
        *BOOLEAN_PARAM_DEFAULTS,
    ],
    "properties": {
        "handler_id": {"const": HANDLER_ID},
        "procedure": {"const": PROCEDURE_NAME},
        "assigned_object_id": {"const": TARGET_OBJECT_ID},
        "target_object_sha256": {"const": TARGET_OBJECT_SHA256},
        "gitea_target_object_sha256": {"const": GITEA_TARGET_OBJECT_SHA256},
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "scope": {"type": "string", "enum": _SCOPES},
        "gitea_scope": {"const": DEFAULT_ORGANIZATION},
        "fence_state": {"type": "string", "enum": ["blocked", "clear", "pending"]},
        "fence_expected_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
        "fence_execution_id": {
            "type": ["integer", "null"],
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        "fence_generation": {
            "type": "integer",
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        "registration_token_secret_ref": PARAMS_SCHEMA["properties"][
            "registration_token_secret_ref"
        ],
        "lane": {"type": "string", "enum": _LANE_NAMES},
        "lane_contract_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
        "gitea_instance_url": {"const": DEFAULT_GITEA_INSTANCE_URL},
        "organization": {"const": DEFAULT_ORGANIZATION},
        "runner_ssh_snapshot_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
        "gitea_ssh_snapshot_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
        **{key: {"type": "boolean"} for key in BOOLEAN_PARAM_DEFAULTS},
    },
    "allOf": [
        *[_lane_fingerprint_binding(lane) for lane in _LANE_NAMES],
        *_secret_reference_operation_bindings(),
    ],
}

NORMALIZED_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "target",
        "target_object",
        "runner_ipv4",
        "gitea_target",
        "gitea_target_object",
        "gitea_ipv4",
        "ssh_policy_ref",
        "runner_ssh_snapshot",
        "gitea_ssh_snapshot",
        "operation",
        "scope",
        "gitea_scope",
        "fence_state",
        "fence_expected_sha256",
        "fence_execution_id",
        "fence_generation",
        "lane",
        "gitea_instance_url",
        "organization",
        "register_helper_sha256",
        "token_reset_helper_sha256",
        *BOOLEAN_PARAM_DEFAULTS,
        "command_fingerprint",
    ],
    "properties": {
        "target": {"const": TARGET_NAME},
        "target_object": {"const": TARGET_OBJECT},
        "runner_ipv4": {"const": TARGET_IPV4_ADDRESS},
        "gitea_target": {"const": GITEA_TARGET_NAME},
        "gitea_target_object": {"const": GITEA_TARGET_OBJECT},
        "gitea_ipv4": {"const": GITEA_IPV4_ADDRESS},
        "ssh_policy_ref": {"const": TARGET_SSH_POLICY_REF},
        "runner_ssh_snapshot": RUNNER_SSH_SNAPSHOT_SCHEMA,
        "gitea_ssh_snapshot": GITEA_SSH_SNAPSHOT_SCHEMA,
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "scope": {"type": "string", "enum": _SCOPES},
        "gitea_scope": {"const": DEFAULT_ORGANIZATION},
        "fence_state": {"type": "string", "enum": ["blocked", "clear", "pending"]},
        "fence_expected_sha256": {"type": "string", "pattern": _SHA256_PATTERN},
        "fence_execution_id": {
            "type": ["integer", "null"],
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        "fence_generation": {
            "type": "integer",
            "minimum": 1,
            "maximum": JS_SAFE_INTEGER_MAX,
        },
        "registration_token_secret_ref": PARAMS_SCHEMA["properties"][
            "registration_token_secret_ref"
        ],
        "lane": {"type": "string", "enum": _LANE_NAMES},
        "gitea_instance_url": {"const": DEFAULT_GITEA_INSTANCE_URL},
        "organization": {"const": DEFAULT_ORGANIZATION},
        "register_helper_sha256": {"const": RUNNER_REGISTER_HELPER_SHA256},
        "token_reset_helper_sha256": {"const": GITEA_TOKEN_RESET_HELPER_SHA256},
        **{key: {"type": "boolean"} for key in BOOLEAN_PARAM_DEFAULTS},
        **_LANE_RESULT_PROPERTIES,
        "command_fingerprint": COMMAND_FINGERPRINT_SCHEMA,
    },
    "allOf": [
        *[_lane_binding(lane) for lane in _LANE_NAMES],
        *_secret_reference_operation_bindings(),
    ],
}

COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "gitea-org-ci-runner-provision"],
        "description": (
            "Backend provisions or reconciles one frozen org-runner lane and "
            "always invalidates the exact resolved registration token."
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


SEMANTIC_CAPABILITY_EXTENSION = {
    "version": VERSION,
    "runtime": {
        "route_budget_seconds": ROUTE_BUDGET_SECONDS,
        "handler_budget_seconds": HANDLER_BUDGET_SECONDS,
        "backend_response_max_bytes": BACKEND_RESPONSE_MAX_BYTES,
        "reconciliation_quiescence_seconds": RECONCILIATION_QUIESCENCE_SECONDS,
    },
    "backend": {
        "backend_id": BACKEND_ID,
        "base_url": BACKEND_BASE_URL,
        "verify_ssl": BACKEND_VERIFY_SSL,
    },
    "runner_target": {
        "object": TARGET_OBJECT,
        "name": TARGET_NAME,
        "ipv4": TARGET_IPV4_ADDRESS,
        "ssh_policy_ref": TARGET_SSH_POLICY_REF,
        "ssh_principal": TARGET_SSH_PRINCIPAL,
    },
    "gitea_target": {
        "object": GITEA_TARGET_OBJECT,
        "name": GITEA_TARGET_NAME,
        "ipv4": GITEA_IPV4_ADDRESS,
        "instance_url": DEFAULT_GITEA_INSTANCE_URL,
        "organization": DEFAULT_ORGANIZATION,
        "ssh_policy_ref": GITEA_SSH_POLICY_REF,
        "ssh_principal": GITEA_SSH_PRINCIPAL,
    },
    "registration": {
        "operations": list(OPERATIONS),
        "scope_by_lane": SCOPE_BY_LANE,
        "gitea_scope_by_scope": GITEA_SCOPE_BY_SCOPE,
        "token_transport": "nms-secret-reference-only",
        "fence_unknown_sha256": FENCE_UNKNOWN_SHA256,
        "shared_fence_protocol": SHARED_FENCE_PROTOCOL,
        "register_helper": RUNNER_REGISTER_HELPER,
        "register_helper_sha256": RUNNER_REGISTER_HELPER_SHA256,
        "token_reset_helper": GITEA_TOKEN_RESET_HELPER,
        "token_reset_helper_sha256": GITEA_TOKEN_RESET_HELPER_SHA256,
    },
    "host_generation": {
        "activation_eligible": HOST_GENERATION_ACTIVATION_ELIGIBLE,
        "activation_blocker": HOST_GENERATION_DEPENDENCY,
        "provision_helper_path": HOST_GENERATION_PROVISION_HELPER_PATH,
        "provision_helper_sha256": HOST_GENERATION_PROVISION_HELPER_SHA256,
        "prove_helper_path": HOST_GENERATION_PROVE_HELPER_PATH,
        "prove_helper_sha256": HOST_GENERATION_PROVE_HELPER_SHA256,
        "base_image_reference": ROOT_BASE_IMAGE,
        "base_image_digest": ROOT_BASE_IMAGE_DIGEST,
        "native_runner_version": NATIVE_RUNNER_VERSION,
        "native_runner_sha256": NATIVE_RUNNER_SHA256,
        "native_runner_overlay_sha256": NATIVE_RUNNER_OVERLAY_SHA256,
        "native_token_reset_sha256": NATIVE_TOKEN_RESET_SHA256,
    },
    "lanes": LANES,
    "lane_contract_sha256": LANE_CONTRACT_SHA256,
    "boolean_defaults": BOOLEAN_PARAM_DEFAULTS,
    "params_schema": PARAMS_SCHEMA,
    "normalized_params_schema": NORMALIZED_PARAMS_SCHEMA,
    "command_fingerprint_schema": COMMAND_FINGERPRINT_SCHEMA,
    "result_schema": RESULT_SCHEMA,
}
SEMANTIC_CAPABILITY_BYTES = canonical_json_bytes(SEMANTIC_CAPABILITY_EXTENSION)
SEMANTIC_CAPABILITY_SHA256 = hashlib.sha256(SEMANTIC_CAPABILITY_BYTES).hexdigest()

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
CAPABILITY_CONTRACT = {
    "handler_id": HANDLER_ID,
    "version": VERSION,
    "effect": EFFECT,
    "commands": [
        {key: command[key] for key in _CAPABILITY_COMMAND_KEYS}
        for command in COMMAND_CONTRACT
    ],
    "semantic_contract": SEMANTIC_CAPABILITY_EXTENSION,
}
CAPABILITY_CONTRACT_BYTES = canonical_json_bytes(CAPABILITY_CONTRACT)
CAPABILITY_CONTRACT_SHA256 = hashlib.sha256(CAPABILITY_CONTRACT_BYTES).hexdigest()

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
    "transport_pinned": TRANSPORT_PINNED,
    "transport_driver_chain": TRANSPORT_DRIVER_CHAIN,
    "output_parser": OUTPUT_PARSER,
    "output_schema": OUTPUT_SCHEMA,
    "command_contract_sha256": canonical_sha256(COMMAND_CONTRACT),
    "semantic_contract_sha256": SEMANTIC_CAPABILITY_SHA256,
}

PROCEDURE_POLICY_SHA256 = canonical_sha256(PROCEDURE_POLICY)
COMMAND_CONTRACT_SHA256 = canonical_sha256(COMMAND_CONTRACT)
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
NORMALIZED_PARAMS_SCHEMA_SHA256 = canonical_sha256(NORMALIZED_PARAMS_SCHEMA)
COMMAND_FINGERPRINT_SCHEMA_SHA256 = canonical_sha256(COMMAND_FINGERPRINT_SCHEMA)
RESULT_SCHEMA_SHA256 = canonical_sha256(RESULT_SCHEMA)
