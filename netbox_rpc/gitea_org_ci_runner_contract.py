"""Immutable contract for the dedicated Gitea organization CI runner host.

The procedure remains unavailable until a paired backend handler ships.  This
module nevertheless defines the exact active policy that admission, approval,
worker claim, capability verification, and signed dispatch leases must agree
on before the gate can ever be opened.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


PROCEDURE_NAME = "service.gitea.actions_runner.provision_org_ci_runner"
HANDLER_ID = PROCEDURE_NAME
VERSION = 1
TARGET_MODELS = ["virtualization.virtualmachine"]
EFFECT = "write"
TIMEOUT_SECONDS = 1800
APPROVAL_REQUIRED = True
TRANSPORT_DRIVER = "asyncssh"
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
DEFAULT_GITEA_INSTANCE_URL = "http://10.0.30.96:3000"
DEFAULT_ORGANIZATION = "N-MultiCloud"

LANES = {
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
BOOLEAN_PARAM_DEFAULTS = {
    "install_docker": True,
    "build_runner_image": True,
    "load_prebuilt_runner_image": False,
    "force_recreate": False,
}

_LANE_NAMES = sorted(LANES)
_ALL_RUNNER_NAMES = sorted(lane["runner_name"] for lane in LANES.values())
_ALL_RUNNER_IMAGES = sorted(lane["runner_image"] for lane in LANES.values())
_ALL_COMPOSE_DIRS = sorted(lane["compose_project_dir"] for lane in LANES.values())
_NMS_SECRET_REF_PATTERN = (
    r"^nms-secret:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?![\s\S])"
)


def _lane_result_binding(lane_name: str) -> dict[str, Any]:
    lane = LANES[lane_name]
    return {
        "if": {"properties": {"lane": {"const": lane_name}}, "required": ["lane"]},
        "then": {
            "properties": {
                **{key: {"const": value} for key, value in lane.items()},
            }
        },
    }


PARAMS_SCHEMA = {
    "type": "object",
    "required": ["lane", "registration_token_secret_ref"],
    "additionalProperties": False,
    "properties": {
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
            "description": (
                "Which frozen runner lane to provision on the assigned host. "
                "Selects the compose directory, runner name, label set, image, "
                "and Docker-socket posture as one reviewed unit."
            ),
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
}

_SHORT_TEXT = {"type": "string", "maxLength": 64}
_ERROR = {"type": "string", "maxLength": 2048}

RESULT_SCHEMA = {
    "type": "object",
    "required": [
        "ok",
        "procedure",
        "target",
        "changed",
        "registered",
        "online",
        "stage",
        "runner_name",
        "organization",
        "lane",
        "runner_labels",
        "runner_image",
        "compose_project_dir",
        "executor",
        "runner_mounts_docker_socket",
        "jobs_mount_docker_socket",
        "runner_cap_drop_all",
        "runner_no_new_privileges",
        "job_user",
        "gitea_instance_url",
        "docker_installed",
        "image_ready",
        "compose_ready",
    ],
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": HANDLER_ID},
        "target": {"const": TARGET_NAME},
        "changed": {"type": ["boolean", "null"]},
        "registered": {"type": "boolean"},
        "online": {"type": "boolean"},
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
                "complete",
                "indeterminate",
            ],
        },
        "runner_name": {"enum": _ALL_RUNNER_NAMES},
        "organization": {"const": DEFAULT_ORGANIZATION},
        "lane": {"enum": _LANE_NAMES},
        "runner_image": {"enum": _ALL_RUNNER_IMAGES},
        "executor": {"type": "string", "enum": ["host", "docker"]},
        "runner_mounts_docker_socket": {"type": "boolean"},
        "jobs_mount_docker_socket": {"type": "boolean"},
        "runner_cap_drop_all": {"type": "boolean"},
        "runner_no_new_privileges": {"type": "boolean"},
        "job_user": {"type": ["string", "null"], "maxLength": 64},
        "runner_labels": {
            "type": "array",
            "items": {"type": "string", "maxLength": 255},
            "minItems": 1,
            "maxItems": 8,
            "uniqueItems": True,
        },
        "gitea_instance_url": {"const": DEFAULT_GITEA_INSTANCE_URL},
        "compose_project_dir": {"enum": _ALL_COMPOSE_DIRS},
        "docker_installed": {"type": "boolean"},
        "image_ready": {"type": "boolean"},
        "compose_ready": {"type": "boolean"},
        "container_state": _SHORT_TEXT,
        "service_state": _SHORT_TEXT,
        "warnings": {
            "type": "array",
            "items": {"type": "string", "maxLength": 512},
            "maxItems": 32,
        },
        "error": _ERROR,
    },
    "allOf": [_lane_result_binding(lane) for lane in _LANE_NAMES],
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "registered": {"const": True},
                "online": {"const": True},
                "stage": {"const": "complete"},
                "docker_installed": {"const": True},
                "image_ready": {"const": True},
                "compose_ready": {"const": True},
            }
        },
        {"properties": {"ok": {"const": False}}},
    ],
}

COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "gitea-org-ci-runner-provision"],
        "description": (
            "Backend installs Docker as needed, applies the selected frozen lane and "
            "trust posture, resolves the vaulted token reference, registers the org "
            "runner, starts it, and verifies online state."
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


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


TARGET_OBJECT_SHA256 = canonical_sha256(TARGET_OBJECT)
SEMANTIC_CAPABILITY_EXTENSION = {
    "version": VERSION,
    "backend": {
        "backend_id": BACKEND_ID,
        "base_url": BACKEND_BASE_URL,
        "verify_ssl": BACKEND_VERIFY_SSL,
    },
    "target": {
        "object": TARGET_OBJECT,
        "name": TARGET_NAME,
        "ipv4": TARGET_IPV4_ADDRESS,
    },
    "gitea": {
        "instance_url": DEFAULT_GITEA_INSTANCE_URL,
        "organization": DEFAULT_ORGANIZATION,
        "registration_token_transport": "nms-secret-reference-only",
    },
    "lanes": LANES,
    "boolean_defaults": BOOLEAN_PARAM_DEFAULTS,
    "params_schema": PARAMS_SCHEMA,
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
