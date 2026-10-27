"""Fixed catalog contract for inspection of the user-scoped Python runner."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

import jsonschema
from pydantic import BaseModel, ConfigDict, Field

INSPECT_HANDLER_ID = "service.gitea.actions_runner.inspect_user_cache"
VERSION = 2
EFFECT = "read"
TIMEOUT_SECONDS = 120
TARGET_NAME = "Gitea-Runner"
TARGET_OBJECT_ID = 604
TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": TARGET_OBJECT_ID,
}
SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:604"
TARGET_SSH_POLICY_REF = SSH_POLICY_REF
HOST_MANAGEMENT_IP = "10.0.30.241"
RUNNER_ID = 44
RUNNER_NAME = "ci-untrusted-emersonfelipesp-241"
RUNNER_LABEL = "ci-untrusted-python312:host"
STACK_PATH = "/opt/nmc-ci-untrusted-user-241"
CONFIG_PATH = f"{STACK_PATH}/config.yaml"
COMPOSE_PATH = f"{STACK_PATH}/docker-compose.yml"
COMPOSE_PROJECT = "nmc-ci-untrusted-user-241"
RUNNER_SERVICE = "runner"
EXPECTED_EXEC_UID = 1000
RUNNER_FILE = "/data/.runner"
CACHE_DIR = "/data/cache"
WORKSPACE_DIR = "/data/workspace"
MAX_FILE_BYTES = 16_384
COMMAND_TIMEOUT_SECONDS = 20
MAX_INSPECT_BYTES = 16_384
BACKEND_RESPONSE_MAX_BYTES = 65_536


def canonical_sha256(value: Any) -> str:
    """Hash the compact, sorted JSON contract representation."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


TARGET_OBJECT_SHA256 = canonical_sha256(TARGET_OBJECT)


class EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InspectionEvidence(BaseModel):
    """The result never contains raw configuration, tokens, or command output."""

    model_config = ConfigDict(extra="forbid")

    target: Literal["Gitea-Runner"]
    target_object_id: Literal[604]
    runner_name: Literal["ci-untrusted-emersonfelipesp-241"]
    config_path: Literal["/opt/nmc-ci-untrusted-user-241/config.yaml"]
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compose_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_fixed_paths: bool
    capacity: int = Field(ge=0, le=16)
    host_label_matches: bool
    config_paths_match: bool
    compose_identity_matches: bool
    configured_image: str = Field(max_length=160)
    running_image: str = Field(max_length=160)
    running_image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_container_name: str = Field(
        max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
    )
    matches_source: bool
    installed_binary_version: str = Field(pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+$")
    exec_process_uid: int = Field(ge=0, le=2_147_483_647)
    container_config_user: str = Field(max_length=64)
    runtime_identity_matches: bool
    state: Literal["running", "created", "restarting", "exited", "paused", "dead"]
    health: Literal["healthy", "unhealthy", "starting"] | None
    cap_drop_all: bool
    cap_add_count: int = Field(ge=0, le=64)
    no_new_privileges: bool
    privileged: bool
    read_only_rootfs: bool
    mount_count: int = Field(ge=0, le=64)
    bind_mount_count: int = Field(ge=0, le=64)
    docker_socket_mounted: bool
    config_mount_read_only: bool
    registration_id: None = None
    user_scope_verified: Literal[False] = False
    active_job: None = None
    scheduling_drained: Literal[False] = False


class InspectResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    procedure: Literal["service.gitea.actions_runner.inspect_user_cache"]
    stage: Literal["complete", "indeterminate"]
    evidence: InspectionEvidence | None


PARAMS_SCHEMA = EmptyParams.model_json_schema()
RESULT_SCHEMA = InspectResult.model_json_schema()
RESULT_SCHEMAS = {INSPECT_HANDLER_ID: RESULT_SCHEMA}
COMMAND_CONTRACT = [
    {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "gitea-user-runner-cache-inspect"],
        "description": "Backend inspects fixed runner source, image, binary, and container fields.",
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
SEMANTIC_CONTRACT = {
    "target": TARGET_OBJECT,
    "target_name": TARGET_NAME,
    "management_ip": HOST_MANAGEMENT_IP,
    "runner_id": RUNNER_ID,
    "runner_name": RUNNER_NAME,
    "runner_label": RUNNER_LABEL,
    "stack_path": STACK_PATH,
    "config_path": CONFIG_PATH,
    "compose_path": COMPOSE_PATH,
    "compose_project": COMPOSE_PROJECT,
    "runner_service": RUNNER_SERVICE,
    "expected_exec_uid": EXPECTED_EXEC_UID,
    "scope_policy": "unknown-until-authenticated-gitea-read",
    "job_policy": "unknown-until-authenticated-gitea-read",
    "params_schema": PARAMS_SCHEMA,
    "result_schema": RESULT_SCHEMA,
    "runtime": {
        "max_file_bytes": MAX_FILE_BYTES,
        "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        "max_inspect_bytes": MAX_INSPECT_BYTES,
    },
}


def fallback_result() -> dict[str, Any]:
    """Return a closed result for an uncertain backend transport outcome."""
    return InspectResult(
        ok=False,
        procedure=INSPECT_HANDLER_ID,
        stage="indeterminate",
        evidence=None,
    ).model_dump(mode="json")


def _closed_envelope_parts(
    data: object,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return the envelope and result only when their public fields are exact."""
    if not isinstance(data, dict) or set(data) != {
        "ok",
        "result",
        "events",
        "error_code",
        "error_message",
    }:
        return None
    result = data.get("result")
    if not isinstance(result, dict):
        return None
    fields_match = (
        type(data.get("ok")) is bool,
        result.get("ok") is data["ok"],
        result.get("procedure") == INSPECT_HANDLER_ID,
        data.get("events") == [],
        isinstance(data.get("error_code"), str),
        isinstance(data.get("error_message"), str),
    )
    return (data, result) if all(fields_match) else None


def _status_matches_result(data: dict[str, Any], result: dict[str, Any]) -> bool:
    """Bind success and failure to their only allowed result states."""
    if data["ok"]:
        return (
            result.get("stage") == "complete"
            and result.get("evidence") is not None
            and not data["error_code"]
            and not data["error_message"]
        )
    return result.get("stage") == "indeterminate" and result.get("evidence") is None


def normalize_backend_response(data: object) -> dict[str, Any] | None:
    """Accept only the closed inspection envelope and return no backend text."""
    parts = _closed_envelope_parts(data)
    if parts is None:
        return None
    envelope, result = parts
    if not _status_matches_result(envelope, result):
        return None
    try:
        jsonschema.validate(result, RESULT_SCHEMA)
    except (jsonschema.ValidationError, jsonschema.SchemaError):
        return None
    return {"ok": envelope["ok"], "result": result}
