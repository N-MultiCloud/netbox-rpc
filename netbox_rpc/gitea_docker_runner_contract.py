"""Immutable catalog contract for the fixed user-scoped Gitea Docker runner."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


DIAGNOSE_PROCEDURE_NAME = "service.gitea.actions_runner.diagnose_user_ci_runner"
RECOVER_PROCEDURE_NAME = "service.gitea.actions_runner.recover_user_ci_runner"
PROCEDURE_NAMES = frozenset({DIAGNOSE_PROCEDURE_NAME, RECOVER_PROCEDURE_NAME})
VERSION = 1
DIAGNOSE_EFFECT = "read"
RECOVER_EFFECT = "write"
DIAGNOSE_TIMEOUT_SECONDS = 120
RECOVER_TIMEOUT_SECONDS = 300
TARGET_MODELS = ["virtualization.virtualmachine"]
TARGET_NAME = "Gitea-Runner"
TARGET_OBJECT_ID = 604
TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": TARGET_OBJECT_ID,
}
TARGET_OBJECT_SHA256 = canonical_sha256(TARGET_OBJECT)
TARGET_SSH_POLICY_REF = "target-owned-ssh:virtualization.virtualmachine:604"

LANE = "user-ubuntu"
RUNNER_IDENTITY = "ci-ubuntu-emersonfelipesp-241"
COMPOSE_PROJECT_DIR = "/opt/nmc-ci-ubuntu-user-241"
COMPOSE_FILE = f"{COMPOSE_PROJECT_DIR}/docker-compose.yml"
RUNNER_SERVICE = "runner"
RUNNER_UNIT = "gitea-runner-ubuntu-user-241.service"
JOB_IMAGE = "nmulti/gitea-act-ubuntu:22.04-actions"
PROBE_HOSTS = ("git.nmulti.cloud", "github.com")
REVIEWED_DNS = ("168.0.96.26", "168.0.96.27")
JOB_NETWORK_PREFIX = "GITEA-ACTIONS-TASK-"
DNS_RECONCILE_SCRIPT_SHA256 = (
    "612e3577905566abad22f4222f3e0f41cb79638a0dab8f012914bdeff4d98980"
)
DIAGNOSE_BUDGET_SECONDS = 90
RECOVER_BUDGET_SECONDS = 240
CAPTURE_MAX_BYTES = 16_384
BACKEND_RESPONSE_MAX_BYTES = 65_536
MAX_NETWORKS = 64
MAX_ADDRESSES_PER_PROBE = 8
MAX_DEFAULT_ADDRESS_POOLS = 16

TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_PINNED = True
TRANSPORT_DRIVER_CHAIN: list[str] = []
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}
BACKEND_ID = 1
BACKEND_BASE_URL = "http://127.0.0.1:16005"
BACKEND_VERIFY_SSL = False


class EmptyParams(BaseModel):
    """The caller has no selector or command surface."""

    model_config = ConfigDict(extra="forbid")


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: Literal["git.nmulti.cloud", "github.com"]
    resolved: bool
    addresses: list[str] = Field(max_length=MAX_ADDRESSES_PER_PROBE)
    status: Literal["ok", "not_found", "error"]


class NetworkEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[0-9a-f]{12,64}$")
    name: str = Field(max_length=128)
    attached_containers: int = Field(ge=0, le=4096)
    disposition: Literal["active", "stale"]


class RunnerDiagnosticSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    docker_active: bool
    runner_container_name: str = Field(max_length=128)
    runner_container_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{12,64}$")
    runner_state: Literal["running", "exited", "missing", "unknown"]
    active_job: bool
    daemon_dns: list[str] = Field(max_length=4)
    default_address_pools: list[str] = Field(max_length=MAX_DEFAULT_ADDRESS_POOLS)
    probes: list[ProbeResult] = Field(min_length=2, max_length=2)
    networks: list[NetworkEvidence] = Field(max_length=MAX_NETWORKS)
    address_pool_exhausted: bool
    last_log_activity: str | None = Field(default=None, max_length=64)
    truncated: bool


class DiagnoseResult(RunnerDiagnosticSnapshot):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    procedure: Literal["service.gitea.actions_runner.diagnose_user_ci_runner"]
    target: Literal["Gitea-Runner"]
    target_object_id: Literal[604]
    lane: Literal["user-ubuntu"]
    stage: Literal["complete", "diagnose"]


class RecoverResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    procedure: Literal["service.gitea.actions_runner.recover_user_ci_runner"]
    target: Literal["Gitea-Runner"]
    target_object_id: Literal[604]
    lane: Literal["user-ubuntu"]
    stage: Literal["complete", "refused_active_job", "failed", "indeterminate"]
    before: RunnerDiagnosticSnapshot
    after: RunnerDiagnosticSnapshot | None
    removed_network_ids: list[Annotated[str, Field(pattern=r"^[0-9a-f]{12,64}$")]] = (
        Field(max_length=MAX_NETWORKS)
    )
    resolver_reconciled: bool
    restart_performed: bool
    refused_active_job: bool


PARAMS_SCHEMA = EmptyParams.model_json_schema()
NORMALIZED_PARAMS_SCHEMA = PARAMS_SCHEMA
DIAGNOSE_RESULT_SCHEMA = DiagnoseResult.model_json_schema()
RECOVER_RESULT_SCHEMA = RecoverResult.model_json_schema()


def _command(argv: list[str], description: str) -> list[dict[str, Any]]:
    return [
        {
            "sequence": 1,
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": argv,
            "description": description,
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
    DIAGNOSE_PROCEDURE_NAME: _command(
        ["backend-orchestrated", "gitea-user-ci-runner-diagnose"],
        "Backend diagnoses only the fixed user-scoped Docker runner lane.",
    ),
    RECOVER_PROCEDURE_NAME: _command(
        ["backend-orchestrated", "gitea-user-ci-runner-recover"],
        "Backend recovers only the fixed user lane after proving no job is active.",
    ),
}

SEMANTIC_CONTRACTS = {
    DIAGNOSE_PROCEDURE_NAME: {
        "target": TARGET_OBJECT,
        "target_name": TARGET_NAME,
        "lane": LANE,
        "runner_identity": RUNNER_IDENTITY,
        "compose_project_dir": COMPOSE_PROJECT_DIR,
        "compose_file": COMPOSE_FILE,
        "runner_service": RUNNER_SERVICE,
        "runner_unit": RUNNER_UNIT,
        "job_image": JOB_IMAGE,
        "probe_hosts": list(PROBE_HOSTS),
        "job_network_prefix": JOB_NETWORK_PREFIX,
        "params_schema": PARAMS_SCHEMA,
        "result_schema": DIAGNOSE_RESULT_SCHEMA,
        "runtime": {
            "budget_seconds": DIAGNOSE_BUDGET_SECONDS,
            "capture_max_bytes": CAPTURE_MAX_BYTES,
            "max_networks": MAX_NETWORKS,
        },
    },
    RECOVER_PROCEDURE_NAME: {
        "target": TARGET_OBJECT,
        "target_name": TARGET_NAME,
        "lane": LANE,
        "runner_identity": RUNNER_IDENTITY,
        "compose_project_dir": COMPOSE_PROJECT_DIR,
        "compose_file": COMPOSE_FILE,
        "runner_service": RUNNER_SERVICE,
        "runner_unit": RUNNER_UNIT,
        "reviewed_dns": list(REVIEWED_DNS),
        "dns_reconcile_script_sha256": DNS_RECONCILE_SCRIPT_SHA256,
        "job_network_prefix": JOB_NETWORK_PREFIX,
        "active_job_policy": "refuse-before-and-after-runner-pause",
        "network_removal_policy": "matching-prefix-and-zero-attached-containers-only",
        "default_address_pools_policy": "diagnostic-only",
        "params_schema": PARAMS_SCHEMA,
        "result_schema": RECOVER_RESULT_SCHEMA,
        "runtime": {
            "budget_seconds": RECOVER_BUDGET_SECONDS,
            "capture_max_bytes": CAPTURE_MAX_BYTES,
            "max_networks": MAX_NETWORKS,
        },
    },
}

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


def _capability_contract(procedure_name: str, effect: str) -> dict[str, Any]:
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
        _capability_contract(DIAGNOSE_PROCEDURE_NAME, DIAGNOSE_EFFECT)
    ),
    RECOVER_PROCEDURE_NAME: canonical_sha256(
        _capability_contract(RECOVER_PROCEDURE_NAME, RECOVER_EFFECT)
    ),
}
EXPECTED_CAPABILITY_CONTRACT_SHA256 = {
    DIAGNOSE_PROCEDURE_NAME: (
        "8e9a33d189f2850e95a77965505cb7e2625ba20c642fc22c7326812bdadb9e7f"
    ),
    RECOVER_PROCEDURE_NAME: (
        "4597aaf1d59c1fc554a3993316ea85444e4673801ea133ebc04c33fcd375da20"
    ),
}
if CAPABILITY_CONTRACT_SHA256 != EXPECTED_CAPABILITY_CONTRACT_SHA256:
    raise RuntimeError("Gitea Docker runner capability contract hash drifted.")


def _procedure_policy(procedure_name: str, effect: str, timeout: int) -> dict[str, Any]:
    return {
        "name": procedure_name,
        "handler_id": procedure_name,
        "version": VERSION,
        "enabled": True,
        "target_models": TARGET_MODELS,
        "effect": effect,
        "timeout_seconds": timeout,
        "approval_required": procedure_name == RECOVER_PROCEDURE_NAME,
        "transport_driver": TRANSPORT_DRIVER,
        "transport_pinned": TRANSPORT_PINNED,
        "transport_driver_chain": TRANSPORT_DRIVER_CHAIN,
        "output_parser": OUTPUT_PARSER,
        "output_schema": OUTPUT_SCHEMA,
        "command_contract_sha256": canonical_sha256(COMMAND_CONTRACTS[procedure_name]),
        "semantic_contract_sha256": canonical_sha256(
            SEMANTIC_CONTRACTS[procedure_name]
        ),
    }


PROCEDURE_POLICIES = {
    DIAGNOSE_PROCEDURE_NAME: _procedure_policy(
        DIAGNOSE_PROCEDURE_NAME, DIAGNOSE_EFFECT, DIAGNOSE_TIMEOUT_SECONDS
    ),
    RECOVER_PROCEDURE_NAME: _procedure_policy(
        RECOVER_PROCEDURE_NAME, RECOVER_EFFECT, RECOVER_TIMEOUT_SECONDS
    ),
}
PROCEDURE_POLICY = PROCEDURE_POLICIES[RECOVER_PROCEDURE_NAME]
RESULT_SCHEMAS = {
    DIAGNOSE_PROCEDURE_NAME: DIAGNOSE_RESULT_SCHEMA,
    RECOVER_PROCEDURE_NAME: RECOVER_RESULT_SCHEMA,
}
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
DIAGNOSE_RESULT_SCHEMA_SHA256 = canonical_sha256(DIAGNOSE_RESULT_SCHEMA)
RECOVER_RESULT_SCHEMA_SHA256 = canonical_sha256(RECOVER_RESULT_SCHEMA)
