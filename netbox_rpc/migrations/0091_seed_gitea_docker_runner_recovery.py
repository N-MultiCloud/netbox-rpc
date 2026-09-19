"""Seed fixed-contract diagnosis and recovery for the user-scoped CI runner."""

from django.db import migrations

_DIAGNOSE_NAME = "service.gitea.actions_runner.diagnose_user_ci_runner"
_RECOVER_NAME = "service.gitea.actions_runner.recover_user_ci_runner"
_PROCEDURE_NAMES = (_DIAGNOSE_NAME, _RECOVER_NAME)

_PARAMS_SCHEMA = {
    "additionalProperties": False,
    "description": "The caller has no selector or command surface.",
    "properties": {},
    "title": "EmptyParams",
    "type": "object",
}
_PROBE_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "host": {
            "enum": ["git.nmulti.cloud", "github.com"],
            "title": "Host",
            "type": "string",
        },
        "resolved": {"title": "Resolved", "type": "boolean"},
        "addresses": {
            "items": {"type": "string"},
            "maxItems": 8,
            "title": "Addresses",
            "type": "array",
        },
        "status": {
            "enum": ["ok", "not_found", "error"],
            "title": "Status",
            "type": "string",
        },
    },
    "required": ["host", "resolved", "addresses", "status"],
    "title": "ProbeResult",
    "type": "object",
}
_NETWORK_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "id": {
            "pattern": r"^[0-9a-f]{12,64}$",
            "title": "Id",
            "type": "string",
        },
        "name": {"maxLength": 128, "title": "Name", "type": "string"},
        "attached_containers": {
            "maximum": 4096,
            "minimum": 0,
            "title": "Attached Containers",
            "type": "integer",
        },
        "disposition": {
            "enum": ["active", "stale"],
            "title": "Disposition",
            "type": "string",
        },
    },
    "required": ["id", "name", "attached_containers", "disposition"],
    "title": "NetworkEvidence",
    "type": "object",
}


def _snapshot_properties():
    return {
        "docker_active": {"title": "Docker Active", "type": "boolean"},
        "runner_container_name": {
            "maxLength": 128,
            "title": "Runner Container Name",
            "type": "string",
        },
        "runner_container_id": {
            "anyOf": [
                {"pattern": r"^[0-9a-f]{12,64}$", "type": "string"},
                {"type": "null"},
            ],
            "default": None,
            "title": "Runner Container Id",
        },
        "runner_state": {
            "enum": ["running", "exited", "missing", "unknown"],
            "title": "Runner State",
            "type": "string",
        },
        "active_job": {"title": "Active Job", "type": "boolean"},
        "daemon_dns": {
            "items": {"type": "string"},
            "maxItems": 4,
            "title": "Daemon Dns",
            "type": "array",
        },
        "default_address_pools": {
            "items": {"type": "string"},
            "maxItems": 16,
            "title": "Default Address Pools",
            "type": "array",
        },
        "probes": {
            "items": {"$ref": "#/$defs/ProbeResult"},
            "maxItems": 2,
            "minItems": 2,
            "title": "Probes",
            "type": "array",
        },
        "networks": {
            "items": {"$ref": "#/$defs/NetworkEvidence"},
            "maxItems": 64,
            "title": "Networks",
            "type": "array",
        },
        "address_pool_exhausted": {
            "title": "Address Pool Exhausted",
            "type": "boolean",
        },
        "last_log_activity": {
            "anyOf": [{"maxLength": 64, "type": "string"}, {"type": "null"}],
            "default": None,
            "title": "Last Log Activity",
        },
        "truncated": {"title": "Truncated", "type": "boolean"},
    }


_SNAPSHOT_REQUIRED = [
    "docker_active",
    "runner_container_name",
    "runner_state",
    "active_job",
    "daemon_dns",
    "default_address_pools",
    "probes",
    "networks",
    "address_pool_exhausted",
    "truncated",
]
_SNAPSHOT_SCHEMA = {
    "additionalProperties": False,
    "properties": _snapshot_properties(),
    "required": _SNAPSHOT_REQUIRED,
    "title": "RunnerDiagnosticSnapshot",
    "type": "object",
}
_DIAGNOSE_RESULT_SCHEMA = {
    "$defs": {
        "NetworkEvidence": _NETWORK_SCHEMA,
        "ProbeResult": _PROBE_SCHEMA,
    },
    "additionalProperties": False,
    "properties": {
        **_snapshot_properties(),
        "ok": {"title": "Ok", "type": "boolean"},
        "procedure": {
            "const": _DIAGNOSE_NAME,
            "title": "Procedure",
            "type": "string",
        },
        "target": {"const": "Gitea-Runner", "title": "Target", "type": "string"},
        "target_object_id": {
            "const": 604,
            "title": "Target Object Id",
            "type": "integer",
        },
        "lane": {"const": "user-ubuntu", "title": "Lane", "type": "string"},
        "stage": {
            "enum": ["complete", "diagnose"],
            "title": "Stage",
            "type": "string",
        },
    },
    "required": [
        *_SNAPSHOT_REQUIRED,
        "ok",
        "procedure",
        "target",
        "target_object_id",
        "lane",
        "stage",
    ],
    "title": "DiagnoseResult",
    "type": "object",
}
_RECOVER_RESULT_SCHEMA = {
    "$defs": {
        "NetworkEvidence": _NETWORK_SCHEMA,
        "ProbeResult": _PROBE_SCHEMA,
        "RunnerDiagnosticSnapshot": _SNAPSHOT_SCHEMA,
    },
    "additionalProperties": False,
    "properties": {
        "ok": {"title": "Ok", "type": "boolean"},
        "procedure": {
            "const": _RECOVER_NAME,
            "title": "Procedure",
            "type": "string",
        },
        "target": {"const": "Gitea-Runner", "title": "Target", "type": "string"},
        "target_object_id": {
            "const": 604,
            "title": "Target Object Id",
            "type": "integer",
        },
        "lane": {"const": "user-ubuntu", "title": "Lane", "type": "string"},
        "stage": {
            "enum": ["complete", "refused_active_job", "failed", "indeterminate"],
            "title": "Stage",
            "type": "string",
        },
        "before": {"$ref": "#/$defs/RunnerDiagnosticSnapshot"},
        "after": {
            "anyOf": [
                {"$ref": "#/$defs/RunnerDiagnosticSnapshot"},
                {"type": "null"},
            ],
        },
        "removed_network_ids": {
            "items": {"pattern": r"^[0-9a-f]{12,64}$", "type": "string"},
            "maxItems": 64,
            "title": "Removed Network Ids",
            "type": "array",
        },
        "resolver_reconciled": {
            "title": "Resolver Reconciled",
            "type": "boolean",
        },
        "restart_performed": {"title": "Restart Performed", "type": "boolean"},
        "refused_active_job": {"title": "Refused Active Job", "type": "boolean"},
    },
    "required": [
        "ok",
        "procedure",
        "target",
        "target_object_id",
        "lane",
        "stage",
        "before",
        "after",
        "removed_network_ids",
        "resolver_reconciled",
        "restart_performed",
        "refused_active_job",
    ],
    "title": "RecoverResult",
    "type": "object",
}


def _procedure_defaults(*, effect, timeout_seconds, approval_required, result_schema):
    return {
        "handler_id": _RECOVER_NAME if approval_required else _DIAGNOSE_NAME,
        "version": 1,
        "enabled": False,
        "target_models": ["virtualization.virtualmachine"],
        "effect": effect,
        "timeout_seconds": timeout_seconds,
        "approval_required": approval_required,
        "params_schema": _PARAMS_SCHEMA,
        "result_schema": result_schema,
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "transport_pinned": True,
        "output_parser": "none",
        "output_schema": {},
    }


_PROCEDURES = (
    {
        "name": _DIAGNOSE_NAME,
        "defaults": {
            **_procedure_defaults(
                effect="read",
                timeout_seconds=120,
                approval_required=False,
                result_schema=_DIAGNOSE_RESULT_SCHEMA,
            ),
            "description": (
                "Diagnose the fixed user-scoped Gitea Docker runner lane with "
                "bounded structured evidence and no caller-selected inputs."
            ),
        },
        "argv": ["backend-orchestrated", "gitea-user-ci-runner-diagnose"],
        "command_description": (
            "Backend diagnoses only the fixed user-scoped Docker runner lane."
        ),
    },
    {
        "name": _RECOVER_NAME,
        "defaults": {
            **_procedure_defaults(
                effect="write",
                timeout_seconds=300,
                approval_required=True,
                result_schema=_RECOVER_RESULT_SCHEMA,
            ),
            "description": (
                "Approval-gated recovery for the fixed user-scoped Gitea Docker "
                "runner; refuses active jobs and accepts no caller selectors."
            ),
        },
        "argv": ["backend-orchestrated", "gitea-user-ci-runner-recover"],
        "command_description": (
            "Backend recovers only the fixed user lane after proving no job is active."
        ),
    },
)


def seed_gitea_docker_runner_recovery(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for seed in _PROCEDURES:
        if RPCProcedure.objects.filter(name=seed["name"]).exists():
            raise RuntimeError(
                "Migration 0091 cannot adopt an existing Gitea Docker runner "
                f"procedure {seed['name']!r}; reconcile the operator-owned row first."
            )
    for seed in _PROCEDURES:
        procedure = RPCProcedure.objects.create(name=seed["name"], **seed["defaults"])
        RPCProcedureCommand.objects.create(
            procedure=procedure,
            sequence=1,
            step_type="shell_argv",
            device_cli_mode="",
            argv=seed["argv"],
            description=seed["command_description"],
            condition_param="",
            condition_negate=False,
            for_each_param="",
            continue_on_error=False,
            render_mode="literal",
            produces_var="",
            capture_kind="",
            capture_expression="",
        )


def disable_gitea_docker_runner_recovery(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=_PROCEDURE_NAMES).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0090_execution_credential_authority")]  # noqa: RUF012

    operations = [  # noqa: RUF012
        migrations.RunPython(
            seed_gitea_docker_runner_recovery,
            reverse_code=disable_gitea_docker_runner_recovery,
        )
    ]
