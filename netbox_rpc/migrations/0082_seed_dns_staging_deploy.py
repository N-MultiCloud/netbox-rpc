"""Seed the exact-SHA, approval-gated staging DNS-pair deploy procedure."""

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

_PROCEDURE_NAME = "service.netbox.staging.deploy_dns_pair"
_PARAMS_SCHEMA = {
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
_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "commit_sha", "deployed", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _PROCEDURE_NAME},
        "target": {"const": "nms-front-door"},
        "commit_sha": {
            "type": "string",
            "pattern": r"^[0-9a-f]{40}(?![\s\S])",
        },
        "deployed": {"type": ["boolean", "null"]},
        "stage": {
            "type": "string",
            "enum": ["execute", "complete", "indeterminate"],
        },
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
_PROCEDURE_DEFAULTS = {
    "handler_id": _PROCEDURE_NAME,
    "version": 1,
    "enabled": True,
    "target_models": ["dcim.device"],
    "effect": "destructive",
    "timeout_seconds": 2700,
    "approval_required": True,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "transport_pinned": True,
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Deploy one reviewed exact commit of the staging NetBox DNS plugin and "
        "sidecar pair on nms-front-door through the fixed root-owned helper."
    ),
}
_REPRESENTATIVE_COMMAND = {
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


def seed_dns_staging_deploy(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    if RPCProcedure.objects.filter(name=_PROCEDURE_NAME).exists():
        raise RuntimeError(
            "Migration 0082 cannot adopt an existing staging DNS deploy procedure; "
            "reconcile the operator-owned row before retrying."
        )
    procedure = RPCProcedure.objects.create(
        name=_PROCEDURE_NAME,
        **_PROCEDURE_DEFAULTS,
    )
    RPCProcedureCommand.objects.create(
        procedure=procedure,
        sequence=1,
        **_REPRESENTATIVE_COMMAND,
    )


def unseed_dns_staging_deploy(apps, schema_editor):
    raise IrreversibleError(
        "Migration 0082 is intentionally irreversible because catalog row "
        "ownership cannot be proven after operator mutation."
    )


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0081_gitea_runner_scope_fence")]

    operations = [
        migrations.RunPython(
            seed_dns_staging_deploy,
            reverse_code=unseed_dns_staging_deploy,
        )
    ]
