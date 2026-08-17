"""Seed the disabled, approval-bound production Gitea 1.27.1 upgrade.

All migration data is inline. The paired backend owns artifact download,
checksum verification, backup, service lifecycle, health checks, and rollback;
no secrets or caller-controlled routing enter this catalog procedure.
"""

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError
from django.db.models.deletion import ProtectedError

_PROCEDURE_NAME = "service.gitea.production.upgrade_1_27_1"
_HANDLER_ID = _PROCEDURE_NAME
_TARGET_MODELS = ["virtualization.virtualmachine"]
_ARTIFACT_SHA256 = (
    "86a7ac26e7f9c9cca0f56c4fac07fff205d5fc3bca0e54af23a204f07b833bc9"
)

_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "changed", "healthy", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _HANDLER_ID},
        "target": {"const": "Gitea"},
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

_PROCEDURE_DEFAULTS = {
    "handler_id": _HANDLER_ID,
    "version": 1,
    "enabled": False,
    "target_models": _TARGET_MODELS,
    "effect": "destructive",
    "timeout_seconds": 1800,
    "approval_required": True,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Upgrade the exact production Gitea VM from 1.26.2 to 1.27.1 using "
        "the official artifact pinned by SHA-256, with backup, health checks, "
        "and safe rollback owned by the backend."
    ),
}

_REPRESENTATIVE_COMMAND = {
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


def seed_gitea_production_upgrade(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")

    procedure, _created = RPCProcedure.objects.update_or_create(
        name=_PROCEDURE_NAME,
        defaults=_PROCEDURE_DEFAULTS,
    )
    RPCProcedureCommand.objects.update_or_create(
        procedure=procedure,
        sequence=1,
        defaults=_REPRESENTATIVE_COMMAND,
    )


def unseed_gitea_production_upgrade(apps, schema_editor):
    """Delete an unused seed or abort while referenced history remains."""
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return
    try:
        procedure.delete()
    except ProtectedError as exc:
        raise IrreversibleError(
            "Cannot reverse migration 0071 while the Gitea upgrade procedure "
            "is referenced; preserve the applied migration or remove the "
            "referencing execution/approval history under operator control."
        ) from exc


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0070_rpcapprovalrequest_policy_hashes"),
    ]

    operations = [
        migrations.RunPython(
            seed_gitea_production_upgrade,
            reverse_code=unseed_gitea_production_upgrade,
        ),
    ]
