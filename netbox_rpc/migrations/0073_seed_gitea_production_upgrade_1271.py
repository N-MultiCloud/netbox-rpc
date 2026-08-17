"""Seed the disabled, approval-bound production Gitea 1.27.1 upgrade.

All migration data is inline. The paired backend owns artifact download,
checksum verification, backup, service lifecycle, health checks, and rollback;
no secrets or caller-controlled routing enter this catalog procedure.
"""

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

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

    # Ownership is deliberately all-or-nothing. ``update_or_create`` would
    # silently adopt and overwrite an operator-owned row under the canonical
    # name; the reverse migration could then mistake it for seed-owned data and
    # destroy it. A pre-existing name therefore aborts the atomic forward
    # migration before either the procedure or its commands are touched.
    if RPCProcedure.objects.filter(name=_PROCEDURE_NAME).exists():
        raise RuntimeError(
            "Migration 0073 cannot seed the production Gitea upgrade because "
            "an RPC procedure with the canonical name already exists; preserve "
            "and reconcile the operator-owned row before retrying."
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


def unseed_gitea_production_upgrade(apps, schema_editor):
    """Always abort before inspecting or mutating catalog data.

    A data migration has no durable row-ownership ledger. Procedure names,
    primary keys, commands, and policy fields are all operator-mutable after the
    forward migration, so reverse-time comparison cannot prove that a matching
    row is still the seed rather than a replacement (or locate a renamed seed).
    Explicit irreversibility keeps 0073 applied and preserves every procedure,
    command, history row, and generic annotation for a reviewed forward repair.
    """

    raise IrreversibleError(
        "Migration 0073 is intentionally irreversible because production Gitea "
        "procedure ownership cannot be proven after operator mutation; keep the "
        "migration applied and use a reviewed forward repair migration."
    )


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0072_seed_influxdb3_debian13_install_procedures"),
    ]

    operations = [
        migrations.RunPython(
            seed_gitea_production_upgrade,
            reverse_code=unseed_gitea_production_upgrade,
        ),
    ]
