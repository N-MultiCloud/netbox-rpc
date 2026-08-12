"""Seed the approval-gated staging NetBox backend-token rotation procedure.

The procedure carries no caller-controlled routing metadata. The exact
``nms-front-door`` device and its enabled, pinned SSH service own transport
routing. Token generation, validation, installation, and service recovery
belong to the backend's fixed root-owned provisioner; plaintext token material
never enters the RPC catalog, parameters, command rows, results, or event
stream.

Migration data stays inline so applying it remains deterministic if runtime
constants or schemas change later.
"""

from django.db import migrations
from django.db.models.deletion import ProtectedError

_PROCEDURE_NAME = "service.netbox.staging.rotate_backend_token"
_HANDLER_ID = "service.netbox.staging.rotate_backend_token"
_TARGET_MODELS = ["dcim.device"]

_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "rotated", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _HANDLER_ID},
        "target": {"const": "nms-front-door"},
        "rotated": {"type": ["boolean", "null"]},
        "stage": {
            "type": "string",
            "enum": ["execute", "complete", "indeterminate"],
        },
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "rotated": {"const": True},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "rotated": {"const": False},
                "stage": {"const": "execute"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "rotated": {"const": True},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "rotated": {"const": None},
                "stage": {"const": "indeterminate"},
            }
        },
    ],
}

_PROCEDURE_DEFAULTS = {
    "handler_id": _HANDLER_ID,
    "version": 1,
    "enabled": True,
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
        "Rotate the staging NetBox service token on the exact nms-front-door "
        "target through the audited root-owned deploy-host provisioner without "
        "exposing secret material."
    ),
}

_REPRESENTATIVE_COMMAND = {
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "netbox-staging-rotate-backend-token"],
    "description": (
        "Backend invokes the fixed root-owned staging-token provisioner; "
        "no token value is accepted as argv, persisted, or returned."
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


def seed_staging_backend_token_rotation(apps, schema_editor):
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


def unseed_staging_backend_token_rotation(apps, schema_editor):
    """Delete an unused seed or retain referenced history in a disabled state."""
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return
    try:
        procedure.delete()
    except ProtectedError:
        procedure.enabled = False
        procedure.save(update_fields=["enabled"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0067_merge_huawei_bgp_and_upgrade_result_limits"),
    ]

    operations = [
        migrations.RunPython(
            seed_staging_backend_token_rotation,
            reverse_code=unseed_staging_backend_token_rotation,
        ),
    ]
