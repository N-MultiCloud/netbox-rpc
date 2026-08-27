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
    """Disable the seeded row instead of deleting it.

    Deliberately non-destructive, matching
    ``0072_seed_influxdb3_debian13_install_procedures``. Two independent reasons:

    1. ``RPCExecution.procedure`` is ``on_delete=PROTECT``, so deleting a procedure
       that has run raises ``ProtectedError`` and aborts the whole downgrade.
       Audited execution history must never be destroyed to allow a rollback.
    2. Deleting through the historical model is not safe even when the row is
       unreferenced. ``Model.delete()`` runs Django's deletion collector, which
       walks related models — and a related model whose app has no migrations is
       rendered from the *real* app registry rather than from the migration state.
       The collector then filters that real model by a historical ``RPCProcedure``
       instance and Django raises ``ValueError: Cannot query "RPCProcedure object
       (N)": Must be "RPCProcedure" instance``.

    The previous implementation caught only ``ProtectedError``, so it handled
    reason 1 and not reason 2 — a ``ValueError`` is not a ``ProtectedError``, so
    the collector failure propagated and aborted the downgrade.

    An ``update()`` touches only this table and never invokes the collector, so
    the reverse is safe in every environment. Re-apply is ``update_or_create``,
    which restores the intended state idempotently.
    """

    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_PROCEDURE_NAME).update(enabled=False)


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
