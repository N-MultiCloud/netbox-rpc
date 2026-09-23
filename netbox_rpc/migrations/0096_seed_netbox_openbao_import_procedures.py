"""Seed the audited netbox-openbao credential importer procedures.

Two fixed-argv procedures targeting the NetBox host device (``dcim.device``),
handled in netbox-rpc-backend:

- ``service.netbox.openbao_import.dry_run`` (read, no approval): runs the
  NetBox venv python with
  ``manage.py openbao_import_nms_credentials --dry-run`` for a NetBox root
  selected by the closed ``environment`` enum (``staging``/``production``),
  mapped server-side to fixed install paths. Returns only bounded summary
  counts; never row content, secret material, or unreviewed raw output.
- ``service.netbox.openbao_import.apply`` (destructive, approval required):
  same argv without ``--dry-run``. The command itself copies and never
  deletes.

Neither procedure accepts a caller-supplied path, flag, or command text.
Migration data stays inline so applying it remains deterministic if runtime
constants or schemas change later.
"""

from django.db import migrations

_DRY_RUN_NAME = "service.netbox.openbao_import.dry_run"
_APPLY_NAME = "service.netbox.openbao_import.apply"
_TARGET_MODELS = ["dcim.device"]

_ENVIRONMENT_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["environment"],
    "properties": {
        "environment": {
            "type": "string",
            "enum": ["staging", "production"],
        },
    },
}

_SOURCE_MODEL_KEYS = [
    "device_credential",
    "device_service",
    "user_ssh_key",
    "proxmox_binding",
    "cloud_vm_credential",
    "observability_secret",
]

_SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": _SOURCE_MODEL_KEYS,
    "properties": {
        key: {"type": "integer", "minimum": 0, "maximum": 1000000}
        for key in _SOURCE_MODEL_KEYS
    },
}


def _result_schema(handler_id):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["ok", "procedure", "target", "environment", "stage"],
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"const": handler_id},
            "target": {"type": "string", "maxLength": 255},
            "environment": {"type": "string", "enum": ["staging", "production"]},
            "summary": {"type": ["object", "null"], **_SUMMARY_SCHEMA},
            "stage": {
                "type": "string",
                "enum": ["execute", "complete", "indeterminate"],
            },
        },
        "oneOf": [
            {
                "properties": {
                    "ok": {"const": True},
                    "stage": {"const": "complete"},
                    "summary": _SUMMARY_SCHEMA,
                },
                "required": ["summary"],
            },
            {
                "properties": {
                    "ok": {"const": False},
                    "stage": {"const": "execute"},
                    "summary": {"const": None},
                },
            },
            {
                "properties": {
                    "ok": {"const": False},
                    "stage": {"const": "indeterminate"},
                    "summary": {"const": None},
                },
            },
        ],
    }


_DRY_RUN_DEFAULTS = {
    "handler_id": _DRY_RUN_NAME,
    "version": 1,
    "enabled": True,
    "target_models": _TARGET_MODELS,
    "effect": "read",
    "timeout_seconds": 300,
    "approval_required": False,
    "params_schema": _ENVIRONMENT_PARAMS_SCHEMA,
    "result_schema": _result_schema(_DRY_RUN_NAME),
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Dry-run the netbox-openbao credential importer against the fixed "
        "staging or production NetBox root, returning bounded summary counts "
        "only."
    ),
}

_APPLY_DEFAULTS = {
    "handler_id": _APPLY_NAME,
    "version": 1,
    "enabled": True,
    "target_models": _TARGET_MODELS,
    "effect": "destructive",
    "timeout_seconds": 900,
    "approval_required": True,
    "params_schema": _ENVIRONMENT_PARAMS_SCHEMA,
    "result_schema": _result_schema(_APPLY_NAME),
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Run the netbox-openbao credential importer against the fixed "
        "staging or production NetBox root. Copies legacy credentials into "
        "netbox-openbao without deleting source rows; returns bounded "
        "summary counts only, never row content or secret material."
    ),
}


def _representative_command(procedure_name):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "netbox-openbao-import", "{environment}"],
        "description": (
            f"Backend maps environment to a fixed NetBox root/venv for "
            f"{procedure_name} and parses only the importer's bounded "
            f"summary counts."
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


def seed_netbox_openbao_import_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")

    for name, defaults in (
        (_DRY_RUN_NAME, _DRY_RUN_DEFAULTS),
        (_APPLY_NAME, _APPLY_DEFAULTS),
    ):
        if RPCProcedure.objects.filter(name=name).exists():
            raise RuntimeError(
                f"netbox-openbao import migration refuses to overwrite an "
                f"existing procedure row named {name!r}."
            )
        procedure = RPCProcedure.objects.create(name=name, **defaults)
        RPCProcedureCommand.objects.create(
            procedure=procedure,
            sequence=1,
            **_representative_command(name),
        )


def unseed_netbox_openbao_import_procedures(apps, schema_editor):
    """Disable the seeded rows instead of deleting them.

    Non-destructive for the same two reasons documented on
    ``0068_seed_staging_backend_token_rotation``:
    ``RPCExecution.procedure`` is ``on_delete=PROTECT`` so a procedure with
    execution history cannot be deleted, and deleting through the historical
    model risks a deletion-collector ``ValueError`` against a related app
    with no migrations. An ``update()`` touches only this table.
    """

    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[_DRY_RUN_NAME, _APPLY_NAME],
    ).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0095_packer_openbao_assignment_id_param"),
    ]

    operations = [  # noqa: RUF012
        migrations.RunPython(
            seed_netbox_openbao_import_procedures,
            reverse_code=unseed_netbox_openbao_import_procedures,
        ),
    ]
