"""Seed the approval-required Proxmox OCI registry pull procedure."""

from django.db import migrations

_NAME = "os.linux.proxmox.oci_registry_pull"
_HANDLER = "os.linux_proxmox.oci_registry_pull"

_PARAMS_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "proxmox_endpoint_id": {"minimum": 1, "type": "integer"},
        "node": {
            "maxLength": 64,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
            "type": "string",
        },
        "storage": {
            "maxLength": 64,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
            "type": "string",
        },
        "reference": {
            "description": (
                "Explicitly tagged public Docker Hub netbox-proxbox appliance reference."
            ),
            "maxLength": 179,
            "pattern": (
                "^(?:docker[.]io/)?emersonfelipesp/netbox-proxbox:"
                "[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
            ),
            "type": "string",
        },
        "filename": {
            "maxLength": 255,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$",
            "type": "string",
        },
    },
    "required": ["proxmox_endpoint_id", "node", "storage", "reference"],
    "type": "object",
}

_RESULT_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _HANDLER, "type": "string"},
        "target": {"type": "string"},
        "node": {"type": "string"},
        "storage": {"type": "string"},
        "reference": {"type": "string"},
        "filename": {"type": ["string", "null"]},
        "upid": {"type": ["string", "null"]},
        "exit_code": {"type": "integer"},
        "stderr": {"type": "string"},
        "stage": {
            "enum": ["complete", "execute", "indeterminate"],
            "type": "string",
        },
    },
    "required": [
        "ok",
        "procedure",
        "target",
        "node",
        "storage",
        "reference",
        "filename",
        "upid",
        "exit_code",
        "stderr",
        "stage",
    ],
    "type": "object",
}


def seed_proxmox_oci_registry_pull(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    if RPCProcedure.objects.filter(name=_NAME).exists():
        raise RuntimeError(
            "Migration 0093 cannot adopt an existing Proxmox OCI pull procedure; "
            "reconcile the operator-owned row first."
        )
    procedure = RPCProcedure.objects.create(
        name=_NAME,
        handler_id=_HANDLER,
        version=1,
        enabled=True,
        target_models=["netbox_proxbox.proxmoxendpoint"],
        effect="write",
        timeout_seconds=3720,
        approval_required=True,
        description=(
            "Pull one explicitly tagged public netbox-proxbox OCI appliance into "
            "a selected Proxmox node storage after operator approval."
        ),
        params_schema=_PARAMS_SCHEMA,
        result_schema=_RESULT_SCHEMA,
        transport_driver="asyncssh",
        transport_driver_chain=[],
        transport_pinned=True,
        output_parser="none",
        output_schema={},
    )
    RPCProcedureCommand.objects.create(
        procedure=procedure,
        sequence=1,
        step_type="shell_argv",
        device_cli_mode="",
        argv=["backend-orchestrated", "proxmox-oci-registry-pull"],
        description=(
            "Backend runs one fixed pvesh OCI registry pull with fallback disabled."
        ),
        condition_param="",
        condition_negate=False,
        for_each_param="",
        continue_on_error=False,
        render_mode="literal",
        produces_var="",
        capture_kind="",
        capture_expression="",
    )


def disable_proxmox_oci_registry_pull(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_NAME).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0092_seed_gitea_org_docker_network_recovery")
    ]

    operations = [  # noqa: RUF012
        migrations.RunPython(
            seed_proxmox_oci_registry_pull,
            reverse_code=disable_proxmox_oci_registry_pull,
        )
    ]
