"""Allow constrained Debian guest network repair through QGA."""

from __future__ import annotations

import copy

from django.db import migrations

_PROCEDURE_NAME = "os.linux.proxmox.qemu_vm_lifecycle"
_OPERATION = "agent_configure_debian_network"
_DESCRIPTION = (
    "Run fixed Proxmox QEMU VM lifecycle operations through audited RPC: "
    "clone, migrate, configure, resize, start, stop, status, agent ping, "
    "QEMU guest-agent network interface inspection, and constrained Debian "
    "guest network repair."
)
_GUEST_NETWORKS_SCHEMA = {
    "type": "array",
    "maxItems": 8,
    "items": {
        "type": "object",
        "required": ["interface", "address"],
        "additionalProperties": False,
        "properties": {
            "interface": {
                "type": "string",
                "minLength": 1,
                "maxLength": 32,
                "pattern": "^[A-Za-z][A-Za-z0-9_.:-]{0,31}$",
            },
            "address": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[^\\s,]+$",
            },
            "gateway": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[^\\s,]+$",
            },
        },
    },
}


def add_debian_network_repair_operation(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    properties = params_schema.setdefault("properties", {})
    operations = (
        properties.setdefault("operations", {})
        .setdefault("items", {})
        .setdefault("enum", [])
    )
    if _OPERATION not in operations:
        operations.append(_OPERATION)
    properties.setdefault("guest_networks", copy.deepcopy(_GUEST_NETWORKS_SCHEMA))

    procedure.params_schema = params_schema
    procedure.description = _DESCRIPTION
    procedure.save(update_fields=["params_schema", "description"])


def remove_debian_network_repair_operation(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    properties = params_schema.setdefault("properties", {})
    operations = (
        properties.setdefault("operations", {})
        .setdefault("items", {})
        .setdefault("enum", [])
    )
    if _OPERATION in operations:
        operations.remove(_OPERATION)
    properties.pop("guest_networks", None)

    procedure.params_schema = params_schema
    procedure.save(update_fields=["params_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0020_add_proxmox_qemu_agent_network_interfaces"),
    ]

    operations = [
        migrations.RunPython(
            add_debian_network_repair_operation,
            reverse_code=remove_debian_network_repair_operation,
        ),
    ]
