"""Allow audited Proxmox QGA network interface inspection."""

from __future__ import annotations

import copy

from django.db import migrations

_PROCEDURE_NAME = "os.linux.proxmox.qemu_vm_lifecycle"
_OPERATION = "agent_network_get_interfaces"
_DESCRIPTION = (
    "Run fixed Proxmox QEMU VM lifecycle operations through audited RPC: "
    "clone, migrate, configure, resize, start, stop, status, agent ping, "
    "and QEMU guest-agent network interface inspection."
)


def add_agent_network_operation(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    operations = (
        params_schema.setdefault("properties", {})
        .setdefault("operations", {})
        .setdefault("items", {})
        .setdefault("enum", [])
    )
    if _OPERATION not in operations:
        operations.append(_OPERATION)

    result_schema = copy.deepcopy(procedure.result_schema or {})
    result_properties = result_schema.setdefault("properties", {})
    result_properties.setdefault("status", {"type": "object"})
    result_properties.setdefault("agent_network_interfaces", {"type": "array"})

    procedure.params_schema = params_schema
    procedure.result_schema = result_schema
    procedure.description = _DESCRIPTION
    procedure.save(update_fields=["params_schema", "result_schema", "description"])


def remove_agent_network_operation(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    operations = (
        params_schema.setdefault("properties", {})
        .setdefault("operations", {})
        .setdefault("items", {})
        .setdefault("enum", [])
    )
    if _OPERATION in operations:
        operations.remove(_OPERATION)

    result_schema = copy.deepcopy(procedure.result_schema or {})
    result_properties = result_schema.setdefault("properties", {})
    result_properties.pop("agent_network_interfaces", None)

    procedure.params_schema = params_schema
    procedure.result_schema = result_schema
    procedure.save(update_fields=["params_schema", "result_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0019_seed_proxmox_qemu_vm_lifecycle"),
    ]

    operations = [
        migrations.RunPython(
            add_agent_network_operation,
            reverse_code=remove_agent_network_operation,
        ),
    ]
