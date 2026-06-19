"""Allow guest password rotation through QGA by credential reference."""

from __future__ import annotations

import copy

from django.db import migrations

_PROCEDURE_NAME = "os.linux.proxmox.qemu_vm_lifecycle"
_OPERATION = "agent_set_user_password"
_DESCRIPTION = (
    "Run audited Proxmox QEMU VM lifecycle operations: clone, migrate, "
    "configure, resize, power, status, QGA ping/interface inspection, "
    "Debian network repair, and guest password rotation by credential reference."
)
_GUEST_CREDENTIAL_SCHEMA = {
    "type": "integer",
    "minimum": 1,
    "description": (
        "netbox-nms DeviceCredential id used by nms-backend to resolve the "
        "guest username/password server-side."
    ),
}


def add_guest_password_operation(apps, schema_editor):
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
    properties.setdefault("guest_credential_pk", copy.deepcopy(_GUEST_CREDENTIAL_SCHEMA))

    procedure.params_schema = params_schema
    procedure.description = _DESCRIPTION
    procedure.save(update_fields=["params_schema", "description"])


def remove_guest_password_operation(apps, schema_editor):
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
    properties.pop("guest_credential_pk", None)

    procedure.params_schema = params_schema
    procedure.save(update_fields=["params_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0014_add_proxmox_qemu_debian_network_repair"),
    ]

    operations = [
        migrations.RunPython(
            add_guest_password_operation,
            reverse_code=remove_guest_password_operation,
        ),
    ]
