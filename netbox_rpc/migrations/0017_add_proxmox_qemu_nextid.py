"""Allow Proxmox QEMU lifecycle VMID allocation."""

from __future__ import annotations

import copy

from django.db import migrations

_PROCEDURE_NAME = "os.linux.proxmox.qemu_vm_lifecycle"
_OPERATION = "nextid"
_DESCRIPTION = (
    "Run audited Proxmox QEMU VM lifecycle operations: nextid, clone, migrate, "
    "configure, resize, power, status, QGA ping/interface inspection, Debian "
    "network repair, guest DNS defaults, and guest password rotation by "
    "credential reference."
)


def add_nextid_operation(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    required = params_schema.setdefault("required", [])
    if "vmid" in required:
        required.remove("vmid")
    operations = (
        params_schema.setdefault("properties", {})
        .setdefault("operations", {})
        .setdefault("items", {})
        .setdefault("enum", [])
    )
    if _OPERATION not in operations:
        operations.insert(1 if "clone" in operations else 0, _OPERATION)

    result_schema = copy.deepcopy(procedure.result_schema or {})
    result_schema.setdefault("properties", {}).setdefault("nextid", {"type": "integer"})

    procedure.params_schema = params_schema
    procedure.result_schema = result_schema
    procedure.description = _DESCRIPTION
    procedure.save(update_fields=["params_schema", "result_schema", "description"])


def remove_nextid_operation(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    required = params_schema.setdefault("required", [])
    if "vmid" not in required:
        required.append("vmid")
    operations = (
        params_schema.setdefault("properties", {})
        .setdefault("operations", {})
        .setdefault("items", {})
        .setdefault("enum", [])
    )
    if _OPERATION in operations:
        operations.remove(_OPERATION)

    result_schema = copy.deepcopy(procedure.result_schema or {})
    result_schema.setdefault("properties", {}).pop("nextid", None)

    procedure.params_schema = params_schema
    procedure.result_schema = result_schema
    procedure.save(update_fields=["params_schema", "result_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0016_add_proxmox_qemu_dns_defaults"),
    ]

    operations = [
        migrations.RunPython(add_nextid_operation, reverse_code=remove_nextid_operation),
    ]
