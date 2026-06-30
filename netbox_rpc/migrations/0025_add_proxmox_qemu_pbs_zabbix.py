"""Allow audited PBS Zabbix Agent 2 guest operations."""

from __future__ import annotations

import copy

from django.db import migrations

_PROCEDURE_NAME = "os.linux.proxmox.qemu_vm_lifecycle"
_OPERATIONS = ("agent_pbs_zabbix_status", "agent_configure_zabbix_agent2")
_DESCRIPTION = (
    "Run audited Proxmox QEMU lifecycle actions, including clone, migrate, "
    "configure, resize, power, QGA checks, Debian guest network/password "
    "repair, and PBS Zabbix Agent 2 status/configure."
)


def add_pbs_zabbix_operations(apps, schema_editor):
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
    for operation in _OPERATIONS:
        if operation not in operations:
            operations.append(operation)
    params_schema.setdefault("properties", {}).setdefault(
        "zabbix_server",
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 253,
            "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?$",
            "default": "zabbix.example.com",
            "description": "Zabbix server endpoint configured in zabbix_agent2.conf.",
        },
    )
    params_schema.setdefault("properties", {}).setdefault("operations", {})["maxItems"] = 10

    result_schema = copy.deepcopy(procedure.result_schema or {})
    result_schema.setdefault("properties", {}).setdefault(
        "pbs_guest_status", {"type": "object"}
    )

    procedure.params_schema = params_schema
    procedure.result_schema = result_schema
    procedure.description = _DESCRIPTION
    procedure.save(update_fields=["params_schema", "result_schema", "description"])


def remove_pbs_zabbix_operations(apps, schema_editor):
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
    for operation in _OPERATIONS:
        if operation in operations:
            operations.remove(operation)
    params_schema.setdefault("properties", {}).pop("zabbix_server", None)

    result_schema = copy.deepcopy(procedure.result_schema or {})
    result_schema.setdefault("properties", {}).pop("pbs_guest_status", None)

    procedure.params_schema = params_schema
    procedure.result_schema = result_schema
    procedure.save(update_fields=["params_schema", "result_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0024_add_proxmox_qemu_nextid"),
    ]

    operations = [
        migrations.RunPython(
            add_pbs_zabbix_operations,
            reverse_code=remove_pbs_zabbix_operations,
        ),
    ]
