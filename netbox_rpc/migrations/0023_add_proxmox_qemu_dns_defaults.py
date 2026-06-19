"""Allow Proxmox QEMU lifecycle DNS cloud-init fields."""

from __future__ import annotations

import copy

from django.db import migrations

_PROCEDURE_NAME = "os.linux.proxmox.qemu_vm_lifecycle"
_DESCRIPTION = (
    "Run audited Proxmox QEMU VM lifecycle operations: clone, migrate, "
    "configure, resize, power, status, QGA ping/interface inspection, "
    "Debian network repair, guest DNS defaults, and guest password rotation "
    "by credential reference."
)
_SEARCH_DOMAIN_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 253,
    "pattern": (
        "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?$"
    ),
    "description": "Cloud-init DNS search domain passed to Proxmox as searchdomain.",
}
_DNS_SERVERS_SCHEMA = {
    "type": "array",
    "maxItems": 3,
    "uniqueItems": True,
    "items": {
        "type": "string",
        "minLength": 1,
        "maxLength": 45,
        "pattern": "^[0-9A-Fa-f:.]+$",
    },
    "description": "Ordered DNS resolvers passed to Proxmox as nameserver.",
}


def add_dns_fields(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    properties = params_schema.setdefault("properties", {})
    properties.setdefault("search_domain", copy.deepcopy(_SEARCH_DOMAIN_SCHEMA))
    properties.setdefault("dns_servers", copy.deepcopy(_DNS_SERVERS_SCHEMA))

    procedure.params_schema = params_schema
    procedure.description = _DESCRIPTION
    procedure.save(update_fields=["params_schema", "description"])


def remove_dns_fields(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return

    params_schema = copy.deepcopy(procedure.params_schema or {})
    properties = params_schema.setdefault("properties", {})
    properties.pop("search_domain", None)
    properties.pop("dns_servers", None)

    procedure.params_schema = params_schema
    procedure.save(update_fields=["params_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0022_add_proxmox_qemu_guest_password"),
    ]

    operations = [
        migrations.RunPython(add_dns_fields, reverse_code=remove_dns_fields),
    ]
