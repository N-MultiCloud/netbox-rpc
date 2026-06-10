"""Add operator bond parameters to the Mellanox conversion params schema.

nms-backend's `os.linux_proxmox.convert_mellanox_nic_to_ethernet` handler now
accepts `bond_name`, `bond_vlans`, and `bond_mtu`. The seeded schema from
migration 0008 uses `additionalProperties: false`, so the new optional keys
must be declared here or execution creation rejects them with a 400.

Data is inlined (no live module imports) per the migration-safety rules.
"""

from django.db import migrations

_PROCEDURE_NAME = "os.linux.proxmox.convert_mellanox_nic_to_ethernet"

_BOND_PARAM_PROPERTIES = {
    "bond_name": {
        "type": "string",
        "pattern": "^[A-Za-z0-9_-]{1,15}$",
        "description": "Linux interface name for the LACP bond (default bond1).",
    },
    "bond_vlans": {
        "type": "string",
        "pattern": "^$|^\\d{1,4}(-\\d{1,4})?(,\\d{1,4}(-\\d{1,4})?)*$",
        "maxLength": 512,
        "description": (
            "Optional comma-separated VLAN IDs/ranges (e.g. 100,200,300-310) emitted as "
            "bridge-vids on the bond stanza; empty declares no VLAN filtering."
        ),
    },
    "bond_mtu": {
        "type": "integer",
        "minimum": 576,
        "maximum": 9216,
        "description": "MTU applied to the bond stanza (default 9216, jumbo frames).",
    },
}


def _add_bond_params(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return
    schema = dict(procedure.params_schema or {})
    properties = dict(schema.get("properties") or {})
    properties.update(_BOND_PARAM_PROPERTIES)
    schema["properties"] = properties
    procedure.params_schema = schema
    procedure.save(update_fields=["params_schema"])


def _remove_bond_params(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedure = RPCProcedure.objects.filter(name=_PROCEDURE_NAME).first()
    if procedure is None:
        return
    schema = dict(procedure.params_schema or {})
    properties = dict(schema.get("properties") or {})
    for key in _BOND_PARAM_PROPERTIES:
        properties.pop(key, None)
    schema["properties"] = properties
    procedure.params_schema = schema
    procedure.save(update_fields=["params_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0009_seed_dell_os10_procedures"),
    ]

    operations = [
        migrations.RunPython(_add_bond_params, _remove_bond_params),
    ]
