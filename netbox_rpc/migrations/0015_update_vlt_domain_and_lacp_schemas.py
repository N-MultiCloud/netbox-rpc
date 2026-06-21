"""Update params_schema for configure_vlt_domain and configure_interface_lacp.

Two schema-only updates:
- network.device.dell_os10.s5232f_on.configure_vlt_domain:
    Remove unit_id from required[] (Dell OS10 10.5.x auto-negotiates unit ID;
    sending 'unit-id N' causes "% Error: Unrecognized command.").
- network.device.dell_os10.s5232f_on.configure_interface_lacp:
    Add "on" to lacp_mode enum to support static LAG (required for VLTi
    discovery-interface port-channel; LACP mode active/passive is rejected).

Data is inlined (no live module imports) per migration-safety rules.
"""

from django.db import migrations

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts at execution time.",
}


def _update_schemas(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")

    # configure_vlt_domain: remove unit_id from required[]
    RPCProcedure.objects.filter(
        name="network.device.dell_os10.s5232f_on.configure_vlt_domain",
    ).update(
        params_schema={
            "type": "object",
            "required": [
                "domain_id",
                "discovery_port_channel",
                "backup_destination",
            ],
            "additionalProperties": False,
            "properties": {
                "domain_id": {"type": "integer", "minimum": 1, "maximum": 255},
                "unit_id": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 2,
                    "description": (
                        "VLT unit ID (1 or 2). Omit on OS10 10.5.x — "
                        "the role is auto-negotiated and 'unit-id' is not recognised."
                    ),
                },
                "primary_priority": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                    "default": 32768,
                },
                "discovery_port_channel": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                },
                "backup_destination": {
                    "type": "string",
                    "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                },
                "vlt_mac": {
                    "type": "string",
                    "pattern": r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$",
                },
                "write_memory": {"type": "boolean", "default": True},
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        }
    )

    # configure_interface_lacp: add "on" to lacp_mode enum (static LAG for VLTi)
    RPCProcedure.objects.filter(
        name="network.device.dell_os10.s5232f_on.configure_interface_lacp",
    ).update(
        params_schema={
            "type": "object",
            "required": ["interface_name", "port_channel_id"],
            "additionalProperties": False,
            "properties": {
                "interface_name": {
                    "type": "string",
                    "pattern": r"^[A-Za-z][A-Za-z0-9/._:-]{0,63}$",
                    "description": (
                        "Ethernet interface name "
                        "(e.g. 'ethernet1/1/1' or 'ethernet1/1/1:1')."
                    ),
                },
                "port_channel_id": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                    "description": "Port-channel ID to assign this interface to.",
                },
                "lacp_mode": {
                    "type": "string",
                    "enum": ["active", "passive", "on"],
                    "default": "active",
                    "description": (
                        "LACP negotiation mode: 'active' or 'passive' for LACP, "
                        "'on' for static LAG (required for VLTi discovery-interface)."
                    ),
                },
                "description": {
                    "type": "string",
                    "maxLength": 240,
                    "description": "Interface description (optional).",
                },
                "remove": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Remove the interface from the port-channel instead of adding it."
                    ),
                },
                "write_memory": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Persist configuration with 'write memory' after changes "
                        "(default false; batch all interface assignments before saving)."
                    ),
                },
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        }
    )


def _revert_schemas(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")

    # Restore configure_vlt_domain with unit_id required
    RPCProcedure.objects.filter(
        name="network.device.dell_os10.s5232f_on.configure_vlt_domain",
    ).update(
        params_schema={
            "type": "object",
            "required": [
                "domain_id",
                "unit_id",
                "discovery_port_channel",
                "backup_destination",
            ],
            "additionalProperties": False,
            "properties": {
                "domain_id": {"type": "integer", "minimum": 1, "maximum": 255},
                "unit_id": {"type": "integer", "minimum": 1, "maximum": 2},
                "primary_priority": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                    "default": 32768,
                },
                "discovery_port_channel": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                },
                "backup_destination": {
                    "type": "string",
                    "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                },
                "vlt_mac": {
                    "type": "string",
                    "pattern": r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$",
                },
                "write_memory": {"type": "boolean", "default": True},
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        }
    )

    # Restore configure_interface_lacp without "on"
    RPCProcedure.objects.filter(
        name="network.device.dell_os10.s5232f_on.configure_interface_lacp",
    ).update(
        params_schema={
            "type": "object",
            "required": ["interface_name", "port_channel_id"],
            "additionalProperties": False,
            "properties": {
                "interface_name": {
                    "type": "string",
                    "pattern": r"^[A-Za-z][A-Za-z0-9/._:-]{0,63}$",
                    "description": (
                        "Ethernet interface name "
                        "(e.g. 'ethernet1/1/1' or 'ethernet1/1/1:1')."
                    ),
                },
                "port_channel_id": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                    "description": "Port-channel ID to assign this interface to.",
                },
                "lacp_mode": {
                    "type": "string",
                    "enum": ["active", "passive"],
                    "default": "active",
                    "description": "LACP negotiation mode (default: active).",
                },
                "description": {
                    "type": "string",
                    "maxLength": 240,
                    "description": "Interface description (optional).",
                },
                "remove": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Remove the interface from the port-channel instead of adding it."
                    ),
                },
                "write_memory": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Persist configuration with 'write memory' after changes "
                        "(default false; batch all interface assignments before saving)."
                    ),
                },
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        }
    )


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0014_seed_dell_os10_fec_procedure"),
    ]

    operations = [
        migrations.RunPython(_update_schemas, _revert_schemas),
    ]
