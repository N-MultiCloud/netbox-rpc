"""Seed Dell OS10 S5232F-ON port-channel and interface LACP procedure records.

Two SSH-backed procedures for port-channel and LACP interface membership:
- network.device.dell_os10.s5232f_on.configure_port_channel (write, approval required)
- network.device.dell_os10.s5232f_on.configure_interface_lacp (write, approval required)

Handler IDs (nms-backend @rpc_handler registrations):
- network.dell_os10_s5232f_on.configure_port_channel
- network.dell_os10_s5232f_on.configure_interface_lacp

Data is inlined (no live module imports) per migration-safety rules.
"""

from django.db import migrations

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts at execution time.",
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
        "output": {"type": "string"},
    },
}

_PORT_CHANNEL_PROCEDURES = [
    {
        "name": "network.device.dell_os10.s5232f_on.configure_port_channel",
        "handler_id": "network.dell_os10_s5232f_on.configure_port_channel",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": (
            "Create, update, or remove a port-channel (LAG) on Dell SmartFabric OS10 "
            "with optional trunk VLANs and description."
        ),
        "params_schema": {
            "type": "object",
            "required": ["port_channel_id"],
            "additionalProperties": False,
            "properties": {
                "port_channel_id": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                    "description": "Port-channel interface ID (e.g. 1 → port-channel1).",
                },
                "trunk_vlans": {
                    "type": "string",
                    "pattern": (r"^\d{1,4}(?:-\d{1,4})?(?:,\d{1,4}(?:-\d{1,4})?)*$"),
                    "description": (
                        "Comma-separated VLAN IDs or ranges to configure as trunk "
                        "(e.g. '20,111' or '10-20,100'). Omit to skip VLAN config."
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
                    "description": "Remove the port-channel instead of creating/updating it.",
                },
                "write_memory": {
                    "type": "boolean",
                    "default": True,
                    "description": "Persist configuration with 'write memory' after changes.",
                },
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.configure_interface_lacp",
        "handler_id": "network.dell_os10_s5232f_on.configure_interface_lacp",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": (
            "Add or remove an Ethernet interface from a port-channel (LACP) "
            "on Dell SmartFabric OS10."
        ),
        "params_schema": {
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
        },
        "result_schema": _RESULT_SCHEMA,
    },
]


def _seed_port_channel_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PORT_CHANNEL_PROCEDURES:
        RPCProcedure.objects.update_or_create(
            name=data["name"],
            defaults={
                "handler_id": data["handler_id"],
                "target_models": data["target_models"],
                "effect": data["effect"],
                "timeout_seconds": data["timeout_seconds"],
                "approval_required": data["approval_required"],
                "description": data["description"],
                "params_schema": data["params_schema"],
                "result_schema": data["result_schema"],
            },
        )


def _remove_port_channel_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PORT_CHANNEL_PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0011_seed_dell_os10_vlt_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_port_channel_procedures, _remove_port_channel_procedures
        ),
    ]
