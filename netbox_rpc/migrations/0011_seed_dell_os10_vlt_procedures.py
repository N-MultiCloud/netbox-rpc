"""Seed Dell OS10 S5232F-ON VLT procedure records.

Three SSH-backed procedures for Virtual Link Trunking management:
- network.device.dell_os10.s5232f_on.show_vlt (read, no approval)
- network.device.dell_os10.s5232f_on.configure_vlt_domain (write, approval required)
- network.device.dell_os10.s5232f_on.configure_vlt_peer (write, approval required)

Handler IDs (nms-backend @rpc_handler registrations):
- network.dell_os10_s5232f_on.show_vlt
- network.dell_os10_s5232f_on.configure_vlt_domain
- network.dell_os10_s5232f_on.configure_vlt_peer

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

_VLT_PROCEDURES = [
    {
        "name": "network.device.dell_os10.s5232f_on.show_vlt",
        "handler_id": "network.dell_os10_s5232f_on.show_vlt",
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Show VLT domain status on Dell SmartFabric OS10.",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "domain_id": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 255,
                    "default": 1,
                    "description": "VLT domain ID (default 1).",
                },
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "handler_id": "network.dell_os10_s5232f_on.configure_vlt_domain",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": True,
        "description": (
            "Configure the VLT domain on Dell SmartFabric OS10 "
            "(unit ID, priorities, backup link)."
        ),
        "params_schema": {
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
        },
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.configure_vlt_peer",
        "handler_id": "network.dell_os10_s5232f_on.configure_vlt_peer",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": (
            "Bind or remove a port-channel as a VLT LAG on Dell SmartFabric OS10."
        ),
        "params_schema": {
            "type": "object",
            "required": ["port_channel_id", "vlt_port_channel_id"],
            "additionalProperties": False,
            "properties": {
                "port_channel_id": {"type": "integer", "minimum": 1, "maximum": 4096},
                "vlt_port_channel_id": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                },
                "remove": {"type": "boolean", "default": False},
                "write_memory": {"type": "boolean", "default": True},
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
]


def _seed_vlt_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _VLT_PROCEDURES:
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


def _remove_vlt_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _VLT_PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0010_mellanox_bond_params_schema"),
    ]

    operations = [
        migrations.RunPython(_seed_vlt_procedures, _remove_vlt_procedures),
    ]
