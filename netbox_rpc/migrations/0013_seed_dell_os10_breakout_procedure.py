"""Seed Dell OS10 S5232F-ON interface breakout procedure record.

One SSH-backed procedure for configuring interface breakout mode:
- network.device.dell_os10.s5232f_on.configure_interface_breakout (write, approval required)

Handler ID (nms-backend @rpc_handler registration):
- network.dell_os10_s5232f_on.configure_interface_breakout

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

_BREAKOUT_PROCEDURES = [
    {
        "name": "network.device.dell_os10.s5232f_on.configure_interface_breakout",
        "handler_id": "network.dell_os10_s5232f_on.configure_interface_breakout",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": (
            "Configure the breakout mode for a physical port on Dell SmartFabric OS10 "
            "(e.g. 'interface breakout 1/1/1 map 40g-1x')."
        ),
        "params_schema": {
            "type": "object",
            "required": ["interface_port", "breakout_mode"],
            "additionalProperties": False,
            "properties": {
                "interface_port": {
                    "type": "string",
                    "pattern": r"^\d+/\d+/\d+$",
                    "description": (
                        "Physical port in slot/port/subport format "
                        "(e.g. '1/1/1'). Do NOT include the 'ethernet' prefix."
                    ),
                },
                "breakout_mode": {
                    "type": "string",
                    "pattern": r"^\d+g-\d+x$",
                    "description": (
                        "Breakout map mode (e.g. '40g-1x', '100g-1x', '10g-4x', '25g-4x')."
                    ),
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
]


def _seed_breakout_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _BREAKOUT_PROCEDURES:
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


def _remove_breakout_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _BREAKOUT_PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0012_seed_dell_os10_port_channel_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_breakout_procedures, _remove_breakout_procedures
        ),
    ]
