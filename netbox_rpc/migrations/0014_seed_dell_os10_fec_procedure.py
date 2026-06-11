"""Seed Dell OS10 S5232F-ON interface FEC configuration procedure record.

One SSH-backed procedure for configuring Forward Error Correction on a physical
interface:
- network.device.dell_os10.s5232f_on.configure_interface_fec (write, approval required)

Handler ID (nms-backend @rpc_handler registration):
- network.dell_os10_s5232f_on.configure_interface_fec

Supported fec_mode values:
- cl91  : RS-FEC (Clause 91) — required for QSFP28 100G SR4/LR4 optics
- cl108 : FC-FEC (Clause 108) — used with some SFP28 25G DAC/SR optics
- auto  : Auto-negotiate FEC with link partner
- none  : Disable FEC (equivalent to 'no fec' in OS10 CLI)

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
        "fallback": {"type": "boolean"},
    },
}

_FEC_PROCEDURES = [
    {
        "name": "network.device.dell_os10.s5232f_on.configure_interface_fec",
        "handler_id": "network.dell_os10_s5232f_on.configure_interface_fec",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 30,
        "approval_required": True,
        "description": (
            "Configure Forward Error Correction (FEC) mode on a Dell SmartFabric OS10 "
            "physical interface. Use 'cl91' (RS-FEC) for QSFP28 100G SR4/LR4 optics, "
            "'cl108' (FC-FEC) for SFP28 25G DAC/SR, 'auto' to negotiate with the peer, "
            "or 'none' to disable FEC ('no fec')."
        ),
        "params_schema": {
            "type": "object",
            "required": ["interface_name"],
            "additionalProperties": False,
            "properties": {
                "interface_name": {
                    "type": "string",
                    "pattern": r"^[A-Za-z][A-Za-z0-9/._:-]{0,63}$",
                    "description": (
                        "OS10 interface identifier (e.g. 'ethernet1/1/31'). "
                        "Must include the 'ethernet' prefix."
                    ),
                },
                "fec_mode": {
                    "type": "string",
                    "enum": ["cl91", "cl108", "auto", "none"],
                    "default": "cl91",
                    "description": (
                        "FEC mode: cl91 (RS-FEC, for 100G SR4/LR4), "
                        "cl108 (FC-FEC, for 25G DAC/SR), auto, or none."
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


def _seed_fec_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _FEC_PROCEDURES:
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


def _remove_fec_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _FEC_PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0013_seed_dell_os10_breakout_procedure"),
    ]

    operations = [
        migrations.RunPython(
            _seed_fec_procedures, _remove_fec_procedures
        ),
    ]
