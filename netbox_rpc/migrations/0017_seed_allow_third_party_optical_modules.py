from django.db import migrations


_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts it at execution time.",
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

_ALLOW_THIRD_PARTY_TRANSCEIVER = {
    "name": "network.device.dell_os10.s5232f_on.allow_third_party_transceiver",
    "handler_id": "network.dell_os10_s5232f_on.allow_third_party_transceiver",
    "target_models": ["dcim.device"],
    "effect": "write",
    "timeout_seconds": 45,
    "approval_required": True,
    "description": "Allow third-part Optical Modules on Dell SmartFabric OS10 (S5232F-ON). "
    "Runs: allow unsupported-transceiver + unlock third-party transceiver + write memory.",
    "params_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "rpc_ssh_credential_pk": _CREDENTIAL_REF,
        },
    },
    "result_schema": _RESULT_SCHEMA,
}


def seed(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    name = _ALLOW_THIRD_PARTY_TRANSCEIVER["name"]
    defaults = {k: v for k, v in _ALLOW_THIRD_PARTY_TRANSCEIVER.items() if k != "name"}
    RPCProcedure.objects.update_or_create(name=name, defaults=defaults)


def unseed(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name=_ALLOW_THIRD_PARTY_TRANSCEIVER["name"]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0016_seed_pterodactyl_procedures"),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
