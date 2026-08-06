from django.db import migrations
from django.db.models.deletion import ProtectedError


_PROCEDURE_NAME = "network.device.huawei.router.ne8000.f1a.show_bgp_peer"
_HANDLER_ID = "network.huawei_ne8000_f1a.show_bgp_peer"

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "output": {"type": "string"},
    },
}

HUAWEI_NE8000_BGP_PROCEDURES = [
    {
        "name": _PROCEDURE_NAME,
        "handler_id": _HANDLER_ID,
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 45,
        "approval_required": False,
        # Seeded disabled even though the netbox-rpc normalizer is present.
        # Live /rpc/* execution belongs to netbox-rpc-backend; retained
        # nms-backend automation/rpc code is not a deployable handler for this
        # procedure. Enable only after the matching netbox-rpc-backend handler
        # is deployed, its capability contract is approved, and the coordinated
        # BGP rollout is authorized. The normalizer derives target from the
        # assigned dcim.device, defaults vrf to "", and resolves credentials
        # only through that device's configured DeviceService.
        "enabled": False,
        "description": "Fetch BGP peer status from a Huawei NE8000-F1A device.",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "vrf": {
                    "type": "string",
                    "default": "",
                    "maxLength": 31,
                    "pattern": "^[A-Za-z0-9_.:-]{0,31}(?![\\s\\S])",
                },
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
]

_REPRESENTATIVE_COMMAND = {
    "step_type": "device_cli",
    "device_cli_mode": "exec",
    "argv": ["display", "bgp", "peer"],
    "description": (
        "Representative read-only command; the backend also performs dynamic "
        "VRF, per-peer verbose, and TCP-correlation reads."
    ),
    "condition_param": "",
    "condition_negate": False,
    "for_each_param": "",
    "continue_on_error": False,
}


def seed_huawei_ne8000_bgp_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for item in HUAWEI_NE8000_BGP_PROCEDURES:
        name = item["name"]
        defaults = {key: value for key, value in item.items() if key != "name"}
        procedure, _created = RPCProcedure.objects.update_or_create(
            name=name, defaults=defaults
        )
        RPCProcedureCommand.objects.update_or_create(
            procedure=procedure,
            sequence=1,
            defaults=_REPRESENTATIVE_COMMAND,
        )


def unseed_huawei_ne8000_bgp_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedures = RPCProcedure.objects.filter(
        name__in=[item["name"] for item in HUAWEI_NE8000_BGP_PROCEDURES]
    )
    try:
        procedures.delete()
    except ProtectedError:
        pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0065_seed_ubuntu_upgrade_26_intent"),
    ]

    operations = [
        migrations.RunPython(
            seed_huawei_ne8000_bgp_procedures,
            unseed_huawei_ne8000_bgp_procedures,
        ),
    ]
