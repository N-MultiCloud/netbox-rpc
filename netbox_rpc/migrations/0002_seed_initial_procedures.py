from django.db import migrations

INITIAL_PROCEDURES = (
    {
        "name": "network.device.huawei.olt.ma5800.r024.start_ont",
        "handler_id": "network.huawei_olt_ma5800_r024.start_ont",
        "target_models": ["netbox_gpon.olt"],
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": False,
        "params_schema": {
            "type": "object",
            "required": ["frame", "slot", "port", "ont_id"],
            "additionalProperties": False,
            "properties": {
                "frame": {"type": "integer", "minimum": 0},
                "slot": {"type": "integer", "minimum": 1, "maximum": 17},
                "port": {"type": "integer", "minimum": 0, "maximum": 15},
                "ont_id": {"type": "integer", "minimum": 0, "maximum": 127},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target", "status"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "status": {"type": "string"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.restart_service",
        "handler_id": "os.linux_ubuntu_24.restart_service",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": False,
        "params_schema": {
            "type": "object",
            "required": ["service_slug"],
            "additionalProperties": False,
            "properties": {
                "service_slug": {"type": "string", "minLength": 1, "maxLength": 100},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target", "service", "active_state"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "service": {"type": "string"},
                "active_state": {"type": "string"},
            },
        },
    },
)


def seed_initial_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for item in INITIAL_PROCEDURES:
        defaults = dict(item)
        name = defaults.pop("name")
        RPCProcedure.objects.update_or_create(name=name, defaults=defaults)


def unseed_initial_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[item["name"] for item in INITIAL_PROCEDURES]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_initial_procedures, unseed_initial_procedures),
    ]
