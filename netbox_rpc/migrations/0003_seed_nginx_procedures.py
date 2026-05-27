from django.db import migrations

NGINX_PROCEDURES = (
    {
        "name": "service.nginx.1.config_test",
        "handler_id": "service.nginx.1.config_test",
        "target_models": ["netbox_proxy.proxynode"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Run nginx -t on target node",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "output": {"type": "string"},
            },
        },
    },
    {
        "name": "service.nginx.1.config_deploy",
        "handler_id": "service.nginx.1.config_deploy",
        "target_models": ["netbox_proxy.proxynode"],
        "effect": "write",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Write rendered config, test, and activate",
        "params_schema": {
            "type": "object",
            "required": ["config_content"],
            "additionalProperties": False,
            "properties": {
                "config_content": {"type": "string", "minLength": 1},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "config_path": {"type": "string"},
                "test_passed": {"type": "boolean"},
            },
        },
    },
    {
        "name": "service.nginx.1.reload",
        "handler_id": "service.nginx.1.reload",
        "target_models": ["netbox_proxy.proxynode"],
        "effect": "write",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Execute systemctl reload nginx",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "active_state": {"type": "string"},
            },
        },
    },
    {
        "name": "service.nginx.1.rollback",
        "handler_id": "service.nginx.1.rollback",
        "target_models": ["netbox_proxy.proxynode"],
        "effect": "destructive",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Restore previous config snapshot and reload",
        "params_schema": {
            "type": "object",
            "required": ["snapshot_id"],
            "additionalProperties": False,
            "properties": {
                "snapshot_id": {"type": "string", "minLength": 1},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "snapshot_id": {"type": "string"},
                "active_state": {"type": "string"},
            },
        },
    },
)


def seed_nginx_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for item in NGINX_PROCEDURES:
        defaults = dict(item)
        name = defaults.pop("name")
        RPCProcedure.objects.update_or_create(name=name, defaults=defaults)


def unseed_nginx_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[item["name"] for item in NGINX_PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0002_seed_initial_procedures"),
    ]

    operations = [
        migrations.RunPython(seed_nginx_procedures, unseed_nginx_procedures),
    ]
