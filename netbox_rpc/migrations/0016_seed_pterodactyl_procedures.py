"""Seed Pterodactyl Panel management procedure records.

Three Docker-exec-backed procedures for managing a Pterodactyl Panel deployment:
- services.pterodactyl.bootstrap_api_key (write, approval required)
- services.pterodactyl.artisan (write, no approval)
- services.pterodactyl.container_logs (read, no approval)

Handler IDs (nms-backend @rpc_handler registrations):
- services.pterodactyl.bootstrap_api_key
- services.pterodactyl.artisan
- services.pterodactyl.container_logs

Data is inlined (no live module imports) per migration-safety rules.
"""

from django.db import migrations

_PTERODACTYL_PROCEDURES = [
    {
        "name": "services.pterodactyl.bootstrap_api_key",
        "handler_id": "services.pterodactyl.bootstrap_api_key",
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Bootstrap Pterodactyl Panel application and client API keys via docker exec.",
        "params_schema": {
            "type": "object",
            "properties": {
                "container_name": {
                    "type": "string",
                    "default": "pterodactyl-panel-1",
                },
            },
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
        "name": "services.pterodactyl.artisan",
        "handler_id": "services.pterodactyl.artisan",
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Run an allowlisted Laravel Artisan command inside the Pterodactyl Panel container.",
        "params_schema": {
            "type": "object",
            "required": ["command"],
            "properties": {
                "command": {
                    "type": "string",
                    "enum": [
                        "queue:status",
                        "schedule:run",
                        "cache:clear",
                        "config:clear",
                        "queue:restart",
                        "migrate",
                    ],
                },
                "container_name": {
                    "type": "string",
                    "default": "pterodactyl-panel-1",
                },
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "command": {"type": "string"},
                "output": {"type": "string"},
            },
        },
    },
    {
        "name": "services.pterodactyl.container_logs",
        "handler_id": "services.pterodactyl.container_logs",
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Fetch recent log output from the Pterodactyl Panel container.",
        "params_schema": {
            "type": "object",
            "properties": {
                "container_name": {
                    "type": "string",
                    "default": "pterodactyl-panel-1",
                },
                "lines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 100,
                },
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "lines": {"type": "integer"},
                "output": {"type": "string"},
            },
        },
    },
]


def _seed_pterodactyl_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PTERODACTYL_PROCEDURES:
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


def _noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0015_update_vlt_domain_and_lacp_schemas"),
    ]

    operations = [
        migrations.RunPython(_seed_pterodactyl_procedures, reverse_code=_noop),
    ]
