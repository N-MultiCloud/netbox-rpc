from django.db import migrations

SYSTEMD_PROCEDURES = (
    {
        "name": "os.linux.ubuntu.24.status_service",
        "handler_id": "os.linux_ubuntu_24.status_service",
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read status for an allowlisted systemd service",
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
                "sub_state": {"type": "string"},
                "unit_file_state": {"type": "string"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.start_service",
        "handler_id": "os.linux_ubuntu_24.start_service",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Start an allowlisted systemd service",
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
                "sub_state": {"type": "string"},
                "unit_file_state": {"type": "string"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.stop_service",
        "handler_id": "os.linux_ubuntu_24.stop_service",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Stop an allowlisted systemd service",
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
                "sub_state": {"type": "string"},
                "unit_file_state": {"type": "string"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.reload_service",
        "handler_id": "os.linux_ubuntu_24.reload_service",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Reload an allowlisted systemd service",
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
                "sub_state": {"type": "string"},
                "unit_file_state": {"type": "string"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.enable_service",
        "handler_id": "os.linux_ubuntu_24.enable_service",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Enable an allowlisted systemd service",
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
            "required": ["ok", "procedure", "target", "service"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "service": {"type": "string"},
                "unit_file_state": {"type": "string"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.disable_service",
        "handler_id": "os.linux_ubuntu_24.disable_service",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Disable an allowlisted systemd service",
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
            "required": ["ok", "procedure", "target", "service"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "service": {"type": "string"},
                "unit_file_state": {"type": "string"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.daemon_reload",
        "handler_id": "os.linux_ubuntu_24.daemon_reload",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Reload the systemd manager configuration",
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
                "exit_code": {"type": "integer"},
            },
        },
    },
    {
        "name": "os.linux.ubuntu.24.journal_tail",
        "handler_id": "os.linux_ubuntu_24.journal_tail",
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read recent journal output for an allowlisted systemd service",
        "params_schema": {
            "type": "object",
            "required": ["service_slug"],
            "additionalProperties": False,
            "properties": {
                "service_slug": {"type": "string", "minLength": 1, "maxLength": 100},
                "lines": {"type": "integer", "minimum": 1, "maximum": 500},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target", "service"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "service": {"type": "string"},
                "lines": {"type": "integer"},
                "output": {"type": "string"},
            },
        },
    },
)


def seed_systemd_management_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for item in SYSTEMD_PROCEDURES:
        defaults = dict(item)
        name = defaults.pop("name")
        RPCProcedure.objects.update_or_create(name=name, defaults=defaults)


def unseed_systemd_management_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[item["name"] for item in SYSTEMD_PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0003_seed_nginx_procedures"),
    ]

    operations = [
        migrations.RunPython(
            seed_systemd_management_procedures,
            unseed_systemd_management_procedures,
        ),
    ]
