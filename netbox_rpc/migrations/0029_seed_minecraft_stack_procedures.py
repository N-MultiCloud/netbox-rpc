"""Seed audited Minecraft stack management procedures.

These records expose fixed SSH-backed handlers in nms-backend for managing
ViaVersion-family plugins, PaperMC/Folia/Velocity server jars, generic plugin
JAR installs, and Pterodactyl Wings service operations. Data is inlined here
per migration-safety rules; do not import live netbox_rpc modules.
"""

from django.db import migrations

_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]
_SERVER_UUID = {
    "type": "string",
    "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
}
_JAR_FILENAME = {
    "type": "string",
    "minLength": 5,
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9._-]+\\.jar$",
}
_RPC_SSH = {
    "rpc_ssh_credential_pk": {"type": "integer", "minimum": 1},
    "rpc_ssh_host": {"type": "string", "minLength": 1, "maxLength": 255},
    "rpc_ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "rpc_ssh_known_hosts_entry": {"type": "string"},
    "rpc_ssh_strict_host_key_checking": {"type": "boolean"},
}
_RESULT = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "server_uuid": {"type": "string"},
        "output": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
    },
}

_PLUGIN_INSTALL_PARAMS = {
    "type": "object",
    "required": ["server_uuid", "source_url", "filename"],
    "additionalProperties": False,
    "properties": {
        "server_uuid": _SERVER_UUID,
        "source_url": {
            "type": "string",
            "minLength": 1,
            "maxLength": 2048,
            "pattern": "^https?://",
        },
        "filename": _JAR_FILENAME,
        "restart": {"type": "boolean", "default": False},
        **_RPC_SSH,
    },
}

_VIAVERSION_PARAMS = {
    "type": "object",
    "required": ["server_uuid"],
    "additionalProperties": False,
    "properties": {
        "server_uuid": _SERVER_UUID,
        "preset": {
            "type": "string",
            "enum": ["minimal", "standard", "full"],
            "default": "standard",
        },
        "plugins": {
            "type": "array",
            "minItems": 1,
            "maxItems": 3,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "enum": ["viaversion", "viabackwards", "viarewind"],
            },
        },
        "restart": {"type": "boolean", "default": False},
        **_RPC_SSH,
    },
}

_PAPERMC_PARAMS = {
    "type": "object",
    "required": ["server_uuid", "project", "version"],
    "additionalProperties": False,
    "properties": {
        "server_uuid": _SERVER_UUID,
        "project": {"type": "string", "enum": ["paper", "folia", "velocity"]},
        "version": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9._+-]+$",
        },
        "build_id": {"type": "integer", "minimum": 1},
        "server_jarfile": {**_JAR_FILENAME, "default": "server.jar"},
        "restart": {"type": "boolean", "default": False},
        **_RPC_SSH,
    },
}

_WINGS_SERVICE_PARAMS = {
    "type": "object",
    "additionalProperties": False,
    "properties": _RPC_SSH,
}

_WINGS_LOGS_PARAMS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "lines": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        **_RPC_SSH,
    },
}

_PROCEDURES = [
    {
        "name": "services.minecraft.plugin.install_url",
        "handler_id": "services.minecraft.plugin.install_url",
        "effect": "write",
        "timeout_seconds": 180,
        "approval_required": False,
        "description": "Install a plugin JAR into a Pterodactyl Wings server volume from a validated URL over SSH.",
        "params_schema": _PLUGIN_INSTALL_PARAMS,
    },
    {
        "name": "services.minecraft.viaversion.install",
        "handler_id": "services.minecraft.viaversion.install",
        "effect": "write",
        "timeout_seconds": 240,
        "approval_required": False,
        "description": "Install ViaVersion, ViaBackwards, and/or ViaRewind into a Wings server volume over SSH.",
        "params_schema": _VIAVERSION_PARAMS,
    },
    {
        "name": "services.minecraft.papermc.install",
        "handler_id": "services.minecraft.papermc.install",
        "effect": "write",
        "timeout_seconds": 240,
        "approval_required": False,
        "description": "Install a PaperMC, Folia, or Velocity server JAR into a Wings server volume over SSH.",
        "params_schema": _PAPERMC_PARAMS,
    },
    {
        "name": "services.pterodactyl.wings.status",
        "handler_id": "services.pterodactyl.wings.status",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read Pterodactyl Wings service status over SSH.",
        "params_schema": _WINGS_SERVICE_PARAMS,
    },
    {
        "name": "services.pterodactyl.wings.logs",
        "handler_id": "services.pterodactyl.wings.logs",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Fetch recent Pterodactyl Wings journal logs over SSH.",
        "params_schema": _WINGS_LOGS_PARAMS,
    },
    {
        "name": "services.pterodactyl.wings.restart",
        "handler_id": "services.pterodactyl.wings.restart",
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Restart Pterodactyl Wings over SSH. This can interrupt game server management.",
        "params_schema": _WINGS_SERVICE_PARAMS,
    },
]


def _seed_minecraft_stack_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PROCEDURES:
        RPCProcedure.objects.update_or_create(
            name=data["name"],
            defaults={
                "handler_id": data["handler_id"],
                "target_models": _TARGET_MODELS,
                "effect": data["effect"],
                "timeout_seconds": data["timeout_seconds"],
                "approval_required": data["approval_required"],
                "description": data["description"],
                "params_schema": data["params_schema"],
                "result_schema": _RESULT,
            },
        )


def _noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0028_seed_linux_agent_install_procedures"),
    ]

    operations = [
        migrations.RunPython(_seed_minecraft_stack_procedures, reverse_code=_noop),
    ]
