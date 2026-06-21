"""Seed direct-SSH Ubuntu agent install RPC procedures."""

from django.db import migrations

_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts it at execution time.",
}

_RPC_SSH_OVERRIDE_PROPERTIES = {
    "rpc_ssh_credential_pk": _CREDENTIAL_REF,
    "rpc_ssh_host": {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "description": "Optional SSH host override consumed by nms-backend.",
    },
    "rpc_ssh_port": {
        "type": "integer",
        "minimum": 1,
        "maximum": 65535,
        "description": "Optional SSH port override consumed by nms-backend.",
    },
    "rpc_ssh_known_hosts_entry": {
        "type": "string",
        "description": "Optional known_hosts line consumed by nms-backend.",
    },
    "rpc_ssh_strict_host_key_checking": {
        "type": "boolean",
        "description": "Optional strict host-key checking override consumed by nms-backend.",
    },
}

_BASE_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": _RPC_SSH_OVERRIDE_PROPERTIES,
}

_ZABBIX_SERVER_PATTERN = (
    "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?$"
)

_ZABBIX_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "zabbix_server": {
            "type": "string",
            "minLength": 1,
            "maxLength": 253,
            "pattern": _ZABBIX_SERVER_PATTERN,
            "default": "zabbix.nmulti.cloud",
            "description": "Zabbix server endpoint configured in zabbix_agent2.conf.",
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "installed": {"type": "boolean"},
        "active": {"type": "string"},
        "enabled": {"type": "string"},
        "zabbix_server": {"type": "string"},
    },
}

_PROCEDURES = [
    {
        "name": "os.linux.ubuntu.24.install_qemu_guest_agent",
        "handler_id": "os.linux_ubuntu_24.install_qemu_guest_agent",
        "effect": "write",
        "approval_required": False,
        "timeout_seconds": 300,
        "enabled": True,
        "version": 1,
        "target_models": _TARGET_MODELS,
        "description": "Install and enable the QEMU Guest Agent over SSH (no rebuild).",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "os.linux.ubuntu.24.install_zabbix_agent2",
        "handler_id": "os.linux_ubuntu_24.install_zabbix_agent2",
        "effect": "write",
        "approval_required": False,
        "timeout_seconds": 600,
        "enabled": True,
        "version": 1,
        "target_models": _TARGET_MODELS,
        "description": (
            "Install and configure Zabbix Agent 2 (ServerActive/Server) over SSH "
            "(no rebuild)."
        ),
        "params_schema": _ZABBIX_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
]


def _seed_linux_agent_install_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in _PROCEDURES:
        RPCProcedure.objects.update_or_create(
            name=procedure["name"],
            defaults={
                "handler_id": procedure["handler_id"],
                "effect": procedure["effect"],
                "approval_required": procedure["approval_required"],
                "timeout_seconds": procedure["timeout_seconds"],
                "enabled": procedure["enabled"],
                "version": procedure["version"],
                "target_models": procedure["target_models"],
                "description": procedure["description"],
                "params_schema": procedure["params_schema"],
                "result_schema": procedure["result_schema"],
            },
        )


def _remove_linux_agent_install_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[procedure["name"] for procedure in _PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0027_seed_dns_host_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_linux_agent_install_procedures,
            reverse_code=_remove_linux_agent_install_procedures,
        ),
    ]
