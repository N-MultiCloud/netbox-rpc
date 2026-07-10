"""Seed the read-only nmap scan RPCProcedure record.

The procedure defines a strictly parameterized nmap XML scan contract for
nms-backend. Data is inlined (no live module imports) per migration-safety
rules.
"""

from django.db import migrations

_TARGET_MODELS = ["ipam.ipaddress", "dcim.device", "virtualization.virtualmachine"]

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

_NMAP_PORTS_PATTERN = r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?){0,31}$"

_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["target"],
    "properties": {
        "target": {
            "type": "string",
            "minLength": 1,
            "maxLength": 253,
            "description": "IPv4 address, IPv4 CIDR, or strict DNS hostname to scan.",
        },
        "ports": {
            "description": (
                "Optional nmap port selector: a comma-separated safe port/range "
                "string or an array of up to 32 TCP/UDP port integers."
            ),
            "oneOf": [
                {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 383,
                    "pattern": _NMAP_PORTS_PATTERN,
                },
                {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "items": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65535,
                    },
                },
            ],
        },
        "scan_type": {
            "type": "string",
            "enum": ["connect", "syn", "os-detect"],
            "default": "connect",
            "description": "nmap scan mode selected by nms-backend.",
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["status", "findings", "details"],
    "properties": {
        "status": {
            "type": "string",
            "enum": ["ok", "warning", "error", "unknown"],
        },
        "findings": {
            "type": "array",
            "items": {"type": "string"},
        },
        "details": {
            "type": "object",
            "additionalProperties": False,
            "required": ["host_state", "os_guess", "open_ports"],
            "properties": {
                "host_state": {"type": "string"},
                "os_guess": {"type": "string"},
                "open_ports": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["port", "protocol", "service", "state"],
                        "properties": {
                            "port": {"type": "integer"},
                            "protocol": {"type": "string"},
                            "service": {"type": "string"},
                            "state": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
}

_PROCEDURE = {
    "name": "nmap-scan",
    "handler_id": "os.linux.nmap.scan",
    "target_models": _TARGET_MODELS,
    "effect": "read",
    "timeout_seconds": 120,
    "approval_required": False,
    "description": "Run a strictly parameterized read-only nmap XML scan.",
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
}


def _seed_nmap_scan_procedure(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.update_or_create(
        name=_PROCEDURE["name"],
        defaults={
            "handler_id": _PROCEDURE["handler_id"],
            "target_models": _PROCEDURE["target_models"],
            "effect": _PROCEDURE["effect"],
            "timeout_seconds": _PROCEDURE["timeout_seconds"],
            "approval_required": _PROCEDURE["approval_required"],
            "description": _PROCEDURE["description"],
            "params_schema": _PROCEDURE["params_schema"],
            "result_schema": _PROCEDURE["result_schema"],
        },
    )


def _remove_nmap_scan_procedure(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_PROCEDURE["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0044_rpcpluginsettings"),
    ]

    operations = [
        migrations.RunPython(
            _seed_nmap_scan_procedure,
            reverse_code=_remove_nmap_scan_procedure,
        ),
    ]
