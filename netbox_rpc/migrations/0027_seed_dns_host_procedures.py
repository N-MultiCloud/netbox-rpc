"""Seed audited DNS host stack RPCProcedure records.

Two SSH-backed procedures manage the PowerDNS + dns-api Docker Compose stack on
the standalone DNS hosts dns01/dns02:

- os.linux.dns_host.deploy_dns_stack (write, approval required)
- os.linux.dns_host.status_dns_stack (read, no approval)

Handler IDs (nms-backend @rpc_handler registrations) match the names exactly.

Data is inlined (no live module imports) per migration-safety rules.
"""

from django.db import migrations

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "netbox-nms DeviceCredential PK; nms-backend decrypts it at execution time.",
}

_TARGET = {
    "type": "string",
    "minLength": 1,
    "maxLength": 63,
    "pattern": "^[A-Za-z0-9][A-Za-z0-9-]{0,62}$",
    "description": "Short DNS host target, e.g. dns01 or dns02.",
}

_SSH_HOST_OVERRIDE = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "description": "Optional SSH host override; if omitted, derived as <target>.<dns_host_domain plugin setting>.",
}

_SSH_PORT_OVERRIDE = {
    "type": "integer",
    "minimum": 1,
    "maximum": 65535,
    "default": 22,
    "description": "Optional SSH port override.",
}

_KNOWN_HOSTS_ENTRY = {
    "type": "string",
    "maxLength": 8192,
    "description": "Optional OpenSSH known_hosts entry for the target host.",
}

_BASE_PARAMS_PROPERTIES = {
    "rpc_ssh_credential_pk": _CREDENTIAL_REF,
    "target": _TARGET,
    "rpc_ssh_host": _SSH_HOST_OVERRIDE,
    "rpc_ssh_port": _SSH_PORT_OVERRIDE,
    "rpc_ssh_known_hosts_entry": _KNOWN_HOSTS_ENTRY,
    "rpc_ssh_strict_host_key_checking": {
        "type": "boolean",
        "default": True,
        "description": "Require host-key verification when connecting over SSH.",
    },
}

_STATUS_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk", "target"],
    "additionalProperties": False,
    "properties": _BASE_PARAMS_PROPERTIES,
}

_DEPLOY_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk", "target"],
    "additionalProperties": False,
    "properties": {
        **_BASE_PARAMS_PROPERTIES,
        "force_recreate": {
            "type": "boolean",
            "default": False,
            "description": "Recreate containers even when Compose detects no changes.",
        },
    },
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "compose_project": {"type": "string"},
        "output": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
    },
}

_DNS_HOST_PROCEDURES = [
    {
        "name": "os.linux.dns_host.deploy_dns_stack",
        "handler_id": "os.linux.dns_host.deploy_dns_stack",
        "target_models": [],
        "effect": "write",
        "timeout_seconds": 180,
        "approval_required": True,
        "description": "Deploy or update the PowerDNS and dns-api Docker Compose stack on a DNS host.",
        "params_schema": _DEPLOY_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "os.linux.dns_host.status_dns_stack",
        "handler_id": "os.linux.dns_host.status_dns_stack",
        "target_models": [],
        "effect": "read",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Read status for the PowerDNS and dns-api Docker Compose stack on a DNS host.",
        "params_schema": _STATUS_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
]


def _seed_dns_host_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _DNS_HOST_PROCEDURES:
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


def _remove_dns_host_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _DNS_HOST_PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0026_merge_packer_and_proxmox"),
    ]

    operations = [
        migrations.RunPython(
            _seed_dns_host_procedures,
            reverse_code=_remove_dns_host_procedures,
        ),
    ]
