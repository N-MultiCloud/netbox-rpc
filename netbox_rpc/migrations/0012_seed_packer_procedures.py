"""Seed netbox-packer post-build verification RPCProcedure records.

Four read-only SSH-backed procedures that target a netbox-packer
``PackerTemplate`` for post-build verification on the Proxmox node that holds
the template:

- packer.vm.test_ssh_connectivity (read, no approval)
- packer.vm.check_agent_running   (read, no approval)
- packer.vm.verify_services       (read, no approval)
- packer.vm.collect_info          (read, no approval)

Handler IDs (nms-backend @rpc_handler registrations) match the names exactly.

Dependency direction (hard constraint): netbox-rpc references netbox-packer
ONLY through these string ``target_models`` content-type labels (lowercase
``netbox_packer.packertemplate``) plus a lazy import in
``netbox_rpc.packer_normalizer``. netbox-packer MUST NOT reference netbox-rpc.

Data is inlined (no live module imports) per migration-safety rules.
"""

from django.db import migrations

_PACKER_TARGET_MODEL = "netbox_packer.packertemplate"

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "netbox-nms DeviceCredential PK; nms-backend decrypts it at execution time.",
}

_SSH_HOST_OVERRIDE = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "description": "Optional SSH host override; defaults to the template's proxmox_node.",
}

_SSH_PORT_OVERRIDE = {
    "type": "integer",
    "minimum": 1,
    "maximum": 65535,
    "description": "Optional SSH port override (default 22).",
}

_BASE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk"],
    "additionalProperties": False,
    "properties": {
        "rpc_ssh_credential_pk": _CREDENTIAL_REF,
        "ssh_host": _SSH_HOST_OVERRIDE,
        "ssh_port": _SSH_PORT_OVERRIDE,
    },
}

_VERIFY_SERVICES_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk"],
    "additionalProperties": False,
    "properties": {
        "rpc_ssh_credential_pk": _CREDENTIAL_REF,
        "ssh_host": _SSH_HOST_OVERRIDE,
        "ssh_port": _SSH_PORT_OVERRIDE,
        "services": {
            "type": "array",
            "maxItems": 32,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100,
                "pattern": r"^[A-Za-z0-9_.@:-]+$",
            },
            "description": "Optional systemd unit names to check; empty checks a default set.",
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
        "command_log": {"type": "array", "items": {"type": "string"}},
        "output": {"type": "string"},
    },
}

_PACKER_PROCEDURES = [
    {
        "name": "packer.vm.test_ssh_connectivity",
        "handler_id": "packer.vm.test_ssh_connectivity",
        "target_models": [_PACKER_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Test SSH connectivity to the Proxmox node that built a packer template.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "packer.vm.check_agent_running",
        "handler_id": "packer.vm.check_agent_running",
        "target_models": [_PACKER_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Verify the QEMU guest agent is responsive on a packer template's node.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "packer.vm.verify_services",
        "handler_id": "packer.vm.verify_services",
        "target_models": [_PACKER_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Check that cloud-init systemd services are running for a packer template.",
        "params_schema": _VERIFY_SERVICES_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "packer.vm.collect_info",
        "handler_id": "packer.vm.collect_info",
        "target_models": [_PACKER_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Collect OS information from a packer template's Proxmox node.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
]


def _seed_packer_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PACKER_PROCEDURES:
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


def _remove_packer_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PACKER_PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0011_seed_dell_os10_vlt_procedures"),
    ]

    operations = [
        migrations.RunPython(_seed_packer_procedures, _remove_packer_procedures),
    ]
