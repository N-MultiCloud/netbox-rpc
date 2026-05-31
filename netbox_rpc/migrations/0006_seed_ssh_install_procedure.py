"""Seed the os.linux.ubuntu.24.install_ssh_key procedure.

This procedure is used by nms-backend to append a user's SSH public key to
the target device's authorized_keys file using the existing DeviceService SSH
credential, enabling key-based NMS CLI SSH access.
"""
from django.db import migrations

_SSH_INSTALL_KEY_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["public_key"],
    "additionalProperties": False,
    "properties": {
        "public_key": {
            "type": "string",
            "minLength": 1,
            "maxLength": 16384,
            "pattern": "^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/]+=*( .*)?$",
            "description": "Full OpenSSH public key (single line, key-type + base64 blob).",
        },
        "username": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "description": "Target user on the device; defaults to the DeviceService SSH username.",
        },
    },
}

_SSH_INSTALL_KEY_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "username": {"type": "string"},
        "fingerprint": {"type": "string"},
    },
}

SSH_KEY_PROCEDURE = {
    "name": "os.linux.ubuntu.24.install_ssh_key",
    "handler_id": "os.linux_ubuntu_24.install_ssh_key",
    "target_models": ["dcim.device", "virtualization.virtualmachine"],
    "effect": "write",
    "timeout_seconds": 30,
    "approval_required": False,
    "description": (
        "Append an SSH public key to the target user's authorized_keys file "
        "on the device, using the existing DeviceService SSH credential. "
        "Called automatically by nms-backend when registering a new NMS CLI key."
    ),
    "params_schema": _SSH_INSTALL_KEY_PARAMS_SCHEMA,
    "result_schema": _SSH_INSTALL_KEY_RESULT_SCHEMA,
}


def _seed_ssh_procedure(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    proc = SSH_KEY_PROCEDURE
    RPCProcedure.objects.update_or_create(
        name=proc["name"],
        defaults={
            "handler_id": proc["handler_id"],
            "version": "1",
            "enabled": True,
            "target_models": proc["target_models"],
            "effect": proc["effect"],
            "timeout_seconds": proc["timeout_seconds"],
            "approval_required": proc["approval_required"],
            "description": proc.get("description", ""),
            "params_schema": proc.get("params_schema") or {},
            "result_schema": proc.get("result_schema") or {},
        },
    )


def _remove_ssh_procedure(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name="os.linux.ubuntu.24.install_ssh_key").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0005_allowlist_ssh_credential_override"),
        # UserSSHKey was added in netbox-nms 0029. Pin to that migration so
        # this migration runs after the SSH key registry table is available.
        # Update this dependency name if netbox-nms ever squashes its migrations.
        ("netbox_nms", "0029_user_ssh_key"),
    ]

    operations = [
        migrations.RunPython(_seed_ssh_procedure, reverse_code=_remove_ssh_procedure),
    ]
