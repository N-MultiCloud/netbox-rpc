"""Seed the os.linux.proxmox.convert_mellanox_nic_to_ethernet procedure.

This procedure converts Mellanox ConnectX-3 (mlx4) NIC ports from InfiniBand to
Ethernet on a Proxmox host. It targets a netbox-proxbox ProxmoxEndpoint; the
SSH connection details are resolved at execution time through the netbox-nms
ProxmoxEndpointSSHBinding (see netbox_rpc/jobs.py normalizer). nms-backend runs
the conversion over SSH via handler os.linux_proxmox.convert_mellanox_nic_to_ethernet.

Seed data is inlined here (never imported from netbox_rpc.constants) so the
migration stays stable across squashes.
"""
from django.db import migrations

_MELLANOX_CONVERT_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["proxmox_endpoint_id"],
    "additionalProperties": False,
    "properties": {
        "proxmox_endpoint_id": {
            "type": "integer",
            "minimum": 1,
            "description": "netbox-proxbox ProxmoxEndpoint id; SSH details come from its netbox-nms binding.",
        },
        "reboot": {
            "type": "boolean",
            "description": "Reboot the host automatically after conversion (default false).",
        },
        "apply_network": {
            "type": "boolean",
            "description": "Run `ifreload -a` after touching /etc/network/interfaces (default false).",
        },
        "interfaces_content": {
            "type": "string",
            "maxLength": 65536,
            "description": "Optional full /etc/network/interfaces override; empty keeps existing config and only ensures Mellanox interfaces are declared.",
        },
        "dry_run": {
            "type": "boolean",
            "description": "Discover only; make no changes (default false).",
        },
    },
}

_MELLANOX_CONVERT_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "dry_run": {"type": "boolean"},
        "nothing_to_do": {"type": "boolean"},
        "already_ethernet": {"type": "boolean"},
        "service_enabled": {"type": "boolean"},
        "reboot_required": {"type": "boolean"},
        "rebooting": {"type": "boolean"},
    },
}

MELLANOX_PROCEDURE = {
    "name": "os.linux.proxmox.convert_mellanox_nic_to_ethernet",
    "handler_id": "os.linux_proxmox.convert_mellanox_nic_to_ethernet",
    "target_models": ["netbox_proxbox.proxmoxendpoint"],
    "effect": "destructive",
    "timeout_seconds": 1800,
    "approval_required": True,
    # RPCProcedure.description is a CharField(max_length=255); keep this short.
    "description": (
        "Convert Mellanox ConnectX-3 (mlx4) NIC ports from InfiniBand to "
        "Ethernet on a Proxmox host, persisting via modprobe and a "
        "mlx4-force-eth systemd unit, with optional network config and reboot."
    ),
    "params_schema": _MELLANOX_CONVERT_PARAMS_SCHEMA,
    "result_schema": _MELLANOX_CONVERT_RESULT_SCHEMA,
}


def _seed_mellanox_procedure(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    proc = MELLANOX_PROCEDURE
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


def _remove_mellanox_procedure(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name="os.linux.proxmox.convert_mellanox_nic_to_ethernet"
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        (
            "netbox_rpc",
            "0007_rename_netbox_rpc_assigned_idx_netbox_rpc__assigne_c5b587_idx_and_more",
        ),
    ]

    operations = [
        migrations.RunPython(
            _seed_mellanox_procedure, reverse_code=_remove_mellanox_procedure
        ),
    ]
