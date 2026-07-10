"""Seed the os.linux.proxmox.show_systemctl_services procedure.

Read-only, no-approval agentless pull of systemd service states from a
Proxmox host, targeting a netbox-proxbox ProxmoxEndpoint. Unlike
os.linux.proxmox.convert_mellanox_nic_to_ethernet and
os.linux.proxmox.qemu_vm_lifecycle, this procedure does NOT resolve the
netbox-nms ProxmoxEndpointSSHBinding and emits no rpc_ssh_* keys: the
execution backend resolves the SSH connection downstream from the endpoint's
OWN stored credential (fetched from netbox-proxbox's SSH-credential secrets
API), gated on the endpoint's allow_writes + registered SSH credential. The
normalizer (see
netbox_rpc/domain/normalization.py:_normalize_show_systemctl_services_execution)
only forwards proxmox_endpoint_id and a validated, allowlisted-charset units
list.

Seed data is inlined here (never imported from netbox_rpc.constants) so the
migration stays stable across future constant renames/squashes.
"""

from django.db import migrations

_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["proxmox_endpoint_id"],
    "properties": {
        "proxmox_endpoint_id": {
            "type": "integer",
            "minimum": 1,
            "description": (
                "netbox-proxbox ProxmoxEndpoint id. The execution backend "
                "resolves the SSH connection using the endpoint's own stored "
                "credential; this procedure does not use the netbox-nms "
                "ProxmoxEndpointSSHBinding."
            ),
        },
        "units": {
            "type": "array",
            "maxItems": 32,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100,
                "pattern": "^[A-Za-z0-9_][A-Za-z0-9_.@:-]*$",
            },
            "description": (
                "Optional systemd unit names to check; empty checks a "
                "backend-defined default set."
            ),
        },
    },
}

_SERVICE_ITEM_SCHEMA = {
    "type": "object",
    "required": ["unit"],
    "properties": {
        "unit": {"type": "string"},
        "id": {"type": "string"},
        "load_state": {"type": "string"},
        "active_state": {"type": "string"},
        "sub_state": {"type": "string"},
        "result": {"type": "string"},
        "main_pid": {"type": ["integer", "null"]},
        "exec_main_code": {"type": ["integer", "null"]},
        "exec_main_status": {"type": ["integer", "null"]},
        "n_restarts": {"type": ["integer", "null"]},
        "active_enter_timestamp": {"type": "string"},
        "unit_file_state": {"type": "string"},
    },
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "reachable", "services"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "reachable": {"type": "boolean"},
        "services": {
            "type": "array",
            "items": _SERVICE_ITEM_SCHEMA,
        },
    },
}

_PROCEDURE_NAME = "os.linux.proxmox.show_systemctl_services"

_PROCEDURE_DEFAULTS = {
    "handler_id": "os.linux_proxmox.show_systemctl_services",
    "version": "1",
    "enabled": True,
    "target_models": ["netbox_proxbox.proxmoxendpoint"],
    "effect": "read",
    "timeout_seconds": 60,
    "approval_required": False,
    "description": (
        "Read-only agentless pull of systemd service states from a Proxmox "
        "host; does not resolve the netbox-nms ProxmoxEndpointSSHBinding or "
        "emit rpc_ssh_* keys. The execution backend uses the endpoint's own "
        "stored SSH credential."
    ),
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
}


def seed_proxmox_show_systemctl_services(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.update_or_create(
        name=_PROCEDURE_NAME,
        defaults=_PROCEDURE_DEFAULTS,
    )


def unseed_proxmox_show_systemctl_services(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_PROCEDURE_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0043_rpcbackend_ip_domain"),
    ]

    operations = [
        migrations.RunPython(
            seed_proxmox_show_systemctl_services,
            reverse_code=unseed_proxmox_show_systemctl_services,
        ),
    ]
