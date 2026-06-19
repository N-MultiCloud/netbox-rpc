"""Seed the audited Proxmox QEMU VM lifecycle procedure."""

from django.db import migrations

_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["proxmox_endpoint_id", "vmid", "operations"],
    "additionalProperties": False,
    "properties": {
        "proxmox_endpoint_id": {"type": "integer", "minimum": 1},
        "operations": {
            "type": "array",
            "minItems": 1,
            "maxItems": 8,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "enum": [
                    "clone",
                    "migrate",
                    "configure",
                    "resize",
                    "start",
                    "stop",
                    "status",
                    "agent_ping",
                ],
            },
        },
        "vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
        "template_vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 63,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$",
        },
        "source_node": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
        },
        "node": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
        },
        "target_node": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
        },
        "storage": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
        },
        "target_storage": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
        },
        "full_clone": {"type": "boolean", "default": True},
        "agent_enabled": {"type": "boolean", "default": True},
        "memory_mb": {"type": "integer", "minimum": 128, "maximum": 1048576},
        "cores": {"type": "integer", "minimum": 1, "maximum": 512},
        "ciuser": {
            "type": "string",
            "minLength": 1,
            "maxLength": 32,
            "pattern": "^[a-z_][a-z0-9_-]{0,31}$",
        },
        "networks": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "required": ["index", "bridge"],
                "additionalProperties": False,
                "properties": {
                    "index": {"type": "integer", "minimum": 0, "maximum": 31},
                    "model": {
                        "type": "string",
                        "enum": ["virtio", "e1000", "e1000e", "vmxnet3", "rtl8139"],
                        "default": "virtio",
                    },
                    "bridge": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$",
                    },
                    "tag": {"type": "integer", "minimum": 1, "maximum": 4094},
                    "firewall": {"type": "boolean"},
                },
            },
        },
        "ipconfigs": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "required": ["index", "ip"],
                "additionalProperties": False,
                "properties": {
                    "index": {"type": "integer", "minimum": 0, "maximum": 31},
                    "ip": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[^\\s,]+$",
                    },
                    "gw": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[^\\s,]+$",
                    },
                },
            },
        },
        "resize_disk": {
            "type": "string",
            "pattern": "^(scsi|virtio|sata|ide)[0-9]+$",
            "default": "scsi0",
        },
        "disk_gb": {"type": "integer", "minimum": 1, "maximum": 262144},
    },
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "vmid"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "vmid": {"type": "integer"},
        "operations": {"type": "array", "items": {"type": "string"}},
        "steps": {"type": "array"},
    },
}

_PROCEDURE = {
    "name": "os.linux.proxmox.qemu_vm_lifecycle",
    "handler_id": "os.linux_proxmox.qemu_vm_lifecycle",
    "target_models": ["netbox_proxbox.proxmoxendpoint"],
    "effect": "destructive",
    "timeout_seconds": 3600,
    "approval_required": True,
    "description": (
        "Run fixed Proxmox QEMU VM lifecycle operations through audited RPC: "
        "clone, migrate, configure, resize, start, stop, status, and agent ping."
    ),
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
}


def seed_proxmox_qemu_vm_lifecycle(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.update_or_create(
        name=_PROCEDURE["name"],
        defaults=_PROCEDURE,
    )


def unseed_proxmox_qemu_vm_lifecycle(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_PROCEDURE["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0017_seed_allow_third_party_optical_modules"),
    ]

    operations = [
        migrations.RunPython(
            seed_proxmox_qemu_vm_lifecycle,
            reverse_code=unseed_proxmox_qemu_vm_lifecycle,
        ),
    ]
