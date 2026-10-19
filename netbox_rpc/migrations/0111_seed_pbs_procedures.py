"""Seed the disabled typed Proxmox Backup Server procedure family."""

from django.db import migrations

_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]
_EMPTY_PARAMS = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
_DATASTORE_PARAMS = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "minLength": 3,
            "maxLength": 32,
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{2,31}(?![\s\S])",
        },
        "disk": {
            "type": "string",
            "minLength": 3,
            "maxLength": 12,
            "pattern": r"^(?:sd[a-z]{1,2}|vd[a-z]{1,2}|nvme[0-9]{1,2}n[0-9]{1,2})(?![\s\S])",
        },
        "filesystem": {"enum": ["ext4", "xfs"]},
        "disk_identity": {
            "type": "string",
            "minLength": 64,
            "maxLength": 64,
            "pattern": r"^[0-9a-f]{64}(?![\s\S])",
        },
    },
    "required": ["name", "disk", "filesystem", "disk_identity"],
    "additionalProperties": False,
}


def _failure_result(name):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["procedure", "failure"],
        "properties": {
            "procedure": {"const": name},
            "failure": {
                "type": "object",
                "additionalProperties": False,
                "required": ["code"],
                "properties": {
                    "code": {
                        "type": "string",
                        "maxLength": 64,
                        "pattern": r"^RPC_[A-Z0-9_]{1,63}(?![\s\S])",
                    }
                },
            },
        },
    }


def _with_failure(name, success):
    return {"anyOf": [success, _failure_result(name)]}


def _status_result(name):
    state = {"enum": ["active", "inactive", "failed", "unknown"]}
    success = {
        "type": "object",
        "required": ["procedure", "services", "version", "cloud_init"],
        "additionalProperties": False,
        "properties": {
            "procedure": {"const": name},
            "services": {
                "type": "object",
                "required": ["proxmox-backup", "proxmox-backup-proxy"],
                "additionalProperties": False,
                "properties": {
                    "proxmox-backup": state,
                    "proxmox-backup-proxy": state,
                },
            },
            "version": {"type": "string", "minLength": 1, "maxLength": 128},
            "cloud_init": {"enum": ["done", "running", "error", "disabled", "unknown"]},
        },
    }
    return _with_failure(name, success)


def _cert_result(name):
    success = {
        "type": "object",
        "required": ["procedure", "fingerprint", "subject", "not_after"],
        "additionalProperties": False,
        "properties": {
            "procedure": {"const": name},
            "fingerprint": {
                "type": "string",
                "minLength": 95,
                "maxLength": 95,
                "pattern": r"^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}(?![\s\S])",
            },
            "subject": {"type": "string", "maxLength": 512},
            "not_after": {"type": "string", "maxLength": 128},
        },
    }
    return _with_failure(name, success)


def _disk_list_result(name):
    success = {
        "type": "object",
        "required": ["procedure", "disks"],
        "additionalProperties": False,
        "properties": {
            "procedure": {"const": name},
            "disks": {
                "type": "array",
                "maxItems": 64,
                "items": {
                    "type": "object",
                    "required": [
                        "name",
                        "size_bytes",
                        "used",
                        "gpt",
                        "model",
                        "identity",
                        "identity_stable",
                    ],
                    "additionalProperties": False,
                    "properties": {
                        "name": {"type": "string", "minLength": 1, "maxLength": 32},
                        "size_bytes": {"type": "integer", "minimum": 0},
                        "used": {"type": "string", "maxLength": 64},
                        "gpt": {"type": "boolean"},
                        "model": {"type": "string", "maxLength": 128},
                        "identity": {
                            "type": "string",
                            "minLength": 64,
                            "maxLength": 64,
                            "pattern": r"^[0-9a-f]{64}(?![\s\S])",
                        },
                        "identity_stable": {"type": "boolean"},
                    },
                },
            },
        },
    }
    return _with_failure(name, success)


def _datastore_result(name):
    success = {
        "type": "object",
        "required": ["procedure", "name", "disk", "filesystem"],
        "additionalProperties": False,
        "properties": {
            "procedure": {"const": name},
            "name": {"type": "string", "minLength": 3, "maxLength": 32},
            "disk": {"type": "string", "minLength": 3, "maxLength": 12},
            "filesystem": {"enum": ["ext4", "xfs"]},
        },
    }
    return _with_failure(name, success)


_PROCEDURES = (
    (
        "service.pbs.1.status",
        "read",
        60,
        False,
        _EMPTY_PARAMS,
        _status_result("service.pbs.1.status"),
        "pbs-status",
        "Report PBS service, package, and cloud-init status.",
    ),
    (
        "service.pbs.1.cert_fingerprint",
        "read",
        30,
        False,
        _EMPTY_PARAMS,
        _cert_result("service.pbs.1.cert_fingerprint"),
        "pbs-cert-fingerprint",
        "Report the PBS SHA-256 certificate fingerprint and metadata.",
    ),
    (
        "service.pbs.1.disk_list",
        "read",
        30,
        False,
        _EMPTY_PARAMS,
        _disk_list_result("service.pbs.1.disk_list"),
        "pbs-disk-list",
        "List bounded PBS disk inventory without changing it.",
    ),
    (
        "service.pbs.1.datastore_from_disk",
        "destructive",
        600,
        True,
        _DATASTORE_PARAMS,
        _datastore_result("service.pbs.1.datastore_from_disk"),
        "pbs-datastore-from-disk",
        "Create one PBS datastore from a lock-held identity-verified unused disk.",
    ),
)


def _command(slug, description):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", slug],
        "description": description,
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
        "render_mode": "literal",
        "produces_var": "",
        "capture_kind": "",
        "capture_expression": "",
    }


def seed_pbs_procedures(apps, schema_editor):
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for (
        name,
        effect,
        timeout,
        approval,
        params,
        result,
        slug,
        description,
    ) in _PROCEDURES:
        procedure, _ = Procedure.objects.update_or_create(
            name=name,
            defaults={
                "handler_id": name,
                "version": 1,
                "description": description,
                "effect": effect,
                "timeout_seconds": timeout,
                "approval_required": approval,
                "enabled": False,
                "target_models": _TARGET_MODELS,
                "params_schema": params,
                "result_schema": result,
                "transport_driver": "asyncssh",
                "transport_pinned": name == "service.pbs.1.datastore_from_disk",
                "transport_driver_chain": [],
                "output_parser": "none",
                "output_schema": {},
            },
        )
        Command.objects.update_or_create(
            procedure=procedure,
            sequence=1,
            defaults=_command(slug, description),
        )


def disable_pbs_procedures(apps, schema_editor):
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Procedure.objects.filter(name__in=[row[0] for row in _PROCEDURES]).update(
        enabled=False
    )


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0110_seed_netbox_production_rq_worker_procedures")]

    operations = [
        migrations.RunPython(seed_pbs_procedures, reverse_code=disable_pbs_procedures),
    ]
