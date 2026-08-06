"""Seed the Ubuntu 24.04 to 26.04 LTS upgrade lifecycle procedures.

The catalog stores only structured schemas and stable handler IDs. Procedure
data is inline so this migration remains stable across runtime constant changes.
"""

from django.db import migrations


_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]
_ABS_PATH = "^/[A-Za-z0-9/._-]{1,255}$"

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": (
        "netbox-nms DeviceCredential PK for the ad-hoc/saved SSH target; "
        "nms-backend decrypts it at execution time. Omit for a device-targeted "
        "execution that resolves SSH from the device's DeviceService."
    ),
}

_BASE_PARAMS_PROPERTIES = {
    "rpc_ssh_credential_pk": _CREDENTIAL_REF,
    "rpc_ssh_host": {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "description": (
            "Optional SSH host override (the speedtest server IP/hostname) for the "
            "ad-hoc/saved target. Omit when targeting a registered device."
        ),
    },
    "rpc_ssh_port": {
        "type": "integer",
        "minimum": 1,
        "maximum": 65535,
        "default": 22,
        "description": "Optional SSH port override.",
    },
    "rpc_ssh_known_hosts_entry": {
        "type": "string",
        "maxLength": 8192,
        "description": "Optional single-line OpenSSH known_hosts entry for the target.",
    },
    "rpc_ssh_strict_host_key_checking": {
        "type": "boolean",
        "default": True,
        "description": "Require host-key verification when connecting over SSH.",
    },
}


def _params(properties=None):
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {**_BASE_PARAMS_PROPERTIES, **(properties or {})},
    }


_COMMON_RESULT_PROPERTIES = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
}


def _result(required=(), properties=None):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", *required],
        "properties": {**_COMMON_RESULT_PROPERTIES, **(properties or {})},
    }


_STRING_ARRAY = {"type": "array", "items": {"type": "string"}}

_PROCEDURES = (
    {
        "name": "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade",
        "handler_id": "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Analyze Ubuntu 24.04 state and blockers before an LTS upgrade.",
        "params_schema": _params(),
        "result_schema": _result(
            properties={
                "os_release": {"type": "object"},
                "kernel": {"type": "string"},
                "disk_free_root": {"type": "string"},
                "held_packages": _STRING_ARRAY,
                "third_party_sources": _STRING_ARRAY,
                "reboot_pending": {"type": "boolean"},
                "active_sessions": {"type": "array"},
                "cron_jobs": {"type": "array"},
                "ready": {"type": "boolean"},
                "blockers": _STRING_ARRAY,
            }
        ),
    },
    {
        "name": "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state",
        "handler_id": "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 300,
        "approval_required": False,
        "description": "Save additive pre-upgrade package and APT source state.",
        "params_schema": _params(
            {
                "backup_dir": {
                    "type": "string",
                    "pattern": _ABS_PATH,
                    "description": "Optional absolute backup directory override.",
                }
            }
        ),
        "result_schema": _result(
            ("backup_dir",),
            {
                "backup_dir": {"type": "string"},
                "manifest_sha256": {"type": "string"},
                "files_backed_up": _STRING_ARRAY,
            },
        ),
    },
    {
        "name": "os.linux.ubuntu.24.upgrade_26.run_upgrade",
        "handler_id": "os.linux.ubuntu.24.upgrade_26.run_upgrade",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "destructive",
        "timeout_seconds": 7200,
        "approval_required": True,
        "description": "Run the approval-gated Ubuntu 24.04 to 26.04 LTS upgrade.",
        "params_schema": _params(
            {
                "dry_run": {
                    "type": "boolean",
                    "default": True,
                    "description": "Analyze the upgrade without applying it.",
                },
                "reboot_after_upgrade": {
                    "type": "boolean",
                    "default": False,
                    "description": "Reboot only after separate operator confirmation.",
                },
            }
        ),
        "result_schema": _result(
            ("dry_run",),
            {
                "dry_run": {"type": "boolean"},
                "reboot_after_upgrade": {"type": "boolean"},
                "reboot_triggered": {"type": "boolean"},
                "upgrade_log_tail": {"type": "string"},
                "new_version_id": {"type": "string"},
            },
        ),
    },
    {
        "name": "os.linux.ubuntu.24.upgrade_26.verify_postupgrade",
        "handler_id": "os.linux.ubuntu.24.upgrade_26.verify_postupgrade",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 300,
        "approval_required": False,
        "description": "Verify release, package, and reboot state after the LTS upgrade.",
        "params_schema": _params(
            {
                "expected_version_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 32,
                    "description": "Optional expected VERSION_ID to compare after upgrade.",
                }
            }
        ),
        "result_schema": _result(
            properties={
                "os_release": {"type": "object"},
                "kernel": {"type": "string"},
                "apt_check_ok": {"type": "boolean"},
                "dpkg_audit_ok": {"type": "boolean"},
                "held_packages": _STRING_ARRAY,
                "reboot_pending": {"type": "boolean"},
                "matches_expected_release": {"type": "boolean"},
            }
        ),
    },
)


def _seed_ubuntu_upgrade_26_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in _PROCEDURES:
        defaults = {key: value for key, value in procedure.items() if key != "name"}
        RPCProcedure.objects.update_or_create(
            name=procedure["name"],
            defaults=defaults,
        )


def _remove_ubuntu_upgrade_26_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[procedure["name"] for procedure in _PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0057_seed_akvorado_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_ubuntu_upgrade_26_procedures,
            reverse_code=_remove_ubuntu_upgrade_26_procedures,
        ),
    ]
