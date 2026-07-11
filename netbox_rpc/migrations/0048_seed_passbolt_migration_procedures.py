"""Seed Passbolt one-time migration RPC procedures.

These procedures are backend-orchestrated and approval-gated. They intentionally
return only file paths, byte sizes, sha256 checksums, and status metadata; DB
dump contents, GPG/JWT archive contents, and credential material must never be
stored in netbox-rpc records.

Data is inlined here (migrations must not import runtime constants). Handler IDs
are stable string bridges to nms-backend.
"""

from django.db import migrations

_RPC_SSH_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts it at execution time.",
}

_RPC_SSH_HOST_PATTERN = r"^[^\s\x00-\x1f]{1,255}$"

_RPC_SSH_OVERRIDE_PROPERTIES = {
    "rpc_ssh_credential_pk": _RPC_SSH_CREDENTIAL_REF,
    "rpc_ssh_host": {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "pattern": _RPC_SSH_HOST_PATTERN,
        "description": "SSH host override consumed by nms-backend.",
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

_SAFE_NAME = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
}
_DB_NAME = {
    "type": "string",
    "minLength": 1,
    "maxLength": 64,
    "pattern": "^[A-Za-z0-9_]{1,64}$",
}
_ENV_NAME = {
    "type": "string",
    "minLength": 1,
    "maxLength": 64,
    "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,63}$",
}
_ABS_PATH = {
    "type": "string",
    "minLength": 2,
    "maxLength": 255,
    # Charset + absolute-path gate only; traversal and broad-directory rejection
    # is enforced authoritatively by the normalizer and nms-backend Pydantic
    # (a single regex cannot reliably reject a leading `/../` segment).
    "pattern": "^/[A-Za-z0-9._/-]{1,254}$",
}
_HOST = {
    "type": "string",
    "minLength": 1,
    "maxLength": 253,
    "pattern": (
        "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
    ),
}
_POSIX_USER = {
    "type": "string",
    "minLength": 1,
    "maxLength": 32,
    "pattern": "^[a-z_][a-z0-9_-]{0,31}$",
}

_FILE_METADATA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["path", "bytes", "sha256"],
    "properties": {
        "path": {"type": "string"},
        "bytes": {"type": "integer", "minimum": 0},
        "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
    },
}

_COMMON_RESULT = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
}

_EXPORT_PARAMS_SCHEMA = {
    "type": "object",
    "required": [
        "rpc_ssh_host",
        "rpc_ssh_credential_pk",
        "app_container_name",
        "db_container_name",
        "db_name",
        "db_host",
        "db_port",
        "db_user_env",
        "db_password_env",
        "staging_dir",
    ],
    "additionalProperties": False,
    "properties": {
        **_RPC_SSH_OVERRIDE_PROPERTIES,
        "app_container_name": _SAFE_NAME,
        "db_container_name": _SAFE_NAME,
        "db_name": _DB_NAME,
        "db_host": _HOST,
        "db_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "db_user_env": _ENV_NAME,
        "db_password_env": _ENV_NAME,
        "gpg_dir": {**_ABS_PATH, "default": "/etc/passbolt/gpg"},
        "jwt_dir": {**_ABS_PATH, "default": "/etc/passbolt/jwt"},
        "staging_dir": _ABS_PATH,
    },
}

_EXPORT_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "files"],
    "properties": {
        **_COMMON_RESULT,
        "files": {
            "type": "object",
            "additionalProperties": False,
            "required": ["db_sql", "gpg_tar", "jwt_tar"],
            "properties": {
                "db_sql": _FILE_METADATA,
                "gpg_tar": _FILE_METADATA,
                "jwt_tar": _FILE_METADATA,
            },
        },
    },
}

_TRANSFER_PARAMS_SCHEMA = {
    "type": "object",
    "required": [
        "rpc_ssh_host",
        "rpc_ssh_credential_pk",
        "source_staging_dir",
        "target_host",
        "target_ssh_user",
        "target_ssh_port",
        "target_staging_dir",
    ],
    "additionalProperties": False,
    "properties": {
        **_RPC_SSH_OVERRIDE_PROPERTIES,
        "source_staging_dir": _ABS_PATH,
        "target_host": _HOST,
        "target_ssh_user": _POSIX_USER,
        "target_ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "target_staging_dir": _ABS_PATH,
    },
}

_TRANSFER_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "source_files", "target_files"],
    "properties": {
        **_COMMON_RESULT,
        "source_files": {"type": "array", "items": _FILE_METADATA},
        "target_files": {"type": "array", "items": _FILE_METADATA},
    },
}

_IMPORT_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_host", "rpc_ssh_credential_pk", "staging_dir", "db_name"],
    "additionalProperties": False,
    "properties": {
        **_RPC_SSH_OVERRIDE_PROPERTIES,
        "staging_dir": _ABS_PATH,
        "db_name": _DB_NAME,
        "gpg_dest_dir": {**_ABS_PATH, "default": "/etc/passbolt/gpg"},
        "jwt_dest_dir": {**_ABS_PATH, "default": "/etc/passbolt/jwt"},
        "cake_bin_path": {
            **_ABS_PATH,
            "default": "/usr/share/php/passbolt/bin/cake",
        },
    },
}

_STATUS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "exit_code"],
    "properties": {"ok": {"type": "boolean"}, "exit_code": {"type": "integer"}},
}

_IMPORT_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "migrate", "healthcheck"],
    "properties": {
        **_COMMON_RESULT,
        "migrate": _STATUS_SCHEMA,
        "healthcheck": _STATUS_SCHEMA,
    },
}

_CLEANUP_PARAMS_SCHEMA = {
    "type": "object",
    "required": [
        "rpc_ssh_host",
        "rpc_ssh_credential_pk",
        "source_staging_dir",
        "target_host",
        "target_ssh_user",
        "target_ssh_port",
        "target_staging_dir",
    ],
    "additionalProperties": False,
    "properties": {
        **_RPC_SSH_OVERRIDE_PROPERTIES,
        "source_staging_dir": _ABS_PATH,
        "target_host": _HOST,
        "target_ssh_user": _POSIX_USER,
        "target_ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "target_staging_dir": _ABS_PATH,
    },
}

_CLEANUP_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "source_removed", "target_removed"],
    "properties": {
        **_COMMON_RESULT,
        "source_removed": {"type": "boolean"},
        "target_removed": {"type": "boolean"},
    },
}

_PROCEDURES = (
    {
        "name": "services.passbolt.export_secrets",
        "handler_id": "services.passbolt.export_secrets",
        "target_models": [],
        "effect": "destructive",
        "timeout_seconds": 1800,
        "approval_required": True,
        "description": "Export Passbolt DB/GPG/JWT material to a source-host staging directory.",
        "params_schema": _EXPORT_PARAMS_SCHEMA,
        "result_schema": _EXPORT_RESULT_SCHEMA,
    },
    {
        "name": "services.passbolt.transfer_secrets",
        "handler_id": "services.passbolt.transfer_secrets",
        "target_models": [],
        "effect": "destructive",
        "timeout_seconds": 1800,
        "approval_required": True,
        "description": "Transfer staged Passbolt migration files host-to-host with rsync over SSH.",
        "params_schema": _TRANSFER_PARAMS_SCHEMA,
        "result_schema": _TRANSFER_RESULT_SCHEMA,
    },
    {
        "name": "services.passbolt.import_secrets",
        "handler_id": "services.passbolt.import_secrets",
        "target_models": [],
        "effect": "destructive",
        "timeout_seconds": 3600,
        "approval_required": True,
        "description": "Import staged Passbolt DB/GPG/JWT material into a native Passbolt VM.",
        "params_schema": _IMPORT_PARAMS_SCHEMA,
        "result_schema": _IMPORT_RESULT_SCHEMA,
    },
    {
        "name": "services.passbolt.cleanup",
        "handler_id": "services.passbolt.cleanup",
        "target_models": [],
        "effect": "destructive",
        "timeout_seconds": 300,
        "approval_required": True,
        "description": "Remove source and target Passbolt migration staging directories.",
        "params_schema": _CLEANUP_PARAMS_SCHEMA,
        "result_schema": _CLEANUP_RESULT_SCHEMA,
    },
)

_COMMAND_STEPS_BY_HANDLER_ID = {
    "services.passbolt.export_secrets": [
        {
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": ["backend-orchestrated", "passbolt-export-secrets"],
            "description": (
                "Backend exports db.sql, gpg.tar, and jwt.tar to the source "
                "staging directory and returns only paths, sizes, and sha256s."
            ),
            "condition_param": "",
            "condition_negate": False,
            "for_each_param": "",
            "continue_on_error": False,
        },
    ],
    "services.passbolt.transfer_secrets": [
        {
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": ["backend-orchestrated", "passbolt-transfer-secrets"],
            "description": (
                "Backend starts source-host rsync over SSH to the target host "
                "and verifies target-side sha256 checksums."
            ),
            "condition_param": "",
            "condition_negate": False,
            "for_each_param": "",
            "continue_on_error": False,
        },
    ],
    "services.passbolt.import_secrets": [
        {
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": ["backend-orchestrated", "passbolt-import-secrets"],
            "description": (
                "Backend imports db.sql, extracts GPG/JWT archives, fixes "
                "ownership/permissions, and runs Passbolt cake checks."
            ),
            "condition_param": "",
            "condition_negate": False,
            "for_each_param": "",
            "continue_on_error": False,
        },
    ],
    "services.passbolt.cleanup": [
        {
            "step_type": "shell_argv",
            "device_cli_mode": "",
            "argv": ["backend-orchestrated", "passbolt-cleanup"],
            "description": "Backend removes approved source and target staging directories.",
            "condition_param": "",
            "condition_negate": False,
            "for_each_param": "",
            "continue_on_error": False,
        },
    ],
}


def _seed_passbolt_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PROCEDURES:
        RPCProcedure.objects.update_or_create(
            name=data["name"],
            defaults=data,
        )


def _remove_passbolt_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


def _seed_passbolt_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for handler_id, steps in _COMMAND_STEPS_BY_HANDLER_ID.items():
        for procedure in RPCProcedure.objects.filter(handler_id=handler_id):
            for index, step in enumerate(steps, start=1):
                RPCProcedureCommand.objects.update_or_create(
                    procedure=procedure,
                    sequence=index,
                    defaults=step,
                )


def _remove_passbolt_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    handler_ids = list(_COMMAND_STEPS_BY_HANDLER_ID)
    procedures = RPCProcedure.objects.filter(handler_id__in=handler_ids)
    RPCProcedureCommand.objects.filter(procedure__in=procedures).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0047_merge_0045_nmap_scan_0046_merge"),
    ]

    operations = [
        migrations.RunPython(
            _seed_passbolt_procedures,
            reverse_code=_remove_passbolt_procedures,
        ),
        migrations.RunPython(
            _seed_passbolt_commands,
            reverse_code=_remove_passbolt_commands,
        ),
    ]
