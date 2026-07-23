"""Seed Samba config write and lifecycle RPC procedures.

These procedures are the write/lifecycle half of the Samba catalog. They keep
the public contract structured: config bodies are strings passed to backend
handlers for stdin use, service control uses enums, and share operations accept
allowlisted fields rather than arbitrary smb.conf option text.

Data is inlined here (never imported from netbox_rpc.constants) so the migration
stays stable across future constant renames/squashes.
"""

from django.db import migrations

_TARGET_MODELS = [
    "netbox_fileserver.sambadomain",
    "virtualization.virtualmachine",
    "dcim.device",
]

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

_MAX_CONFIG_BODY_LENGTH = 1024 * 1024

# The trailing anchor is ``(?![\s\S])`` (absolute end of string) rather than
# ``$``: Python's ``re`` -- which ``jsonschema`` uses to enforce ``pattern`` --
# lets ``$`` match *before* a single trailing newline, so ``smb.conf\n`` would
# otherwise satisfy the schema. ``(?![\s\S])`` is valid in both Python and
# ECMA-262 regex dialects, unlike ``\Z``.
_SAMBA_INCLUDE_FILE_PATTERN = (
    r"^(?!.*(?:^|/)\.\.(?:/|$))(?:/etc/samba/)?"
    r"[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*\.conf(?![\s\S])"
)
_SAMBA_SHARE_NAME_PATTERN = r"^[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,79}(?![\s\S])"
_SAMBA_SNAPSHOT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])"
_SAMBA_SHARE_PATH_PATTERN = (
    r"^/(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._@+-]+"
    r"(?:/[A-Za-z0-9._@+-]+)*(?![\s\S])"
)
_SAMBA_SAFE_TEXT_PATTERN = r"^[^\r\n\x00-\x1f]{0,240}(?![\s\S])"
_SAMBA_PRINCIPAL_PATTERN = r"^@?[A-Za-z0-9_][A-Za-z0-9_.@+\\-]{0,127}(?![\s\S])"
_SAMBA_OCTAL_MASK_PATTERN = r"^[0-7]{3,4}(?![\s\S])"
_SAMBA_SERVICE_UNITS = ["smbd", "nmbd", "winbind", "samba-ad-dc"]
_SAMBA_SERVICE_ACTIONS = ["start", "stop", "restart", "reload"]

_BASE_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": _RPC_SSH_OVERRIDE_PROPERTIES,
}

_CONFIG_DEPLOY_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["config_content"],
    "additionalProperties": False,
    "properties": {
        "config_content": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_CONFIG_BODY_LENGTH,
            "description": (
                "Full smb.conf content. The backend writes this via stdin to a "
                "temporary candidate, validates it with testparm, snapshots the "
                "active config, then activates and reloads."
            ),
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_CONFIG_ROLLBACK_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["snapshot_id"],
    "additionalProperties": False,
    "properties": {
        "snapshot_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": _SAMBA_SNAPSHOT_ID_PATTERN,
            "description": "Backend-issued Samba config snapshot identifier.",
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_INCLUDE_FILE_WRITE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["include_path", "content"],
    "additionalProperties": False,
    "properties": {
        "include_path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "pattern": _SAMBA_INCLUDE_FILE_PATTERN,
            "description": (
                "Samba include file to write. Relative paths are resolved under "
                "/etc/samba; absolute paths must start with /etc/samba/."
            ),
        },
        "content": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_CONFIG_BODY_LENGTH,
            "description": "Include-file content; the backend writes it via stdin.",
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_INCLUDE_FILE_DELETE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["include_path"],
    "additionalProperties": False,
    "properties": {
        "include_path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "pattern": _SAMBA_INCLUDE_FILE_PATTERN,
            "description": "Samba include file to delete, confined under /etc/samba.",
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_SHARE_NAME_PROPERTY = {
    "type": "string",
    "minLength": 1,
    "maxLength": 80,
    "pattern": _SAMBA_SHARE_NAME_PATTERN,
    "description": "Safe Samba share name.",
}

_SHARE_UPSERT_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["share_name", "path"],
    "additionalProperties": False,
    "properties": {
        "share_name": _SHARE_NAME_PROPERTY,
        "path": {
            "type": "string",
            "minLength": 2,
            "maxLength": 255,
            "pattern": _SAMBA_SHARE_PATH_PATTERN,
            "description": "Absolute POSIX data path for the share.",
        },
        "comment": {
            "type": "string",
            "maxLength": 240,
            "pattern": _SAMBA_SAFE_TEXT_PATTERN,
        },
        "read_only": {"type": "boolean", "default": True},
        "browseable": {"type": "boolean", "default": True},
        "guest_ok": {"type": "boolean", "default": False},
        "valid_users": {
            "type": "array",
            "maxItems": 64,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": _SAMBA_PRINCIPAL_PATTERN,
            },
        },
        "write_list": {
            "type": "array",
            "maxItems": 64,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": _SAMBA_PRINCIPAL_PATTERN,
            },
        },
        "create_mask": {
            "type": "string",
            "pattern": _SAMBA_OCTAL_MASK_PATTERN,
        },
        "directory_mask": {
            "type": "string",
            "pattern": _SAMBA_OCTAL_MASK_PATTERN,
        },
        "force_group": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": _SAMBA_PRINCIPAL_PATTERN,
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_SHARE_DELETE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["share_name"],
    "additionalProperties": False,
    "properties": {
        "share_name": _SHARE_NAME_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_SERVICE_CONTROL_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["unit", "action"],
    "additionalProperties": False,
    "properties": {
        "unit": {
            "type": "string",
            "enum": _SAMBA_SERVICE_UNITS,
            "description": "Samba systemd unit slug.",
        },
        "action": {
            "type": "string",
            "enum": _SAMBA_SERVICE_ACTIONS,
            "description": "Allowed systemctl action.",
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_SHA256 = {"type": "string", "pattern": "^[a-f0-9]{64}$"}

_COMMON_RESULT_PROPERTIES = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
}

_CONFIG_LIFECYCLE_RESULT_PROPERTIES = {
    "stage": {
        "type": "string",
        "enum": ["validate", "snapshot", "activate", "reload", "rollback"],
        "description": "Last lifecycle stage reached by the backend handler.",
    },
    "snapshot_id": {"type": "string"},
    "activated": {"type": "boolean"},
    "reloaded": {"type": "boolean"},
    "rolled_back": {"type": "boolean"},
    "rollback_error": {"type": ["string", "null"]},
}

_CONFIG_DEPLOY_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "ok",
        "procedure",
        "target",
        "config_path",
        "test_passed",
        "stage",
        "activated",
        "reloaded",
        "rolled_back",
    ],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "config_path": {"type": "string"},
        "test_passed": {"type": "boolean"},
        **_CONFIG_LIFECYCLE_RESULT_PROPERTIES,
        "config_sha256": _SHA256,
        "stdout": {"type": "string"},
        "stderr": {"type": "string"},
    },
}

_CONFIG_ROLLBACK_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "ok",
        "procedure",
        "target",
        "snapshot_id",
        "stage",
        "restored",
        "reloaded",
        "rolled_back",
    ],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        **_CONFIG_LIFECYCLE_RESULT_PROPERTIES,
        "config_path": {"type": "string"},
        "test_passed": {"type": "boolean"},
        "restored": {"type": "boolean"},
    },
}

_INCLUDE_FILE_WRITE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "path", "sha256"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "path": {"type": "string"},
        "sha256": _SHA256,
        "test_passed": {"type": "boolean"},
        "snapshot_id": {"type": "string"},
        "reloaded": {"type": "boolean"},
    },
}

_INCLUDE_FILE_DELETE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "path", "deleted"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "path": {"type": "string"},
        "deleted": {"type": "boolean"},
        "test_passed": {"type": "boolean"},
        "snapshot_id": {"type": "string"},
        "reloaded": {"type": "boolean"},
    },
}

_SHARE_UPSERT_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "share_name"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "share_name": {"type": "string"},
        "path": {"type": "string"},
        "test_passed": {"type": "boolean"},
        "snapshot_id": {"type": "string"},
        "reloaded": {"type": "boolean"},
    },
}

_SHARE_DELETE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "share_name", "deleted"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "share_name": {"type": "string"},
        "deleted": {"type": "boolean"},
        "test_passed": {"type": "boolean"},
        "snapshot_id": {"type": "string"},
        "reloaded": {"type": "boolean"},
    },
}

_SERVICE_CONTROL_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "unit", "action"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "unit": {"type": "string"},
        "action": {"type": "string"},
        "active_state": {"type": "string"},
        "sub_state": {"type": "string"},
        "unit_file_state": {"type": "string"},
    },
}

_PROCEDURES = (
    {
        "name": "service.samba.1.config_deploy",
        "handler_id": "service.samba_1.config_deploy",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": (
            "Deploy smb.conf via temp file, testparm validation, snapshot, "
            "atomic activation, reload, and post-snapshot rollback on any "
            "activation, reload, timeout, or lost-response failure."
        ),
        "params_schema": _CONFIG_DEPLOY_PARAMS_SCHEMA,
        "result_schema": _CONFIG_DEPLOY_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.config_rollback",
        "handler_id": "service.samba_1.config_rollback",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "destructive",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Restore a backend-issued Samba config snapshot and reload.",
        "params_schema": _CONFIG_ROLLBACK_PARAMS_SCHEMA,
        "result_schema": _CONFIG_ROLLBACK_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.include_file_write",
        "handler_id": "service.samba_1.include_file_write",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Write one confined Samba include file via stdin and validate.",
        "params_schema": _INCLUDE_FILE_WRITE_PARAMS_SCHEMA,
        "result_schema": _INCLUDE_FILE_WRITE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.include_file_delete",
        "handler_id": "service.samba_1.include_file_delete",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "destructive",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Delete one confined Samba include file with validation guardrails.",
        "params_schema": _INCLUDE_FILE_DELETE_PARAMS_SCHEMA,
        "result_schema": _INCLUDE_FILE_DELETE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.share_upsert",
        "handler_id": "service.samba_1.share_upsert",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Create or update one Samba share from structured fields.",
        "params_schema": _SHARE_UPSERT_PARAMS_SCHEMA,
        "result_schema": _SHARE_UPSERT_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.share_delete",
        "handler_id": "service.samba_1.share_delete",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "destructive",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Delete one safe Samba share definition with validation guardrails.",
        "params_schema": _SHARE_DELETE_PARAMS_SCHEMA,
        "result_schema": _SHARE_DELETE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.service_control",
        "handler_id": "service.samba_1.service_control",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Run an enum-constrained systemctl action on one Samba unit.",
        "params_schema": _SERVICE_CONTROL_PARAMS_SCHEMA,
        "result_schema": _SERVICE_CONTROL_RESULT_SCHEMA,
    },
)


def _seed_samba_write_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in _PROCEDURES:
        defaults = {key: value for key, value in procedure.items() if key != "name"}
        RPCProcedure.objects.update_or_create(
            name=procedure["name"],
            defaults=defaults,
        )


def _remove_samba_write_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[procedure["name"] for procedure in _PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0050_seed_samba_read_commands"),
    ]

    operations = [
        migrations.RunPython(
            _seed_samba_write_procedures,
            reverse_code=_remove_samba_write_procedures,
        ),
    ]
