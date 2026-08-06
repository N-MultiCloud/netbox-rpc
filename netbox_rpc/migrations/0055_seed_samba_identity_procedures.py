"""Seed Samba/AD user and group identity management RPC procedures (#160).

user_create and user_set_password accept a password. It is scrubbed to a
sha256+byte-count fingerprint at execution-creation time
(command_handlers.create_execution()) before the RPCExecution row is ever
persisted, so params/normalized_params/result/events never contain the
plaintext value; both handlers are EXEMPT_HANDLER_RATIONALE entries because
the stdin-secret delivery has no faithful fixed-argv representation.
user_delete and group_delete are destructive and approval-gated. Data is
inline so migrations remain stable across runtime constant changes.
"""

from django.db import migrations

_TARGET_MODELS = [
    "netbox_fileserver.sambadomain",
    "virtualization.virtualmachine",
    "dcim.device",
]

# Shared optional SSH connection-override properties (mirrors 0049/0051).
_RPC_SSH_HOST_PATTERN = r"^[^\s\x00-\x1f]{1,255}(?![\s\S])"
_RPC_SSH_OVERRIDE_PROPERTIES = {
    "rpc_ssh_host": {"type": "string", "pattern": _RPC_SSH_HOST_PATTERN},
    "rpc_ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "rpc_ssh_credential_pk": {"type": "integer", "minimum": 1},
    "rpc_ssh_known_hosts_entry": {"type": "string", "maxLength": 8192},
    "rpc_ssh_strict_host_key_checking": {"type": "boolean"},
}

# jsonschema validates "pattern" via re.search, under which a bare "$" allows
# a trailing "\n" to pass. Every new pattern here anchors with "(?![\s\S])"
# instead, matching the precedent set in 0051_seed_samba_write_procedures.
_SAMBA_IDENTIFIER_PATTERN = r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}(?![\s\S])"
_SAMBA_PASSWORD_PATTERN = r"^[^\x00-\x1f\x7f]{1,256}(?![\s\S])"
_SAMBA_FULL_NAME_PATTERN = r"^[^\r\n\x00-\x1f]{0,128}(?![\s\S])"

_USERNAME_PROPERTY = {
    "type": "string",
    "minLength": 1,
    "maxLength": 64,
    "pattern": _SAMBA_IDENTIFIER_PATTERN,
}
_GROUP_NAME_PROPERTY = {
    "type": "string",
    "minLength": 1,
    "maxLength": 64,
    "pattern": _SAMBA_IDENTIFIER_PATTERN,
}
_PASSWORD_PROPERTY = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "pattern": _SAMBA_PASSWORD_PATTERN,
    "description": (
        "Delivered to samba-tool over stdin only; never persisted. Scrubbed to "
        "password_sha256/password_bytes before the execution row is created."
    ),
}

_USER_CREATE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["username", "password"],
    "additionalProperties": False,
    "properties": {
        "username": _USERNAME_PROPERTY,
        "password": _PASSWORD_PROPERTY,
        "full_name": {
            "type": "string",
            "maxLength": 128,
            "pattern": _SAMBA_FULL_NAME_PATTERN,
        },
        "disabled": {"type": "boolean", "default": False},
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_USER_DELETE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["username"],
    "additionalProperties": False,
    "properties": {
        "username": _USERNAME_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_USER_SET_PASSWORD_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["username", "password"],
    "additionalProperties": False,
    "properties": {
        "username": _USERNAME_PROPERTY,
        "password": _PASSWORD_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_USER_ENABLE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["username"],
    "additionalProperties": False,
    "properties": {
        "username": _USERNAME_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_USER_DISABLE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["username"],
    "additionalProperties": False,
    "properties": {
        "username": _USERNAME_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_GROUP_CREATE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["group_name"],
    "additionalProperties": False,
    "properties": {
        "group_name": _GROUP_NAME_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_GROUP_DELETE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["group_name"],
    "additionalProperties": False,
    "properties": {
        "group_name": _GROUP_NAME_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_MEMBERS_PROPERTY = {
    "type": "array",
    "minItems": 1,
    "maxItems": 128,
    "uniqueItems": True,
    "items": _USERNAME_PROPERTY,
}

_GROUP_ADD_MEMBERS_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["group_name", "members"],
    "additionalProperties": False,
    "properties": {
        "group_name": _GROUP_NAME_PROPERTY,
        "members": _MEMBERS_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_GROUP_REMOVE_MEMBERS_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["group_name", "members"],
    "additionalProperties": False,
    "properties": {
        "group_name": _GROUP_NAME_PROPERTY,
        "members": _MEMBERS_PROPERTY,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_COMMON_RESULT_PROPERTIES = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
}

_USER_CREATE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "username", "created"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "username": {"type": "string"},
        "created": {"type": "boolean"},
        "stdout": {"type": "string"},
        "stderr": {"type": "string"},
    },
}

_USER_DELETE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "username", "deleted"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "username": {"type": "string"},
        "deleted": {"type": "boolean"},
    },
}

_USER_SET_PASSWORD_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "username", "password_set"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "username": {"type": "string"},
        "password_set": {"type": "boolean"},
    },
}

_USER_ENABLE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "username", "enabled"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "username": {"type": "string"},
        "enabled": {"type": "boolean"},
    },
}

_USER_DISABLE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "username", "disabled"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "username": {"type": "string"},
        "disabled": {"type": "boolean"},
    },
}

_GROUP_CREATE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "group_name", "created"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "group_name": {"type": "string"},
        "created": {"type": "boolean"},
    },
}

_GROUP_DELETE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "group_name", "deleted"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "group_name": {"type": "string"},
        "deleted": {"type": "boolean"},
    },
}

_GROUP_ADD_MEMBERS_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "group_name", "members"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "group_name": {"type": "string"},
        "members": {"type": "array", "items": {"type": "string"}},
    },
}

_GROUP_REMOVE_MEMBERS_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "group_name", "members"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "group_name": {"type": "string"},
        "members": {"type": "array", "items": {"type": "string"}},
    },
}

_PROCEDURES = (
    {
        "name": "service.samba.1.user_create",
        "handler_id": "service.samba_1.user_create",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": (
            "Create a Samba/AD user. The password is delivered to samba-tool "
            "over stdin only and is scrubbed to a sha256+byte-count fingerprint "
            "before the execution row is persisted; it is never stored or "
            "returned in plaintext."
        ),
        "params_schema": _USER_CREATE_PARAMS_SCHEMA,
        "result_schema": _USER_CREATE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.user_delete",
        "handler_id": "service.samba_1.user_delete",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "destructive",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Delete a Samba/AD user by username.",
        "params_schema": _USER_DELETE_PARAMS_SCHEMA,
        "result_schema": _USER_DELETE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.user_set_password",
        "handler_id": "service.samba_1.user_set_password",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": (
            "Reset a Samba/AD user's password. The password is delivered to "
            "samba-tool over stdin only and is scrubbed to a sha256+byte-count "
            "fingerprint before the execution row is persisted; it is never "
            "stored or returned in plaintext."
        ),
        "params_schema": _USER_SET_PASSWORD_PARAMS_SCHEMA,
        "result_schema": _USER_SET_PASSWORD_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.user_enable",
        "handler_id": "service.samba_1.user_enable",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Enable a disabled Samba/AD user account.",
        "params_schema": _USER_ENABLE_PARAMS_SCHEMA,
        "result_schema": _USER_ENABLE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.user_disable",
        "handler_id": "service.samba_1.user_disable",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Disable an active Samba/AD user account.",
        "params_schema": _USER_DISABLE_PARAMS_SCHEMA,
        "result_schema": _USER_DISABLE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.group_create",
        "handler_id": "service.samba_1.group_create",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Create a Samba/AD group.",
        "params_schema": _GROUP_CREATE_PARAMS_SCHEMA,
        "result_schema": _GROUP_CREATE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.group_delete",
        "handler_id": "service.samba_1.group_delete",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "destructive",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Delete a Samba/AD group by name.",
        "params_schema": _GROUP_DELETE_PARAMS_SCHEMA,
        "result_schema": _GROUP_DELETE_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.group_add_members",
        "handler_id": "service.samba_1.group_add_members",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Add one or more users to a Samba/AD group.",
        "params_schema": _GROUP_ADD_MEMBERS_PARAMS_SCHEMA,
        "result_schema": _GROUP_ADD_MEMBERS_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.group_remove_members",
        "handler_id": "service.samba_1.group_remove_members",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Remove one or more users from a Samba/AD group.",
        "params_schema": _GROUP_REMOVE_MEMBERS_PARAMS_SCHEMA,
        "result_schema": _GROUP_REMOVE_MEMBERS_RESULT_SCHEMA,
    },
)


def _seed_samba_identity_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in _PROCEDURES:
        defaults = {key: value for key, value in procedure.items() if key != "name"}
        RPCProcedure.objects.update_or_create(
            name=procedure["name"],
            defaults=defaults,
        )


def _remove_samba_identity_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[procedure["name"] for procedure in _PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0054_merge_approval_and_samba"),
    ]

    operations = [
        migrations.RunPython(
            _seed_samba_identity_procedures,
            reverse_code=_remove_samba_identity_procedures,
        ),
    ]
