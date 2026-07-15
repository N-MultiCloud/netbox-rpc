"""Seed read-only Samba RPC procedures.

These procedures observe Samba configuration, service state, shares, status,
domain metadata, users, groups, and share ACLs through the audited catalog.
Data is inlined here (never imported from netbox_rpc.constants) so the
migration stays stable across future constant renames/squashes.
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

_BASE_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": _RPC_SSH_OVERRIDE_PROPERTIES,
}

# The trailing anchor is ``(?![\s\S])`` (absolute end of string) rather than
# ``$``: Python's ``re`` — which ``jsonschema`` uses to enforce ``pattern`` —
# lets ``$`` match *before* a single trailing newline, so ``smb.conf\n`` would
# otherwise satisfy the schema. ``(?![\s\S])`` is valid in both Python and
# ECMA-262 regex dialects, unlike ``\Z``.
_SAMBA_INCLUDE_FILE_PATTERN = (
    r"^(?!.*(?:^|/)\.\.(?:/|$))(?:/etc/samba/)?"
    r"[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*\.conf(?![\s\S])"
)

_INCLUDE_FILE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["include_path"],
    "additionalProperties": False,
    "properties": {
        "include_path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "pattern": _SAMBA_INCLUDE_FILE_PATTERN,
            "description": (
                "Samba include file to read. Relative paths are resolved under "
                "/etc/samba; absolute paths must start with /etc/samba/."
            ),
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_SHARE_ACL_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["share_name"],
    "additionalProperties": False,
    "properties": {
        "share_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80,
            # See _SAMBA_INCLUDE_FILE_PATTERN for why this is not anchored with `$`.
            "pattern": r"^[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,79}(?![\s\S])",
            "description": "Samba share name to inspect with sharesec --view.",
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

_CONFIG_READ_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "path", "content", "sha256"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "path": {"type": "string"},
        "content": {"type": "string"},
        "sha256": _SHA256,
    },
}

_CONFIG_TEST_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "valid"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "valid": {"type": "boolean"},
        "exit_code": {"type": "integer"},
        "stdout": {"type": "string"},
        "stderr": {"type": "string"},
    },
}

_CONFIG_FILE_ENTRY = {
    "type": "object",
    "additionalProperties": False,
    "required": ["path", "size", "mtime", "sha256"],
    "properties": {
        "path": {"type": "string"},
        "size": {"type": "integer", "minimum": 0},
        "mtime": {"type": "string"},
        "sha256": _SHA256,
    },
}

_CONFIG_LIST_FILES_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "files"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "files": {"type": "array", "items": _CONFIG_FILE_ENTRY},
    },
}

_SERVICE_ITEM = {
    "type": "object",
    "additionalProperties": False,
    "required": ["unit"],
    "properties": {
        "unit": {"type": "string"},
        "active_state": {"type": "string"},
        "sub_state": {"type": "string"},
        "unit_file_state": {"type": "string"},
        "load_state": {"type": "string"},
    },
}

_SERVICE_STATUS_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "services"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "services": {"type": "array", "items": _SERVICE_ITEM},
    },
}

_VERSION_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "version"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "version": {"type": "string"},
    },
}

_SHARE_ITEM = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name"],
    "properties": {
        "name": {"type": "string"},
        "type": {"type": "string"},
        "path": {"type": "string"},
        "comment": {"type": "string"},
        "options": {"type": "object"},
    },
}

_LIST_SHARES_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "shares"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "shares": {"type": "array", "items": _SHARE_ITEM},
    },
}

# Raw `smbstatus --json` shape, per Samba source3/utils/status.c +
# status_json.c. Each section is added with `add_section_to_json()`, which calls
# `json_new_object()` -- so sections are OBJECTS keyed by id, NOT arrays. The
# section keys are `sessions`, `tcons`, `open_files`, `byte_range_locks`, and
# `notifies`; there is no top-level `locks` key (`--locks` is a CLI flag name).
# Which sections appear depends on the flags smbstatus was invoked with, so
# nothing is required here. `version` and `smb_conf` are added at the root.
# additionalProperties stays open so a newer Samba adding a section does not
# fail validation of an otherwise-good read.
_SMBSTATUS_SECTION = {"type": "object", "additionalProperties": {"type": "object"}}

_STATUS_REPORT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "smb_conf": {"type": "string"},
        "sessions": _SMBSTATUS_SECTION,
        "tcons": _SMBSTATUS_SECTION,
        "open_files": _SMBSTATUS_SECTION,
        "byte_range_locks": _SMBSTATUS_SECTION,
        "notifies": _SMBSTATUS_SECTION,
    },
}

# The handler's own envelope. It flattens each raw smbstatus section object into
# a list of its values, so downstream consumers (netbox-fileserver observed
# state) get stable arrays rather than id-keyed maps.
_STATUS_REPORT_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "sessions", "tcons", "open_files"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "samba_version": {"type": "string"},
        "sessions": {"type": "array", "items": {"type": "object"}},
        "tcons": {"type": "array", "items": {"type": "object"}},
        "open_files": {"type": "array", "items": {"type": "object"}},
        "byte_range_locks": {"type": "array", "items": {"type": "object"}},
    },
}

_DOMAIN_INFO_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "netbios_domain": {"type": "string"},
        "dns_domain": {"type": "string"},
        "domain_sid": {"type": "string"},
        "server_site": {"type": "string"},
        "server_role": {"type": "string"},
        "forest_function_level": {"type": "string"},
        "domain_function_level": {"type": "string"},
        "dc_function_level": {"type": "string"},
    },
}

_USER_ITEM = {
    "type": "object",
    "additionalProperties": False,
    "required": ["username"],
    "properties": {
        "username": {"type": "string"},
        "full_name": {"type": "string"},
        "uid": {"type": ["integer", "null"]},
        "sid": {"type": "string"},
        "disabled": {"type": ["boolean", "null"]},
        "locked": {"type": ["boolean", "null"]},
        "source": {"type": "string"},
    },
}

_USER_LIST_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "users"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "users": {"type": "array", "items": _USER_ITEM},
    },
}

_GROUP_ITEM = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name"],
    "properties": {
        "name": {"type": "string"},
        "sid": {"type": "string"},
        "members": {"type": "array", "items": {"type": "string"}},
    },
}

_GROUP_LIST_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "groups"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "groups": {"type": "array", "items": _GROUP_ITEM},
    },
}

_SHARE_ACL_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "share_name"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "share_name": {"type": "string"},
        "acl": {"type": "array", "items": {"type": "object"}},
        "sddl": {"type": "string"},
        "raw": {"type": "string"},
    },
}

_PROCEDURES = (
    {
        "name": "service.samba.1.config_read",
        "handler_id": "service.samba_1.config_read",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read /etc/samba/smb.conf and return its content and sha256.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _CONFIG_READ_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.config_test",
        "handler_id": "service.samba_1.config_test",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Validate the effective Samba configuration with testparm -s.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _CONFIG_TEST_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.config_list_files",
        "handler_id": "service.samba_1.config_list_files",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Enumerate /etc/samba/**/*.conf with size, mtime, and sha256.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _CONFIG_LIST_FILES_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.include_file_read",
        "handler_id": "service.samba_1.include_file_read",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read one .conf include file confined to /etc/samba/.",
        "params_schema": _INCLUDE_FILE_PARAMS_SCHEMA,
        "result_schema": _CONFIG_READ_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.service_status",
        "handler_id": "service.samba_1.service_status",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read systemd state for smbd, nmbd, winbind, and samba-ad-dc.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _SERVICE_STATUS_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.version",
        "handler_id": "service.samba_1.version",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read Samba server version with smbd -V.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _VERSION_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.list_shares",
        "handler_id": "service.samba_1.list_shares",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "List effective Samba share definitions from testparm output.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _LIST_SHARES_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.status_report",
        "handler_id": "service.samba_1.status_report",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read smbstatus --json sessions, tree connects, and locks.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _STATUS_REPORT_RESULT_SCHEMA,
        "output_parser": "json",
        "output_schema": _STATUS_REPORT_OUTPUT_SCHEMA,
    },
    {
        "name": "service.samba.1.domain_info",
        "handler_id": "service.samba_1.domain_info",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Read Samba domain metadata and functional levels.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _DOMAIN_INFO_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.user_list",
        "handler_id": "service.samba_1.user_list",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "List Samba users without password or hash material.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _USER_LIST_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.group_list",
        "handler_id": "service.samba_1.group_list",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 90,
        "approval_required": False,
        "description": "List Samba groups and group members.",
        "params_schema": _BASE_PARAMS_SCHEMA,
        "result_schema": _GROUP_LIST_RESULT_SCHEMA,
    },
    {
        "name": "service.samba.1.share_acl_read",
        "handler_id": "service.samba_1.share_acl_read",
        "version": 1,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read sharesec --view ACL data for one safe Samba share name.",
        "params_schema": _SHARE_ACL_PARAMS_SCHEMA,
        "result_schema": _SHARE_ACL_RESULT_SCHEMA,
    },
)


def _seed_samba_read_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in _PROCEDURES:
        defaults = {key: value for key, value in procedure.items() if key != "name"}
        RPCProcedure.objects.update_or_create(
            name=procedure["name"],
            defaults=defaults,
        )


def _remove_samba_read_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[procedure["name"] for procedure in _PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0048_seed_passbolt_migration_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_samba_read_procedures,
            reverse_code=_remove_samba_read_procedures,
        ),
    ]
