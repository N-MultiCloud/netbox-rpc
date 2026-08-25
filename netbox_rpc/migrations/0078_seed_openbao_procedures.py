"""Seed the callable OpenBao 1 procedure catalog and representative commands.

Seven backend handlers remain deliberately absent until netbox-rpc-backend #80
closes their durability, disclosure, filesystem-race, and replay gaps.  The 23
rows below are the complete callable subset reviewed for issue #252.

OpenBao SSH credentials are resolved by the execution backend from the audited
NetBox target identity.  Unlike the older InfluxDB catalog, these closed input
schemas intentionally expose no caller-supplied ``rpc_ssh_*`` override.
"""

from django.db import migrations


_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]
_HANDLER_IDS = (
    "service.openbao_1.inspect",
    "service.openbao_1.seal_status",
    "service.openbao_1.health",
    "service.openbao_1.policies_list",
    "service.openbao_1.auth_list",
    "service.openbao_1.secrets_list",
    "service.openbao_1.audit_list",
    "service.openbao_1.raft_list_peers",
    "service.openbao_1.raft_autopilot_state",
    "service.openbao_1.snapshots_list",
    "service.openbao_1.policy_write",
    "service.openbao_1.auth_enable",
    "service.openbao_1.secrets_enable",
    "service.openbao_1.audit_enable",
    "service.openbao_1.snapshot_create",
    "service.openbao_1.service_action",
    "service.openbao_1.seal",
    "service.openbao_1.step_down",
    "service.openbao_1.raft_remove_peer",
    "service.openbao_1.policy_delete",
    "service.openbao_1.auth_disable",
    "service.openbao_1.secrets_disable",
    "service.openbao_1.audit_disable",
)
_MAX_CONTENT = 1024 * 1024
_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?![\s\S])"
_MOUNT_PATH_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
    r"(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,63})*/?(?![\s\S])"
)
_NON_EMPTY_NON_NUL_PATTERN = r"^(?=[\s\S]*\S)(?![\s\S]*\x00)[\s\S]*(?![\s\S])"
_SECRET_CONTENT_PATTERNS = (
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    (
        r"(?im)(?:^|[,{]\s*|-\s+)[\"']?"
        r"(?!(?:key_id|key_label|key_name|tls_key_file|token_label)[\"']?\s*[:=])"
        r"[A-Za-z0-9_.-]*"
        r"(?:token|password|passphrase|secret|authorization|api[-_]?key|"
        r"access[-_]?key|private[-_]?key|credential)"
        r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?(?!/)[^\s\"']+"
    ),
    (
        r"(?im)(?:^|[,{]\s*|-\s+)[\"']?"
        r"(?:auth_info|connection_string|connection_url|key|keys|"
        r"(?:access|account|api|client|current|previous|private|root|shared)"
        r"[_.-]+keys?)[\"']?\s*[:=]\s*[\"']?[^\s\"']+"
    ),
    r"(?im)\b(?:authorization|bearer)\s*[:=]\s*[\"']?[^\s\"']+",
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    r"(?i)\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{8,}\b",
    (
        r"(?<![A-Za-z0-9+/_=-])"
        r"(?=[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_=-]))"
        r"(?=[A-Za-z0-9+/_-]*[G-Zg-z+/_-])"
        r"[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_=-])"
    ),
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}(?![0-9A-Fa-f])",
    (
        r"(?im)^\s*(?:unseal\s+key(?:\s+\d+)?|initial\s+root\s+token|"
        r"root\s+token)\s*[=:]\s*.*$"
    ),
)


def _params(required=(), properties=None):
    # This is the primary admission boundary: RPCExecution.params is persisted
    # before the backend can perform its own validation.  OpenBao therefore
    # exposes only operation fields and never the shared rpc_ssh_* overrides.
    return {
        "type": "object",
        "required": list(required),
        "additionalProperties": False,
        "properties": dict(properties or {}),
    }


_NAME = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": _NAME_PATTERN,
}
_MOUNT_PATH = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": _MOUNT_PATH_PATTERN,
}
_OPTIONAL_MOUNT_PATH = {**_MOUNT_PATH, "type": ["string", "null"]}
_OPTIONAL_NAME = {**_NAME, "type": ["string", "null"]}
_CONTENT = {
    "type": "string",
    "minLength": 1,
    "maxLength": _MAX_CONTENT,
    "pattern": _NON_EMPTY_NON_NUL_PATTERN,
    "allOf": [{"not": {"pattern": pattern}} for pattern in _SECRET_CONTENT_PATTERNS],
    "description": "Non-secret content delivered to the backend through stdin.",
}

_TEXT = {"type": "string"}
_ERROR = {"type": "string", "maxLength": 1000}
_SHA256 = {"type": "string", "pattern": r"^[a-f0-9]{64}(?![\s\S])"}
_SERVICE = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "unit",
        "load_state",
        "active_state",
        "sub_state",
        "unit_file_state",
    ],
    "properties": {
        "unit": _TEXT,
        "load_state": _TEXT,
        "active_state": _TEXT,
        "sub_state": _TEXT,
        "unit_file_state": _TEXT,
    },
}
_LIST_PAYLOAD = {
    "oneOf": [
        {"type": "array", "maxItems": 512},
        {"type": "object"},
    ]
}
_SNAPSHOT = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name", "size", "mtime"],
    "properties": {
        "name": _TEXT,
        "size": {"type": "integer", "minimum": 0},
        "mtime": _TEXT,
    },
}


def _result(handler_id, required=(), properties=None):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", *required],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"const": handler_id},
            "target": _TEXT,
            **(properties or {}),
        },
    }


def _row(
    operation,
    *,
    effect,
    approval_required,
    timeout_seconds,
    description,
    params_schema,
    result_schema,
):
    handler_id = f"service.openbao_1.{operation}"
    return {
        "name": f"service.openbao.1.{operation}",
        "handler_id": handler_id,
        "effect": effect,
        "timeout_seconds": timeout_seconds,
        "approval_required": approval_required,
        "description": description,
        "params_schema": params_schema,
        "result_schema": _result(handler_id, **result_schema),
    }


_TARGET_ONLY = _params()
_SECRETS_ENABLE_PARAMS = _params(
    ("engine_type",),
    {
        "engine_type": {
            "type": "string",
            "enum": ["database", "kv", "pki", "ssh", "transit", "totp"],
        },
        "mount_path": _OPTIONAL_MOUNT_PATH,
        "kv_version": {"enum": [1, 2, None]},
    },
)
_SECRETS_ENABLE_PARAMS["allOf"] = [
    {
        "if": {
            "required": ["kv_version"],
            "properties": {"kv_version": {"type": "integer"}},
        },
        "then": {"properties": {"engine_type": {"const": "kv"}}},
    }
]

_PROCEDURES = (
    _row(
        "inspect",
        effect="read",
        approval_required=False,
        timeout_seconds=30,
        description="Inspect the installed OpenBao package, binary, unit, and fixed paths.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("installation",),
            "properties": {
                "installation": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "installed",
                        "version",
                        "binary",
                        "unit",
                        "config_path",
                        "snapshot_root",
                    ],
                    "properties": {
                        "installed": {"type": "boolean"},
                        "version": _TEXT,
                        "binary": _TEXT,
                        "unit": _TEXT,
                        "config_path": _TEXT,
                        "snapshot_root": _TEXT,
                    },
                }
            },
        },
    ),
    _row(
        "seal_status",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="Read bounded OpenBao initialization, seal, storage, and HA status.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": (
                "sealed",
                "initialized",
                "version",
                "storage_type",
                "ha_enabled",
                "progress",
                "threshold",
                "error",
            ),
            "properties": {
                "sealed": {"type": "boolean"},
                "initialized": {"type": "boolean"},
                "version": _TEXT,
                "storage_type": _TEXT,
                "ha_enabled": {"type": "boolean"},
                "progress": {"type": "integer", "minimum": 0},
                "threshold": {"type": "integer", "minimum": 0},
                "error": _ERROR,
            },
        },
    ),
    _row(
        "health",
        effect="read",
        approval_required=False,
        timeout_seconds=60,
        description="Probe the OpenBao systemd unit and validate its bounded status response.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("service", "sealed", "initialized", "error"),
            "properties": {
                "service": _SERVICE,
                "sealed": {"type": "boolean"},
                "initialized": {"type": "boolean"},
                "error": _ERROR,
            },
        },
    ),
    _row(
        "policies_list",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="List OpenBao policy names without returning policy bodies.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("policies", "error"),
            "properties": {"policies": _LIST_PAYLOAD, "error": _ERROR},
        },
    ),
    _row(
        "auth_list",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="List configured OpenBao authentication methods.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("auth_methods", "error"),
            "properties": {"auth_methods": _LIST_PAYLOAD, "error": _ERROR},
        },
    ),
    _row(
        "secrets_list",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="List configured OpenBao secrets engines.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("secret_engines", "error"),
            "properties": {"secret_engines": _LIST_PAYLOAD, "error": _ERROR},
        },
    ),
    _row(
        "audit_list",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="List configured OpenBao audit devices.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("audit_devices", "error"),
            "properties": {"audit_devices": _LIST_PAYLOAD, "error": _ERROR},
        },
    ),
    _row(
        "raft_list_peers",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="List OpenBao integrated-storage raft peers.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("peers", "error"),
            "properties": {"peers": _LIST_PAYLOAD, "error": _ERROR},
        },
    ),
    _row(
        "raft_autopilot_state",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="Read the OpenBao raft autopilot state.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("autopilot", "error"),
            "properties": {"autopilot": _LIST_PAYLOAD, "error": _ERROR},
        },
    ),
    _row(
        "snapshots_list",
        effect="read",
        approval_required=False,
        timeout_seconds=45,
        description="List bounded metadata for host-side OpenBao raft snapshots.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("snapshot_root", "snapshots", "error"),
            "properties": {
                "snapshot_root": _TEXT,
                "snapshots": {
                    "type": "array",
                    "items": _SNAPSHOT,
                    "maxItems": 256,
                },
                "error": _ERROR,
            },
        },
    ),
    _row(
        "policy_write",
        effect="write",
        approval_required=False,
        timeout_seconds=60,
        description="Write one named non-secret OpenBao policy through backend stdin.",
        params_schema=_params(
            ("policy_name", "policy_content"),
            {"policy_name": _NAME, "policy_content": _CONTENT},
        ),
        result_schema={
            "required": ("policy_name", "error"),
            "properties": {"policy_name": _TEXT, "error": _ERROR},
        },
    ),
    _row(
        "auth_enable",
        effect="write",
        approval_required=False,
        timeout_seconds=60,
        description="Enable an enum-constrained OpenBao authentication method.",
        params_schema=_params(
            ("auth_type",),
            {
                "auth_type": {
                    "type": "string",
                    "enum": [
                        "approle",
                        "cert",
                        "jwt",
                        "kubernetes",
                        "ldap",
                        "oidc",
                        "userpass",
                    ],
                },
                "mount_path": _OPTIONAL_MOUNT_PATH,
            },
        ),
        result_schema={
            "required": ("auth_type", "mount_path", "error"),
            "properties": {
                "auth_type": _TEXT,
                "mount_path": _TEXT,
                "error": _ERROR,
            },
        },
    ),
    _row(
        "secrets_enable",
        effect="write",
        approval_required=False,
        timeout_seconds=60,
        description="Enable an enum-constrained OpenBao secrets engine.",
        params_schema=_SECRETS_ENABLE_PARAMS,
        result_schema={
            "required": ("engine_type", "mount_path", "kv_version", "error"),
            "properties": {
                "engine_type": _TEXT,
                "mount_path": _TEXT,
                "kv_version": {"type": ["integer", "null"], "enum": [1, 2, None]},
                "error": _ERROR,
            },
        },
    ),
    _row(
        "audit_enable",
        effect="write",
        approval_required=False,
        timeout_seconds=60,
        description="Enable an enum-constrained OpenBao audit device.",
        params_schema=_params(
            ("audit_type",),
            {
                "audit_type": {"type": "string", "enum": ["file", "syslog"]},
                "mount_path": _OPTIONAL_MOUNT_PATH,
            },
        ),
        result_schema={
            "required": ("audit_type", "mount_path", "error"),
            "properties": {
                "audit_type": _TEXT,
                "mount_path": _TEXT,
                "error": _ERROR,
            },
        },
    ),
    _row(
        "snapshot_create",
        effect="write",
        approval_required=False,
        timeout_seconds=240,
        description="Create a host-side OpenBao raft snapshot with a confined name.",
        params_schema=_params((), {"snapshot_name": _OPTIONAL_NAME}),
        result_schema={
            "required": ("snapshot_name", "path", "error"),
            "properties": {
                "snapshot_name": _TEXT,
                "path": _TEXT,
                "error": _ERROR,
            },
        },
    ),
    _row(
        "service_action",
        effect="write",
        approval_required=False,
        timeout_seconds=90,
        description="Run an enum-constrained action on openbao.service and read final state.",
        params_schema=_params(
            ("action",),
            {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "restart", "reload", "enable", "disable"],
                }
            },
        ),
        result_schema={
            "required": ("action", "service", "error"),
            "properties": {"action": _TEXT, "service": _SERVICE, "error": _ERROR},
        },
    ),
    _row(
        "seal",
        effect="destructive",
        approval_required=True,
        timeout_seconds=60,
        description="Seal the OpenBao instance; clients lose secret access until unsealed.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("sealed", "error"),
            "properties": {"sealed": {"type": "boolean"}, "error": _ERROR},
        },
    ),
    _row(
        "step_down",
        effect="destructive",
        approval_required=True,
        timeout_seconds=60,
        description="Force the active OpenBao raft leader to step down.",
        params_schema=_TARGET_ONLY,
        result_schema={
            "required": ("error",),
            "properties": {"error": _ERROR},
        },
    ),
    _row(
        "raft_remove_peer",
        effect="destructive",
        approval_required=True,
        timeout_seconds=60,
        description="Remove one named peer from the OpenBao raft cluster.",
        params_schema=_params(("peer_id",), {"peer_id": _NAME}),
        result_schema={
            "required": ("peer_id", "error"),
            "properties": {"peer_id": _TEXT, "error": _ERROR},
        },
    ),
    _row(
        "policy_delete",
        effect="destructive",
        approval_required=True,
        timeout_seconds=60,
        description="Delete one named OpenBao policy.",
        params_schema=_params(("policy_name",), {"policy_name": _NAME}),
        result_schema={
            "required": ("policy_name", "error"),
            "properties": {"policy_name": _TEXT, "error": _ERROR},
        },
    ),
    _row(
        "auth_disable",
        effect="destructive",
        approval_required=True,
        timeout_seconds=60,
        description="Disable one mounted OpenBao authentication method.",
        params_schema=_params(("mount_path",), {"mount_path": _MOUNT_PATH}),
        result_schema={
            "required": ("mount_path", "error"),
            "properties": {"mount_path": _TEXT, "error": _ERROR},
        },
    ),
    _row(
        "secrets_disable",
        effect="destructive",
        approval_required=True,
        timeout_seconds=60,
        description="Disable one mounted OpenBao secrets engine and destroy its data.",
        params_schema=_params(("mount_path",), {"mount_path": _MOUNT_PATH}),
        result_schema={
            "required": ("mount_path", "error"),
            "properties": {"mount_path": _TEXT, "error": _ERROR},
        },
    ),
    _row(
        "audit_disable",
        effect="destructive",
        approval_required=True,
        timeout_seconds=60,
        description="Disable one mounted OpenBao audit device.",
        params_schema=_params(("mount_path",), {"mount_path": _MOUNT_PATH}),
        result_schema={
            "required": ("mount_path", "error"),
            "properties": {"mount_path": _TEXT, "error": _ERROR},
        },
    ),
)


def _command(handler_id, description):
    operation = handler_id.removeprefix("service.openbao_1.").replace("_", "-")
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", f"openbao-{operation}"],
        "description": description,
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
    }


def _seed(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    if {row["handler_id"] for row in _PROCEDURES} != set(_HANDLER_IDS):
        raise RuntimeError("OpenBao seed handler inventory is inconsistent")
    for row in _PROCEDURES:
        defaults = {
            **{key: value for key, value in row.items() if key != "name"},
            "version": 1,
            "enabled": True,
            "target_models": _TARGET_MODELS,
        }
        procedure, _ = RPCProcedure.objects.update_or_create(
            name=row["name"], defaults=defaults
        )
        RPCProcedureCommand.objects.update_or_create(
            procedure=procedure,
            sequence=1,
            defaults=_command(row["handler_id"], row["description"]),
        )


def _remove(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[row["name"] for row in _PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0077_seed_openbao_service_allowlist")]
    operations = [migrations.RunPython(_seed, reverse_code=_remove)]
