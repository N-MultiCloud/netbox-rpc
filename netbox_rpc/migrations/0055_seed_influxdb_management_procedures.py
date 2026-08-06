"""Seed the typed InfluxDB 2/3 guest-management procedure catalog.

The execution backend owns family-specific paths and orchestration.  NetBox
persists only bounded, schema-shaped parameters; command bodies are delivered
to the backend as stdin and never become arbitrary command text.
"""

from django.db import migrations


_TARGET_MODELS = ["virtualization.virtualmachine", "dcim.device"]
_FAMILIES = ["oss2", "core3"]
_FILE_SCOPES = ["managed", "plugins"]
_SERVICE_ACTIONS = ["start", "stop", "restart", "enable", "disable"]
_MAX_CONTENT = 1024 * 1024
_SSH_PROPERTIES = {
    "rpc_ssh_credential_pk": {"type": "integer", "minimum": 1},
    "rpc_ssh_host": {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "pattern": r"^[^\s\x00-\x1f]{1,255}$",
    },
    "rpc_ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "rpc_ssh_known_hosts_entry": {"type": "string", "maxLength": 16384},
    "rpc_ssh_strict_host_key_checking": {"type": "boolean"},
}
_RELATIVE_PATH_PATTERN = (
    r"^(?!.*(?:^|/)\.\.(?:/|$))(?!.*(?:^|/)(?:\.env|[^/]*(?:secret|token|password|private)[^/]*)(?:/|$))"
    r"[A-Za-z0-9][A-Za-z0-9._@+-]*(?:/[A-Za-z0-9][A-Za-z0-9._@+-]*){0,7}"
    r"\.(?:conf|toml|json|yaml|yml|py|txt|crt|pem)(?![\s\S])"
)
_SNAPSHOT_ID_PATTERN = r"^[0-9]{8}T[0-9]{12}Z(?![\s\S])"
_SHA256 = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
_SECRET_CONTENT_PATTERNS = (
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    (
        r"(?im)(?:^|[,{]\s*|-\s+)[\"']?[A-Za-z0-9_.-]*"
        r"(?:token|password|passphrase|secret|authorization|api[-_]?key|access[-_]?key|"
        r"private[-_]?key|credential)"
        r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?(?!/)[^\s\"']+"
    ),
    r"(?im)\b(?:authorization|bearer)\s*[:=]\s*[\"']?[^\s\"']+",
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    r"\x00",
)


def _params(required=(), properties=None):
    return {
        "type": "object",
        "required": list(required),
        "additionalProperties": False,
        "properties": {**(properties or {}), **_SSH_PROPERTIES},
    }


_FAMILY = {"type": "string", "enum": _FAMILIES}
_SCOPE = {"type": "string", "enum": _FILE_SCOPES}
_RELATIVE_PATH = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "pattern": _RELATIVE_PATH_PATTERN,
}
_CONTENT = {
    "type": "string",
    "minLength": 1,
    "maxLength": _MAX_CONTENT,
    "pattern": r"\S",
    "allOf": [{"not": {"pattern": pattern}} for pattern in _SECRET_CONTENT_PATTERNS],
    "description": "Non-secret content; transported to the execution backend via stdin.",
}
_FAMILY_PARAMS = _params(("family",), {"family": _FAMILY})
_FILE_PARAMS = _params(
    ("family", "scope", "relative_path"),
    {"family": _FAMILY, "scope": _SCOPE, "relative_path": _RELATIVE_PATH},
)

_COMMON_RESULT = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
}


def _result(required=(), properties=None):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", *required],
        "additionalProperties": False,
        "properties": {**_COMMON_RESULT, **(properties or {})},
    }


_INSTALLATION = {
    "type": "object",
    "additionalProperties": False,
    "required": ["family", "installed", "version", "binary", "unit", "config_path"],
    "properties": {
        "family": _FAMILY,
        "installed": {"type": "boolean"},
        "version": {"type": "string"},
        "binary": {"type": "string"},
        "unit": {"type": "string"},
        "config_path": {"type": "string"},
    },
}
_FILE_ENTRY = {
    "type": "object",
    "additionalProperties": False,
    "required": ["scope", "path", "size", "mtime", "sha256"],
    "properties": {
        "scope": {"type": "string"},
        "path": {"type": "string"},
        "size": {"type": "integer", "minimum": 0},
        "mtime": {"type": "string"},
        "sha256": _SHA256,
    },
}
_SNAPSHOT_ENTRY = {
    "type": "object",
    "additionalProperties": False,
    "required": ["snapshot_id", "path", "size", "mtime", "sha256"],
    "properties": {
        "snapshot_id": {"type": "string"},
        "path": {"type": "string"},
        "size": {"type": "integer", "minimum": 0},
        "mtime": {"type": "string"},
        "sha256": _SHA256,
    },
}
_SERVICE_PROPERTIES = {
    "family": _FAMILY,
    "unit": {"type": "string"},
    "load_state": {"type": "string"},
    "active_state": {"type": "string"},
    "sub_state": {"type": "string"},
    "unit_file_state": {"type": "string"},
}
_MUTATION_PROPERTIES = {
    "family": _FAMILY,
    "config_path": {"type": "string"},
    "stage": {
        "type": "string",
        "enum": ["validate", "snapshot", "activate", "restart", "health", "rollback"],
    },
    "validated": {"type": "boolean"},
    "snapshot_id": {"type": "string"},
    "config_sha256": _SHA256,
    "activated": {"type": "boolean"},
    "restarted": {"type": "boolean"},
    "healthy": {"type": "boolean"},
    "rolled_back": {"type": "boolean"},
    "restored": {"type": "boolean"},
    "error": {"type": "string"},
}

_PROCEDURES = (
    {
        "name": "service.influxdb.1.inspect",
        "handler_id": "service.influxdb_1.inspect",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Detect installed InfluxDB OSS 2 and Core 3 packages and paths.",
        "params_schema": _params(),
        "result_schema": _result(
            ("installations",),
            {"installations": {"type": "array", "items": _INSTALLATION, "maxItems": 2}},
        ),
    },
    {
        "name": "service.influxdb.1.config_read",
        "handler_id": "service.influxdb_1.config_read",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read and redact the active family-specific InfluxDB TOML config.",
        "params_schema": _FAMILY_PARAMS,
        "result_schema": _result(
            ("family", "path", "content", "sha256", "redacted"),
            {
                "family": _FAMILY,
                "path": {"type": "string"},
                "content": {"type": "string"},
                "sha256": _SHA256,
                "redacted": {"type": "boolean"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.files_list",
        "handler_id": "service.influxdb_1.files_list",
        "effect": "read",
        "timeout_seconds": 45,
        "approval_required": False,
        "description": "List confined managed/plugin files and config snapshots.",
        "params_schema": _FAMILY_PARAMS,
        "result_schema": _result(
            ("family", "files", "snapshots"),
            {
                "family": _FAMILY,
                "files": {"type": "array", "items": _FILE_ENTRY, "maxItems": 512},
                "snapshots": {
                    "type": "array",
                    "items": _SNAPSHOT_ENTRY,
                    "maxItems": 128,
                },
            },
        ),
    },
    {
        "name": "service.influxdb.1.file_read",
        "handler_id": "service.influxdb_1.file_read",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read one confined non-secret managed or Core plugin file.",
        "params_schema": _FILE_PARAMS,
        "result_schema": _result(
            ("family", "scope", "path", "content", "sha256", "redacted"),
            {
                "family": _FAMILY,
                "scope": _SCOPE,
                "path": {"type": "string"},
                "content": {"type": "string"},
                "sha256": _SHA256,
                "redacted": {"type": "boolean"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.service_status",
        "handler_id": "service.influxdb_1.service_status",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read family-specific InfluxDB systemd state.",
        "params_schema": _FAMILY_PARAMS,
        "result_schema": _result(
            (
                "family",
                "unit",
                "load_state",
                "active_state",
                "sub_state",
                "unit_file_state",
            ),
            _SERVICE_PROPERTIES,
        ),
    },
    {
        "name": "service.influxdb.1.health",
        "handler_id": "service.influxdb_1.health",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Probe the product-local OSS /health or Core /ready endpoint.",
        "params_schema": _FAMILY_PARAMS,
        "result_schema": _result(
            ("family", "url", "status_code", "status", "message", "version"),
            {
                "family": _FAMILY,
                "url": {"type": "string"},
                "status_code": {"type": "integer", "minimum": 0, "maximum": 599},
                "status": {"type": "string"},
                "message": {"type": "string"},
                "version": {"type": "string"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.journal",
        "handler_id": "service.influxdb_1.journal",
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read bounded, redacted family-specific systemd journal output.",
        "params_schema": _params(
            ("family",),
            {
                "family": _FAMILY,
                "lines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 100,
                },
            },
        ),
        "result_schema": _result(
            ("family", "unit", "lines", "content", "redacted"),
            {
                "family": _FAMILY,
                "unit": {"type": "string"},
                "lines": {"type": "integer"},
                "content": {"type": "string"},
                "redacted": {"type": "boolean"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.config_deploy",
        "handler_id": "service.influxdb_1.config_deploy",
        "effect": "write",
        "timeout_seconds": 120,
        "approval_required": True,
        "description": "Validate, snapshot, atomically deploy, restart, health-check, and roll back InfluxDB config.",
        "params_schema": _params(
            ("family", "config_content"),
            {"family": _FAMILY, "config_content": _CONTENT},
        ),
        "result_schema": _result(
            (
                "family",
                "config_path",
                "stage",
                "validated",
                "activated",
                "restarted",
                "healthy",
                "rolled_back",
            ),
            _MUTATION_PROPERTIES,
        ),
    },
    {
        "name": "service.influxdb.1.config_rollback",
        "handler_id": "service.influxdb_1.config_rollback",
        "effect": "destructive",
        "timeout_seconds": 120,
        "approval_required": True,
        "description": "Restore a backend-issued InfluxDB config snapshot with restart and health verification.",
        "params_schema": _params(
            ("family", "snapshot_id"),
            {
                "family": _FAMILY,
                "snapshot_id": {
                    "type": "string",
                    "minLength": 22,
                    "maxLength": 22,
                    "pattern": _SNAPSHOT_ID_PATTERN,
                },
            },
        ),
        "result_schema": _result(
            (
                "family",
                "config_path",
                "stage",
                "validated",
                "activated",
                "restarted",
                "healthy",
                "rolled_back",
                "restored",
            ),
            _MUTATION_PROPERTIES,
        ),
    },
    {
        "name": "service.influxdb.1.file_write",
        "handler_id": "service.influxdb_1.file_write",
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Atomically write one confined non-secret managed or Core plugin file.",
        "params_schema": _params(
            ("family", "scope", "relative_path", "content"),
            {
                "family": _FAMILY,
                "scope": _SCOPE,
                "relative_path": _RELATIVE_PATH,
                "content": _CONTENT,
                "mode": {"type": "string", "enum": ["0640", "0644"], "default": "0640"},
            },
        ),
        "result_schema": _result(
            ("family", "scope", "path", "sha256", "written"),
            {
                "family": _FAMILY,
                "scope": _SCOPE,
                "path": {"type": "string"},
                "sha256": _SHA256,
                "written": {"type": "boolean"},
                "snapshot_id": {"type": "string"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.file_delete",
        "handler_id": "service.influxdb_1.file_delete",
        "effect": "destructive",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Delete one confined non-secret managed or Core plugin file after snapshotting it.",
        "params_schema": _FILE_PARAMS,
        "result_schema": _result(
            ("family", "scope", "path", "deleted"),
            {
                "family": _FAMILY,
                "scope": _SCOPE,
                "path": {"type": "string"},
                "deleted": {"type": "boolean"},
                "snapshot_id": {"type": "string"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.service_control",
        "handler_id": "service.influxdb_1.service_control",
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Run an enum-constrained action on the family-specific InfluxDB systemd unit.",
        "params_schema": _params(
            ("family", "action"),
            {"family": _FAMILY, "action": {"type": "string", "enum": _SERVICE_ACTIONS}},
        ),
        "result_schema": _result(
            (
                "family",
                "unit",
                "action",
                "load_state",
                "active_state",
                "sub_state",
                "unit_file_state",
            ),
            {
                **_SERVICE_PROPERTIES,
                "action": {"type": "string", "enum": _SERVICE_ACTIONS},
            },
        ),
    },
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
    }


_COMMANDS = {
    procedure["handler_id"]: _command(
        procedure["handler_id"]
        .replace("service.influxdb_1.", "influxdb-")
        .replace("_", "-"),
        procedure["description"],
    )
    for procedure in _PROCEDURES
}


def _seed(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
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
            defaults=_COMMANDS[row["handler_id"]],
        )


def _remove(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[row["name"] for row in _PROCEDURES]).delete()


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0054_merge_approval_and_samba")]
    operations = [migrations.RunPython(_seed, reverse_code=_remove)]
