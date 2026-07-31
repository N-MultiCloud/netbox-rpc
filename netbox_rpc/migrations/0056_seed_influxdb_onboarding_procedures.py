"""Seed typed InfluxDB bootstrap, database, and token procedures.

These procedures complete first-use administration without the InfluxDB UI or
interactive SSH.  Plaintext credentials are generated/resolved only by the
execution backend and are represented in NetBox by ``nms-secret:`` references.
"""

from django.db import migrations


_TARGET_MODELS = ["virtualization.virtualmachine", "dcim.device"]
_FAMILY = {"type": "string", "enum": ["oss2", "core3"]}
_NAME = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$",
}
_SECRET_NAME = {
    "type": "string",
    "minLength": 1,
    "maxLength": 160,
    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,159}$",
}
_SECRET_REF = {
    "type": "string",
    "pattern": (
        r"^nms-secret:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    ),
}
_TENANT_ID = {"type": "integer", "minimum": 1}
_RETENTION_SECONDS = {
    "type": "integer",
    "minimum": 3600,
    "maximum": 315360000,
    "description": "Optional retention in seconds; omit for infinite retention.",
}
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
_COMMON_RESULT = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
    "family": _FAMILY,
}


def _params(required=(), properties=None):
    return {
        "type": "object",
        "required": list(required),
        "additionalProperties": False,
        "properties": {**(properties or {}), **_SSH_PROPERTIES},
    }


def _result(required=(), properties=None):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", "family", *required],
        "additionalProperties": False,
        "properties": {**_COMMON_RESULT, **(properties or {})},
    }


_PROCEDURES = (
    {
        "name": "service.influxdb.1.bootstrap",
        "handler_id": "service.influxdb_1.bootstrap",
        "effect": "write",
        "timeout_seconds": 120,
        "approval_required": True,
        "description": (
            "Initialize a fresh OSS 2 or Core 3 instance and store generated credentials "
            "as netbox-nms secret references without returning plaintext."
        ),
        "params_schema": _params(
            ("family", "secret_name_prefix"),
            {
                "family": _FAMILY,
                "secret_name_prefix": _SECRET_NAME,
                "tenant_id": _TENANT_ID,
                "username": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$",
                },
                "organization": _NAME,
                "database": _NAME,
                "retention_seconds": _RETENTION_SECONDS,
            },
        ),
        "result_schema": _result(
            (
                "initialized",
                "organization",
                "database",
            ),
            {
                "initialized": {"type": "boolean"},
                "admin_password_secret_ref": {"type": "string"},
                "operator_token_secret_ref": _SECRET_REF,
                "organization": {"type": "string"},
                "database": {"type": "string"},
                "error": {"type": "string"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.database_create",
        "handler_id": "service.influxdb_1.database_create",
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": True,
        "description": (
            "Create an OSS 2 bucket or Core 3 database through its loopback API using an "
            "administrative nms-secret reference."
        ),
        "params_schema": _params(
            ("family", "admin_secret_ref", "database"),
            {
                "family": _FAMILY,
                "admin_secret_ref": _SECRET_REF,
                "database": _NAME,
                "organization": _NAME,
                "retention_seconds": _RETENTION_SECONDS,
            },
        ),
        "result_schema": _result(
            ("created", "database", "organization", "retention_seconds"),
            {
                "created": {"type": "boolean"},
                "database": _NAME,
                "organization": {"type": "string"},
                "retention_seconds": {"type": "integer", "minimum": 0},
                "resource_id": {"type": "string"},
                "error": {"type": "string"},
            },
        ),
    },
    {
        "name": "service.influxdb.1.token_create",
        "handler_id": "service.influxdb_1.token_create",
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": True,
        "description": (
            "Create an OSS 2 database reader/writer token or Core 3 named admin token and "
            "store its one-time plaintext in netbox-nms."
        ),
        "params_schema": _params(
            ("family", "admin_secret_ref", "token_name", "access"),
            {
                "family": _FAMILY,
                "admin_secret_ref": _SECRET_REF,
                "token_name": _SECRET_NAME,
                "access": {"type": "string", "enum": ["query", "writer", "admin"]},
                "database": _NAME,
                "organization": _NAME,
                "tenant_id": _TENANT_ID,
                "expiry_seconds": {
                    "type": "integer",
                    "minimum": 3600,
                    "maximum": 315360000,
                },
            },
        ),
        "result_schema": _result(
            ("created", "token_name", "access", "external_reference"),
            {
                "created": {"type": "boolean"},
                "token_name": _SECRET_NAME,
                "access": {"type": "string", "enum": ["query", "writer", "admin"]},
                "secret_ref": _SECRET_REF,
                "external_reference": {"type": "string"},
                "error": {"type": "string"},
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
        slug = row["handler_id"].replace("service.influxdb_1.", "influxdb-").replace(
            "_", "-"
        )
        RPCProcedureCommand.objects.update_or_create(
            procedure=procedure,
            sequence=1,
            defaults=_command(slug, row["description"]),
        )


def _remove(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[row["name"] for row in _PROCEDURES]).delete()


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0055_seed_influxdb_management_procedures")]
    operations = [migrations.RunPython(_seed, reverse_code=_remove)]
