"""Seed the audited InfluxDB 3 Core installation catalog for Debian 13.

The typed ``service.influxdb.1.*`` family (migrations ``0055``/``0056``) manages an
InfluxDB instance that already exists. Nothing in the catalog could *install* one, so
standing up InfluxDB 3 Core on a Debian 13 guest still meant an interactive SSH
session, which estate policy forbids. These two procedures close that gap:

* ``preflight_influxdb3_core`` (read) reports current posture — Debian release,
  architecture, systemd presence, package/hold state, managed-config marker, unit
  state, configured bind, and TLS-material readability. It is both the pre-install
  gate and the post-install verification read.
* ``install_influxdb3_core`` (write, approval required) is the audited installer:
  fingerprint-verified repository key, pinned package install, managed configuration,
  systemd drop-in, restart, readiness probe, and package hold.

**No credential is generated, accepted, or returned here.** The first administrative
token is created and vaulted exclusively by the pre-existing typed procedure
``service.influxdb.1.bootstrap`` (``family="core3"``, migration ``0056``), which stores
the plaintext through the netbox-nms secret bridge and returns only an ``nms-secret:``
reference. Operators chain ``preflight`` -> ``install`` ->
``service.influxdb.1.bootstrap`` so the product family keeps exactly one token
contract.

Every ``pattern`` below is anchored with ``(?![\\s\\S])`` rather than ``$``, because
``jsonschema`` applies ``pattern`` with ``re.search`` and Python's ``$`` also matches
immediately before a single trailing newline.
"""

from django.db import migrations

_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]

_SSH_PROPERTIES = {
    "rpc_ssh_credential_pk": {"type": "integer", "minimum": 1},
    "rpc_ssh_host": {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "pattern": r"^[^\s\x00-\x1f]{1,255}(?![\s\S])",
    },
    "rpc_ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "rpc_ssh_known_hosts_entry": {"type": "string", "maxLength": 16384},
    "rpc_ssh_strict_host_key_checking": {"type": "boolean"},
}

# Absolute path, no whitespace, no traversal segment, no control characters.
_ABSOLUTE_PATH_PATTERN = (
    r"^(?!.*(?:^|/)\.\.(?:/|$))/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*(?![\s\S])"
)
_ABSOLUTE_PATH = {
    "type": "string",
    "minLength": 2,
    "maxLength": 255,
    "pattern": _ABSOLUTE_PATH_PATTERN,
}

_NODE_ID = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"^[A-Za-z0-9]+(?:[A-Za-z0-9-]*[A-Za-z0-9])?(?![\s\S])",
    "description": "Letters, digits, and internal hyphens only.",
}
_HTTP_BIND = {
    "type": "string",
    "minLength": 3,
    "maxLength": 261,
    "pattern": r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}:[0-9]{1,5}(?![\s\S])",
    "description": "hostname-or-IPv4:port, for example 127.0.0.1:8181.",
}
_WAL_FLUSH_INTERVAL = {
    "type": "string",
    "minLength": 2,
    "maxLength": 16,
    "pattern": r"^[0-9]{1,9}(?:ms|s)(?![\s\S])",
}
_LOG_FILTER = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"^[A-Za-z0-9_=,.-]{1,128}(?![\s\S])",
}
_PACKAGE_VERSION = {
    "type": "string",
    "minLength": 1,
    "maxLength": 64,
    "pattern": r"^[A-Za-z0-9.+:~_-]{1,64}(?![\s\S])",
    "description": "Exact apt candidate version, as shown by apt-cache policy.",
}

_COMMON_RESULT_PROPERTIES = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
}
_UNIT_STATE_PROPERTIES = {
    "unit": {"type": "string"},
    "load_state": {"type": "string"},
    "active_state": {"type": "string"},
    "sub_state": {"type": "string"},
    "unit_file_state": {"type": "string"},
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
        "required": ["ok", "procedure", "target", *required],
        "additionalProperties": False,
        "properties": {**_COMMON_RESULT_PROPERTIES, **(properties or {})},
    }


_PREFLIGHT_PARAMS = _params(
    properties={
        "tls_cert": _ABSOLUTE_PATH,
        "tls_key": _ABSOLUTE_PATH,
    }
)

_PREFLIGHT_RESULT = _result(
    (
        "supported",
        "os_id",
        "os_version_id",
        "architecture",
        "systemd_present",
        "package_installed",
        "package_held",
        "config_present",
        "config_managed",
        "ready",
    ),
    {
        "supported": {"type": "boolean"},
        "os_id": {"type": "string"},
        "os_version_id": {"type": "string"},
        "architecture": {"type": "string"},
        "systemd_present": {"type": "boolean"},
        "package_installed": {"type": "boolean"},
        "package_version": {"type": "string"},
        "package_held": {"type": "boolean"},
        "binary_version": {"type": "string"},
        "service_account_present": {"type": "boolean"},
        "config_present": {"type": "boolean"},
        "config_managed": {"type": "boolean"},
        "config_path": {"type": "string"},
        "installer_state_present": {"type": "boolean"},
        "http_bind": {"type": "string"},
        "node_id": {"type": "string"},
        "data_dir": {"type": "string"},
        "data_dir_populated": {"type": "boolean"},
        "plugins_enabled": {"type": "boolean"},
        "telemetry_upload_disabled": {"type": "boolean"},
        "tls_enabled": {"type": "boolean"},
        "tls_cert_readable": {"type": "boolean"},
        "tls_key_readable": {"type": "boolean"},
        "ready": {"type": "boolean"},
        "blockers": {
            "type": "array",
            "items": {"type": "string", "maxLength": 512},
            "maxItems": 32,
        },
        **_UNIT_STATE_PROPERTIES,
    },
)

_INSTALL_PARAMS = _params(
    properties={
        "node_id": _NODE_ID,
        "data_dir": _ABSOLUTE_PATH,
        "http_bind": _HTTP_BIND,
        "tls_cert": _ABSOLUTE_PATH,
        "tls_key": _ABSOLUTE_PATH,
        "enable_plugins": {"type": "boolean", "default": False},
        "disable_telemetry": {"type": "boolean", "default": True},
        "wal_flush_interval": _WAL_FLUSH_INTERVAL,
        "log_filter": _LOG_FILTER,
        "package_version": _PACKAGE_VERSION,
        "hold_package": {"type": "boolean", "default": True},
        "upgrade_package": {"type": "boolean", "default": False},
        "force_reconfigure": {"type": "boolean", "default": False},
        "allow_plaintext_remote": {"type": "boolean", "default": False},
    }
)

_INSTALL_RESULT = _result(
    (
        "installed",
        "package_version",
        "service_state",
        "service_enabled",
        "http_bind",
        "node_id",
        "data_dir",
        "config_path",
        "plugins_enabled",
        "package_held",
    ),
    {
        "installed": {"type": "boolean"},
        "package_version": {"type": "string"},
        "binary_version": {"type": "string"},
        "service_state": {"type": "string"},
        "service_enabled": {"type": "string"},
        "http_bind": {"type": "string"},
        "base_url": {"type": "string"},
        "node_id": {"type": "string"},
        "data_dir": {"type": "string"},
        "config_path": {"type": "string"},
        "installer_state_path": {"type": "string"},
        "plugins_enabled": {"type": "boolean"},
        "telemetry_upload_disabled": {"type": "boolean"},
        "tls_enabled": {"type": "boolean"},
        "package_held": {"type": "boolean"},
        "package_preexisted": {"type": "boolean"},
        "upgraded": {"type": "boolean"},
        "reconfigured": {"type": "boolean"},
        "ready": {"type": "boolean"},
        "stage": {
            "type": "string",
            "enum": [
                "preconditions",
                "repository",
                "package",
                "filesystem",
                "configure",
                "activate",
                "verify",
                "hold",
                "complete",
            ],
        },
        "warnings": {
            "type": "array",
            "items": {"type": "string", "maxLength": 512},
            "maxItems": 32,
        },
        "error": {"type": "string", "maxLength": 2048},
        **_UNIT_STATE_PROPERTIES,
    },
)

_PROCEDURES = (
    {
        "name": "os.linux.debian.13.preflight_influxdb3_core",
        "handler_id": "os.linux_debian_13.preflight_influxdb3_core",
        "effect": "read",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": (
            "Report Debian 13 InfluxDB 3 Core installation posture: release, "
            "architecture, systemd, package/hold state, managed configuration, unit "
            "state, configured bind, and TLS-material readability."
        ),
        "params_schema": _PREFLIGHT_PARAMS,
        "result_schema": _PREFLIGHT_RESULT,
        "command_slug": "influxdb3-core-preflight",
    },
    {
        "name": "os.linux.debian.13.install_influxdb3_core",
        "handler_id": "os.linux_debian_13.install_influxdb3_core",
        "effect": "write",
        "timeout_seconds": 900,
        "approval_required": True,
        "description": (
            "Install and configure InfluxDB 3 Core on Debian 13 from the "
            "fingerprint-verified InfluxData repository: pinned package install, "
            "managed configuration, systemd drop-in, restart, readiness probe, and "
            "package hold. Creates no credential; token bootstrap stays with "
            "service.influxdb.1.bootstrap."
        ),
        "params_schema": _INSTALL_PARAMS,
        "result_schema": _INSTALL_RESULT,
        "command_slug": "influxdb3-core-install",
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


def seed_influxdb3_debian13_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for row in _PROCEDURES:
        defaults = {
            key: value
            for key, value in row.items()
            if key not in {"name", "command_slug"}
        }
        defaults.update(
            {
                "version": 1,
                "enabled": True,
                "target_models": _TARGET_MODELS,
            }
        )
        procedure, _ = RPCProcedure.objects.update_or_create(
            name=row["name"], defaults=defaults
        )
        RPCProcedureCommand.objects.update_or_create(
            procedure=procedure,
            sequence=1,
            defaults=_command(row["command_slug"], row["description"]),
        )


def unseed_influxdb3_debian13_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[row["name"] for row in _PROCEDURES]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0071_seed_influxdb3_core_service_allowlist"),
    ]

    operations = [
        migrations.RunPython(
            seed_influxdb3_debian13_procedures,
            reverse_code=unseed_influxdb3_debian13_procedures,
        ),
    ]
