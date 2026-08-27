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

**No credential of any kind is accepted, generated, or returned here.** Neither
procedure declares the shared ``rpc_ssh_*`` connection overrides: the execution
backend must resolve the SSH destination, credential, and known-host policy
exclusively from the execution's assigned NetBox object, exactly as
``network.device.huawei.router.ne8000.f1a.show_bgp_peer`` does. Accepting a
caller-supplied ``rpc_ssh_credential_pk``/``rpc_ssh_host`` would let a requester
select a credential they cannot view and pivot SSH away from the authorized target,
because that parameter is not yet object-scoped against the requester (issue #203).
The first administrative token is likewise created and vaulted only by the
pre-existing ``service.influxdb.1.bootstrap`` (``family="core3"``, migration
``0056``), which stores the plaintext through the netbox-nms secret bridge and
returns an ``nms-secret:`` reference. Operators chain ``preflight`` -> ``install``
-> ``service.influxdb.1.bootstrap`` so the product family keeps exactly one token
contract.

**Both rows are seeded ``enabled=False``.** No ``os.linux_debian_13.*`` handler
exists in ``netbox-rpc-backend`` yet, and a paired fail-closed code gate
(``_INFLUXDB3_DEBIAN13_AVAILABLE``) refuses them at admission, advertisement, and
worker claim regardless of this mutable flag. Enabling is a coordinated rollout
step: deploy the handlers, get their capability contract approved, then flip both
the gate and the flag in an **additive** migration.

Every ``pattern`` below is anchored with ``(?![\\s\\S])`` rather than ``$``, because
``jsonschema`` applies ``pattern`` with ``re.search`` and Python's ``$`` also matches
immediately before a single trailing newline. Every result string carries an explicit
``maxLength``: ``event_store`` silently clamps unbounded strings at 4096 characters,
which would quietly truncate the audited completion report, and an unbounded contract
lets a malformed backend return an arbitrarily large valid result.
"""

from django.db import migrations

_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]

# Absolute path: no whitespace, no control characters, and no "." or ".." segment.
# The normalizer re-checks the segments, because a charset alone cannot express
# "no dot segment" without this negative lookahead.
_ABSOLUTE_PATH_PATTERN = (
    r"^(?!(?:.*/)?\.{1,2}(?:/|(?![\s\S])))"
    r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*(?![\s\S])"
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

_SHORT_TEXT = {"type": "string", "maxLength": 64}
_IDENTIFIER_TEXT = {"type": "string", "maxLength": 128}
_PATH_TEXT = {"type": "string", "maxLength": 255}
_URL_TEXT = {"type": "string", "maxLength": 512}
_UNIT_STATE_PROPERTIES = {
    "unit": _IDENTIFIER_TEXT,
    "load_state": _SHORT_TEXT,
    "active_state": _SHORT_TEXT,
    "sub_state": _SHORT_TEXT,
    "unit_file_state": _SHORT_TEXT,
}


def _params(properties=None):
    """Build a closed params schema.

    Deliberately does NOT merge the shared ``rpc_ssh_*`` connection overrides — see
    the module docstring. Adding them back would reopen the unscoped-credential and
    SSH-pivot gap.
    """

    return {
        "type": "object",
        "required": [],
        "additionalProperties": False,
        "properties": dict(properties or {}),
    }


def _result(procedure_name, required=(), properties=None):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", *required],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            # Constant per row: the backend cannot relabel which procedure ran.
            "procedure": {"const": procedure_name},
            "target": {"type": "string", "maxLength": 255},
            **(properties or {}),
        },
    }


_PREFLIGHT_NAME = "os.linux.debian.13.preflight_influxdb3_core"
_INSTALL_NAME = "os.linux.debian.13.install_influxdb3_core"

_PREFLIGHT_PARAMS = _params(
    {
        "tls_cert": _ABSOLUTE_PATH,
        "tls_key": _ABSOLUTE_PATH,
    }
)

_PREFLIGHT_RESULT = _result(
    _PREFLIGHT_NAME,
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
        "os_id": _SHORT_TEXT,
        "os_version_id": _SHORT_TEXT,
        "architecture": _SHORT_TEXT,
        "systemd_present": {"type": "boolean"},
        "package_installed": {"type": "boolean"},
        "package_version": _IDENTIFIER_TEXT,
        "package_held": {"type": "boolean"},
        "binary_version": _IDENTIFIER_TEXT,
        "service_account_present": {"type": "boolean"},
        "config_present": {"type": "boolean"},
        "config_managed": {"type": "boolean"},
        "config_path": _PATH_TEXT,
        "installer_state_present": {"type": "boolean"},
        "http_bind": {"type": "string", "maxLength": 261},
        "node_id": _IDENTIFIER_TEXT,
        "data_dir": _PATH_TEXT,
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
    {
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
    _INSTALL_NAME,
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
        "ready",
        "stage",
    ),
    {
        "installed": {"type": "boolean"},
        "package_version": _IDENTIFIER_TEXT,
        "binary_version": _IDENTIFIER_TEXT,
        "service_state": _SHORT_TEXT,
        "service_enabled": _SHORT_TEXT,
        "http_bind": {"type": "string", "maxLength": 261},
        "base_url": _URL_TEXT,
        "node_id": _IDENTIFIER_TEXT,
        "data_dir": _PATH_TEXT,
        "config_path": _PATH_TEXT,
        "installer_state_path": _PATH_TEXT,
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
# A success envelope must actually describe a completed installation. Without this,
# a nested result carrying ok=false / installed=false / stage="package" still
# validates, and event_store selects ExecutionSucceeded from the *outer* response
# ok — so a failed or partial install would be recorded as successful. Mirrors the
# closed oneOf envelope used by service.netbox.staging.rotate_backend_token.
_INSTALL_RESULT["oneOf"] = [
    {
        "properties": {
            "ok": {"const": True},
            "installed": {"const": True},
            "ready": {"const": True},
            "stage": {"const": "complete"},
        }
    },
    {"properties": {"ok": {"const": False}}},
]

_PROCEDURES = (
    {
        "name": _PREFLIGHT_NAME,
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
        "name": _INSTALL_NAME,
        "handler_id": "os.linux_debian_13.install_influxdb3_core",
        "effect": "write",
        "timeout_seconds": 900,
        "approval_required": True,
        # Keep this under RPCProcedure/RPCProcedureCommand.description's
        # max_length=255; the same string is stored on both rows.
        "description": (
            "Install and configure InfluxDB 3 Core on Debian 13 from the "
            "fingerprint-verified InfluxData repository: pinned install, managed "
            "configuration, systemd drop-in, restart, readiness probe, and package "
            "hold. Creates no credential."
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
                # Seeded DISABLED on purpose: no os.linux_debian_13.* handler exists
                # in netbox-rpc-backend yet, so an execution could only queue and
                # then fail on an unknown handler, while /procedures/available/
                # would advertise the rows as dispatchable. Capability discovery is
                # not a substitute — a backend advertising no manifest yields
                # verification UNKNOWN and admission proceeds. The matching
                # fail-closed code gate (_INFLUXDB3_DEBIAN13_AVAILABLE in
                # netbox_rpc.domain.normalization, enforced at admission,
                # advertisement, and worker claim) stays closed even if an operator
                # flips this mutable catalog flag. Enable both together in the
                # coordinated rollout, via an additive migration — never by editing
                # this one in place (Django tracks an applied migration by name, so
                # an in-place data edit silently skips databases that already ran
                # it; see the 0060/0061 precedent).
                "enabled": False,
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
    """Disable the seeded rows instead of deleting them.

    Deliberately non-destructive, for two independent reasons.

    1. ``RPCExecution.procedure`` is ``on_delete=PROTECT``, so deleting a procedure
       that has run would raise ``ProtectedError`` and abort the whole downgrade.
       Audited execution history must never be destroyed to allow a rollback.
    2. Deleting through the historical model is not even safe when the row is
       unreferenced. ``Model.delete()`` and ``QuerySet.delete()`` both run Django's
       deletion collector, which walks related models — and a related model whose
       app has no migrations is rendered from the *real* app registry, not from the
       migration state. The collector then filters that real model by a historical
       ``RPCProcedure`` instance and Django raises
       ``ValueError: Cannot query "RPCProcedure object (N)": Must be "RPCProcedure"
       instance``. That is not hypothetical: it failed the NetBox 4.5.8
       compatibility job, which migrates backwards past this migration with the
       seeded rows present.

    An ``update()`` touches only this table and never invokes the collector, so the
    reverse is safe in every environment. The rows are seeded ``enabled=False``
    anyway, so nothing is lost by leaving them in place: a re-apply is
    ``update_or_create``, which restores the intended state idempotently.
    """

    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[row["name"] for row in _PROCEDURES]).update(
        enabled=False
    )


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
