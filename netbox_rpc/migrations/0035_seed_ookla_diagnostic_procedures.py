"""Seed read-only Ookla / Speedtest server diagnostic RPCProcedure records.

Five audited, read-only SSH-backed procedures diagnose a self-hosted
OoklaServer (Ookla Speedtest custom server) on Ubuntu:

- os.linux.ubuntu.24.ookla.diagnose        (comprehensive, 180s)
- os.linux.ubuntu.24.ookla.check_service   (service + OoklaServer.properties)
- os.linux.ubuntu.24.ookla.check_listeners (IPv4/IPv6 listeners)
- os.linux.ubuntu.24.ookla.check_tls       (TLS certificate)
- os.linux.ubuntu.24.ookla.check_firewall  (ufw / iptables / nftables)

All are effect="read", approval_required=False, and never accept arbitrary SSH
command text. Handler IDs (nms-backend @rpc_handler registrations) equal the
names. Data is inlined (no live module imports) per migration-safety rules.
"""

from django.db import migrations

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": (
        "netbox-nms DeviceCredential PK for the ad-hoc/saved SSH target; "
        "nms-backend decrypts it at execution time. Omit for a device-targeted "
        "execution that resolves SSH from the device's DeviceService."
    ),
}

_ABS_PATH = "^/[A-Za-z0-9/._-]{1,255}$"

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
    "install_dir": {
        "type": "string",
        "pattern": _ABS_PATH,
        "description": (
            "Optional absolute-path hint for the OoklaServer install directory; "
            "the handler still auto-discovers it from the running process."
        ),
    },
    "config_path": {
        "type": "string",
        "pattern": _ABS_PATH,
        "description": (
            "Optional absolute-path hint for OoklaServer.properties; the handler "
            "still auto-discovers it when omitted."
        ),
    },
    "ports": {
        "type": "array",
        "maxItems": 16,
        "items": {"type": "integer", "minimum": 1, "maximum": 65535},
        "description": (
            "Optional explicit port list to check when the server uses non-default "
            "ports; merged with the ports parsed from OoklaServer.properties."
        ),
    },
}

_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": _BASE_PARAMS_PROPERTIES,
}

_SECTION_RESULT = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["ok", "warning", "error", "unknown"]},
        "findings": {"type": "array", "items": {"type": "string"}},
        "details": {"type": "object"},
    },
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "status": {"type": "string", "enum": ["ok", "warning", "error", "unknown"]},
        "summary": {"type": "string"},
        "service": _SECTION_RESULT,
        "listeners": _SECTION_RESULT,
        "tls": _SECTION_RESULT,
        "firewall": _SECTION_RESULT,
    },
}

_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]

_OOKLA_PROCEDURES = [
    {
        "name": "os.linux.ubuntu.24.ookla.diagnose",
        "timeout_seconds": 180,
        "description": (
            "Comprehensive read-only diagnosis of a self-hosted OoklaServer "
            "(service/config, IPv4/IPv6 listeners, TLS certificate, and firewall)."
        ),
    },
    {
        "name": "os.linux.ubuntu.24.ookla.check_service",
        "timeout_seconds": 60,
        "description": (
            "Check the OoklaServer process/service, binary and "
            "OoklaServer.properties, parsed ports, IPv6 setting, allowedDomains, "
            "and version."
        ),
    },
    {
        "name": "os.linux.ubuntu.24.ookla.check_listeners",
        "timeout_seconds": 60,
        "description": (
            "Check that OoklaServer is actually listening on its ports over IPv4 "
            "and IPv6."
        ),
    },
    {
        "name": "os.linux.ubuntu.24.ookla.check_tls",
        "timeout_seconds": 60,
        "description": (
            "Inspect the OoklaServer TLS certificate (validity, CN/SAN, "
            "issuer/chain) and confirm HTTPS serves it on the SSL port."
        ),
    },
    {
        "name": "os.linux.ubuntu.24.ookla.check_firewall",
        "timeout_seconds": 60,
        "description": (
            "Check ufw and iptables/nftables rules against the OoklaServer ports."
        ),
    },
]


def _seed_ookla_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _OOKLA_PROCEDURES:
        RPCProcedure.objects.update_or_create(
            name=data["name"],
            defaults={
                "handler_id": data["name"],
                "target_models": _TARGET_MODELS,
                "effect": "read",
                "timeout_seconds": data["timeout_seconds"],
                "approval_required": False,
                "description": data["description"],
                "params_schema": _PARAMS_SCHEMA,
                "result_schema": _RESULT_SCHEMA,
            },
        )


def _remove_ookla_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for data in _OOKLA_PROCEDURES:
        RPCProcedure.objects.filter(name=data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0034_decouple_netbox_nms_fk_constraints"),
    ]

    operations = [
        migrations.RunPython(
            _seed_ookla_procedures,
            reverse_code=_remove_ookla_procedures,
        ),
    ]
