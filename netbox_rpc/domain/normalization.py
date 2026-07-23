from __future__ import annotations

import hashlib
import json
import re
from ipaddress import ip_address, ip_network
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from ..constants import (
    DELL_OS10_S5232F_ALLOW_THIRD_PARTY_TRANSCEIVER,
    DELL_OS10_S5232F_BOOTSTRAP_RESTCONF,
    DELL_OS10_S5232F_CONFIGURE_INTERFACE_BREAKOUT,
    DELL_OS10_S5232F_CONFIGURE_INTERFACE_FEC,
    DELL_OS10_S5232F_CONFIGURE_INTERFACE_LACP,
    DELL_OS10_S5232F_CONFIGURE_PORT_CHANNEL,
    DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN,
    DELL_OS10_S5232F_CONFIGURE_VLT_PEER,
    DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION,
    DELL_OS10_S5232F_SET_VLAN_DESCRIPTION,
    DELL_OS10_S5232F_SHOW_VERSION,
    DELL_OS10_S5232F_SHOW_VERSION_STRUCTURED,
    DELL_OS10_S5232F_SHOW_VLT,
    DELL_OS10_S5232F_WRITE_MEMORY,
    DNS_HOST_DEPLOY_PROCEDURE,
    DNS_HOST_STATUS_PROCEDURE,
    HUAWEI_MA5800_R024_START_ONT,
    LINUX_COLLECT_FACTS,
    LINUX_INSTALL_QEMU_GUEST_AGENT,
    LINUX_INSTALL_SSH_KEY,
    LINUX_INSTALL_ZABBIX_AGENT2,
    LINUX_PROXMOX_CONVERT_MELLANOX_NIC,
    LINUX_PROXMOX_PVESH_JSON,
    LINUX_PROXMOX_QEMU_VM_LIFECYCLE,
    LINUX_PROXMOX_SHOW_SYSTEMCTL_SERVICES,
    MINECRAFT_PAPERMC_INSTALL,
    MINECRAFT_PLUGIN_INSTALL_URL,
    MINECRAFT_VIAVERSION_INSTALL,
    NGINX_1_CONFIG_DEPLOY,
    NGINX_1_CONFIG_TEST,
    NGINX_1_RELOAD,
    NGINX_1_ROLLBACK,
    OOKLA_PROCEDURE_NAMES,
    PACKER_PROCEDURE_NAMES,
    PASSBOLT_CLEANUP,
    PASSBOLT_EXPORT_SECRETS,
    PASSBOLT_IMPORT_SECRETS,
    PASSBOLT_PROCEDURE_NAMES,
    PASSBOLT_TRANSFER_SECRETS,
    PTERODACTYL_ARTISAN,
    PTERODACTYL_BOOTSTRAP_API_KEY,
    PTERODACTYL_CONTAINER_LOGS,
    PTERODACTYL_WINGS_LOGS,
    PTERODACTYL_WINGS_RESTART,
    PTERODACTYL_WINGS_STATUS,
    SAMBA_1_CONFIG_DEPLOY,
    SAMBA_1_CONFIG_ROLLBACK,
    SAMBA_1_INCLUDE_FILE_READ,
    SAMBA_1_INCLUDE_FILE_DELETE,
    SAMBA_1_INCLUDE_FILE_WRITE,
    SAMBA_1_PROCEDURE_NAMES,
    SAMBA_1_SHARE_ACL_READ,
    SAMBA_1_SHARE_DELETE,
    SAMBA_1_SHARE_UPSERT,
    SAMBA_1_SERVICE_CONTROL,
    UBUNTU_24_DAEMON_RELOAD,
    UBUNTU_24_DISABLE_SERVICE,
    UBUNTU_24_ENABLE_SERVICE,
    UBUNTU_24_JOURNAL_TAIL,
    UBUNTU_24_RELOAD_SERVICE,
    UBUNTU_24_RESTART_SERVICE,
    UBUNTU_24_START_SERVICE,
    UBUNTU_24_STATUS_SERVICE,
    UBUNTU_24_STOP_SERVICE,
)
from ..command_templating import RENDER_JINJA
from ..models import RPCLinuxServiceAllowlist, RPCExecution

_PROXMOX_NODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PROXMOX_STORAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROXMOX_BRIDGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_PROXMOX_VM_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_PROXMOX_DISK_RE = re.compile(r"(?:scsi|virtio|sata|ide)[0-9]+$")
_PROXMOX_NO_COMMA_SPACE_RE = re.compile(r"[^\s,]{1,64}$")
_DNS_SEARCH_DOMAIN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)
_PROXMOX_QEMU_OPERATIONS = {
    "nextid",
    "clone",
    "migrate",
    "configure",
    "resize",
    "start",
    "stop",
    "status",
    "agent_ping",
    "agent_network_get_interfaces",
    "agent_configure_debian_network",
    "agent_set_user_password",
    "agent_pbs_zabbix_status",
    "agent_configure_zabbix_agent2",
}
_PROXMOX_QEMU_NIC_MODELS = {"virtio", "e1000", "e1000e", "vmxnet3", "rtl8139"}
_POSIX_USERNAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}$")
_DELL_OS10_INTERFACE_RE = re.compile(r"[A-Za-z][A-Za-z0-9/._:-]{0,63}$")
_DELL_OS10_IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_DELL_OS10_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")
_DELL_OS10_TRUNK_VLANS_RE = re.compile(
    r"\d{1,4}(?:-\d{1,4})?(?:,\d{1,4}(?:-\d{1,4})?)*"
)
_DELL_OS10_BREAKOUT_PORT_RE = re.compile(r"\d+/\d+/\d+")
_DELL_OS10_BREAKOUT_MODE_RE = re.compile(r"\d+g-\d+x")
_PVESH_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.\-]{1,128}$")
_PTERODACTYL_CONTAINER_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_MINECRAFT_SERVER_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MINECRAFT_JAR_FILENAME_RE = re.compile(r"[A-Za-z0-9._-]+\.jar$")
_MINECRAFT_VERSION_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}$")
_MINECRAFT_VIAVERSION_PRESETS = {
    "minimal": ("viaversion",),
    "standard": ("viaversion", "viabackwards"),
    "full": ("viaversion", "viabackwards", "viarewind"),
}
_MINECRAFT_VIAVERSION_PLUGINS = frozenset({"viaversion", "viabackwards", "viarewind"})
_MINECRAFT_PAPERMC_PROJECTS = frozenset({"paper", "folia", "velocity"})
_NMAP_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\.?$)(?=.*[A-Za-z])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?"
)
_NMAP_PORT_TOKEN_RE = re.compile(r"\d{1,5}(?:-\d{1,5})?")
_NMAP_SCAN_TYPES = frozenset({"connect", "syn", "os-detect"})
# Bound CIDR scan targets so an unapproved read-only scan cannot sweep a huge
# range (e.g. 0.0.0.0/0). A /24 (256 addresses) covers the managed cloud
# prefixes (a /25 = 128 hosts) while rejecting anything broader.
_NMAP_MIN_CIDR_PREFIXLEN = 24
_NMAP_MAX_CIDR_HOSTS = 256
_DNS_HOST_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}")
_DNS_HOST_COMPOSE_PROJECT = "powerdns-dns-api"
_PTERODACTYL_ARTISAN_ALLOWLIST = frozenset(
    {
        "queue:status",
        "schedule:run",
        "cache:clear",
        "config:clear",
        "queue:restart",
        "migrate",
    }
)
_PASSBOLT_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PASSBOLT_DB_NAME_RE = re.compile(r"[A-Za-z0-9_]{1,64}$")
_PASSBOLT_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}$")
_PASSBOLT_PATH_SAFE_CHARS_RE = re.compile(r"/[A-Za-z0-9._/-]{1,254}")
_PASSBOLT_BROAD_DIRS = frozenset({"/", "/tmp", "/var/tmp", "/etc"})
_PASSBOLT_HOST_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_PASSBOLT_POSIX_USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}$")
_SAMBA_INCLUDE_FILE_RE = re.compile(
    r"^(?!.*(?:^|/)\.\.(?:/|$))(?:/etc/samba/)?"
    r"[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*\.conf$"
)
_SAMBA_SHARE_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,79}$")
_SAMBA_CONF_ROOT = PurePosixPath("/etc/samba")
_SAMBA_MAX_CONFIG_BODY_LEN = 1024 * 1024
_SAMBA_SNAPSHOT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAMBA_SHARE_PATH_RE = re.compile(r"/[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*$")
_SAMBA_SHARE_TEXT_MAX_LEN = 240
_SAMBA_PRINCIPAL_RE = re.compile(r"@?[A-Za-z0-9_][A-Za-z0-9_.@+\\-]{0,127}$")
_SAMBA_MASK_RE = re.compile(r"[0-7]{3,4}$")
_SAMBA_SERVICE_UNITS = frozenset({"smbd", "nmbd", "winbind", "samba-ad-dc"})
_SAMBA_SERVICE_ACTIONS = frozenset({"start", "stop", "restart", "reload"})
# Samba smb.conf parameter names are case-insensitive and whitespace-insensitive.
# Several parameter families execute host commands: "* script", "* command", and
# "* action", plus the preexec/postexec family. "root preexec" runs as root, so
# config bodies must be rejected before persistence/dispatch when these names
# appear in caller-controlled smb.conf or include-file content.
_SAMBA_COMMAND_DIRECTIVE_SUFFIXES = ("script", "command", "action")
_SAMBA_COMMAND_DIRECTIVE_NAMES = frozenset(
    {
        "preexec",
        "postexec",
        "rootpreexec",
        "rootpostexec",
        "preexecclose",
        "rootpreexecclose",
    }
)
# systemd unit-name allowlist charset for os.linux.proxmox.show_systemctl_services.
# The first character must be alphanumeric/underscore so a value can never be
# mistaken for a `systemctl` option (e.g. "--user"); "-", ".", ":" and "@" are
# only allowed after the first character.
_SYSTEMCTL_UNIT_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*$")
_MAX_SYSTEMCTL_UNITS = 32


class RPCExecutionError(RuntimeError):
    def __init__(self, message: str, *, code: str = "RPC_EXECUTION_FAILED") -> None:
        super().__init__(message)
        self.code = code


# Defaults that reproduce the historical execution behaviour. When a procedure
# leaves these untouched, no driver/parser keys are injected into normalized
# params, keeping legacy payloads byte-for-byte identical.
_DEFAULT_TRANSPORT_DRIVER = "asyncssh"
_DEFAULT_OUTPUT_PARSER = "none"
# Deployment-specific defaults are intentionally empty so the public plugin
# ships no site-specific hostnames. Configure them per deployment via the
# netbox_rpc plugin settings ("dns_host_domain", "default_zabbix_server"), or
# pass explicit values in the execution params.
_DEFAULT_DNS_HOST_DOMAIN = ""
_DEFAULT_ZABBIX_SERVER = ""


def _netbox_rpc_plugin_setting(key: str, default: str) -> str:
    try:
        from django.conf import settings
    except ImportError:
        return default
    try:
        plugin_config = getattr(settings, "PLUGINS_CONFIG", {}) or {}
    except Exception:
        return default
    value = (plugin_config.get("netbox_rpc") or {}).get(key, default)
    return str(value or default)


def _default_dns_host_domain() -> str:
    return _netbox_rpc_plugin_setting(
        "dns_host_domain",
        _DEFAULT_DNS_HOST_DOMAIN,
    ).strip(".")


def _default_zabbix_server() -> str:
    return _netbox_rpc_plugin_setting(
        "default_zabbix_server",
        _DEFAULT_ZABBIX_SERVER,
    )


def normalize_execution_params(execution: RPCExecution) -> dict[str, Any]:
    """Build normalized params for an execution and inject driver/parser routing.

    The per-procedure dispatch lives in ``_dispatch_normalize_execution_params``;
    this wrapper centrally threads the procedure's ``transport_driver`` /
    ``output_parser`` / ``output_schema`` selection into the normalized payload
    (and its command fingerprint) so the nms-backend execution pipeline can read
    them from ``normalized_params``. Non-default values only are injected, so
    legacy AsyncSSH/raw-output procedures keep a byte-for-byte identical payload.
    """
    normalized = _dispatch_normalize_execution_params(execution)
    _apply_driver_pipeline_overrides(execution, normalized)
    _apply_target_object_context(execution, normalized)
    return normalized


def _apply_driver_pipeline_overrides(
    execution: RPCExecution, normalized: dict[str, Any]
) -> None:
    procedure = execution.procedure
    fingerprint = normalized.get("command_fingerprint")

    driver = str(getattr(procedure, "transport_driver", "") or "").strip()
    if driver and driver != _DEFAULT_TRANSPORT_DRIVER:
        normalized["transport_driver"] = driver
        if isinstance(fingerprint, dict):
            fingerprint["transport_driver"] = driver

    # Ordered driver priority + fallback chain. Injected only when the operator
    # configured a non-empty chain, so legacy procedures keep a byte-for-byte
    # identical payload. The backend reads it from normalized_params, tries the
    # drivers in order, and falls through on unavailable/connection errors.
    raw_chain = getattr(procedure, "transport_driver_chain", None) or []
    chain = [str(entry).strip() for entry in raw_chain if str(entry).strip()]
    if chain:
        normalized["transport_driver_chain"] = chain
        if isinstance(fingerprint, dict):
            fingerprint["transport_driver_chain"] = chain

    parser = str(getattr(procedure, "output_parser", "") or "").strip()
    if parser and parser != _DEFAULT_OUTPUT_PARSER:
        normalized["output_parser"] = parser
        if isinstance(fingerprint, dict):
            fingerprint["output_parser"] = parser

    schema = getattr(procedure, "output_schema", None)
    if schema:
        normalized["output_schema"] = schema
        if isinstance(fingerprint, dict):
            fingerprint["output_schema_sha256"] = _hash_json(schema)


# ── Target-object context for Jinja command templating ───────────────────────
#
# netbox-rpc owns the NetBox target object; the nms-backend executor only sees
# the serialized execution payload. So when a procedure has a Jinja command
# (``render_mode="jinja"``), netbox-rpc serializes a bounded, redacted snapshot
# of the target object into ``normalized_params["_target_object"]`` — that is the
# ``{{ target.* }}`` render context ("NetBox objects as variables"). This is
# gated on the procedure actually having a Jinja command, so every legacy /
# literal procedure keeps a byte-for-byte identical normalized payload.

_TARGET_SNAPSHOT_MAX_FIELDS = 100
_TARGET_SNAPSHOT_MAX_VALUE_LEN = 1024
# Field/custom-field names whose values must never be serialized into the
# snapshot. Biased toward over-redaction (omitting a field is safe; leaking a
# secret is not).
_SENSITIVE_FIELD_RE = re.compile(
    r"pass|secret|token|credential|community|psk|passphrase"
    r"|private[_-]?key|api[_-]?key|ssh[_-]?key|auth[_-]?key"
    r"|access[_-]?key|encryption[_-]?key|secret[_-]?key",
    re.IGNORECASE,
)


def _has_jinja_command(procedure: Any) -> bool:
    """True when the procedure has at least one ``render_mode="jinja"`` command.

    Uses a single ``EXISTS`` query for a real related manager; falls back to
    iterating a plain list (test stubs). Returns False when no command relation
    is present.
    """

    manager = getattr(procedure, "commands", None)
    if manager is None:
        return False
    filter_fn = getattr(manager, "filter", None)
    if callable(filter_fn):
        return filter_fn(render_mode=RENDER_JINJA).exists()
    all_fn = getattr(manager, "all", None)
    commands = all_fn() if callable(all_fn) else manager
    return any(
        (getattr(command, "render_mode", "") or "") == RENDER_JINJA
        for command in commands
    )


def _json_safe_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        safe = value
    else:
        safe = str(value)
    if isinstance(safe, str) and len(safe) > _TARGET_SNAPSHOT_MAX_VALUE_LEN:
        safe = safe[:_TARGET_SNAPSHOT_MAX_VALUE_LEN]
    return safe


def _target_field_items(obj: Any):
    """Yield ``(name, value)`` for the object's concrete fields.

    Prefers a Django model's concrete local fields (``_meta.fields``); falls
    back to the object's public ``__dict__`` entries for plain objects/stubs.
    """

    meta = getattr(obj, "_meta", None)
    fields = getattr(meta, "fields", None) if meta is not None else None
    if fields:
        for field in fields:
            attname = getattr(field, "attname", None) or getattr(field, "name", None)
            if attname:
                yield attname, getattr(obj, attname, None)
        return
    data = getattr(obj, "__dict__", None)
    if isinstance(data, dict):
        for key, value in data.items():
            if not key.startswith("_"):
                yield key, value


def _build_target_object_snapshot(obj: Any) -> dict[str, Any] | None:
    """Bounded, redacted, JSON-safe snapshot of the run's NetBox target object."""

    if obj is None:
        return None
    snapshot: dict[str, Any] = {}
    for name, value in _target_field_items(obj):
        if name.startswith("_") or _SENSITIVE_FIELD_RE.search(name):
            continue
        if len(snapshot) >= _TARGET_SNAPSHOT_MAX_FIELDS:
            break
        snapshot[name] = _json_safe_scalar(value)

    pk = getattr(obj, "pk", None)
    snapshot.setdefault("id", pk if pk is not None else getattr(obj, "id", None))
    snapshot["display"] = _json_safe_scalar(str(obj))
    if "name" not in snapshot:
        name_value = getattr(obj, "name", None)
        if name_value is not None:
            snapshot["name"] = _json_safe_scalar(name_value)

    custom_fields = getattr(obj, "custom_field_data", None)
    if isinstance(custom_fields, dict) and custom_fields:
        redacted_cf = {
            key: _json_safe_scalar(value)
            for key, value in list(custom_fields.items())[:_TARGET_SNAPSHOT_MAX_FIELDS]
            if not _SENSITIVE_FIELD_RE.search(str(key))
        }
        if redacted_cf:
            snapshot["custom_fields"] = redacted_cf
    return snapshot


def _apply_target_object_context(
    execution: RPCExecution, normalized: dict[str, Any]
) -> None:
    if not _has_jinja_command(execution.procedure):
        return
    snapshot = _build_target_object_snapshot(
        getattr(execution, "assigned_object", None)
    )
    if not snapshot:
        return
    normalized["_target_object"] = snapshot
    fingerprint = normalized.get("command_fingerprint")
    if isinstance(fingerprint, dict):
        fingerprint["target_object_sha256"] = _hash_json(snapshot)


def _dispatch_normalize_execution_params(execution: RPCExecution) -> dict[str, Any]:
    procedure_name = execution.procedure.name
    target = execution.target_display

    if procedure_name in {
        UBUNTU_24_RESTART_SERVICE,
        UBUNTU_24_STATUS_SERVICE,
        UBUNTU_24_START_SERVICE,
        UBUNTU_24_STOP_SERVICE,
        UBUNTU_24_RELOAD_SERVICE,
        UBUNTU_24_ENABLE_SERVICE,
        UBUNTU_24_DISABLE_SERVICE,
        UBUNTU_24_JOURNAL_TAIL,
    }:
        normalized = _normalize_linux_service_execution(execution, target)
        if procedure_name == UBUNTU_24_JOURNAL_TAIL:
            lines = int((execution.params or {}).get("lines", 100))
            normalized["lines"] = lines
        return normalized

    if procedure_name == UBUNTU_24_DAEMON_RELOAD:
        return {
            "target": target,
            "command_fingerprint": {"handler_id": execution.procedure.handler_id},
        }

    if procedure_name == HUAWEI_MA5800_R024_START_ONT:
        params = execution.params or {}
        normalized = {
            "target": target,
            "frame": _int_range(params, "frame", 0, None),
            "slot": _int_range(params, "slot", 1, 17),
            "port": _int_range(params, "port", 0, 15),
            "ont_id": _int_range(params, "ont_id", 0, 127),
        }
        normalized["command_fingerprint"] = {
            "handler_id": execution.procedure.handler_id,
            "frame": normalized["frame"],
            "slot": normalized["slot"],
            "port": normalized["port"],
            "ont_id": normalized["ont_id"],
        }
        return normalized

    if procedure_name == LINUX_INSTALL_SSH_KEY:
        return _normalize_ssh_install_key_execution(execution, target)

    if procedure_name == DNS_HOST_DEPLOY_PROCEDURE:
        return _normalize_dns_host_deploy_execution(execution)

    if procedure_name == DNS_HOST_STATUS_PROCEDURE:
        return _normalize_dns_host_status_execution(execution)

    if procedure_name == LINUX_INSTALL_QEMU_GUEST_AGENT:
        return _normalize_linux_agent_install_execution(execution, target)

    if procedure_name == LINUX_INSTALL_ZABBIX_AGENT2:
        return _normalize_linux_agent_install_execution(
            execution,
            target,
            zabbix_server=True,
        )

    if procedure_name == LINUX_PROXMOX_CONVERT_MELLANOX_NIC:
        return _normalize_convert_mellanox_nic_execution(execution, target)

    if procedure_name == LINUX_PROXMOX_PVESH_JSON:
        return _normalize_pvesh_json_execution(execution, target)

    if procedure_name == LINUX_COLLECT_FACTS:
        return _normalize_pipeline_fixed_execution(execution, target)

    if procedure_name in OOKLA_PROCEDURE_NAMES:
        return _normalize_ookla_execution(execution, target)

    if procedure_name == "nmap-scan":
        return _normalize_nmap_execution(execution)

    if procedure_name in PACKER_PROCEDURE_NAMES:
        # Function-local import keeps the netbox-packer reference lazy: this
        # module imports packer_normalizer only when a packer.vm.* execution is
        # actually normalized, and packer_normalizer in turn lazy-imports
        # netbox_packer. netbox-rpc never hard-depends on netbox-packer.
        from ..packer_normalizer import normalize_packer_vm_execution

        return normalize_packer_vm_execution(execution, target)

    if procedure_name in PASSBOLT_PROCEDURE_NAMES:
        return _normalize_passbolt_migration_execution(execution, target)

    if procedure_name in SAMBA_1_PROCEDURE_NAMES:
        return _normalize_samba_1_execution(execution, target)

    if procedure_name == LINUX_PROXMOX_QEMU_VM_LIFECYCLE:
        return _normalize_proxmox_qemu_vm_lifecycle_execution(execution, target)

    if procedure_name == LINUX_PROXMOX_SHOW_SYSTEMCTL_SERVICES:
        return _normalize_show_systemctl_services_execution(execution, target)

    if procedure_name == DELL_OS10_S5232F_BOOTSTRAP_RESTCONF:
        return _normalize_dell_os10_bootstrap_execution(execution, target)

    if procedure_name in {
        DELL_OS10_S5232F_ALLOW_THIRD_PARTY_TRANSCEIVER,
        DELL_OS10_S5232F_SHOW_VERSION,
        DELL_OS10_S5232F_WRITE_MEMORY,
    }:
        return _normalize_dell_os10_simple_execution(execution, target)

    if procedure_name == DELL_OS10_S5232F_SHOW_VERSION_STRUCTURED:
        return _normalize_pipeline_fixed_execution(execution, target)

    if procedure_name == DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION:
        params = execution.params or {}
        interface_name = str(params.get("interface_name") or "").strip()
        if not _DELL_OS10_INTERFACE_RE.fullmatch(interface_name):
            raise RPCExecutionError(
                "interface_name must be a valid OS10 interface identifier.",
                code="RPC_PARAM_INVALID",
            )
        description = _dell_os10_description(params)
        write_memory = _bool_param(params, "write_memory", False)
        normalized = {
            "target": target,
            "interface_name": interface_name,
            "description": description,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_name": interface_name,
                "description_sha256": _hash_text(description),
                "write_memory": write_memory,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_SET_VLAN_DESCRIPTION:
        params = execution.params or {}
        vlan_id = _int_range(params, "vlan_id", 1, 4094)
        description = _dell_os10_description(params)
        write_memory = _bool_param(params, "write_memory", False)
        normalized = {
            "target": target,
            "vlan_id": vlan_id,
            "description": description,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "vlan_id": vlan_id,
                "description_sha256": _hash_text(description),
                "write_memory": write_memory,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_SHOW_VLT:
        params = execution.params or {}
        domain_id = _optional_int_range(params, "domain_id", 1, 255)
        if domain_id is None:
            domain_id = 1
        normalized = {
            "target": target,
            "domain_id": domain_id,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "domain_id": domain_id,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN:
        params = execution.params or {}
        domain_id = _int_range(params, "domain_id", 1, 255)
        # unit_id is optional — Dell OS10 10.5.x auto-negotiates the unit role
        # and does not recognise the 'unit-id' CLI command; omit it when absent.
        unit_id = _optional_int_range(params, "unit_id", 1, 2)
        primary_priority = _optional_int_range(params, "primary_priority", 1, 65535)
        if primary_priority is None:
            primary_priority = 32768
        discovery_port_channel = _int_range(params, "discovery_port_channel", 1, 4096)
        backup_destination = str(params.get("backup_destination") or "").strip()
        if not _DELL_OS10_IP_RE.fullmatch(backup_destination):
            raise RPCExecutionError(
                "backup_destination must be a valid IPv4 address.",
                code="RPC_PARAM_INVALID",
            )
        vlt_mac = str(params.get("vlt_mac") or "").strip()
        if vlt_mac and not _DELL_OS10_MAC_RE.fullmatch(vlt_mac):
            raise RPCExecutionError(
                "vlt_mac must be a valid MAC address (XX:XX:XX:XX:XX:XX).",
                code="RPC_PARAM_INVALID",
            )
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "domain_id": domain_id,
            "primary_priority": primary_priority,
            "discovery_port_channel": discovery_port_channel,
            "backup_destination": backup_destination,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "domain_id": domain_id,
                "primary_priority": primary_priority,
                "discovery_port_channel": discovery_port_channel,
                "backup_destination": backup_destination,
            },
        }
        if unit_id is not None:
            normalized["unit_id"] = unit_id
            normalized["command_fingerprint"]["unit_id"] = unit_id
        if vlt_mac:
            normalized["vlt_mac"] = vlt_mac
            normalized["command_fingerprint"]["vlt_mac"] = vlt_mac
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_VLT_PEER:
        params = execution.params or {}
        port_channel_id = _int_range(params, "port_channel_id", 1, 4096)
        vlt_port_channel_id = _int_range(params, "vlt_port_channel_id", 1, 4096)
        remove = _bool_param(params, "remove", False)
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "port_channel_id": port_channel_id,
            "vlt_port_channel_id": vlt_port_channel_id,
            "remove": remove,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "port_channel_id": port_channel_id,
                "vlt_port_channel_id": vlt_port_channel_id,
                "remove": remove,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_PORT_CHANNEL:
        params = execution.params or {}
        port_channel_id = _int_range(params, "port_channel_id", 1, 4096)
        trunk_vlans = str(params.get("trunk_vlans") or "").strip()
        if trunk_vlans and not _DELL_OS10_TRUNK_VLANS_RE.fullmatch(trunk_vlans):
            raise RPCExecutionError(
                "trunk_vlans must be a comma-separated list of VLAN IDs or ranges "
                "(e.g. '20,111' or '10-20,100').",
                code="RPC_PARAM_INVALID",
            )
        description = _dell_os10_description(params)
        remove = _bool_param(params, "remove", False)
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "port_channel_id": port_channel_id,
            "remove": remove,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "port_channel_id": port_channel_id,
                "remove": remove,
            },
        }
        if trunk_vlans:
            normalized["trunk_vlans"] = trunk_vlans
            normalized["command_fingerprint"]["trunk_vlans"] = trunk_vlans
        if description:
            normalized["description"] = description
            normalized["command_fingerprint"]["description_sha256"] = _hash_text(
                description
            )
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_INTERFACE_LACP:
        params = execution.params or {}
        interface_name = str(params.get("interface_name") or "").strip()
        if not _DELL_OS10_INTERFACE_RE.fullmatch(interface_name):
            raise RPCExecutionError(
                "interface_name must be a valid OS10 interface identifier.",
                code="RPC_PARAM_INVALID",
            )
        port_channel_id = _int_range(params, "port_channel_id", 1, 4096)
        lacp_mode = str(params.get("lacp_mode") or "active").strip().lower()
        if lacp_mode not in {"active", "passive", "on"}:
            raise RPCExecutionError(
                "lacp_mode must be 'active', 'passive', or 'on'.",
                code="RPC_PARAM_INVALID",
            )
        description = _dell_os10_description(params)
        remove = _bool_param(params, "remove", False)
        write_memory = _bool_param(params, "write_memory", False)
        normalized = {
            "target": target,
            "interface_name": interface_name,
            "port_channel_id": port_channel_id,
            "lacp_mode": lacp_mode,
            "remove": remove,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_name": interface_name,
                "port_channel_id": port_channel_id,
                "lacp_mode": lacp_mode,
                "remove": remove,
            },
        }
        if description:
            normalized["description"] = description
            normalized["command_fingerprint"]["description_sha256"] = _hash_text(
                description
            )
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_INTERFACE_BREAKOUT:
        params = execution.params or {}
        interface_port = str(params.get("interface_port") or "").strip()
        if not _DELL_OS10_BREAKOUT_PORT_RE.fullmatch(interface_port):
            raise RPCExecutionError(
                "interface_port must be in slot/port/subport format, e.g. '1/1/1'.",
                code="RPC_PARAM_INVALID",
            )
        breakout_mode = str(params.get("breakout_mode") or "").strip()
        if not _DELL_OS10_BREAKOUT_MODE_RE.fullmatch(breakout_mode):
            raise RPCExecutionError(
                "breakout_mode must be in Ng-Mx format, e.g. '40g-1x' or '10g-4x'.",
                code="RPC_PARAM_INVALID",
            )
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "interface_port": interface_port,
            "breakout_mode": breakout_mode,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_port": interface_port,
                "breakout_mode": breakout_mode,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_INTERFACE_FEC:
        params = execution.params or {}
        interface_name = str(params.get("interface_name") or "").strip()
        if not _DELL_OS10_INTERFACE_RE.fullmatch(interface_name):
            raise RPCExecutionError(
                "interface_name must be a valid OS10 interface identifier.",
                code="RPC_PARAM_INVALID",
            )
        fec_mode = str(params.get("fec_mode") or "cl91").strip().lower()
        if fec_mode not in {"cl91", "cl108", "auto", "none"}:
            raise RPCExecutionError(
                "fec_mode must be one of: cl91, cl108, auto, none.",
                code="RPC_PARAM_INVALID",
            )
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "interface_name": interface_name,
            "fec_mode": fec_mode,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_name": interface_name,
                "fec_mode": fec_mode,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == NGINX_1_CONFIG_TEST:
        return _normalize_nginx_node_execution(execution, target, extra_params={})

    if procedure_name == NGINX_1_CONFIG_DEPLOY:
        params = execution.params or {}
        config_content = str(params.get("config_content") or "").strip()
        if not config_content:
            raise RPCExecutionError(
                "config_content must be a non-empty string.", code="RPC_PARAM_INVALID"
            )
        deployment_id = _int_range(params, "deployment_id", 1, None)
        extra: dict[str, Any] = {
            "config_content": config_content,
            "deployment_id": deployment_id,
        }
        config_path = str(params.get("config_path") or "").strip()
        if config_path:
            extra["config_path"] = config_path
        return _normalize_nginx_node_execution(execution, target, extra_params=extra)

    if procedure_name == NGINX_1_RELOAD:
        return _normalize_nginx_node_execution(execution, target, extra_params={})

    if procedure_name == NGINX_1_ROLLBACK:
        params = execution.params or {}
        deployment_id = _int_range(params, "deployment_id", 1, None)
        previous_config = str(params.get("previous_config") or "").strip()
        if not previous_config:
            raise RPCExecutionError(
                "previous_config must be a non-empty string.", code="RPC_PARAM_INVALID"
            )
        extra = {"deployment_id": deployment_id, "previous_config": previous_config}
        return _normalize_nginx_node_execution(execution, target, extra_params=extra)

    if procedure_name == PTERODACTYL_BOOTSTRAP_API_KEY:
        params = execution.params or {}
        container_name = str(
            params.get("container_name") or "pterodactyl-panel-1"
        ).strip()
        if not _PTERODACTYL_CONTAINER_NAME_RE.fullmatch(container_name):
            raise RPCExecutionError(
                "container_name contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        return {
            "target": target,
            "container_name": container_name,
            "command_fingerprint": {"handler_id": execution.procedure.handler_id},
        }

    if procedure_name == PTERODACTYL_ARTISAN:
        params = execution.params or {}
        command = str(params.get("command") or "").strip()
        if command not in _PTERODACTYL_ARTISAN_ALLOWLIST:
            raise RPCExecutionError(
                f"command must be one of: {', '.join(sorted(_PTERODACTYL_ARTISAN_ALLOWLIST))}",
                code="RPC_PARAM_INVALID",
            )
        container_name = str(
            params.get("container_name") or "pterodactyl-panel-1"
        ).strip()
        if not _PTERODACTYL_CONTAINER_NAME_RE.fullmatch(container_name):
            raise RPCExecutionError(
                "container_name contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        return {
            "target": target,
            "command": command,
            "container_name": container_name,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "command": command,
                "container_name": container_name,
            },
        }

    if procedure_name == PTERODACTYL_CONTAINER_LOGS:
        params = execution.params or {}
        container_name = str(
            params.get("container_name") or "pterodactyl-panel-1"
        ).strip()
        if not _PTERODACTYL_CONTAINER_NAME_RE.fullmatch(container_name):
            raise RPCExecutionError(
                "container_name contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        lines = max(1, min(500, int(params.get("lines", 100))))
        return {
            "target": target,
            "container_name": container_name,
            "lines": lines,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "container_name": container_name,
                "lines": lines,
            },
        }

    if procedure_name == MINECRAFT_PLUGIN_INSTALL_URL:
        return _normalize_minecraft_plugin_install_url_execution(execution, target)

    if procedure_name == MINECRAFT_VIAVERSION_INSTALL:
        return _normalize_minecraft_viaversion_install_execution(execution, target)

    if procedure_name == MINECRAFT_PAPERMC_INSTALL:
        return _normalize_minecraft_papermc_install_execution(execution, target)

    if procedure_name == PTERODACTYL_WINGS_STATUS:
        return _normalize_pterodactyl_wings_service_execution(
            execution, target, action="status"
        )

    if procedure_name == PTERODACTYL_WINGS_LOGS:
        normalized = _normalize_pterodactyl_wings_service_execution(
            execution,
            target,
            action="logs",
        )
        lines = max(1, min(500, int((execution.params or {}).get("lines", 100))))
        normalized["lines"] = lines
        normalized["command_fingerprint"]["lines"] = lines
        return normalized

    if procedure_name == PTERODACTYL_WINGS_RESTART:
        return _normalize_pterodactyl_wings_service_execution(
            execution, target, action="restart"
        )

    raise RPCExecutionError(
        f"Procedure {procedure_name!r} has no NetBox normalizer.",
        code="RPC_PROCEDURE_NOT_NORMALIZABLE",
    )


def _normalize_samba_1_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize Samba catalog procedures.

    The backend handlers own Samba command execution and parsing; netbox-rpc
    forwards only bounded, schema-shaped parameters. Caller-supplied path/share
    values are revalidated here so pure-domain execution paths fail closed even
    before nms-backend repeats the same confinement checks.
    """

    params = execution.params or {}
    procedure_name = execution.procedure.name
    normalized: dict[str, Any] = {
        "target": target,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "procedure": procedure_name,
        },
    }

    if procedure_name == SAMBA_1_CONFIG_DEPLOY:
        content = _normalize_samba_config_body(
            params.get("config_content"),
            "config_content",
        )
        normalized["config_content"] = content
        normalized["command_fingerprint"]["config_content_sha256"] = _hash_text(
            content
        )
        normalized["command_fingerprint"]["config_content_bytes"] = len(
            content.encode("utf-8")
        )

    if procedure_name == SAMBA_1_CONFIG_ROLLBACK:
        snapshot_id = _normalize_samba_snapshot_id(params.get("snapshot_id"))
        normalized["snapshot_id"] = snapshot_id
        normalized["command_fingerprint"]["snapshot_id"] = snapshot_id

    if procedure_name in {
        SAMBA_1_INCLUDE_FILE_READ,
        SAMBA_1_INCLUDE_FILE_WRITE,
        SAMBA_1_INCLUDE_FILE_DELETE,
    }:
        include_path = _normalize_samba_include_path(params.get("include_path"))
        normalized["include_path"] = include_path
        normalized["command_fingerprint"]["include_path"] = include_path

    if procedure_name == SAMBA_1_INCLUDE_FILE_WRITE:
        content = _normalize_samba_config_body(params.get("content"), "content")
        normalized["content"] = content
        normalized["command_fingerprint"]["content_sha256"] = _hash_text(content)
        normalized["command_fingerprint"]["content_bytes"] = len(
            content.encode("utf-8")
        )

    if procedure_name in {
        SAMBA_1_SHARE_ACL_READ,
        SAMBA_1_SHARE_UPSERT,
        SAMBA_1_SHARE_DELETE,
    }:
        share_name = _normalize_samba_share_name(params.get("share_name"))
        normalized["share_name"] = share_name
        normalized["command_fingerprint"]["share_name"] = share_name

    if procedure_name == SAMBA_1_SHARE_UPSERT:
        _copy_samba_share_upsert_params(params, normalized)

    if procedure_name == SAMBA_1_SERVICE_CONTROL:
        unit = _normalize_samba_service_unit(params.get("unit"))
        action = _normalize_samba_service_action(params.get("action"))
        systemd_unit = f"{unit}.service"
        normalized["unit"] = unit
        normalized["action"] = action
        normalized["systemd_unit"] = systemd_unit
        normalized["command_fingerprint"]["unit"] = unit
        normalized["command_fingerprint"]["action"] = action
        normalized["command_fingerprint"]["systemd_unit"] = systemd_unit

    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _normalize_samba_config_body(raw_content: object, field_name: str) -> str:
    content = str(raw_content or "")
    if not content.strip():
        raise RPCExecutionError(
            f"{field_name} must be a non-empty string.",
            code="RPC_PARAM_INVALID",
        )
    if "\x00" in content:
        raise RPCExecutionError(
            f"{field_name} must not contain NUL bytes.",
            code="RPC_PARAM_INVALID",
        )
    if len(content) > _SAMBA_MAX_CONFIG_BODY_LEN:
        raise RPCExecutionError(
            f"{field_name} may contain at most {_SAMBA_MAX_CONFIG_BODY_LEN} characters.",
            code="RPC_PARAM_INVALID",
        )
    _validate_samba_config_body_directives(content, field_name)
    return content


def _validate_samba_config_body_directives(content: str, field_name: str) -> None:
    for line_number, raw_name, raw_value in _iter_samba_config_assignments(content):
        name = _normalize_samba_config_param_name(raw_name)
        if not name:
            continue
        if name in _SAMBA_COMMAND_DIRECTIVE_NAMES or name.endswith(
            _SAMBA_COMMAND_DIRECTIVE_SUFFIXES
        ):
            raise RPCExecutionError(
                f"{field_name} line {line_number} uses forbidden Samba command "
                f"directive {raw_name.strip()!r}.",
                code="RPC_PARAM_INVALID",
            )
        if name == "include":
            _validate_samba_config_include_directive(
                raw_value,
                field_name,
                line_number,
            )


def _iter_samba_config_assignments(content: str):
    for line_number, raw_line in _iter_samba_logical_lines(content):
        stripped = raw_line.strip()
        if (
            not stripped
            or stripped.startswith(("#", ";"))
            or stripped.startswith("[")
            or "=" not in raw_line
        ):
            continue
        raw_name, raw_value = raw_line.split("=", 1)
        if not raw_name.strip():
            continue
        yield line_number, raw_name, raw_value


def _iter_samba_logical_lines(content: str):
    """Yield ``(line_number, logical_line)`` after joining smb.conf line
    continuations, exactly the way Samba's own parser does.

    Samba (``lib/util/tini.c``) accumulates characters into one buffer and, when
    a physical line ends in ``\\`` (or ``\\`` followed by whitespace), drops the
    backslash and keeps reading the *next* physical line into the same buffer —
    all **before** the parameter name is split off at ``=``. So
    ``root pree\\`` / ``xec = /bin/sh`` is one logical directive ``root preexec``
    to Samba. Scanning physical lines independently would see two harmless
    fragments and miss the command directive, so we must join first.
    """
    joined = ""
    start_line = None
    for line_number, physical in enumerate(content.splitlines(), start=1):
        if start_line is None:
            start_line = line_number
        # Match tini's trailing-whitespace zap before testing for continuation:
        # a line ending in ``\`` or ``\ `` continues onto the next one.
        trimmed = physical.rstrip()
        if trimmed.endswith("\\"):
            joined += trimmed[:-1]
            continue
        joined += physical
        yield start_line, joined
        joined = ""
        start_line = None
    if start_line is not None:
        # Trailing continuation with no following line: emit what we have.
        yield start_line, joined


def _normalize_samba_config_param_name(raw_name: str) -> str:
    return "".join(str(raw_name).lower().split())


def _validate_samba_config_include_directive(
    raw_value: str,
    field_name: str,
    line_number: int,
) -> None:
    include_target = _strip_samba_config_value(raw_value)
    if include_target.lower() == "registry":
        raise RPCExecutionError(
            f"{field_name} line {line_number} uses forbidden Samba registry include.",
            code="RPC_PARAM_INVALID",
        )
    try:
        _normalize_samba_include_path(include_target)
    except RPCExecutionError as exc:
        raise RPCExecutionError(
            f"{field_name} line {line_number} include target must be confined "
            "under /etc/samba.",
            code="RPC_PARAM_INVALID",
        ) from exc


def _strip_samba_config_value(raw_value: str) -> str:
    value = str(raw_value or "").strip()
    for marker in ("#", ";"):
        value = _strip_samba_inline_comment(value, marker)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


def _strip_samba_inline_comment(value: str, marker: str) -> str:
    for index, char in enumerate(value):
        if char == marker and (index == 0 or value[index - 1].isspace()):
            return value[:index].strip()
    return value.strip()


def _normalize_samba_snapshot_id(raw_snapshot_id: object) -> str:
    snapshot_id = str(raw_snapshot_id or "").strip()
    if not snapshot_id or not _SAMBA_SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise RPCExecutionError(
            "snapshot_id must be a safe backend-issued Samba snapshot identifier.",
            code="RPC_PARAM_INVALID",
        )
    return snapshot_id


def _copy_samba_share_upsert_params(
    params: dict[str, Any],
    normalized: dict[str, Any],
) -> None:
    share_path = _normalize_samba_share_path(params.get("path"))
    normalized["path"] = share_path
    normalized["command_fingerprint"]["path"] = share_path

    comment = _normalize_samba_share_text(params.get("comment"))
    if comment:
        normalized["comment"] = comment
        normalized["command_fingerprint"]["comment_sha256"] = _hash_text(comment)

    for key, default in {
        "read_only": True,
        "browseable": True,
        "guest_ok": False,
    }.items():
        value = _bool_param(params, key, default)
        normalized[key] = value
        normalized["command_fingerprint"][key] = value

    for key in ("valid_users", "write_list"):
        values = _normalize_samba_principal_list(params.get(key), key)
        if values:
            normalized[key] = values
            normalized["command_fingerprint"][key] = values

    for key in ("create_mask", "directory_mask"):
        value = _normalize_samba_octal_mask(params.get(key), key)
        if value:
            normalized[key] = value
            normalized["command_fingerprint"][key] = value

    force_group = _normalize_samba_optional_principal(
        params.get("force_group"),
        "force_group",
    )
    if force_group:
        normalized["force_group"] = force_group
        normalized["command_fingerprint"]["force_group"] = force_group


def _normalize_samba_share_path(raw_path: object) -> str:
    value = str(raw_path or "").strip()
    if not value or len(value) > 255 or not _SAMBA_SHARE_PATH_RE.fullmatch(value):
        raise RPCExecutionError(
            "path must be an absolute safe POSIX path without traversal or shell "
            "metacharacters.",
            code="RPC_PARAM_INVALID",
        )
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or path == PurePosixPath("/"):
        raise RPCExecutionError(
            "path must be an absolute safe POSIX path below a concrete directory.",
            code="RPC_PARAM_INVALID",
        )
    return str(path)


def _normalize_samba_share_text(raw_text: object) -> str:
    text = str(raw_text or "").strip()
    if len(text) > _SAMBA_SHARE_TEXT_MAX_LEN or any(
        ord(ch) < 32 for ch in text
    ):
        raise RPCExecutionError(
            "comment must not contain control characters and may contain at most "
            f"{_SAMBA_SHARE_TEXT_MAX_LEN} characters.",
            code="RPC_PARAM_INVALID",
        )
    return text


def _normalize_samba_principal_list(raw_values: object, field_name: str) -> list[str]:
    if raw_values in (None, ""):
        return []
    if not isinstance(raw_values, (list, tuple)):
        raise RPCExecutionError(
            f"{field_name} must be a list of safe Samba principals.",
            code="RPC_PARAM_INVALID",
        )
    if len(raw_values) > 64:
        raise RPCExecutionError(
            f"{field_name} may contain at most 64 entries.",
            code="RPC_PARAM_INVALID",
        )
    values: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        value = _normalize_samba_optional_principal(raw_value, field_name)
        if not value:
            raise RPCExecutionError(
                f"{field_name} entries must be non-empty.",
                code="RPC_PARAM_INVALID",
            )
        if value in seen:
            raise RPCExecutionError(
                f"{field_name} entries must be unique.",
                code="RPC_PARAM_INVALID",
            )
        seen.add(value)
        values.append(value)
    return values


def _normalize_samba_optional_principal(raw_value: object, field_name: str) -> str:
    value = str(raw_value or "").strip()
    if not value:
        return ""
    if not _SAMBA_PRINCIPAL_RE.fullmatch(value):
        raise RPCExecutionError(
            f"{field_name} must contain only safe Samba principal characters.",
            code="RPC_PARAM_INVALID",
        )
    return value


def _normalize_samba_octal_mask(raw_value: object, field_name: str) -> str:
    value = str(raw_value or "").strip()
    if not value:
        return ""
    if not _SAMBA_MASK_RE.fullmatch(value):
        raise RPCExecutionError(
            f"{field_name} must be a three- or four-digit octal mask.",
            code="RPC_PARAM_INVALID",
        )
    return value


def _normalize_samba_service_unit(raw_unit: object) -> str:
    unit = str(raw_unit or "").strip()
    if unit not in _SAMBA_SERVICE_UNITS:
        raise RPCExecutionError(
            "unit must be one of: samba-ad-dc, smbd, nmbd, winbind.",
            code="RPC_PARAM_INVALID",
        )
    return unit


def _normalize_samba_service_action(raw_action: object) -> str:
    action = str(raw_action or "").strip()
    if action not in _SAMBA_SERVICE_ACTIONS:
        raise RPCExecutionError(
            "action must be one of: start, stop, restart, reload.",
            code="RPC_PARAM_INVALID",
        )
    return action


def _normalize_samba_include_path(raw_path: object) -> str:
    value = str(raw_path or "").strip()
    if (
        not value
        or len(value) > 255
        or not _SAMBA_INCLUDE_FILE_RE.fullmatch(value)
    ):
        raise RPCExecutionError(
            "include_path must be a .conf file under /etc/samba without traversal "
            "or shell metacharacters.",
            code="RPC_PARAM_INVALID",
        )

    path = PurePosixPath(value)
    confined_path = path if path.is_absolute() else _SAMBA_CONF_ROOT / path
    if (
        ".." in confined_path.parts
        or not confined_path.is_relative_to(_SAMBA_CONF_ROOT)
        or confined_path == _SAMBA_CONF_ROOT
    ):
        raise RPCExecutionError(
            "include_path must be confined under /etc/samba.",
            code="RPC_PARAM_INVALID",
        )
    # Return the resolved absolute path, not the caller's raw value. The command
    # rows run `cat {include_path}`, so returning a relative value would read the
    # file relative to the backend process cwd instead of /etc/samba.
    return str(confined_path)


def _normalize_samba_share_name(raw_name: object) -> str:
    share_name = str(raw_name or "").strip()
    if not share_name or not _SAMBA_SHARE_NAME_RE.fullmatch(share_name):
        raise RPCExecutionError(
            "share_name must be a safe Samba share name without shell metacharacters.",
            code="RPC_PARAM_INVALID",
        )
    return share_name


def _normalize_passbolt_migration_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize approval-gated Passbolt migration helper params.

    The backend handlers own execution; netbox-rpc forwards only validated
    runtime parameters and a redacted fingerprint. No DB password, DB dump,
    GPG/JWT content, private key, or archive bytes are accepted or recorded here.
    """

    params = execution.params or {}
    procedure_name = execution.procedure.name
    normalized: dict[str, Any] = {
        "target": target,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "procedure": procedure_name,
        },
    }
    _copy_required_ssh_overrides(params, normalized)

    if procedure_name == PASSBOLT_EXPORT_SECRETS:
        _copy_passbolt_field(params, normalized, "app_container_name", "container")
        _copy_passbolt_field(params, normalized, "db_container_name", "container")
        _copy_passbolt_field(params, normalized, "db_name", "db_name")
        _copy_passbolt_field(params, normalized, "db_host", "host")
        normalized["db_port"] = _int_range(params, "db_port", 1, 65535)
        normalized["command_fingerprint"]["db_port"] = normalized["db_port"]
        _copy_passbolt_field(params, normalized, "db_user_env", "env")
        _copy_passbolt_field(params, normalized, "db_password_env", "env")
        _copy_passbolt_path(params, normalized, "gpg_dir", "/etc/passbolt/gpg")
        _copy_passbolt_path(params, normalized, "jwt_dir", "/etc/passbolt/jwt")
        _copy_passbolt_path(params, normalized, "staging_dir", None)
        return normalized

    if procedure_name == PASSBOLT_TRANSFER_SECRETS:
        _copy_passbolt_path(params, normalized, "source_staging_dir", None)
        _copy_passbolt_field(params, normalized, "target_host", "host")
        _copy_passbolt_field(params, normalized, "target_ssh_user", "posix_user")
        normalized["target_ssh_port"] = _int_range(params, "target_ssh_port", 1, 65535)
        normalized["command_fingerprint"]["target_ssh_port"] = normalized[
            "target_ssh_port"
        ]
        _copy_passbolt_path(params, normalized, "target_staging_dir", None)
        return normalized

    if procedure_name == PASSBOLT_IMPORT_SECRETS:
        _copy_passbolt_path(params, normalized, "staging_dir", None)
        _copy_passbolt_field(params, normalized, "db_name", "db_name")
        _copy_passbolt_path(params, normalized, "gpg_dest_dir", "/etc/passbolt/gpg")
        _copy_passbolt_path(params, normalized, "jwt_dest_dir", "/etc/passbolt/jwt")
        _copy_passbolt_path(
            params,
            normalized,
            "cake_bin_path",
            "/usr/share/php/passbolt/bin/cake",
        )
        return normalized

    if procedure_name == PASSBOLT_CLEANUP:
        _copy_passbolt_path(params, normalized, "source_staging_dir", None)
        _copy_passbolt_field(params, normalized, "target_host", "host")
        _copy_passbolt_field(params, normalized, "target_ssh_user", "posix_user")
        normalized["target_ssh_port"] = _int_range(params, "target_ssh_port", 1, 65535)
        normalized["command_fingerprint"]["target_ssh_port"] = normalized[
            "target_ssh_port"
        ]
        _copy_passbolt_path(params, normalized, "target_staging_dir", None)
        return normalized

    raise RPCExecutionError(
        f"Procedure {procedure_name!r} is not a Passbolt migration procedure.",
        code="RPC_PARAM_INVALID",
    )


def _copy_required_ssh_overrides(
    params: dict[str, Any],
    normalized: dict[str, Any],
) -> None:
    _copy_optional_ssh_overrides(params, normalized)
    if "rpc_ssh_host" not in normalized or "rpc_ssh_credential_pk" not in normalized:
        raise RPCExecutionError(
            "rpc_ssh_host and rpc_ssh_credential_pk are required.",
            code="RPC_PARAM_INVALID",
        )
    host = str(normalized["rpc_ssh_host"])
    if not _PASSBOLT_HOST_RE.fullmatch(host):
        raise RPCExecutionError(
            "rpc_ssh_host must be a DNS name or IP address without shell metacharacters.",
            code="RPC_PARAM_INVALID",
        )


def _copy_passbolt_field(
    params: dict[str, Any],
    normalized: dict[str, Any],
    key: str,
    kind: str,
) -> None:
    value = str(params.get(key) or "").strip()
    if not value:
        raise RPCExecutionError(f"{key} is required.", code="RPC_PARAM_INVALID")
    validators = {
        "container": (_PASSBOLT_SAFE_NAME_RE, "must be a safe Docker container name"),
        "db_name": (_PASSBOLT_DB_NAME_RE, "must contain only letters, digits, and _"),
        "env": (_PASSBOLT_ENV_NAME_RE, "must be a valid environment variable name"),
        "host": (_PASSBOLT_HOST_RE, "must be a DNS name or IP address"),
        "posix_user": (_PASSBOLT_POSIX_USER_RE, "must be a POSIX username"),
    }
    pattern, message = validators[kind]
    if not pattern.fullmatch(value):
        raise RPCExecutionError(f"{key} {message}.", code="RPC_PARAM_INVALID")
    normalized[key] = value
    normalized["command_fingerprint"][key] = value


def _copy_passbolt_path(
    params: dict[str, Any],
    normalized: dict[str, Any],
    key: str,
    default: str | None,
) -> None:
    raw = params.get(key)
    value = str(raw if raw not in (None, "") else default or "").strip()
    if not value:
        raise RPCExecutionError(f"{key} is required.", code="RPC_PARAM_INVALID")
    if not _PASSBOLT_PATH_SAFE_CHARS_RE.fullmatch(value):
        raise RPCExecutionError(
            f"{key} must be an absolute safe path without traversal or shell metacharacters.",
            code="RPC_PARAM_INVALID",
        )
    path = PurePosixPath("/" + value.lstrip("/"))
    if ".." in path.parts:
        raise RPCExecutionError(
            f"{key} must be an absolute safe path without traversal or shell metacharacters.",
            code="RPC_PARAM_INVALID",
        )
    if any(
        path == PurePosixPath(blocked) or PurePosixPath(blocked).is_relative_to(path)
        for blocked in _PASSBOLT_BROAD_DIRS
    ):
        raise RPCExecutionError(
            f"{key} must not be a root or broad system directory.",
            code="RPC_PARAM_INVALID",
        )
    normalized[key] = value
    normalized["command_fingerprint"][key] = value


def _normalize_minecraft_plugin_install_url_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    server_uuid = _minecraft_server_uuid(params)
    source_url = _minecraft_public_url(params.get("source_url"))
    filename = _minecraft_jar_filename(params.get("filename"), "filename")
    restart = _bool_param(params, "restart", False)
    normalized = {
        "target": target,
        "server_uuid": server_uuid,
        "source_url": source_url,
        "filename": filename,
        "restart": restart,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "server_uuid": server_uuid,
            "source_url_sha256": _hash_text(source_url),
            "filename": filename,
            "restart": restart,
        },
    }
    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _normalize_minecraft_viaversion_install_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    server_uuid = _minecraft_server_uuid(params)
    raw_plugins = params.get("plugins")
    if raw_plugins:
        if not isinstance(raw_plugins, list):
            raise RPCExecutionError("plugins must be a list.", code="RPC_PARAM_INVALID")
        plugins = tuple(str(item).strip().lower() for item in raw_plugins)
        if not plugins or len(plugins) > 3 or len(set(plugins)) != len(plugins):
            raise RPCExecutionError(
                "plugins must contain one to three unique entries.",
                code="RPC_PARAM_INVALID",
            )
        if any(plugin not in _MINECRAFT_VIAVERSION_PLUGINS for plugin in plugins):
            raise RPCExecutionError(
                "plugins must be viaversion, viabackwards, and/or viarewind.",
                code="RPC_PARAM_INVALID",
            )
        ordered = [
            plugin
            for plugin in ("viaversion", "viabackwards", "viarewind")
            if plugin in plugins
        ]
        plugins = tuple(ordered)
        preset = "custom"
    else:
        preset = str(params.get("preset") or "standard").strip().lower()
        if preset not in _MINECRAFT_VIAVERSION_PRESETS:
            raise RPCExecutionError(
                "preset must be minimal, standard, or full.",
                code="RPC_PARAM_INVALID",
            )
        plugins = _MINECRAFT_VIAVERSION_PRESETS[preset]
    restart = _bool_param(params, "restart", False)
    normalized = {
        "target": target,
        "server_uuid": server_uuid,
        "preset": preset,
        "plugins": list(plugins),
        "restart": restart,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "server_uuid": server_uuid,
            "preset": preset,
            "plugins": list(plugins),
            "restart": restart,
        },
    }
    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _normalize_minecraft_papermc_install_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    server_uuid = _minecraft_server_uuid(params)
    project = str(params.get("project") or "").strip().lower()
    if project not in _MINECRAFT_PAPERMC_PROJECTS:
        raise RPCExecutionError(
            "project must be paper, folia, or velocity.",
            code="RPC_PARAM_INVALID",
        )
    version = str(params.get("version") or "").strip()
    if not _MINECRAFT_VERSION_RE.fullmatch(version):
        raise RPCExecutionError(
            "version must be a safe PaperMC version identifier.",
            code="RPC_PARAM_INVALID",
        )
    server_jarfile = _minecraft_jar_filename(
        params.get("server_jarfile") or "server.jar",
        "server_jarfile",
    )
    restart = _bool_param(params, "restart", False)
    normalized = {
        "target": target,
        "server_uuid": server_uuid,
        "project": project,
        "version": version,
        "server_jarfile": server_jarfile,
        "restart": restart,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "server_uuid": server_uuid,
            "project": project,
            "version": version,
            "server_jarfile": server_jarfile,
            "restart": restart,
        },
    }
    build_id = _optional_int_range(params, "build_id", 1, None)
    if build_id is not None:
        normalized["build_id"] = build_id
        normalized["command_fingerprint"]["build_id"] = build_id
    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _normalize_pterodactyl_wings_service_execution(
    execution: RPCExecution,
    target: str,
    *,
    action: str,
) -> dict[str, Any]:
    params = execution.params or {}
    normalized = {
        "target": target,
        "service_name": "wings.service",
        "action": action,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "service_name": "wings.service",
            "action": action,
        },
    }
    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _minecraft_server_uuid(params: dict[str, Any]) -> str:
    server_uuid = str(params.get("server_uuid") or "").strip()
    if not _MINECRAFT_SERVER_UUID_RE.fullmatch(server_uuid):
        raise RPCExecutionError(
            "server_uuid must be a canonical UUID.",
            code="RPC_PARAM_INVALID",
        )
    return server_uuid.lower()


def _minecraft_jar_filename(raw: object, field_name: str) -> str:
    filename = str(raw or "").strip()
    if (
        not _MINECRAFT_JAR_FILENAME_RE.fullmatch(filename)
        or ".." in filename
        or "/" in filename
        or "\\" in filename
    ):
        raise RPCExecutionError(
            f"{field_name} must be a safe .jar filename.",
            code="RPC_PARAM_INVALID",
        )
    return filename


def _minecraft_public_url(raw: object) -> str:
    value = str(raw or "").strip()
    if len(value) > 2048:
        raise RPCExecutionError(
            "source_url may contain at most 2048 characters.",
            code="RPC_PARAM_INVALID",
        )
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
    ):
        raise RPCExecutionError(
            "source_url must be an http(s) URL.",
            code="RPC_PARAM_INVALID",
        )
    host = parsed.hostname.strip().lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise RPCExecutionError(
            "source_url host is not allowed.",
            code="RPC_PARAM_INVALID",
        )
    try:
        ip = ip_address(host)
    except ValueError:
        pass
    else:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            raise RPCExecutionError(
                "source_url must not point to a private or local IP address.",
                code="RPC_PARAM_INVALID",
            )
    if any(ord(ch) < 32 for ch in value):
        raise RPCExecutionError(
            "source_url must not contain control characters.",
            code="RPC_PARAM_INVALID",
        )
    return value


def _normalize_nginx_node_execution(
    execution: RPCExecution,
    target: str,
    extra_params: dict[str, Any],
) -> dict[str, Any]:
    params = execution.params or {}
    node_id = _int_range(params, "node_id", 1, None)
    result: dict[str, Any] = {
        "target": target,
        "node_id": node_id,
        **extra_params,
    }
    result["command_fingerprint"] = {
        "handler_id": execution.procedure.handler_id,
        "node_id": node_id,
    }
    return result


def _normalize_linux_service_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    slug = str((execution.params or {}).get("service_slug") or "").strip()
    allow = RPCLinuxServiceAllowlist.objects.filter(slug=slug, enabled=True).first()
    if allow is None:
        raise RPCExecutionError(
            f"Linux service {slug!r} is not allowlisted.",
            code="RPC_LINUX_SERVICE_NOT_ALLOWLISTED",
        )
    target_models = set(allow.target_models or [])
    if target_models and execution.target_model_label not in target_models:
        raise RPCExecutionError(
            f"Linux service {slug!r} is not allowed for {execution.target_model_label}.",
            code="RPC_LINUX_SERVICE_TARGET_DENIED",
        )
    unit = allow.systemd_unit
    result = {
        "target": target,
        "service_slug": slug,
        "systemd_unit": unit,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "systemd_unit": unit,
        },
    }
    if allow.ssh_credential_override_id is not None:
        result["rpc_ssh_credential_pk"] = allow.ssh_credential_override_id
    return result


def _normalize_ssh_install_key_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for os.linux.ubuntu.24.install_ssh_key.

    Validates that public_key is a single-line OpenSSH key (no newlines),
    extracts the optional username, and builds the normalized dict for
    nms-backend to execute the authorized_keys append via SSH.
    """
    params = execution.params or {}
    public_key = str(params.get("public_key") or "").strip()
    if not public_key:
        raise RPCExecutionError("public_key is required.", code="RPC_PARAM_INVALID")
    if "\n" in public_key or "\r" in public_key:
        raise RPCExecutionError(
            "public_key must be a single line without newlines.",
            code="RPC_PARAM_INVALID",
        )
    if not any(
        public_key.startswith(prefix)
        for prefix in ("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")
    ):
        raise RPCExecutionError(
            "public_key must start with a supported key type prefix.",
            code="RPC_PARAM_INVALID",
        )
    # Strip any comment field — only key-type + base64-blob is forwarded to nms-backend.
    # This eliminates comment-field characters from the authorized_keys append path.
    key_parts = public_key.split(None, 2)
    public_key = " ".join(key_parts[:2]) if len(key_parts) >= 2 else public_key

    result: dict[str, Any] = {
        "target": target,
        "public_key": public_key,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "public_key_prefix": public_key[:64],
        },
    }

    username = str(params.get("username") or "").strip()
    if username:
        if not _POSIX_USERNAME_RE.fullmatch(username):
            raise RPCExecutionError(
                "username must be a valid POSIX username "
                "(lowercase letters, digits, _ or -; starts with letter or _; max 32 chars).",
                code="RPC_PARAM_INVALID",
            )
        result["username"] = username

    return result


def _normalize_dns_host_deploy_execution(execution: RPCExecution) -> dict[str, Any]:
    """Normalize the audited DNS stack deploy procedure for an arbitrary SSH host."""
    normalized = _normalize_dns_host_execution(execution)
    force_recreate = _bool_param(execution.params or {}, "force_recreate", False)
    normalized["force_recreate"] = force_recreate
    normalized["command_fingerprint"]["force_recreate"] = force_recreate
    return normalized


def _normalize_dns_host_status_execution(execution: RPCExecution) -> dict[str, Any]:
    """Normalize the read-only DNS stack status procedure for an arbitrary SSH host."""
    return _normalize_dns_host_execution(execution)


def _normalize_dns_host_execution(execution: RPCExecution) -> dict[str, Any]:
    params = execution.params or {}
    target = str(params.get("target") or "").strip()
    if not _DNS_HOST_TARGET_RE.fullmatch(target):
        raise RPCExecutionError(
            "target must be a short DNS host name such as dns01 or dns02.",
            code="RPC_PARAM_INVALID",
        )

    credential_pk = _int_range(params, "rpc_ssh_credential_pk", 1, None)
    host = str(params.get("rpc_ssh_host") or "").strip()
    if not host:
        domain = _default_dns_host_domain()
        if not domain:
            raise RPCExecutionError(
                "rpc_ssh_host is required: pass it explicitly, or configure the "
                "netbox_rpc 'dns_host_domain' plugin setting to derive "
                "'<target>.<domain>'.",
                code="RPC_PARAM_INVALID",
            )
        host = f"{target}.{domain}"
    _validate_dns_host_ssh_host(host)
    ssh_port = _optional_int_range(params, "rpc_ssh_port", 1, 65535) or 22
    known_hosts_entry = str(params.get("rpc_ssh_known_hosts_entry") or "")
    if "\n" in known_hosts_entry or "\r" in known_hosts_entry:
        raise RPCExecutionError(
            "rpc_ssh_known_hosts_entry must be a single line.",
            code="RPC_PARAM_INVALID",
        )
    if len(known_hosts_entry) > 8192:
        raise RPCExecutionError(
            "rpc_ssh_known_hosts_entry may contain at most 8192 characters.",
            code="RPC_PARAM_INVALID",
        )

    return {
        "target": target,
        "rpc_ssh_host": host,
        "rpc_ssh_port": ssh_port,
        "rpc_ssh_credential_pk": credential_pk,
        "rpc_ssh_known_hosts_entry": known_hosts_entry,
        "rpc_ssh_strict_host_key_checking": _bool_param(
            params, "rpc_ssh_strict_host_key_checking", True
        ),
        "compose_project": _DNS_HOST_COMPOSE_PROJECT,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "procedure": execution.procedure.name,
            "target": target,
            "compose_project": _DNS_HOST_COMPOSE_PROJECT,
            "rpc_ssh_host": host,
            "rpc_ssh_port": ssh_port,
        },
    }


def _validate_ssh_host(host: str, *, empty_message: str) -> None:
    if not host:
        raise RPCExecutionError(
            empty_message,
            code="RPC_PARAM_INVALID",
        )
    if len(host) > 255:
        raise RPCExecutionError(
            "rpc_ssh_host may contain at most 255 characters.",
            code="RPC_PARAM_INVALID",
        )
    if any(ch.isspace() or ord(ch) < 32 for ch in host):
        raise RPCExecutionError(
            "rpc_ssh_host must not contain whitespace or control characters.",
            code="RPC_PARAM_INVALID",
        )


def _validate_dns_host_ssh_host(host: str) -> None:
    _validate_ssh_host(
        host,
        empty_message="rpc_ssh_host could not be resolved from params.",
    )


def _normalize_nmap_execution(execution: RPCExecution) -> dict[str, Any]:
    """Normalize a read-only nmap scan execution.

    nmap receives only a validated IPv4/CIDR/hostname target, an enum scan
    type, and a tightly bounded port selector. There is no raw command text.
    """
    params = execution.params or {}
    target = _normalize_nmap_target(params.get("target"))
    scan_type = str(params.get("scan_type") or "connect").strip()
    if scan_type not in _NMAP_SCAN_TYPES:
        raise RPCExecutionError(
            "scan_type must be one of: connect, syn, os-detect.",
            code="RPC_PARAM_INVALID",
        )

    normalized: dict[str, Any] = {
        "target": target,
        "scan_type": scan_type,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "procedure": execution.procedure.name,
            "target": target,
            "scan_type": scan_type,
        },
    }

    ports = _normalize_nmap_ports(params.get("ports")) if "ports" in params else ""
    if ports:
        normalized["ports"] = ports
        normalized["command_fingerprint"]["ports"] = ports

    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _normalize_nmap_target(raw_target: object) -> str:
    target = str(raw_target or "").strip()
    if not target:
        raise RPCExecutionError(
            "target is required.",
            code="RPC_PARAM_INVALID",
        )
    if any(ch.isspace() or ord(ch) < 32 for ch in target):
        raise RPCExecutionError(
            "target must not contain whitespace or control characters.",
            code="RPC_PARAM_INVALID",
        )

    if "/" in target:
        try:
            network = ip_network(target, strict=True)
        except ValueError as exc:
            raise RPCExecutionError(
                "target CIDR must be a valid IPv4 network.",
                code="RPC_PARAM_INVALID",
            ) from exc
        if network.version != 4:
            raise RPCExecutionError(
                "target CIDR must be IPv4.",
                code="RPC_PARAM_INVALID",
            )
        if network.num_addresses > _NMAP_MAX_CIDR_HOSTS:
            raise RPCExecutionError(
                "target CIDR is too broad; use a network no larger than "
                f"/{_NMAP_MIN_CIDR_PREFIXLEN} ({_NMAP_MAX_CIDR_HOSTS} addresses).",
                code="RPC_PARAM_INVALID",
            )
        return str(network)

    try:
        address = ip_address(target)
    except ValueError:
        pass
    else:
        if address.version != 4:
            raise RPCExecutionError(
                "target IP address must be IPv4.",
                code="RPC_PARAM_INVALID",
            )
        return str(address)

    if _NMAP_HOSTNAME_RE.fullmatch(target):
        return target.lower()

    raise RPCExecutionError(
        "target must be an IPv4 address, IPv4 CIDR, or strict hostname.",
        code="RPC_PARAM_INVALID",
    )


def _normalize_nmap_ports(raw_ports: object) -> str:
    if raw_ports is None:
        return ""

    if isinstance(raw_ports, str):
        ports = raw_ports.strip()
        if not ports:
            raise RPCExecutionError(
                "ports must not be empty when provided.",
                code="RPC_PARAM_INVALID",
            )
        if any(ch.isspace() or ord(ch) < 32 for ch in ports):
            raise RPCExecutionError(
                "ports must not contain whitespace or control characters.",
                code="RPC_PARAM_INVALID",
            )
        return _normalize_nmap_port_tokens(ports.split(","))

    if isinstance(raw_ports, (list, tuple)):
        if not raw_ports:
            raise RPCExecutionError(
                "ports must not be empty when provided.",
                code="RPC_PARAM_INVALID",
            )
        if len(raw_ports) > 32:
            raise RPCExecutionError(
                "ports may contain at most 32 entries.",
                code="RPC_PARAM_INVALID",
            )
        normalized_ports: list[str] = []
        for value in raw_ports:
            if isinstance(value, bool) or not isinstance(value, int):
                raise RPCExecutionError(
                    "ports entries must be integers.",
                    code="RPC_PARAM_INVALID",
                )
            if not 1 <= value <= 65535:
                raise RPCExecutionError(
                    "ports entries must be between 1 and 65535.",
                    code="RPC_PARAM_INVALID",
                )
            normalized_ports.append(str(value))
        return ",".join(normalized_ports)

    raise RPCExecutionError(
        "ports must be a comma-separated string or list of integers.",
        code="RPC_PARAM_INVALID",
    )


def _normalize_nmap_port_tokens(tokens: list[str]) -> str:
    if len(tokens) > 32:
        raise RPCExecutionError(
            "ports may contain at most 32 entries.",
            code="RPC_PARAM_INVALID",
        )
    normalized: list[str] = []
    for token in tokens:
        if not _NMAP_PORT_TOKEN_RE.fullmatch(token):
            raise RPCExecutionError(
                "ports must contain only integers or integer ranges.",
                code="RPC_PARAM_INVALID",
            )
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise RPCExecutionError(
                    "ports ranges must be ascending.",
                    code="RPC_PARAM_INVALID",
                )
            if not 1 <= start <= 65535 or not 1 <= end <= 65535:
                raise RPCExecutionError(
                    "ports entries must be between 1 and 65535.",
                    code="RPC_PARAM_INVALID",
                )
            normalized.append(f"{start}-{end}")
            continue

        port = int(token)
        if not 1 <= port <= 65535:
            raise RPCExecutionError(
                "ports entries must be between 1 and 65535.",
                code="RPC_PARAM_INVALID",
            )
        normalized.append(str(port))
    return ",".join(normalized)


_OOKLA_ABS_PATH_RE = re.compile(r"^/[A-Za-z0-9/._-]{1,255}$")


def _normalize_ookla_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize a read-only Ookla/Speedtest diagnostic execution.

    Targets a registered device/VM (SSH resolved from its DeviceService) or an
    ad-hoc/saved host via the ``rpc_ssh_host`` + ``rpc_ssh_credential_pk``
    overrides. Only structured, validated fields are emitted; there is never any
    arbitrary SSH command text.
    """
    params = execution.params or {}
    normalized: dict[str, Any] = {
        "target": target,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "procedure": execution.procedure.name,
        },
    }

    install_dir = str(params.get("install_dir") or "").strip()
    if install_dir:
        if not _OOKLA_ABS_PATH_RE.fullmatch(install_dir):
            raise RPCExecutionError(
                "install_dir must be an absolute path (/... up to 255 safe chars).",
                code="RPC_PARAM_INVALID",
            )
        normalized["install_dir"] = install_dir
        normalized["command_fingerprint"]["install_dir"] = install_dir

    config_path = str(params.get("config_path") or "").strip()
    if config_path:
        if not _OOKLA_ABS_PATH_RE.fullmatch(config_path):
            raise RPCExecutionError(
                "config_path must be an absolute path (/... up to 255 safe chars).",
                code="RPC_PARAM_INVALID",
            )
        normalized["config_path"] = config_path
        normalized["command_fingerprint"]["config_path"] = config_path

    if "ports" in params and params.get("ports") is not None:
        raw_ports = params.get("ports")
        if not isinstance(raw_ports, (list, tuple)):
            raise RPCExecutionError(
                "ports must be a list of integers.",
                code="RPC_PARAM_INVALID",
            )
        if len(raw_ports) > 16:
            raise RPCExecutionError(
                "ports may contain at most 16 entries.",
                code="RPC_PARAM_INVALID",
            )
        ports: list[int] = []
        for value in raw_ports:
            if isinstance(value, bool) or not isinstance(value, int):
                raise RPCExecutionError(
                    "ports entries must be integers.",
                    code="RPC_PARAM_INVALID",
                )
            if not 1 <= value <= 65535:
                raise RPCExecutionError(
                    "ports entries must be between 1 and 65535.",
                    code="RPC_PARAM_INVALID",
                )
            ports.append(value)
        if ports:
            normalized["ports"] = ports
            normalized["command_fingerprint"]["ports"] = ports

    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _normalize_linux_agent_install_execution(
    execution: RPCExecution,
    target: str,
    *,
    zabbix_server: bool = False,
) -> dict[str, Any]:
    params = execution.params or {}
    normalized: dict[str, Any] = {
        "target": target,
        "command_fingerprint": {"handler_id": execution.procedure.handler_id},
    }
    if zabbix_server:
        raw_server = (
            str(params.get("zabbix_server") or "").strip() or _default_zabbix_server()
        )
        if not raw_server:
            raise RPCExecutionError(
                "zabbix_server is required: pass it explicitly, or configure the "
                "netbox_rpc 'default_zabbix_server' plugin setting.",
                code="RPC_PARAM_INVALID",
            )
        server = _normalize_zabbix_server(raw_server)
        normalized["zabbix_server"] = server
        normalized["command_fingerprint"]["zabbix_server"] = server
    _copy_optional_ssh_overrides(params, normalized)
    return normalized


def _normalize_convert_mellanox_nic_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for os.linux.proxmox.convert_mellanox_nic_to_ethernet.

    Resolves SSH connection details for the selected ProxmoxEndpoint through the
    netbox-nms ``resolve_proxmox_endpoint_ssh`` helper and emits the
    ``rpc_ssh_*`` host-override keys that nms-backend consumes. The import is
    function-local so importing this module never requires the (possibly older)
    installed netbox-nms to expose ``proxmox_ssh`` — only an actual Mellanox
    execution does.
    """
    params = execution.params or {}
    endpoint_id = _int_range(params, "proxmox_endpoint_id", 1, None)
    resolved = _resolve_proxmox_ssh_binding(endpoint_id)

    reboot = bool(params.get("reboot", False))
    apply_network = bool(params.get("apply_network", False))
    dry_run = bool(params.get("dry_run", False))
    interfaces_content = str(params.get("interfaces_content") or "")
    # Operator bond parameters. The params_schema (migration 0010) gates the
    # accepted shapes at execution creation, and nms-backend re-validates them
    # strictly in Pydantic before any shell embedding.
    bond_name = str(params.get("bond_name") or "bond1").strip() or "bond1"
    bond_vlans = str(params.get("bond_vlans") or "").strip().replace(" ", "")
    bond_mtu = _int_range(
        {"bond_mtu": params.get("bond_mtu", 9216)}, "bond_mtu", 576, 9216
    )

    normalized: dict[str, Any] = {
        "target": target,
        "rpc_ssh_host": resolved["host"],
        "rpc_ssh_port": int(resolved.get("port") or 22),
        "rpc_ssh_credential_pk": int(resolved["credential_pk"]),
        "rpc_ssh_known_hosts_entry": str(resolved.get("known_hosts_entry") or ""),
        "rpc_ssh_strict_host_key_checking": bool(
            resolved.get("strict_host_key_checking", True)
        ),
        "reboot": reboot,
        "apply_network": apply_network,
        "interfaces_content": interfaces_content,
        "dry_run": dry_run,
        "bond_name": bond_name,
        "bond_vlans": bond_vlans,
        "bond_mtu": bond_mtu,
    }
    normalized["command_fingerprint"] = {
        "handler_id": execution.procedure.handler_id,
        "proxmox_endpoint_id": endpoint_id,
        "reboot": reboot,
        "apply_network": apply_network,
        "dry_run": dry_run,
        "bond_name": bond_name,
        "bond_vlans": bond_vlans,
        "bond_mtu": bond_mtu,
        # Hash (not the body) of any custom interfaces content keeps the
        # fingerprint stable-sized while still reflecting content changes.
        "interfaces_content_sha": _hash_json(interfaces_content)
        if interfaces_content
        else "",
    }
    return normalized


def _normalize_show_systemctl_services_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for os.linux.proxmox.show_systemctl_services.

    Unlike _normalize_convert_mellanox_nic_execution and
    _normalize_proxmox_qemu_vm_lifecycle_execution, this read-only procedure
    does NOT resolve the netbox-nms ProxmoxEndpointSSHBinding and emits no
    rpc_ssh_* keys. The execution backend resolves the SSH connection
    downstream from the endpoint's OWN stored credential (fetched from
    netbox-proxbox's SSH-credential secrets API), so only proxmox_endpoint_id
    and a validated units list are forwarded.
    """
    params = execution.params or {}
    endpoint_id = _int_range(params, "proxmox_endpoint_id", 1, None)

    # Audit integrity: the SSH target the backend resolves (proxmox_endpoint_id)
    # must match the execution's audited target object. Otherwise a caller could
    # target ProxmoxEndpoint A in NetBox while reading services from endpoint B.
    assigned_id = getattr(execution, "assigned_object_id", None)
    if assigned_id is not None and int(assigned_id) != endpoint_id:
        raise RPCExecutionError(
            "proxmox_endpoint_id must match the execution target object.",
            code="RPC_PARAM_INVALID",
        )

    units: list[str] = []
    raw_units = params.get("units")
    if raw_units not in (None, ""):
        if not isinstance(raw_units, (list, tuple)):
            raise RPCExecutionError(
                "units must be a list of systemd unit names.",
                code="RPC_PARAM_INVALID",
            )
        if len(raw_units) > _MAX_SYSTEMCTL_UNITS:
            raise RPCExecutionError(
                f"units may contain at most {_MAX_SYSTEMCTL_UNITS} entries.",
                code="RPC_PARAM_INVALID",
            )
        for value in raw_units:
            if not isinstance(value, str):
                raise RPCExecutionError(
                    "each units entry must be a string systemd unit name.",
                    code="RPC_PARAM_INVALID",
                )
            name = value.strip()
            if (
                not name
                or len(name) > 100
                or not _SYSTEMCTL_UNIT_NAME_RE.fullmatch(name)
            ):
                raise RPCExecutionError(
                    "each units entry must be a valid systemd unit name.",
                    code="RPC_PARAM_INVALID",
                )
            units.append(name)

    normalized: dict[str, Any] = {
        "target": target,
        "proxmox_endpoint_id": endpoint_id,
        "units": units,
    }
    normalized["command_fingerprint"] = {
        "handler_id": execution.procedure.handler_id,
        "proxmox_endpoint_id": endpoint_id,
        "units": units,
    }
    return normalized


def _normalize_proxmox_qemu_vm_lifecycle_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize a constrained Proxmox QEMU VM lifecycle request."""
    params = execution.params or {}
    endpoint_id = _int_range(params, "proxmox_endpoint_id", 1, None)
    resolved = _resolve_proxmox_ssh_binding(endpoint_id)
    operations = _proxmox_operations(params)
    vmid = _optional_int_range(params, "vmid", 100, 999999999)

    normalized: dict[str, Any] = {
        "target": target,
        "rpc_ssh_host": resolved["host"],
        "rpc_ssh_port": int(resolved.get("port") or 22),
        "rpc_ssh_credential_pk": int(resolved["credential_pk"]),
        "rpc_ssh_known_hosts_entry": str(resolved.get("known_hosts_entry") or ""),
        "rpc_ssh_strict_host_key_checking": bool(
            resolved.get("strict_host_key_checking", True)
        ),
        "proxmox_endpoint_id": endpoint_id,
        "operations": operations,
    }
    if vmid is not None:
        normalized["vmid"] = vmid

    command_fingerprint: dict[str, Any] = {
        "handler_id": execution.procedure.handler_id,
        "proxmox_endpoint_id": endpoint_id,
        "operations": operations,
    }
    if vmid is not None:
        command_fingerprint["vmid"] = vmid

    for key, regex in (
        ("name", _PROXMOX_VM_NAME_RE),
        ("source_node", _PROXMOX_NODE_RE),
        ("node", _PROXMOX_NODE_RE),
        ("target_node", _PROXMOX_NODE_RE),
        ("storage", _PROXMOX_STORAGE_RE),
        ("target_storage", _PROXMOX_STORAGE_RE),
    ):
        value = _optional_regex_param(params, key, regex)
        if value:
            normalized[key] = value
            command_fingerprint[key] = value

    for key, minimum, maximum in (
        ("template_vmid", 100, 999999999),
        ("memory_mb", 128, 1048576),
        ("cores", 1, 512),
        ("disk_gb", 1, 262144),
        ("guest_credential_pk", 1, None),
    ):
        value = _optional_int_range(params, key, minimum, maximum)
        if value is not None:
            normalized[key] = value
            command_fingerprint[key] = value

    if "full_clone" in params:
        normalized["full_clone"] = _bool_param(params, "full_clone", True)
    else:
        normalized["full_clone"] = True
    command_fingerprint["full_clone"] = normalized["full_clone"]

    normalized["agent_enabled"] = _bool_param(params, "agent_enabled", True)
    command_fingerprint["agent_enabled"] = normalized["agent_enabled"]

    ciuser = str(params.get("ciuser") or "").strip()
    if ciuser:
        if not _POSIX_USERNAME_RE.fullmatch(ciuser):
            raise RPCExecutionError(
                "ciuser must be a valid POSIX username.", code="RPC_PARAM_INVALID"
            )
        normalized["ciuser"] = ciuser
        command_fingerprint["ciuser"] = ciuser

    search_domain = _normalize_dns_search_domain(params.get("search_domain"))
    if search_domain:
        normalized["search_domain"] = search_domain
        command_fingerprint["search_domain"] = search_domain
    dns_servers = _normalize_dns_servers(params.get("dns_servers") or [])
    if dns_servers:
        normalized["dns_servers"] = dns_servers
        command_fingerprint["dns_servers"] = dns_servers

    resize_disk = str(params.get("resize_disk") or "scsi0").strip()
    if "resize" in operations:
        if not _PROXMOX_DISK_RE.fullmatch(resize_disk):
            raise RPCExecutionError(
                "resize_disk must be a valid Proxmox disk key.",
                code="RPC_PARAM_INVALID",
            )
        normalized["resize_disk"] = resize_disk
        command_fingerprint["resize_disk"] = resize_disk

    networks = _normalize_proxmox_networks(params.get("networks") or [])
    if networks:
        normalized["networks"] = networks
        command_fingerprint["networks"] = networks
    ipconfigs = _normalize_proxmox_ipconfigs(params.get("ipconfigs") or [])
    if ipconfigs:
        normalized["ipconfigs"] = ipconfigs
        command_fingerprint["ipconfigs"] = ipconfigs
    guest_networks = _normalize_proxmox_guest_networks(
        params.get("guest_networks") or []
    )
    if guest_networks:
        normalized["guest_networks"] = guest_networks
        command_fingerprint["guest_networks"] = guest_networks

    if {"agent_pbs_zabbix_status", "agent_configure_zabbix_agent2"} & set(operations):
        raw_zabbix = (
            str(params.get("zabbix_server") or "").strip() or _default_zabbix_server()
        )
        if not raw_zabbix:
            raise RPCExecutionError(
                "zabbix_server is required for the requested operation: pass it "
                "explicitly, or configure the netbox_rpc 'default_zabbix_server' "
                "plugin setting.",
                code="RPC_PARAM_INVALID",
            )
        zabbix_server = _normalize_zabbix_server(raw_zabbix)
        normalized["zabbix_server"] = zabbix_server
        command_fingerprint["zabbix_server"] = zabbix_server

    _require_proxmox_fields(operations, normalized)
    normalized["command_fingerprint"] = command_fingerprint
    return normalized


def _resolve_proxmox_ssh_binding(endpoint_id: int) -> dict[str, Any]:
    try:
        from netbox_nms.proxmox_ssh import resolve_proxmox_endpoint_ssh
    except ImportError as exc:
        raise RPCExecutionError(
            "netbox-nms does not expose the Proxmox SSH resolver; "
            "upgrade netbox-nms to a version with ProxmoxEndpointSSHBinding.",
            code="RPC_PROXMOX_SSH_RESOLVER_MISSING",
        ) from exc

    resolved = resolve_proxmox_endpoint_ssh(endpoint_id)
    if not resolved:
        raise RPCExecutionError(
            f"No Proxmox Endpoint SSH binding is configured for endpoint "
            f"{endpoint_id}. Create one in NetBox NMS "
            "(Proxmox Endpoint SSH Bindings) before running this procedure.",
            code="RPC_PROXMOX_SSH_BINDING_NOT_FOUND",
        )
    host = str(resolved.get("host") or "").strip()
    if not host:
        raise RPCExecutionError(
            f"The Proxmox Endpoint SSH binding for endpoint {endpoint_id} has no "
            "resolvable host. Set an SSH host override or an endpoint IP/domain.",
            code="RPC_PROXMOX_SSH_HOST_UNRESOLVED",
        )
    if resolved.get("credential_pk") is None:
        raise RPCExecutionError(
            f"The Proxmox Endpoint SSH binding for endpoint {endpoint_id} has no "
            "linked SSH credential.",
            code="RPC_PROXMOX_SSH_CREDENTIAL_MISSING",
        )
    return {**resolved, "host": host}


def _proxmox_operations(params: dict[str, Any]) -> list[str]:
    raw = params.get("operations")
    if not isinstance(raw, list) or not raw:
        raise RPCExecutionError(
            "operations must be a non-empty list.", code="RPC_PARAM_INVALID"
        )
    operations: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if value not in _PROXMOX_QEMU_OPERATIONS:
            raise RPCExecutionError(
                f"Unsupported Proxmox QEMU operation: {value}", code="RPC_PARAM_INVALID"
            )
        if value in operations:
            raise RPCExecutionError(
                "operations must not contain duplicates.", code="RPC_PARAM_INVALID"
            )
        operations.append(value)
    return operations


def _optional_regex_param(
    params: dict[str, Any],
    key: str,
    regex: re.Pattern[str],
) -> str:
    value = str(params.get(key) or "").strip()
    if not value:
        return ""
    if not regex.fullmatch(value):
        raise RPCExecutionError(
            f"{key} contains invalid characters.", code="RPC_PARAM_INVALID"
        )
    return value


def _normalize_proxmox_networks(raw: Any) -> list[dict[str, Any]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError("networks must be a list.", code="RPC_PARAM_INVALID")
    if len(raw) > 8:
        raise RPCExecutionError(
            "networks may contain at most 8 entries.", code="RPC_PARAM_INVALID"
        )
    seen: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RPCExecutionError(
                "network entries must be objects.", code="RPC_PARAM_INVALID"
            )
        index = _int_range(item, "index", 0, 31)
        if index in seen:
            raise RPCExecutionError(
                "network indexes must be unique.", code="RPC_PARAM_INVALID"
            )
        seen.add(index)
        model = str(item.get("model") or "virtio").strip()
        if model not in _PROXMOX_QEMU_NIC_MODELS:
            raise RPCExecutionError(
                "network model is not allowlisted.", code="RPC_PARAM_INVALID"
            )
        bridge = str(item.get("bridge") or "").strip()
        if not _PROXMOX_BRIDGE_RE.fullmatch(bridge):
            raise RPCExecutionError(
                "network bridge contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        entry: dict[str, Any] = {"index": index, "model": model, "bridge": bridge}
        if item.get("tag") not in (None, ""):
            entry["tag"] = _int_range(item, "tag", 1, 4094)
        if "firewall" in item:
            entry["firewall"] = _bool_param(item, "firewall", False)
        normalized.append(entry)
    return sorted(normalized, key=lambda entry: int(entry["index"]))


def _normalize_proxmox_ipconfigs(raw: Any) -> list[dict[str, Any]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError("ipconfigs must be a list.", code="RPC_PARAM_INVALID")
    if len(raw) > 8:
        raise RPCExecutionError(
            "ipconfigs may contain at most 8 entries.", code="RPC_PARAM_INVALID"
        )
    seen: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RPCExecutionError(
                "ipconfig entries must be objects.", code="RPC_PARAM_INVALID"
            )
        index = _int_range(item, "index", 0, 31)
        if index in seen:
            raise RPCExecutionError(
                "ipconfig indexes must be unique.", code="RPC_PARAM_INVALID"
            )
        seen.add(index)
        ip = str(item.get("ip") or "").strip()
        if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(ip):
            raise RPCExecutionError(
                "ipconfig ip contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        entry: dict[str, Any] = {"index": index, "ip": ip}
        gw = str(item.get("gw") or "").strip()
        if gw:
            if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(gw):
                raise RPCExecutionError(
                    "ipconfig gw contains invalid characters.", code="RPC_PARAM_INVALID"
                )
            entry["gw"] = gw
        normalized.append(entry)
    return sorted(normalized, key=lambda entry: int(entry["index"]))


def _normalize_proxmox_guest_networks(raw: Any) -> list[dict[str, Any]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError(
            "guest_networks must be a list.", code="RPC_PARAM_INVALID"
        )
    if len(raw) > 8:
        raise RPCExecutionError(
            "guest_networks may contain at most 8 entries.", code="RPC_PARAM_INVALID"
        )
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RPCExecutionError(
                "guest_network entries must be objects.", code="RPC_PARAM_INVALID"
            )
        interface = str(item.get("interface") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,31}", interface):
            raise RPCExecutionError(
                "guest_network interface contains invalid characters.",
                code="RPC_PARAM_INVALID",
            )
        if interface in seen:
            raise RPCExecutionError(
                "guest_network interfaces must be unique.", code="RPC_PARAM_INVALID"
            )
        seen.add(interface)
        address = str(item.get("address") or "").strip()
        if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(address):
            raise RPCExecutionError(
                "guest_network address contains invalid characters.",
                code="RPC_PARAM_INVALID",
            )
        entry: dict[str, Any] = {"interface": interface, "address": address}
        gateway = str(item.get("gateway") or "").strip()
        if gateway:
            if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(gateway):
                raise RPCExecutionError(
                    "guest_network gateway contains invalid characters.",
                    code="RPC_PARAM_INVALID",
                )
            entry["gateway"] = gateway
        normalized.append(entry)
    return sorted(normalized, key=lambda entry: str(entry["interface"]))


def _normalize_dns_search_domain(raw: Any) -> str:
    value = str(raw or "").strip().rstrip(".")
    if not value:
        return ""
    if len(value) > 253 or not _DNS_SEARCH_DOMAIN_RE.fullmatch(value):
        raise RPCExecutionError(
            "search_domain must be a valid DNS search domain.", code="RPC_PARAM_INVALID"
        )
    return value


def _normalize_dns_servers(raw: Any) -> list[str]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError("dns_servers must be a list.", code="RPC_PARAM_INVALID")
    if len(raw) > 3:
        raise RPCExecutionError(
            "dns_servers may contain at most 3 entries.", code="RPC_PARAM_INVALID"
        )
    normalized: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if not value:
            raise RPCExecutionError(
                "dns_servers must not contain empty entries.", code="RPC_PARAM_INVALID"
            )
        try:
            ip_address(value)
        except ValueError as exc:
            raise RPCExecutionError(
                "dns_servers entries must be valid IP addresses.",
                code="RPC_PARAM_INVALID",
            ) from exc
        if value in normalized:
            raise RPCExecutionError(
                "dns_servers must not contain duplicates.", code="RPC_PARAM_INVALID"
            )
        normalized.append(value)
    return normalized


def _normalize_zabbix_server(raw: Any) -> str:
    value = str(raw or "").strip().rstrip(".")
    if not value:
        raise RPCExecutionError("zabbix_server is required.", code="RPC_PARAM_INVALID")
    try:
        ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not _DNS_SEARCH_DOMAIN_RE.fullmatch(value):
        raise RPCExecutionError(
            "zabbix_server must be a valid DNS name or IP address.",
            code="RPC_PARAM_INVALID",
        )
    return value


def _require_proxmox_fields(operations: list[str], params: dict[str, Any]) -> None:
    if "nextid" in operations:
        if len(operations) != 1:
            raise RPCExecutionError(
                "nextid must be run as a standalone operation.",
                code="RPC_PARAM_INVALID",
            )
        return
    _require_keys(params, ["vmid"])
    if "clone" in operations:
        _require_keys(params, ["template_vmid", "source_node", "name"])
    if "migrate" in operations:
        _require_keys(params, ["source_node", "target_node"])
    if {
        "configure",
        "resize",
        "start",
        "stop",
        "status",
        "agent_ping",
        "agent_network_get_interfaces",
        "agent_configure_debian_network",
        "agent_set_user_password",
        "agent_pbs_zabbix_status",
        "agent_configure_zabbix_agent2",
    } & set(operations):
        _require_keys(params, ["node"])
    if "resize" in operations:
        _require_keys(params, ["disk_gb", "resize_disk"])
    if "agent_configure_debian_network" in operations:
        _require_keys(params, ["guest_networks"])
    if "agent_set_user_password" in operations:
        _require_keys(params, ["guest_credential_pk"])


def _require_keys(params: dict[str, Any], keys: list[str]) -> None:
    missing = [key for key in keys if params.get(key) in (None, "", [])]
    if missing:
        raise RPCExecutionError(
            f"Missing required Proxmox lifecycle field(s): {', '.join(missing)}.",
            code="RPC_PARAM_INVALID",
        )


def _normalize_dell_os10_simple_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    result: dict[str, Any] = {
        "target": target,
        "command_fingerprint": {"handler_id": execution.procedure.handler_id},
    }
    _copy_optional_credential_override(params, result)
    return result


def _normalize_pipeline_fixed_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    result: dict[str, Any] = {
        "target": target,
        "command_fingerprint": {"handler_id": execution.procedure.handler_id},
    }
    _copy_optional_credential_override(params, result)
    return result


def _normalize_pvesh_json_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    pvesh_path = str(params.get("pvesh_path") or "").strip()
    if not _PVESH_PATH_RE.fullmatch(pvesh_path):
        raise RPCExecutionError(
            "pvesh_path must match ^/[A-Za-z0-9/_.-]{1,128}$.",
            code="RPC_PARAM_INVALID",
        )
    timeout = _optional_int_range(params, "timeout", 1, 600)
    result: dict[str, Any] = {
        "target": target,
        "pvesh_path": pvesh_path,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "pvesh_path": pvesh_path,
        },
    }
    if timeout is not None:
        result["timeout"] = timeout
        result["command_fingerprint"]["timeout"] = timeout
    _copy_optional_credential_override(params, result)
    return result


def _normalize_dell_os10_bootstrap_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    configure_user = _bool_param(params, "configure_user", False)
    restconf_credential_pk = _optional_int_range(
        params,
        "restconf_credential_pk",
        1,
        None,
    )
    if configure_user and restconf_credential_pk is None:
        raise RPCExecutionError(
            "restconf_credential_pk is required when configure_user is true.",
            code="RPC_PARAM_INVALID",
        )
    session_timeout = _optional_int_range(params, "session_timeout", 1, 1440)
    cipher_suites = params.get("cipher_suites") or []
    if not isinstance(cipher_suites, list):
        raise RPCExecutionError(
            "cipher_suites must be a list of OS10 cipher suite names.",
            code="RPC_PARAM_INVALID",
        )
    cipher_suites = [str(item).strip() for item in cipher_suites if str(item).strip()]
    if len(cipher_suites) > 12:
        raise RPCExecutionError(
            "cipher_suites may contain at most 12 entries.",
            code="RPC_PARAM_INVALID",
        )
    certificate_name = str(params.get("certificate_name") or "").strip()
    if any(
        any(ch.isspace() or ord(ch) < 32 for ch in item)
        for item in [certificate_name, *cipher_suites]
    ):
        raise RPCExecutionError(
            "Dell OS10 RESTCONF bootstrap parameters must not contain whitespace or control characters.",
            code="RPC_PARAM_INVALID",
        )

    normalized: dict[str, Any] = {
        "target": target,
        "configure_user": configure_user,
        "enable_ssh": _bool_param(params, "enable_ssh", True),
        "enable_restconf": _bool_param(params, "enable_restconf", True),
        "write_memory": _bool_param(params, "write_memory", True),
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "configure_user": configure_user,
            "enable_ssh": _bool_param(params, "enable_ssh", True),
            "enable_restconf": _bool_param(params, "enable_restconf", True),
            "write_memory": _bool_param(params, "write_memory", True),
        },
    }
    if restconf_credential_pk is not None:
        normalized["restconf_credential_pk"] = restconf_credential_pk
        normalized["command_fingerprint"]["restconf_credential_pk"] = (
            restconf_credential_pk
        )
    if certificate_name:
        normalized["certificate_name"] = certificate_name
        normalized["command_fingerprint"]["certificate_name"] = certificate_name
    if session_timeout is not None:
        normalized["session_timeout"] = session_timeout
        normalized["command_fingerprint"]["session_timeout"] = session_timeout
    if cipher_suites:
        normalized["cipher_suites"] = cipher_suites
        normalized["command_fingerprint"]["cipher_suites"] = cipher_suites
    _copy_optional_credential_override(params, normalized)
    return normalized


def _copy_optional_credential_override(
    params: dict[str, Any],
    normalized: dict[str, Any],
) -> None:
    credential_pk = _optional_int_range(params, "rpc_ssh_credential_pk", 1, None)
    if credential_pk is not None:
        normalized["rpc_ssh_credential_pk"] = credential_pk
        normalized["command_fingerprint"]["rpc_ssh_credential_pk"] = credential_pk


def _copy_optional_ssh_overrides(
    params: dict[str, Any],
    normalized: dict[str, Any],
) -> None:
    credential_pk = _optional_int_range(params, "rpc_ssh_credential_pk", 1, None)
    if credential_pk is not None:
        normalized["rpc_ssh_credential_pk"] = credential_pk
        normalized["command_fingerprint"]["rpc_ssh_credential_pk"] = credential_pk

    if "rpc_ssh_host" in params:
        host = str(params.get("rpc_ssh_host") or "").strip()
        _validate_ssh_host(
            host,
            empty_message="rpc_ssh_host must be a non-empty string.",
        )
        normalized["rpc_ssh_host"] = host
        normalized["command_fingerprint"]["rpc_ssh_host"] = host

    port = _optional_int_range(params, "rpc_ssh_port", 1, 65535)
    if port is not None:
        normalized["rpc_ssh_port"] = port
        normalized["command_fingerprint"]["rpc_ssh_port"] = port

    if "rpc_ssh_known_hosts_entry" in params:
        known_hosts_entry = str(params.get("rpc_ssh_known_hosts_entry") or "").strip()
        normalized["rpc_ssh_known_hosts_entry"] = known_hosts_entry
        normalized["command_fingerprint"]["rpc_ssh_known_hosts_entry_sha256"] = (
            _hash_text(known_hosts_entry)
        )

    if "rpc_ssh_strict_host_key_checking" in params:
        strict = _bool_param(params, "rpc_ssh_strict_host_key_checking", True)
        normalized["rpc_ssh_strict_host_key_checking"] = strict
        normalized["command_fingerprint"]["rpc_ssh_strict_host_key_checking"] = strict


def _dell_os10_description(params: dict[str, Any]) -> str:
    description = str(params.get("description") or "")
    if len(description) > 240:
        raise RPCExecutionError(
            "description may contain at most 240 characters.",
            code="RPC_PARAM_INVALID",
        )
    if any(ord(ch) < 32 and ch not in ("\t",) for ch in description):
        raise RPCExecutionError(
            "description must not contain control characters.",
            code="RPC_PARAM_INVALID",
        )
    return description


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_json(value: object) -> str:
    if value is None:
        return ""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _optional_int_range(
    params: dict[str, Any],
    key: str,
    minimum: int,
    maximum: int | None,
) -> int | None:
    if key not in params or params.get(key) in (None, ""):
        return None
    return _int_range(params, key, minimum, maximum)


def _bool_param(params: dict[str, Any], key: str, default: bool) -> bool:
    if key not in params or params.get(key) is None:
        return default
    value = params.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    raise RPCExecutionError(
        f"{key} must be a boolean.",
        code="RPC_PARAM_INVALID",
    )


def _int_range(
    params: dict[str, Any], key: str, minimum: int, maximum: int | None
) -> int:
    try:
        value = int(params[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise RPCExecutionError(
            f"{key} must be an integer.", code="RPC_PARAM_INVALID"
        ) from exc
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" and <= {maximum}" if maximum is not None else ""
        raise RPCExecutionError(
            f"{key} must be >= {minimum}{suffix}.",
            code="RPC_PARAM_OUT_OF_RANGE",
        )
    return value
