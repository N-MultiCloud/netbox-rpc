"""Immutable protected contract for the Ubuntu 26.04 Samba AD DC provision.

``os.linux.ubuntu.26.samba_ad_dc.provision`` creates the first domain controller
of a NEW Active Directory domain and cannot be rerun, so it is registered in the
protected approval catalog: creation stays ``pending_approval`` until an
authorized approver decides, the approval snapshot pins the complete catalog policy,
both schemas, the command contract and the backend target, and dispatch requires a
signed one-time lease.

The schemas and command row below are the single reviewed source of truth. They
must stay byte-identical to the inline data in migration
``0103_seed_ubuntu_26_samba_ad_dc_procedures`` (``tests`` compare the two), and
``command_handlers`` refuses admission if the mutable catalog row differs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROCEDURE_NAME = "os.linux.ubuntu.26.samba_ad_dc.provision"
HANDLER_ID = "os.linux.ubuntu.26.samba_ad_dc.provision"
VERSION = 1
TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]
EFFECT = "destructive"
TIMEOUT_SECONDS = 3600
APPROVAL_REQUIRED = True
ENABLED = True
TRANSPORT_DRIVER = "asyncssh"
TRANSPORT_DRIVER_CHAIN: list[str] = []
TRANSPORT_PINNED = True
OUTPUT_PARSER = "none"
OUTPUT_SCHEMA: dict[str, Any] = {}

COMMAND_CONTRACT = [
    {
        "argv": ["backend-orchestrated", "ubuntu-26-samba-ad-dc-provision"],
        "capture_expression": "",
        "capture_kind": "",
        "condition_negate": False,
        "condition_param": "",
        "continue_on_error": False,
        "description": "Backend uploads the hash-pinned installer program, delivers "
        "settings on stdin, runs the staged bootstrap, and proves the "
        "firewall over a new SSH connection.",
        "device_cli_mode": "",
        "for_each_param": "",
        "produces_var": "",
        "render_mode": "literal",
        "sequence": 1,
        "step_type": "shell_argv",
    }
]

PARAMS_SCHEMA = {
    "additionalProperties": False,
    "if": {"properties": {"dry_run": {"const": False}}, "required": ["dry_run"]},
    "properties": {
        "admin_credential_pk": {
            "description": "netbox-nms "
            "DeviceCredential PK "
            "holding the NEW domain "
            "Administrator "
            "password. Required for "
            "a live run. A "
            "reference only: the "
            "password never enters "
            "params, events or "
            "results.",
            "minimum": 1,
            "type": "integer",
        },
        "ban_exempt_networks": {
            "default": [],
            "description": "Additional Fail2ban "
            "never-ban IPs/CIDRs. "
            "Do not exempt the "
            "whole client LAN. "
            "Exemptions do not open "
            "firewall ports.",
            "items": {
                "maxLength": 49,
                "pattern": "^[0-9A-Fa-f:.]{2,45}(?:/[0-9]{1,3}){0,1}(?![\\s\\S])",
                "type": "string",
            },
            "maxItems": 32,
            "type": "array",
            "uniqueItems": True,
        },
        "client_networks": {
            "description": "Trusted Windows/NTP client "
            "IPv4 CIDRs (explicit "
            "prefix length, not /0, "
            "loopback, multicast or "
            "link-local).",
            "items": {
                "maxLength": 18,
                "pattern": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}(?![\\s\\S])",
                "type": "string",
            },
            "maxItems": 16,
            "minItems": 1,
            "type": "array",
            "uniqueItems": True,
        },
        "domain": {
            "description": "NEW AD DNS domain: at least two DNS "
            "labels, at most 237 characters, not "
            ".local and not ending in an "
            "all-digit label.",
            "maxLength": 237,
            "minLength": 3,
            "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![\\s\\S])",
            "type": "string",
        },
        "dry_run": {
            "default": True,
            "description": "Validate and return the full plan "
            "and rendered configuration without "
            "changing the host. Defaults to "
            "true.",
            "type": "boolean",
        },
        "fail2ban_findtime": {
            "default": 600,
            "description": "Failure counting window in seconds.",
            "maximum": 86400,
            "minimum": 60,
            "type": "integer",
        },
        "forwarder": {
            "description": "Upstream DNS resolver IPv4. Must not be the DC itself.",
            "maxLength": 15,
            "minLength": 7,
            "pattern": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![\\s\\S])",
            "type": "string",
        },
        "freeze_cloud_init": {
            "default": True,
            "description": "Disable future "
            "cloud-init runs when "
            "cloud-init is present "
            "and ready. False with "
            "cloud-init ready fails "
            "closed on the host.",
            "type": "boolean",
        },
        "hostname": {
            "description": "DC short hostname (1-15 "
            "characters), lower-cased. Must "
            "differ from the NetBIOS domain "
            "name.",
            "maxLength": 15,
            "minLength": 1,
            "pattern": "^[A-Za-z](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?(?![\\s\\S])",
            "type": "string",
        },
        "ip": {
            "description": "The DC's persistent static routable "
            "unicast IPv4. Must equal the VM's "
            "current address.",
            "maxLength": 15,
            "minLength": 7,
            "pattern": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![\\s\\S])",
            "type": "string",
        },
        "legacy_netbios": {
            "default": False,
            "description": "Also allow legacy NetBIOS ports 137/138 UDP and 139 TCP.",
            "type": "boolean",
        },
        "netbios": {
            "description": "NetBIOS domain name (1-15 characters). Upper-cased.",
            "maxLength": 15,
            "minLength": 1,
            "pattern": "^[A-Za-z](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?(?![\\s\\S])",
            "type": "string",
        },
        "ntp_servers": {
            "default": ["a.ntp.br", "b.ntp.br", "c.ntp.br"],
            "description": "Upstream plain-NTP servers: "
            "DNS names or unicast IP "
            "addresses.",
            "items": {
                "maxLength": 253,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9:.-]{1,253}(?![\\s\\S])",
                "type": "string",
            },
            "maxItems": 8,
            "minItems": 1,
            "type": "array",
            "uniqueItems": True,
        },
        "share_name": {
            "default": "shared",
            "description": "Windows share name. Reserved "
            "names (global, homes, printers, "
            "sysvol, netlogon, ipc, admin) "
            "are rejected.",
            "maxLength": 64,
            "minLength": 1,
            "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,63}(?![\\s\\S])",
            "type": "string",
        },
        "share_path": {
            "description": "Share directory below /srv with "
            "no . or .. components. Defaults "
            "to /srv/samba/<share_name>. "
            "Must be absent or empty on the "
            "host.",
            "maxLength": 255,
            "minLength": 6,
            "pattern": "^/srv(?:/[A-Za-z0-9_.-]+)+(?![\\s\\S])",
            "type": "string",
        },
        "smb_bantime": {
            "default": 900,
            "description": "SMB ban duration in seconds.",
            "maximum": 86400,
            "minimum": 60,
            "type": "integer",
        },
        "smb_max_retry": {
            "default": 10,
            "description": "SMB failed logins before a ban.",
            "maximum": 100,
            "minimum": 3,
            "type": "integer",
        },
        "ssh_bantime": {
            "default": 3600,
            "description": "SSH ban duration in seconds.",
            "maximum": 86400,
            "minimum": 60,
            "type": "integer",
        },
        "ssh_max_retry": {
            "default": 5,
            "description": "SSH failed logins before a ban.",
            "maximum": 100,
            "minimum": 3,
            "type": "integer",
        },
        "ssh_networks": {
            "default": [],
            "description": "SSH administration source "
            "IPs/CIDRs (IPv4 or IPv6). "
            "Required, and must cover the "
            "executing session's source, "
            "for a live run.",
            "items": {
                "maxLength": 49,
                "pattern": "^[0-9A-Fa-f:.]{2,45}(?:/[0-9]{1,3}){0,1}(?![\\s\\S])",
                "type": "string",
            },
            "maxItems": 32,
            "type": "array",
            "uniqueItems": True,
        },
        "ssh_ports": {
            "default": [],
            "description": "SSH TCP ports the firewall keeps "
            "open. Required for a live run "
            "and must include the executing "
            "session's port.",
            "items": {
                "maximum": 65535,
                "minimum": 1,
                "not": {"enum": [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269]},
                "type": "integer",
            },
            "maxItems": 16,
            "type": "array",
            "uniqueItems": True,
        },
        "timezone": {
            "default": "America/Sao_Paulo",
            "description": "System timezone; verified against "
            "the installed zoneinfo on the "
            "host.",
            "maxLength": 64,
            "minLength": 1,
            "pattern": "^(?!/)[A-Za-z0-9_+/-]{1,64}(?![\\s\\S])",
            "type": "string",
        },
    },
    "required": ["domain", "netbios", "hostname", "ip", "forwarder", "client_networks"],
    "then": {
        "properties": {"ssh_networks": {"minItems": 1}, "ssh_ports": {"minItems": 1}},
        "required": ["admin_credential_pk", "ssh_ports", "ssh_networks"],
    },
    "type": "object",
}

RESULT_SCHEMA = {
    "allOf": [
        {
            "if": {"properties": {"ok": {"const": False}}, "required": ["ok"]},
            "then": {"required": ["rerunnable", "stage"]},
        },
        {
            "if": {
                "properties": {"dry_run": {"const": False}, "ok": {"const": True}},
                "required": ["ok", "dry_run"],
            },
            "then": {
                "properties": {
                    "checks": {"minItems": 1},
                    "firewall": {
                        "properties": {"confirmed": {"const": True}},
                        "required": ["confirmed"],
                    },
                    "stage": {"const": "complete"},
                },
                "required": ["stage", "firewall", "checks", "installer_sha256"],
            },
        },
        {
            "if": {
                "properties": {"dry_run": {"const": True}, "ok": {"const": True}},
                "required": ["ok", "dry_run"],
            },
            "then": {"required": ["stage", "plan"]},
        },
    ],
    "properties": {
        "backup_dir": {"maxLength": 255, "type": ["string", "null"]},
        "checks": {
            "items": {
                "properties": {
                    "detail": {"maxLength": 1024, "type": "string"},
                    "name": {"maxLength": 64, "type": "string"},
                    "ok": {"type": "boolean"},
                },
                "required": ["name", "ok"],
                "type": "object",
            },
            "maxItems": 128,
            "type": "array",
        },
        "dry_run": {"type": "boolean"},
        "error": {"maxLength": 2048, "type": ["string", "null"]},
        "error_code": {"maxLength": 64, "type": ["string", "null"]},
        "firewall": {
            "properties": {
                "confirmed": {"type": "boolean"},
                "rolled_back": {"type": "boolean"},
            },
            "type": "object",
        },
        "installer_sha256": {
            "maxLength": 64,
            "pattern": "^[0-9a-f]{64}(?![\\s\\S])",
            "type": "string",
        },
        "log_tail": {"maxLength": 65536, "type": "string"},
        "ok": {"type": "boolean"},
        "plan": {
            "properties": {
                "client_networks": {
                    "items": {"maxLength": 18, "type": "string"},
                    "maxItems": 16,
                    "type": "array",
                },
                "dc_fqdn": {"maxLength": 253, "type": "string"},
                "domain": {"maxLength": 237, "type": "string"},
                "fail2ban": {
                    "properties": {
                        "ban_exempt_networks": {
                            "items": {"maxLength": 49, "type": "string"},
                            "maxItems": 32,
                            "type": "array",
                        },
                        "findtime": {"minimum": 0, "type": "integer"},
                        "smb_bantime": {"minimum": 0, "type": "integer"},
                        "smb_max_retry": {"minimum": 0, "type": "integer"},
                        "ssh_bantime": {"minimum": 0, "type": "integer"},
                        "ssh_max_retry": {"minimum": 0, "type": "integer"},
                    },
                    "type": "object",
                },
                "firewall": {
                    "properties": {
                        "legacy_netbios": {"type": "boolean"},
                        "ssh_networks": {
                            "items": {"maxLength": 49, "type": "string"},
                            "maxItems": 32,
                            "type": "array",
                        },
                        "ssh_ports": {
                            "items": {
                                "maximum": 65535,
                                "minimum": 1,
                                "type": "integer",
                            },
                            "maxItems": 16,
                            "type": "array",
                        },
                    },
                    "type": "object",
                },
                "forwarder": {"maxLength": 15, "type": "string"},
                "ip": {"maxLength": 15, "type": "string"},
                "netbios": {"maxLength": 15, "type": "string"},
                "ntp_servers": {
                    "items": {"maxLength": 253, "type": "string"},
                    "maxItems": 8,
                    "type": "array",
                },
                "realm": {"maxLength": 237, "type": "string"},
                "share_path": {"maxLength": 255, "type": "string"},
                "share_unc": {"maxLength": 400, "type": "string"},
                "timezone": {"maxLength": 64, "type": "string"},
            },
            "type": "object",
        },
        "procedure": {"maxLength": 255, "type": "string"},
        "rendered_configs": {
            "properties": {
                "chrony": {"maxLength": 16384, "type": "string"},
                "fail2ban_filter": {"maxLength": 16384, "type": "string"},
                "fail2ban_jails": {"maxLength": 16384, "type": "string"},
                "hosts": {"maxLength": 16384, "type": "string"},
                "nftables": {"maxLength": 16384, "type": "string"},
                "resolv_conf": {"maxLength": 16384, "type": "string"},
                "smb_conf_global": {"maxLength": 16384, "type": "string"},
                "smb_conf_share": {"maxLength": 16384, "type": "string"},
            },
            "type": "object",
        },
        "rerunnable": {
            "const": False,
            "description": "Always false: the bootstrap is "
            "not rerunnable and has no "
            "domain rollback. Recovery is a "
            "restore of the pre-run VM "
            "snapshot.",
            "type": "boolean",
        },
        "stage": {"maxLength": 64, "type": "string"},
        "target": {"maxLength": 255, "type": "string"},
    },
    "required": ["ok", "dry_run", "stage"],
    "type": "object",
}


def canonical_sha256(value: Any) -> str:
    """Return a stable SHA-256 fingerprint for a JSON-compatible value."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


PROCEDURE_POLICY = {
    "name": PROCEDURE_NAME,
    "handler_id": HANDLER_ID,
    "version": VERSION,
    "enabled": ENABLED,
    "target_models": TARGET_MODELS,
    "effect": EFFECT,
    "timeout_seconds": TIMEOUT_SECONDS,
    "approval_required": APPROVAL_REQUIRED,
    "transport_driver": TRANSPORT_DRIVER,
    "transport_driver_chain": TRANSPORT_DRIVER_CHAIN,
    "output_parser": OUTPUT_PARSER,
    "output_schema": OUTPUT_SCHEMA,
    "command_contract_sha256": canonical_sha256(COMMAND_CONTRACT),
    "transport_pinned": TRANSPORT_PINNED,
}

PROCEDURE_POLICY_SHA256 = canonical_sha256(PROCEDURE_POLICY)
COMMAND_CONTRACT_SHA256 = canonical_sha256(COMMAND_CONTRACT)
PARAMS_SCHEMA_SHA256 = canonical_sha256(PARAMS_SCHEMA)
RESULT_SCHEMA_SHA256 = canonical_sha256(RESULT_SCHEMA)
