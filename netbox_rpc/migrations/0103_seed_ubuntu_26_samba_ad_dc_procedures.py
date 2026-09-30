"""Seed the audited Ubuntu 26.04 Samba AD DC bootstrap procedures.

Three procedures convert the reviewed operator installer for a fresh Ubuntu
Server 26.04 LTS VM into the audited catalog:

``os.linux.ubuntu.26.samba_ad_dc.preflight``
    Read-only. Reports whether the VM is a clean, supported candidate and the
    values the operator needs to fill in ``provision`` (detected interface and
    IPv4, suggested forwarder and client subnet, SSH ports, cloud-init state).
``os.linux.ubuntu.26.samba_ad_dc.provision``
    Destructive and on the protected two-person approval path (a distinct
    approver, an immutable approval snapshot and a signed one-time dispatch
    lease). Creates the FIRST domain controller of a NEW
    Active Directory domain, a private encrypted SMB3 share, a restricted
    nftables host firewall and Fail2ban jails. It is not rerunnable and there is
    no domain rollback: recovery is a VM snapshot restore.
``os.linux.ubuntu.26.samba_ad_dc.verify``
    Read-only, credential-free post-install and post-reboot health report.

Security contract encoded here and mirrored by the pure-domain normalizer:

* No procedure accepts, stores or returns a password or hash. The domain
  Administrator password is referenced only by ``admin_credential_pk`` (a
  netbox-nms ``DeviceCredential`` id) and is resolved by the execution backend
  at run time.
* ``dry_run`` defaults to true. A live run requires ``admin_credential_pk`` and
  a non-empty SSH port and source allowlist, because the installer proves from
  the executing SSH session that the firewall will not lock the operator out.
* The SSH destination is derived from the assigned NetBox object. ``provision``
  accepts no ``rpc_ssh_*`` override at all, so the execution always runs against
  the object named in the request.
* Every free-form result string carries an explicit ``maxLength`` (see migration
  0066 for why an undeclared string silently clamps at 4096 characters).

Rows are seeded enabled and transport-pinned. All three names are in
``EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES``, so until the paired
``netbox-rpc-backend`` advertises a matching capability every admission, listing
and worker claim fails closed. ``provision``'s complete catalog policy and both
schemas are pinned by ``netbox_rpc.samba_ad_dc_protected_contract``, which must
stay byte-identical to the data below. Existing rows are never overwritten: drift
raises. The reverse migration disables rather than deletes audited procedures.
Data is inline so the migration is stable across runtime constant changes.
"""

from django.db import migrations

_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]

_PREFLIGHT_NAME = "os.linux.ubuntu.26.samba_ad_dc.preflight"
_PROVISION_NAME = "os.linux.ubuntu.26.samba_ad_dc.provision"
_VERIFY_NAME = "os.linux.ubuntu.26.samba_ad_dc.verify"

_LOG_TAIL_MAX_LENGTH = 65536
_RENDERED_CONFIG_MAX_LENGTH = 16384

# Every pattern is anchored with (?![\s\S]) rather than $: jsonschema applies
# ``pattern`` with re.search and Python's $ also matches before a trailing newline.
_END = r"(?![\s\S])"
_DNS_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_PATTERN = rf"^{_DNS_LABEL}(?:\.{_DNS_LABEL})+{_END}"
_SHORT_NAME_PATTERN = rf"^[A-Za-z](?:[A-Za-z0-9-]{{0,13}}[A-Za-z0-9])?{_END}"
_IPV4_PATTERN = rf"^(?:[0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}{_END}"
_IPV4_CIDR_PATTERN = rf"^(?:[0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}/[0-9]{{1,2}}{_END}"
_NTP_SOURCE_PATTERN = rf"^[A-Za-z0-9:.-]{{1,253}}{_END}"
_TIMEZONE_PATTERN = rf"^(?!/)[A-Za-z0-9_+/-]{{1,64}}{_END}"
_SHARE_NAME_PATTERN = rf"^[A-Za-z][A-Za-z0-9_-]{{0,63}}{_END}"
_SHARE_PATH_PATTERN = rf"^/srv(?:/[A-Za-z0-9_.-]+)+{_END}"
_SOURCE_NETWORK_PATTERN = rf"^[0-9A-Fa-f:.]{{2,45}}(?:/[0-9]{{1,3}}){{0,1}}{_END}"
_SHA256_PATTERN = rf"^[0-9a-f]{{64}}{_END}"

# Ports that collide with Samba AD service ports are never valid SSH ports.
_RESERVED_SSH_PORTS = [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269]

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": (
        "netbox-nms DeviceCredential PK for an ad-hoc SSH target; nms-backend "
        "decrypts it at execution time. Omit to use the assigned object's SSH "
        "DeviceService."
    ),
}

_SSH_OVERRIDE_PROPERTIES = {
    "rpc_ssh_credential_pk": _CREDENTIAL_REF,
    "rpc_ssh_host": {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "description": "Optional SSH host override. Omit when targeting a registered object.",
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
}


def _source_network_list(description):
    return {
        "type": "array",
        "items": {
            "type": "string",
            "maxLength": 49,
            "pattern": _SOURCE_NETWORK_PATTERN,
        },
        "maxItems": 32,
        "uniqueItems": True,
        "default": [],
        "description": description,
    }


def _bounded_integer(minimum, maximum, default, description):
    return {
        "type": "integer",
        "minimum": minimum,
        "maximum": maximum,
        "default": default,
        "description": description,
    }


_READ_PARAMS = {
    "type": "object",
    "additionalProperties": False,
    "properties": dict(_SSH_OVERRIDE_PROPERTIES),
}

_PROVISION_PARAMS = {
    "type": "object",
    "required": [
        "domain",
        "netbios",
        "hostname",
        "ip",
        "forwarder",
        "client_networks",
    ],
    "additionalProperties": False,
    "properties": {
        "dry_run": {
            "type": "boolean",
            "default": True,
            "description": (
                "Validate and return the full plan and rendered configuration "
                "without changing the host. Defaults to true."
            ),
        },
        "domain": {
            "type": "string",
            "minLength": 3,
            "maxLength": 237,
            "pattern": _DOMAIN_PATTERN,
            "description": (
                "NEW AD DNS domain: at least two DNS labels, at most 237 "
                "characters, not .local and not ending in an all-digit label."
            ),
        },
        "netbios": {
            "type": "string",
            "minLength": 1,
            "maxLength": 15,
            "pattern": _SHORT_NAME_PATTERN,
            "description": "NetBIOS domain name (1-15 characters). Upper-cased.",
        },
        "hostname": {
            "type": "string",
            "minLength": 1,
            "maxLength": 15,
            "pattern": _SHORT_NAME_PATTERN,
            "description": (
                "DC short hostname (1-15 characters), lower-cased. Must differ "
                "from the NetBIOS domain name."
            ),
        },
        "ip": {
            "type": "string",
            "minLength": 7,
            "maxLength": 15,
            "pattern": _IPV4_PATTERN,
            "description": (
                "The DC's persistent static routable unicast IPv4. Must equal "
                "the VM's current address."
            ),
        },
        "forwarder": {
            "type": "string",
            "minLength": 7,
            "maxLength": 15,
            "pattern": _IPV4_PATTERN,
            "description": "Upstream DNS resolver IPv4. Must not be the DC itself.",
        },
        "client_networks": {
            "type": "array",
            "items": {
                "type": "string",
                "maxLength": 18,
                "pattern": _IPV4_CIDR_PATTERN,
            },
            "minItems": 1,
            "maxItems": 16,
            "uniqueItems": True,
            "description": (
                "Trusted Windows/NTP client IPv4 CIDRs (explicit prefix length, "
                "not /0, loopback, multicast or link-local)."
            ),
        },
        "ntp_servers": {
            "type": "array",
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 253,
                "pattern": _NTP_SOURCE_PATTERN,
            },
            "minItems": 1,
            "maxItems": 8,
            "uniqueItems": True,
            "default": ["a.ntp.br", "b.ntp.br", "c.ntp.br"],
            "description": "Upstream plain-NTP servers: DNS names or unicast IP addresses.",
        },
        "timezone": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": _TIMEZONE_PATTERN,
            "default": "America/Sao_Paulo",
            "description": "System timezone; verified against the installed zoneinfo on the host.",
        },
        "share_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": _SHARE_NAME_PATTERN,
            "default": "shared",
            "description": (
                "Windows share name. Reserved names (global, homes, printers, "
                "sysvol, netlogon, ipc, admin) are rejected."
            ),
        },
        "share_path": {
            "type": "string",
            "minLength": 6,
            "maxLength": 255,
            "pattern": _SHARE_PATH_PATTERN,
            "description": (
                "Share directory below /srv with no . or .. components. Defaults "
                "to /srv/samba/<share_name>. Must be absent or empty on the host."
            ),
        },
        "ssh_ports": {
            "type": "array",
            "items": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535,
                "not": {"enum": _RESERVED_SSH_PORTS},
            },
            "maxItems": 16,
            "uniqueItems": True,
            "default": [],
            "description": (
                "SSH TCP ports the firewall keeps open. Required for a live run "
                "and must include the executing session's port."
            ),
        },
        "ssh_networks": _source_network_list(
            "SSH administration source IPs/CIDRs (IPv4 or IPv6). Required, and "
            "must cover the executing session's source, for a live run."
        ),
        "ban_exempt_networks": _source_network_list(
            "Additional Fail2ban never-ban IPs/CIDRs. Do not exempt the whole "
            "client LAN. Exemptions do not open firewall ports."
        ),
        "fail2ban_findtime": _bounded_integer(
            60, 86400, 600, "Failure counting window in seconds."
        ),
        "smb_max_retry": _bounded_integer(
            3, 100, 10, "SMB failed logins before a ban."
        ),
        "smb_bantime": _bounded_integer(60, 86400, 900, "SMB ban duration in seconds."),
        "ssh_max_retry": _bounded_integer(3, 100, 5, "SSH failed logins before a ban."),
        "ssh_bantime": _bounded_integer(
            60, 86400, 3600, "SSH ban duration in seconds."
        ),
        "legacy_netbios": {
            "type": "boolean",
            "default": False,
            "description": "Also allow legacy NetBIOS ports 137/138 UDP and 139 TCP.",
        },
        "freeze_cloud_init": {
            "type": "boolean",
            "default": True,
            "description": (
                "Disable future cloud-init runs when cloud-init is present and "
                "ready. False with cloud-init ready fails closed on the host."
            ),
        },
        "admin_credential_pk": {
            "type": "integer",
            "minimum": 1,
            "description": (
                "netbox-nms DeviceCredential PK holding the NEW domain "
                "Administrator password. Required for a live run. A reference "
                "only: the password never enters params, events or results."
            ),
        },
    },
    "if": {
        "properties": {"dry_run": {"const": False}},
        "required": ["dry_run"],
    },
    "then": {
        "required": ["admin_credential_pk", "ssh_ports", "ssh_networks"],
        "properties": {
            "ssh_ports": {"minItems": 1},
            "ssh_networks": {"minItems": 1},
        },
    },
}


def _text(max_length):
    return {"type": "string", "maxLength": max_length}


def _nullable_text(max_length):
    return {"type": ["string", "null"], "maxLength": max_length}


_CHECK_ITEM = {
    "type": "object",
    "required": ["name", "ok"],
    "properties": {
        "name": _text(64),
        "ok": {"type": "boolean"},
        "detail": _text(1024),
    },
}

_CHECKS = {"type": "array", "items": _CHECK_ITEM, "maxItems": 128}

_COMMON_RESULT_PROPERTIES = {
    "ok": {"type": "boolean"},
    "procedure": _text(255),
    "target": _text(255),
}

_PREFLIGHT_RESULT = {
    "type": "object",
    "required": ["ok", "verdicts", "detected"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "verdicts": _CHECKS,
        "detected": {
            "type": "object",
            "properties": {
                "interface": _nullable_text(64),
                "ipv4": _nullable_text(15),
                "prefixlen": {"type": ["integer", "null"], "minimum": 0, "maximum": 32},
                "suggested_forwarder": _nullable_text(15),
                "suggested_client_subnet": _nullable_text(18),
                "ssh_ports": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "maxItems": 64,
                },
                "cloud_init": {
                    "type": "object",
                    "properties": {
                        "present": {"type": "boolean"},
                        "status": _nullable_text(64),
                        "freeze_required": {"type": "boolean"},
                    },
                },
            },
        },
    },
}

_PROVISION_RESULT = {
    "type": "object",
    "required": ["ok", "dry_run", "stage"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "dry_run": {"type": "boolean"},
        "stage": _text(64),
        "error_code": _nullable_text(64),
        "error": _nullable_text(2048),
        "plan": {
            "type": "object",
            "properties": {
                "domain": _text(237),
                "realm": _text(237),
                "netbios": _text(15),
                "dc_fqdn": _text(253),
                "ip": _text(15),
                "forwarder": _text(15),
                "share_unc": _text(400),
                "share_path": _text(255),
                "ntp_servers": {
                    "type": "array",
                    "items": _text(253),
                    "maxItems": 8,
                },
                "timezone": _text(64),
                "client_networks": {
                    "type": "array",
                    "items": _text(18),
                    "maxItems": 16,
                },
                "firewall": {
                    "type": "object",
                    "properties": {
                        "ssh_ports": {
                            "type": "array",
                            "items": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 65535,
                            },
                            "maxItems": 16,
                        },
                        "ssh_networks": {
                            "type": "array",
                            "items": _text(49),
                            "maxItems": 32,
                        },
                        "legacy_netbios": {"type": "boolean"},
                    },
                },
                "fail2ban": {
                    "type": "object",
                    "properties": {
                        "findtime": {"type": "integer", "minimum": 0},
                        "smb_max_retry": {"type": "integer", "minimum": 0},
                        "smb_bantime": {"type": "integer", "minimum": 0},
                        "ssh_max_retry": {"type": "integer", "minimum": 0},
                        "ssh_bantime": {"type": "integer", "minimum": 0},
                        "ban_exempt_networks": {
                            "type": "array",
                            "items": _text(49),
                            "maxItems": 32,
                        },
                    },
                },
            },
        },
        "rendered_configs": {
            "type": "object",
            "properties": {
                name: _text(_RENDERED_CONFIG_MAX_LENGTH)
                for name in (
                    "hosts",
                    "resolv_conf",
                    "chrony",
                    "smb_conf_global",
                    "smb_conf_share",
                    "nftables",
                    "fail2ban_filter",
                    "fail2ban_jails",
                )
            },
        },
        "checks": _CHECKS,
        "firewall": {
            "type": "object",
            "properties": {
                "confirmed": {"type": "boolean"},
                "rolled_back": {"type": "boolean"},
            },
        },
        "backup_dir": _nullable_text(255),
        "installer_sha256": {
            "type": "string",
            "maxLength": 64,
            "pattern": _SHA256_PATTERN,
        },
        "log_tail": _text(_LOG_TAIL_MAX_LENGTH),
        "rerunnable": {
            "type": "boolean",
            "const": False,
            "description": (
                "Always false: the bootstrap is not rerunnable and has no domain "
                "rollback. Recovery is a restore of the pre-run VM snapshot."
            ),
        },
    },
    # An unverified success is never accepted, and a failure must say it cannot
    # be retried. Live success needs the completed stage, a confirmed firewall,
    # at least one check and the installer digest; a dry-run success needs a plan.
    "allOf": [
        {
            "if": {"properties": {"ok": {"const": False}}, "required": ["ok"]},
            "then": {"required": ["rerunnable", "stage"]},
        },
        {
            "if": {
                "properties": {
                    "ok": {"const": True},
                    "dry_run": {"const": False},
                },
                "required": ["ok", "dry_run"],
            },
            "then": {
                "required": ["stage", "firewall", "checks", "installer_sha256"],
                "properties": {
                    "stage": {"const": "complete"},
                    "firewall": {
                        "required": ["confirmed"],
                        "properties": {"confirmed": {"const": True}},
                    },
                    "checks": {"minItems": 1},
                },
            },
        },
        {
            "if": {
                "properties": {
                    "ok": {"const": True},
                    "dry_run": {"const": True},
                },
                "required": ["ok", "dry_run"],
            },
            "then": {"required": ["stage", "plan"]},
        },
    ],
}

_VERIFY_RESULT = {
    "type": "object",
    "required": ["ok", "checks", "services"],
    "properties": {
        **_COMMON_RESULT_PROPERTIES,
        "checks": _CHECKS,
        "services": {
            "type": "object",
            "properties": {
                unit: _text(64)
                for unit in ("samba_ad_dc", "chrony", "nftables", "fail2ban")
            },
            "additionalProperties": _text(64),
        },
    },
}

_PROCEDURES = (
    {
        "name": _PREFLIGHT_NAME,
        "handler_id": _PREFLIGHT_NAME,
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": (
            "Read-only Ubuntu 26.04 Samba AD DC readiness report: OS, systemd, "
            "clean-VM checks, package candidates, static IPv4, Netplan, "
            "firewall, cloud-init and SSH ports."
        ),
        "params_schema": _READ_PARAMS,
        "result_schema": _PREFLIGHT_RESULT,
        "command_slug": "ubuntu-26-samba-ad-dc-preflight",
    },
    {
        "name": _PROVISION_NAME,
        "handler_id": _PROVISION_NAME,
        "effect": "destructive",
        "timeout_seconds": 3600,
        "approval_required": True,
        "description": (
            "Destructive, non-rerunnable Ubuntu 26.04 bootstrap of the FIRST "
            "Samba AD DC of a NEW domain with a private SMB3 share, nftables "
            "and Fail2ban. Recovery is a VM snapshot restore."
        ),
        "params_schema": _PROVISION_PARAMS,
        "result_schema": _PROVISION_RESULT,
        "command_slug": "ubuntu-26-samba-ad-dc-provision",
    },
    {
        "name": _VERIFY_NAME,
        "handler_id": _VERIFY_NAME,
        "effect": "read",
        "timeout_seconds": 180,
        "approval_required": False,
        "description": (
            "Credential-free Samba AD DC health report: services, testparm, "
            "dbcheck, SYSVOL ACLs, DNS SRV records, chrony, nftables and "
            "Fail2ban."
        ),
        "params_schema": _READ_PARAMS,
        "result_schema": _VERIFY_RESULT,
        "command_slug": "ubuntu-26-samba-ad-dc-verify",
    },
)

_COMMAND_DESCRIPTIONS = {
    "ubuntu-26-samba-ad-dc-preflight": (
        "Backend uploads the hash-pinned installer program and runs its "
        "check-only mode, returning structured verdicts without mutation."
    ),
    "ubuntu-26-samba-ad-dc-provision": (
        "Backend uploads the hash-pinned installer program, delivers settings "
        "on stdin, runs the staged bootstrap, and proves the firewall over a "
        "new SSH connection."
    ),
    "ubuntu-26-samba-ad-dc-verify": (
        "Backend runs the credential-free health probes and returns one "
        "bounded structured report."
    ),
}


def _command(slug):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", slug],
        "description": _COMMAND_DESCRIPTIONS[slug],
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
        "render_mode": "literal",
        "produces_var": "",
        "capture_kind": "",
        "capture_expression": "",
    }


def _assert_fields_match(instance, expected, *, label):
    mismatched = [
        key for key, value in expected.items() if getattr(instance, key, None) != value
    ]
    if mismatched:
        raise RuntimeError(
            f"Refusing to overwrite existing {label}; mismatched fields: "
            + ", ".join(sorted(mismatched))
        )


def _seed_commands(RPCProcedureCommand, procedure, name, slug, *, created):
    expected = _command(slug)
    commands = list(
        RPCProcedureCommand.objects.filter(procedure=procedure).order_by("sequence")
    )
    if created:
        if commands:
            raise RuntimeError(
                f"Refusing to seed {name}; orphan commands already exist."
            )
        RPCProcedureCommand.objects.create(procedure=procedure, sequence=1, **expected)
        return
    if len(commands) != 1 or getattr(commands[0], "sequence", None) != 1:
        raise RuntimeError(
            f"Refusing to overwrite existing procedure {name}; "
            "expected exactly one command at sequence 1."
        )
    _assert_fields_match(commands[0], expected, label=f"command for {name}")


def seed_ubuntu_26_samba_ad_dc_procedures(apps, schema_editor):
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
                "transport_driver": "asyncssh",
                "transport_pinned": True,
                "transport_driver_chain": [],
                "output_parser": "none",
                "output_schema": {},
            }
        )
        procedure = RPCProcedure.objects.filter(name=row["name"]).first()
        created = procedure is None
        if created:
            procedure = RPCProcedure.objects.create(name=row["name"], **defaults)
        else:
            _assert_fields_match(procedure, defaults, label=f"procedure {row['name']}")
        _seed_commands(
            RPCProcedureCommand,
            procedure,
            row["name"],
            row["command_slug"],
            created=created,
        )


def unseed_ubuntu_26_samba_ad_dc_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[row["name"] for row in _PROCEDURES]).update(
        enabled=False
    )


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0102_seed_proxbox_api_image_recovery"),
    ]

    operations = [
        migrations.RunPython(
            seed_ubuntu_26_samba_ad_dc_procedures,
            reverse_code=unseed_ubuntu_26_samba_ad_dc_procedures,
        ),
    ]
