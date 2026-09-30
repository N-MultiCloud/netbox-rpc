"""Pure validation contract for the Ubuntu 26.04 Samba AD DC bootstrap.

Every validator here mirrors a validator of the reviewed operator installer
(``ad_domain``, ``short_name``, ``ipv4``, ``client_networks``, ``ntp_sources``,
``share_name``, ``share_path``, ``port_list``, ``source_networks`` and
``bounded_integer``) and is never looser than it. Where the installer accepts a
spelling that has no safe canonical form (netmask notation, scoped IPv6, non-ASCII
letters that case-fold into ASCII), this contract rejects it.

The module is stdlib-only so the pure-domain test tier can exercise it without
Django or NetBox. Errors are :class:`SambaParamError` with a field name and a
fixed reason; the offending value is never echoed, so a caller who pastes a
secret into a parameter cannot make it appear in an error message, event or log.

No function in this module accepts, derives, hashes or forwards a password. The
domain Administrator password is referenced only by ``admin_credential_pk`` (a
netbox-nms ``DeviceCredential`` id) and is resolved by the execution backend.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# Keys the platform itself stamps into params after schema validation (intent
# origin markers, the frozen RQ timeout snapshot). They are not caller input.
INTERNAL_PARAM_KEYS = frozenset(
    {"_intent", "_intent_name", "_timeout_seconds_snapshot"}
)

SSH_OVERRIDE_PARAM_KEYS = frozenset(
    {
        "rpc_ssh_credential_pk",
        "rpc_ssh_host",
        "rpc_ssh_port",
        "rpc_ssh_known_hosts_entry",
        "rpc_ssh_strict_host_key_checking",
    }
)

DEFAULT_NTP_SERVERS = ("a.ntp.br", "b.ntp.br", "c.ntp.br")
DEFAULT_TIMEZONE = "America/Sao_Paulo"
DEFAULT_SHARE_NAME = "shared"

# Ports that collide with Samba AD service ports are never valid SSH ports.
RESERVED_SSH_PORTS = frozenset({53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269})
RESERVED_SHARE_NAMES = frozenset(
    {"global", "homes", "printers", "sysvol", "netlogon", "ipc", "admin"}
)

# Explicit-default parameter table for ``provision``: (name, default, minimum,
# maximum) for the bounded fail2ban integers, mirroring ``bounded_integer``.
BOUNDED_INTEGER_PARAMS = (
    ("fail2ban_findtime", 600, 60, 86400),
    ("smb_max_retry", 10, 3, 100),
    ("smb_bantime", 900, 60, 86400),
    ("ssh_max_retry", 5, 3, 100),
    ("ssh_bantime", 3600, 60, 86400),
)

PROVISION_REQUIRED_PARAMS = frozenset(
    {"domain", "netbios", "hostname", "ip", "forwarder", "client_networks"}
)
PROVISION_OPTIONAL_PARAMS = frozenset(
    {
        "dry_run",
        "ntp_servers",
        "timezone",
        "share_name",
        "share_path",
        "ssh_ports",
        "ssh_networks",
        "ban_exempt_networks",
        "legacy_netbios",
        "freeze_cloud_init",
        "admin_credential_pk",
    }
    | {name for name, _default, _minimum, _maximum in BOUNDED_INTEGER_PARAMS}
)
PROVISION_PARAMS = PROVISION_REQUIRED_PARAMS | PROVISION_OPTIONAL_PARAMS

_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SHORT_NAME_RE = re.compile(r"[A-Za-z](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?")
_IPV4_RE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
_IPV4_CIDR_RE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}")
_SOURCE_NETWORK_RE = re.compile(r"[0-9A-Fa-f:.]{2,45}(?:/[0-9]{1,3})?")
_TIMEZONE_RE = re.compile(r"[A-Za-z0-9_+/-]{1,64}")
_SHARE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_SHARE_PATH_RE = re.compile(r"/srv(?:/[A-Za-z0-9_.-]+)+")
_SHARE_PATH_MAX_LENGTH = 255
_NTP_SOURCE_RE = re.compile(r"[A-Za-z0-9:.-]{1,253}")


class SambaParamError(ValueError):
    """A parameter failed validation. The message never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field} {reason}")
        self.field = field
        self.reason = reason


def _ascii_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise SambaParamError(field, "must be an ASCII string.")
    return value


def strict_bool(value: object, field: str) -> bool:
    """Accept only a real boolean; ``"false"``, ``0`` and ``None`` are rejected."""

    if not isinstance(value, bool):
        raise SambaParamError(field, "must be a boolean.")
    return value


def strict_int(value: object, field: str, minimum: int, maximum: int | None) -> int:
    """Accept only a real integer inside the bounds (not ``True``, ``"5"``, ``5.5``)."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise SambaParamError(field, "must be an integer.")
    if value < minimum or (maximum is not None and value > maximum):
        raise SambaParamError(field, "is outside the permitted range.")
    return value


def _strict_list(value: object, field: str, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise SambaParamError(field, "must be an array.")
    if not minimum <= len(value) <= maximum:
        raise SambaParamError(
            field, f"must contain between {minimum} and {maximum} entries."
        )
    return value


def _reject_duplicates(canonical: list[str], field: str) -> list[str]:
    if len(set(canonical)) != len(canonical):
        raise SambaParamError(field, "must not contain duplicate entries.")
    return canonical


def dns_name(value: object, field: str) -> str:
    """Return the lower-cased DNS name (installer ``dns_name``); ASCII labels only."""

    text = _ascii_text(value, field).lower()
    if len(text) > 253 or not all(
        _DNS_LABEL_RE.fullmatch(label) for label in text.split(".")
    ):
        raise SambaParamError(
            field, "must be a DNS name of letters, digits and hyphens."
        )
    return text


def ad_domain(value: object, field: str = "domain") -> str:
    """Multi-label AD DNS domain, at most 237 characters, not ``.local``."""

    text = dns_name(value, field)
    if (
        "." not in text
        or text.endswith(".local")
        or text.split(".")[-1].isdigit()
        or len(text) > 237
    ):
        raise SambaParamError(
            field,
            "must be a multi-label DNS domain of at most 237 characters, "
            "not an IP address or a .local name.",
        )
    return text


def short_name(value: object, field: str) -> str:
    """NetBIOS-style short name: 1-15 characters, letter first, alphanumeric last."""

    text = _ascii_text(value, field)
    if not _SHORT_NAME_RE.fullmatch(text):
        raise SambaParamError(
            field,
            "must be 1-15 characters, beginning with a letter and ending in "
            "a letter or digit.",
        )
    return text


def ipv4(value: object, field: str) -> str:
    """Routable unicast IPv4 (private LAN addresses allowed)."""

    text = _ascii_text(value, field)
    if not _IPV4_RE.fullmatch(text):
        raise SambaParamError(field, "must be a dotted-quad IPv4 address.")
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        raise SambaParamError(field, "must be a valid IPv4 address.") from None
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or int(address) >> 24 == 0
    ):
        raise SambaParamError(field, "must be a routable unicast IPv4 address.")
    return str(address)


def client_networks(value: object, field: str = "client_networks") -> list[str]:
    """1-16 unique strict IPv4 CIDRs written with an explicit prefix length."""

    canonical = []
    for item in _strict_list(value, field, 1, 16):
        text = _ascii_text(item, field)
        if not _IPV4_CIDR_RE.fullmatch(text):
            raise SambaParamError(
                field, "entries must be IPv4 CIDRs with a prefix length."
            )
        try:
            network = ipaddress.IPv4Network(text, strict=True)
        except ValueError:
            raise SambaParamError(
                field, "entries must be strict IPv4 networks."
            ) from None
        if (
            network.prefixlen == 0
            or network.is_multicast
            or network.is_loopback
            or network.is_link_local
        ):
            raise SambaParamError(
                field,
                "entries must be trusted client networks, not /0, loopback or multicast.",
            )
        canonical.append(str(network))
    return _reject_duplicates(canonical, field)


def _ntp_source(item: object, field: str) -> str:
    text = _ascii_text(item, field)
    if not _NTP_SOURCE_RE.fullmatch(text):
        raise SambaParamError(field, "entries must be DNS names or IP addresses.")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return dns_name(text, field)
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
    ):
        raise SambaParamError(
            field, "entries must be reachable upstream unicast hosts."
        )
    return str(address)


def ntp_servers(value: object, field: str = "ntp_servers") -> list[str]:
    """1-8 unique NTP sources: strict DNS names or non-special IP addresses."""

    canonical = [_ntp_source(item, field) for item in _strict_list(value, field, 1, 8)]
    return _reject_duplicates(canonical, field)


def timezone_name(value: object, field: str = "timezone") -> str:
    """Timezone identifier charset; the host validates it against zoneinfo."""

    text = _ascii_text(value, field)
    if (
        not _TIMEZONE_RE.fullmatch(text)
        or text.startswith("/")
        or ".." in text
        or "" in text.split("/")
    ):
        raise SambaParamError(
            field, "must be a relative timezone identifier such as America/Sao_Paulo."
        )
    return text


def share_name(value: object, field: str = "share_name") -> str:
    text = _ascii_text(value, field)
    if not _SHARE_NAME_RE.fullmatch(text):
        raise SambaParamError(
            field,
            "must be 1-64 letters, digits, underscores or hyphens, starting "
            "with a letter.",
        )
    if text.lower() in RESERVED_SHARE_NAMES:
        raise SambaParamError(field, "is a reserved share name.")
    return text


def share_path(value: object, field: str = "share_path") -> str:
    """Absolute path below ``/srv`` with no ``.`` or ``..`` component."""

    text = _ascii_text(value, field)
    if (
        len(text) > _SHARE_PATH_MAX_LENGTH
        or not _SHARE_PATH_RE.fullmatch(text)
        or any(part in {".", ".."} for part in text.split("/"))
    ):
        raise SambaParamError(
            field,
            "must be an absolute path below /srv without spaces or . / .. components.",
        )
    return text


def ssh_ports(value: object, field: str = "ssh_ports") -> list[int]:
    """0-16 unique TCP ports that do not collide with Samba AD service ports."""

    ports = [
        strict_int(item, field, 1, 65535) for item in _strict_list(value, field, 0, 16)
    ]
    if len(set(ports)) != len(ports):
        raise SambaParamError(field, "must not contain duplicate entries.")
    if RESERVED_SSH_PORTS & set(ports):
        raise SambaParamError(field, "must not use a Samba AD service port.")
    return ports


def _source_network(item: object, field: str) -> str:
    text = _ascii_text(item, field)
    if not _SOURCE_NETWORK_RE.fullmatch(text):
        raise SambaParamError(
            field, "entries must be IPv4/IPv6 addresses or CIDRs without a scope id."
        )
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise SambaParamError(
            field, "entries must be strict IPv4/IPv6 networks."
        ) from None
    if (
        network.prefixlen == 0
        or network.is_multicast
        or network.is_loopback
        or network.is_link_local
        or network.is_unspecified
        or network.is_reserved
    ):
        raise SambaParamError(
            field,
            "entries must be specific unicast hosts or networks, not /0 or special ranges.",
        )
    return str(network)


def source_networks(value: object, field: str) -> list[str]:
    """0-32 unique strict IPv4/IPv6 hosts or CIDRs (installer ``source_networks``)."""

    canonical = [
        _source_network(item, field) for item in _strict_list(value, field, 0, 32)
    ]
    return _reject_duplicates(canonical, field)


def credential_pk(value: object, field: str = "admin_credential_pk") -> int:
    """A netbox-nms DeviceCredential id. Only the reference is ever forwarded."""

    return strict_int(value, field, 1, None)


def unknown_params(params: dict[str, Any], allowed: frozenset[str]) -> list[str]:
    """Sorted unexpected keys, tolerating only the platform-stamped internal keys."""

    return sorted(str(key)[:64] for key in set(params) - allowed - INTERNAL_PARAM_KEYS)[
        :16
    ]


def _resolve_identity(params: dict[str, Any]) -> dict[str, Any]:
    resolved = {
        "domain": ad_domain(params["domain"]),
        "netbios": short_name(params["netbios"], "netbios").upper(),
        "hostname": short_name(params["hostname"], "hostname").lower(),
    }
    if resolved["hostname"].upper() == resolved["netbios"]:
        raise SambaParamError("hostname", "must differ from the NetBIOS domain name.")
    return resolved


def _resolve_network(params: dict[str, Any]) -> dict[str, Any]:
    resolved = {
        "ip": ipv4(params["ip"], "ip"),
        "forwarder": ipv4(params["forwarder"], "forwarder"),
        "client_networks": client_networks(params["client_networks"]),
        "ntp_servers": ntp_servers(
            params.get("ntp_servers", list(DEFAULT_NTP_SERVERS))
        ),
        "timezone": timezone_name(params.get("timezone", DEFAULT_TIMEZONE)),
    }
    if resolved["forwarder"] == resolved["ip"]:
        raise SambaParamError("forwarder", "must not point back to the DC itself.")
    return resolved


def _resolve_share(params: dict[str, Any]) -> dict[str, Any]:
    name = share_name(params.get("share_name", DEFAULT_SHARE_NAME))
    default_path = f"/srv/samba/{name}"
    return {
        "share_name": name,
        "share_path": share_path(params.get("share_path", default_path)),
    }


def _resolve_security(params: dict[str, Any]) -> dict[str, Any]:
    resolved: dict[str, Any] = {
        "ssh_ports": ssh_ports(params.get("ssh_ports", [])),
        "ssh_networks": source_networks(params.get("ssh_networks", []), "ssh_networks"),
        "ban_exempt_networks": source_networks(
            params.get("ban_exempt_networks", []), "ban_exempt_networks"
        ),
    }
    for name, default, minimum, maximum in BOUNDED_INTEGER_PARAMS:
        resolved[name] = strict_int(params.get(name, default), name, minimum, maximum)
    resolved["legacy_netbios"] = strict_bool(
        params.get("legacy_netbios", False), "legacy_netbios"
    )
    resolved["freeze_cloud_init"] = strict_bool(
        params.get("freeze_cloud_init", True), "freeze_cloud_init"
    )
    return resolved


def _check_ssh_allowlist(resolved: dict[str, Any], *, dry_run: bool) -> None:
    has_ports = bool(resolved["ssh_ports"])
    has_networks = bool(resolved["ssh_networks"])
    if has_ports != has_networks:
        raise SambaParamError(
            "ssh_networks", "must be provided if and only if ssh_ports is provided."
        )
    if not dry_run and not has_ports:
        raise SambaParamError(
            "ssh_ports",
            "must list the executing session's SSH port for a live run; the "
            "installer proves the firewall will not lock the operator out.",
        )


def resolve_provision_settings(params: dict[str, Any]) -> dict[str, Any]:
    """Validate and canonicalize every ``provision`` parameter.

    Returns a new dict holding every resolved value, defaults included, so the
    approval snapshot binds concrete values and the backend never re-derives a
    default. Raises :class:`SambaParamError` on the first violation.
    """

    unexpected = unknown_params(params, PROVISION_PARAMS)
    if unexpected:
        raise SambaParamError(
            "params", f"contains unsupported parameters: {', '.join(unexpected)}."
        )
    missing = sorted(PROVISION_REQUIRED_PARAMS - set(params))
    if missing:
        raise SambaParamError(
            "params", f"is missing required parameters: {', '.join(missing)}."
        )

    dry_run = strict_bool(params.get("dry_run", True), "dry_run")
    settings: dict[str, Any] = {"dry_run": dry_run}
    settings.update(_resolve_identity(params))
    settings.update(_resolve_network(params))
    settings.update(_resolve_share(params))
    settings.update(_resolve_security(params))
    _check_ssh_allowlist(settings, dry_run=dry_run)

    if "admin_credential_pk" in params:
        settings["admin_credential_pk"] = credential_pk(params["admin_credential_pk"])
    elif not dry_run:
        raise SambaParamError(
            "admin_credential_pk", "is required for a live run (dry_run=false)."
        )
    return settings
