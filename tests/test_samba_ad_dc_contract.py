"""Validator matrices for the Ubuntu 26.04 Samba AD DC bootstrap contract.

Every accept/reject case below is transcribed by hand from the behaviour of the
reviewed operator installer's validators (``ad_domain``, ``short_name``,
``ipv4``, ``client_networks``, ``ntp_sources``, ``share_name``, ``share_path``,
``port_list``, ``source_networks``, ``bounded_integer``). Expected values are
never derived from the code under test. Where this contract is deliberately
stricter than the installer (netmask notation, scoped IPv6, non-ASCII letters
that case-fold into ASCII, non-boolean ``dry_run`` spellings), the case is
marked ``STRICTER`` so a reviewer can see the deviation is intentional.

The module under test is stdlib-only, so it is loaded straight from its file
with no Django or NetBox stubs (importing the ``netbox_rpc`` package would pull
in ``netbox.plugins``).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_contract():
    spec = importlib.util.spec_from_file_location(
        "samba_ad_dc_contract_under_test",
        ROOT / "netbox_rpc/samba_ad_dc_contract.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = _load_contract()

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

VALID_PARAMS = {
    "domain": "ad.example.com",
    "netbios": "EXAMPLE",
    "hostname": "ad01",
    "ip": "10.0.30.10",
    "forwarder": "10.0.30.1",
    "client_networks": ["10.0.30.0/24"],
}
LIVE_EXTRAS = {
    "dry_run": False,
    "admin_credential_pk": 73,
    "ssh_ports": [22],
    "ssh_networks": ["10.0.50.0/24"],
}


def _label(length: int, char: str = "a") -> str:
    return char * length


# A 237-character domain: three 63-character labels plus a 45-character label
# with three separators (63 * 3 + 45 + 3 = 237).
DOMAIN_237 = ".".join([_label(63), _label(63), _label(63), _label(45)])
DOMAIN_238 = ".".join([_label(63), _label(63), _label(63), _label(46)])
assert len(DOMAIN_237) == 237
assert len(DOMAIN_238) == 238


# --------------------------------------------------------------------------- #
# ad_domain / short_name / ipv4
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ad.example.com", "ad.example.com"),
        ("AD.Example.COM", "ad.example.com"),  # installer lower-cases first
        ("corp.example.br", "corp.example.br"),
        ("a.b", "a.b"),
        ("a-b.c-d.example", "a-b.c-d.example"),
        ("ad.example.co.uk", "ad.example.co.uk"),
        ("1.example.com", "1.example.com"),  # a digit-only NON-last label is fine
        (DOMAIN_237, DOMAIN_237),
    ],
)
def test_domain_accepts(value: str, expected: str) -> None:
    assert contract.ad_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "example",  # single label
        "example.local",  # .local is refused
        "EXAMPLE.LOCAL",
        "ad.example.123",  # all-digit last label
        "192.168.1.1",  # an IP address
        "-a.example.com",
        "a-.example.com",
        "a..example.com",  # empty label
        "ad.example.com.",  # trailing dot => empty label
        ".ad.example.com",
        " ad.example.com",
        "ad.example.com ",
        "ad.example.com\n",
        "ad_ex.example.com",  # underscore is not a DNS-label character
        "ad.example.com/x",
        "ad.exa mple.com",
        "",
        _label(64) + ".com",  # a label longer than 63 characters
        DOMAIN_238,  # one character over the 237 limit
        "ad.exämple.com",  # non-ASCII
        "ad.Kelvin.com",  # STRICTER: the installer's str.lower() folds this to ASCII 'k'
        123,
        None,
        True,
        ["ad.example.com"],
        b"ad.example.com",
    ],
)
def test_domain_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.ad_domain(value)


@pytest.mark.parametrize(
    "value",
    [
        "CORP",
        "corp",
        "A",
        "A1",
        "AB-C1",
        "A" + "B" * 13 + "C",  # 15 characters
        "Ad01",
    ],
)
def test_short_name_accepts(value: str) -> None:
    assert contract.short_name(value, "netbios") == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "A" * 16,
        "1CORP",  # must begin with a letter
        "-CORP",
        "CORP-",  # must end with a letter or digit
        "CO RP",
        "CORP\n",
        "CORP.X",
        "CO_RP",
        "ÇORP",
        "corpK",
        7,
        None,
    ],
)
def test_short_name_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.short_name(value, "netbios")


@pytest.mark.parametrize(
    "value",
    [
        "10.0.30.10",
        "192.168.1.5",
        "172.16.0.1",
        "100.64.0.1",
        "8.8.8.8",
        "1.2.3.4",
        "223.255.255.254",
    ],
)
def test_ipv4_accepts_routable_unicast_including_private(value: str) -> None:
    assert contract.ipv4(value, "ip") == value


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",  # loopback
        "127.255.255.254",
        "0.0.0.0",  # unspecified
        "0.1.2.3",  # first octet zero
        "224.0.0.1",  # multicast
        "239.255.255.255",
        "169.254.1.1",  # link-local
        "240.0.0.1",  # reserved
        "255.255.255.255",
        "256.1.1.1",
        "10.0.0",
        "10.0.0.1.1",
        "010.0.0.1",  # leading zero (ambiguous octal)
        "10.0.0.1/24",
        "::1",
        " 10.0.0.1",
        "10.0.0.1 ",
        "10.0.0.1\n",
        "１０.0.0.1",  # full-width digits
        "10.0.0.a",
        "",
        167772161,  # an int must never be coerced to an address
        None,
        True,
    ],
)
def test_ipv4_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.ipv4(value, "ip")


# --------------------------------------------------------------------------- #
# client_networks / ntp_servers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (["10.0.30.0/24"], ["10.0.30.0/24"]),
        (
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        ),
        (["10.0.0.5/32"], ["10.0.0.5/32"]),
        (["10.0.0.0/08"], ["10.0.0.0/8"]),  # canonicalized
        ([f"10.{n}.0.0/16" for n in range(16)], [f"10.{n}.0.0/16" for n in range(16)]),
    ],
)
def test_client_networks_accepts(value: list[str], expected: list[str]) -> None:
    assert contract.client_networks(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        [],
        [f"10.{n}.0.0/16" for n in range(17)],  # 17 entries
        ["10.0.30.0"],  # no prefix length
        ["10.0.30.5/24"],  # host bits set
        ["0.0.0.0/0"],
        ["224.0.0.0/4"],
        ["127.0.0.0/8"],
        ["169.254.0.0/16"],
        ["10.0.0.0/24", "10.0.0.0/24"],  # duplicate
        ["10.0.0.0/8", "10.0.0.0/08"],  # duplicate only after canonicalization
        "10.0.0.0/24",  # a string, not an array
        ["10.0.0.0/255.255.255.0"],  # STRICTER: netmask notation
        ["10.0.0.0/0.0.0.255"],  # STRICTER: hostmask notation
        ["10.0.0.0/33"],
        ["10.0.0.0/024"],
        ["10.0.0.0/24 "],
        ["10.0.0.0/24\n"],
        [10],
        [None],
        ["2001:db8::/32"],  # IPv6 is not a client network
        None,
    ],
)
def test_client_networks_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.client_networks(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (["a.ntp.br", "b.ntp.br", "c.ntp.br"], ["a.ntp.br", "b.ntp.br", "c.ntp.br"]),
        (["time.cloudflare.com"], ["time.cloudflare.com"]),
        (["200.160.0.8"], ["200.160.0.8"]),
        (["2001:db8::1"], ["2001:db8::1"]),
        (["NTP.BR"], ["ntp.br"]),  # DNS names are lower-cased
        (["pool"], ["pool"]),  # a single DNS label is accepted by the installer
        ([f"n{n}.ntp.br" for n in range(8)], [f"n{n}.ntp.br" for n in range(8)]),
    ],
)
def test_ntp_servers_accepts(value: list[str], expected: list[str]) -> None:
    assert contract.ntp_servers(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        [],
        [f"n{n}.ntp.br" for n in range(9)],  # 9 entries
        ["0.0.0.0"],
        ["127.0.0.1"],
        ["224.0.0.1"],
        ["169.254.1.1"],
        ["::"],
        ["::1"],
        ["ff02::1"],
        ["fe80::1"],
        ["fe80::1%eth0"],  # STRICTER: scoped IPv6
        ["2001:db8::1%eth0"],  # STRICTER: scoped IPv6
        ["-a.example.com"],
        ["a..b"],
        ["a.ntp.br."],
        ["a b"],
        ["a.ntp.br", "A.NTP.BR"],  # duplicate after lower-casing
        ["ntp.br;id"],
        ["ntp.br\n"],
        [""],
        [1],
        ["a_b.example.com"],
        ["x" * 254],
        "a.ntp.br",
        None,
    ],
)
def test_ntp_servers_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.ntp_servers(value)


# --------------------------------------------------------------------------- #
# timezone / share_name / share_path
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    [
        "America/Sao_Paulo",
        "UTC",
        "Etc/GMT+3",
        "America/Argentina/Buenos_Aires",
        "America/Port-au-Prince",
        "Europe/London",
    ],
)
def test_timezone_accepts(value: str) -> None:
    assert contract.timezone_name(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/etc/passwd",  # leading slash
        "../etc/passwd",
        "America/../x",
        "America//Sao_Paulo",
        "America/",
        "Sao Paulo",
        "America/Sao_Paulo\n",
        "A" * 65,
        "UTC;id",
        "America\\Sao",
        "América/Sao_Paulo",
        None,
        5,
    ],
)
def test_timezone_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.timezone_name(value)


@pytest.mark.parametrize("value", ["shared", "Data_1", "a", "A" * 64, "x-y", "Shared"])
def test_share_name_accepts(value: str) -> None:
    assert contract.share_name(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "1data",
        "_data",
        "-data",
        "A" * 65,
        "da ta",
        "data.x",
        "data\n",
        "global",  # reserved, in every case spelling
        "GLOBAL",
        "homes",
        "HOMES",
        "printers",
        "Printers",
        "sysvol",
        "SYSVOL",
        "netlogon",
        "NetLogon",
        "ipc",
        "IPC",
        "admin",
        "Admin",
        "ipc$",
        None,
        7,
    ],
)
def test_share_name_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.share_name(value)


@pytest.mark.parametrize(
    "value",
    [
        "/srv/samba/shared",
        "/srv/data",
        "/srv/a.b/c-d_e",
        "/srv/.hidden",  # a dot-prefixed component that is not "." or ".."
        "/srv/..hidden",
        "/srv/" + "a" * 250,  # 255 characters
    ],
)
def test_share_path_accepts(value: str) -> None:
    assert contract.share_path(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "/srv",  # needs at least one component
        "/srv/",
        "/srv/samba/",
        "/srv//x",
        "/srv/samba/../etc",
        "/srv/./x",
        "/srv/..",
        "/srv/.",
        "/etc/samba",
        "/root/share",
        "/var/lib/samba/private",
        "/srvx/data",
        "srv/data",
        "/srv/da ta",
        "/srv/data\n",
        "/srv/a;b",
        "/srv/" + "a" * 251,  # 256 characters: over the explicit bound
        "",
        None,
        7,
    ],
)
def test_share_path_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.share_path(value)


# --------------------------------------------------------------------------- #
# ssh_ports / source networks
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    [
        [],
        [22],
        [22, 2222],
        [1],
        [65535],
        list(range(2000, 2016)),  # 16 unique ports
    ],
)
def test_ssh_ports_accepts(value: list[int]) -> None:
    assert contract.ssh_ports(value) == value


@pytest.mark.parametrize(
    "value",
    [
        list(range(2000, 2017)),  # 17 entries
        [0],
        [65536],
        [-1],
        [22, 22],
        [53],
        [88],
        [135],
        [139],
        [389],
        [445],
        [464],
        [636],
        [3268],
        [3269],
        [22, 445],
        ["22"],
        [22.0],
        [True],
        [22.5],
        [None],
        "22",
        22,
        None,
    ],
)
def test_ssh_ports_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.ssh_ports(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ([], []),
        (["10.0.30.5"], ["10.0.30.5/32"]),
        (["10.0.30.0/24"], ["10.0.30.0/24"]),
        (["2001:db8::/32"], ["2001:db8::/32"]),
        (["2001:db8::1"], ["2001:db8::1/128"]),
        (["fd00::/8"], ["fd00::/8"]),
        (["10.0.30.0/24", "fd00::/8"], ["10.0.30.0/24", "fd00::/8"]),
        ([f"10.0.{n}.0/24" for n in range(32)], [f"10.0.{n}.0/24" for n in range(32)]),
    ],
)
def test_source_networks_accepts(value: list[str], expected: list[str]) -> None:
    assert contract.source_networks(value, "ssh_networks") == expected


@pytest.mark.parametrize(
    "value",
    [
        ["10.0.30.5/24"],  # host bits set
        ["0.0.0.0/0"],
        ["::/0"],
        ["224.0.0.1"],
        ["127.0.0.1"],
        ["::1"],
        ["169.254.1.1"],
        ["fe80::/10"],
        ["ff02::1"],
        ["0.0.0.0"],
        ["::"],
        ["240.0.0.1"],  # reserved
        ["fe80::1%eth0"],  # STRICTER: scoped IPv6
        ["10.0.0.0/255.0.0.0"],  # STRICTER: netmask notation
        ["10.0.0.5", "10.0.0.5/32"],  # duplicate after canonicalization
        [f"10.0.{n}.0/24" for n in range(33)],  # 33 entries
        "none",  # the installer's interactive sentinel is not a JSON value
        ["none"],
        [""],
        [10],
        [None],
        "10.0.30.0/24",
        None,
    ],
)
def test_source_networks_rejects(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.source_networks(value, "ssh_networks")


# --------------------------------------------------------------------------- #
# strict scalar helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "minimum", "maximum"),
    [
        ("fail2ban_findtime", 60, 86400),
        ("smb_max_retry", 3, 100),
        ("smb_bantime", 60, 86400),
        ("ssh_max_retry", 3, 100),
        ("ssh_bantime", 60, 86400),
    ],
)
def test_bounded_integers_enforce_the_installer_bounds(
    name: str, minimum: int, maximum: int
) -> None:
    for accepted in (minimum, minimum + 1, maximum - 1, maximum):
        assert contract.strict_int(accepted, name, minimum, maximum) == accepted
    for rejected in (minimum - 1, maximum + 1, 0, -1, "600", 600.0, 600.7, True, None):
        with pytest.raises(contract.SambaParamError):
            contract.strict_int(rejected, name, minimum, maximum)


def test_bounded_integer_table_matches_the_installer_defaults() -> None:
    # Transcribed from gather_security(): (name, default, minimum, maximum).
    assert contract.BOUNDED_INTEGER_PARAMS == (
        ("fail2ban_findtime", 600, 60, 86400),
        ("smb_max_retry", 10, 3, 100),
        ("smb_bantime", 900, 60, 86400),
        ("ssh_max_retry", 5, 3, 100),
        ("ssh_bantime", 3600, 60, 86400),
    )


@pytest.mark.parametrize("value", ["false", "true", "yes", 0, 1, None, "", [], {}])
def test_strict_bool_rejects_everything_but_a_boolean(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.strict_bool(value, "dry_run")
    assert contract.strict_bool(True, "dry_run") is True
    assert contract.strict_bool(False, "dry_run") is False


@pytest.mark.parametrize("value", [1, 73, 2**31])
def test_credential_pk_accepts_positive_integers(value: int) -> None:
    assert contract.credential_pk(value) == value


@pytest.mark.parametrize("value", [0, -1, "5", 5.0, 1.5, True, None, [], {}])
def test_credential_pk_rejects_non_positive_or_non_integer(value: object) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.credential_pk(value)


def test_errors_never_echo_the_offending_value() -> None:
    marker = "S3cr3t-marker-value"
    for call in (
        lambda: contract.ad_domain(marker),
        lambda: contract.ad_domain("S3cr3t_marker.example.com"),  # dns_name error path
        lambda: contract.ntp_servers(["-S3cr3t-marker.example.com"]),  # dns_name path
        lambda: contract.ipv4(marker, "ip"),
        lambda: contract.client_networks([marker]),
        lambda: contract.ntp_servers([marker + "!"]),
        lambda: contract.timezone_name(marker + "!"),
        lambda: contract.share_name(marker + "!"),
        lambda: contract.share_path(marker),
        lambda: contract.source_networks([marker], "ssh_networks"),
        lambda: contract.resolve_provision_settings({**VALID_PARAMS, marker: 1}),
    ):
        with pytest.raises(contract.SambaParamError) as excinfo:
            call()
        if "params" not in excinfo.value.field:
            assert "s3cr3t" not in str(excinfo.value).lower()


# --------------------------------------------------------------------------- #
# resolve_provision_settings
# --------------------------------------------------------------------------- #


def test_defaults_are_resolved_and_explicit() -> None:
    settings = contract.resolve_provision_settings(dict(VALID_PARAMS))

    # Transcribed from the installer's defaults; every one is emitted so the
    # payload holds concrete values and the backend re-derives nothing.
    assert settings == {
        "dry_run": True,
        "domain": "ad.example.com",
        "netbios": "EXAMPLE",
        "hostname": "ad01",
        "ip": "10.0.30.10",
        "forwarder": "10.0.30.1",
        "client_networks": ["10.0.30.0/24"],
        "ntp_servers": ["a.ntp.br", "b.ntp.br", "c.ntp.br"],
        "timezone": "America/Sao_Paulo",
        "share_name": "shared",
        "share_path": "/srv/samba/shared",
        "ssh_ports": [],
        "ssh_networks": [],
        "ban_exempt_networks": [],
        "fail2ban_findtime": 600,
        "smb_max_retry": 10,
        "smb_bantime": 900,
        "ssh_max_retry": 5,
        "ssh_bantime": 3600,
        "legacy_netbios": False,
        "freeze_cloud_init": True,
    }


def test_canonicalization_of_case_sensitive_names() -> None:
    settings = contract.resolve_provision_settings(
        {
            **VALID_PARAMS,
            "domain": "AD.Example.COM",
            "netbios": "example",
            "hostname": "AD01",
            "share_name": "Data",
        }
    )

    assert settings["domain"] == "ad.example.com"
    assert settings["netbios"] == "EXAMPLE"
    assert settings["hostname"] == "ad01"
    assert settings["share_name"] == "Data"  # the share name keeps its case
    assert settings["share_path"] == "/srv/samba/Data"


def test_a_live_run_with_every_requirement_resolves() -> None:
    settings = contract.resolve_provision_settings({**VALID_PARAMS, **LIVE_EXTRAS})

    assert settings["dry_run"] is False
    assert settings["admin_credential_pk"] == 73
    assert settings["ssh_ports"] == [22]
    assert settings["ssh_networks"] == ["10.0.50.0/24"]


def test_dry_run_may_carry_or_omit_the_credential_reference() -> None:
    omitted = contract.resolve_provision_settings(dict(VALID_PARAMS))
    assert "admin_credential_pk" not in omitted
    carried = contract.resolve_provision_settings(
        {**VALID_PARAMS, "admin_credential_pk": 9}
    )
    assert carried["admin_credential_pk"] == 9


@pytest.mark.parametrize(
    ("override", "field"),
    [
        ({"hostname": "example"}, "hostname"),  # hostname.upper() == netbios
        ({"hostname": "EXAMPLE"}, "hostname"),
        ({"forwarder": "10.0.30.10"}, "forwarder"),  # forwarder == the DC
        ({"ssh_ports": [22]}, "ssh_networks"),  # ports without networks
        ({"ssh_networks": ["10.0.50.0/24"]}, "ssh_networks"),  # networks without ports
        (
            {"dry_run": False, "admin_credential_pk": 73},
            "ssh_ports",
        ),  # live run with no SSH allowlist
        (
            {"dry_run": False, "ssh_ports": [22], "ssh_networks": ["10.0.50.0/24"]},
            "admin_credential_pk",
        ),  # live run with no credential reference
    ],
)
def test_cross_field_constraints(override: dict, field: str) -> None:
    with pytest.raises(contract.SambaParamError) as excinfo:
        contract.resolve_provision_settings({**VALID_PARAMS, **override})
    assert excinfo.value.field == field


@pytest.mark.parametrize("missing", sorted(contract.PROVISION_REQUIRED_PARAMS))
def test_every_required_parameter_is_required(missing: str) -> None:
    params = {key: value for key, value in VALID_PARAMS.items() if key != missing}
    with pytest.raises(contract.SambaParamError) as excinfo:
        contract.resolve_provision_settings(params)
    assert missing in str(excinfo.value)


@pytest.mark.parametrize(
    "extra",
    [
        "password",
        "admin_password",
        "administrator_password",
        "password_hash",
        "token",
        "secret",
        "passphrase",
        "shell",
        "command",
        "argv",
        "rpc_ssh_host",
        "rpc_ssh_credential_pk",
        "unknown_param",
    ],
)
def test_unknown_and_secret_shaped_parameters_are_rejected(extra: str) -> None:
    with pytest.raises(contract.SambaParamError) as excinfo:
        contract.resolve_provision_settings({**VALID_PARAMS, extra: "x"})
    assert extra in str(excinfo.value)


def test_platform_stamped_internal_keys_are_tolerated() -> None:
    settings = contract.resolve_provision_settings(
        {
            **VALID_PARAMS,
            "_intent": 3,
            "_intent_name": "bootstrap",
            "_timeout_seconds_snapshot": 3600,
        }
    )
    assert not any(key.startswith("_") for key in settings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dry_run", "false"),  # bool("false") is True; must be rejected, not coerced
        ("dry_run", 0),
        ("dry_run", None),
        ("legacy_netbios", "no"),
        ("freeze_cloud_init", 1),
        ("fail2ban_findtime", "600"),
        ("smb_max_retry", 10.5),
        ("ssh_bantime", True),
        ("admin_credential_pk", "73"),
        ("admin_credential_pk", None),
        ("ntp_servers", None),
        ("timezone", None),
        ("share_name", None),
        ("ssh_ports", None),
    ],
)
def test_explicit_wrong_types_are_never_coerced_to_defaults(
    field: str, value: object
) -> None:
    with pytest.raises(contract.SambaParamError):
        contract.resolve_provision_settings({**VALID_PARAMS, field: value})
