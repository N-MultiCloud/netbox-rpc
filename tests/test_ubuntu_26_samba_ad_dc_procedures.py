"""Catalog contract tests for the Ubuntu 26.04 Samba AD DC bootstrap procedures.

Gating, timeouts, parameter sets and schema bounds are transcribed once from the
shared contract below, never read back from the migration. The properties that
matter most:

1. ``provision`` is destructive, approval-gated and has a 3600-second budget;
   ``preflight`` and ``verify`` are read-only and need no approval.
2. No params or result schema declares anything password-shaped, and the params
   schema is closed, so a password can never even be submitted.
3. Every free-form result string has an explicit ``maxLength`` (an undeclared
   string is silently clamped at 4096 characters by the event store).
4. The JSON schema is never stricter than the installer's validators and always
   rejects the shapes the installer rejects that a schema can express.
5. The rows ship enabled, transport-pinned and capability-gated (no separate code
   gate), ``provision`` is registered in the protected two-person catalog with an
   immutable contract identical to the seed, and the migration is additive,
   inline and never deletes audited procedures.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import re
import runpy
import sys
import types
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SEED_MODULE = "netbox_rpc.migrations.0103_seed_ubuntu_26_samba_ad_dc_procedures"
PREFLIGHT = "os.linux.ubuntu.26.samba_ad_dc.preflight"
PROVISION = "os.linux.ubuntu.26.samba_ad_dc.provision"
VERIFY = "os.linux.ubuntu.26.samba_ad_dc.verify"
ALL_PROCEDURES = (PREFLIGHT, PROVISION, VERIFY)

# Transcribed from the shared contract.
EXPECTED_GATING = {
    PREFLIGHT: {"effect": "read", "approval_required": False, "timeout_seconds": 120},
    PROVISION: {
        "effect": "destructive",
        "approval_required": True,
        "timeout_seconds": 3600,
    },
    VERIFY: {"effect": "read", "approval_required": False, "timeout_seconds": 180},
}
EXPECTED_COMMAND_SLUGS = {
    PREFLIGHT: "ubuntu-26-samba-ad-dc-preflight",
    PROVISION: "ubuntu-26-samba-ad-dc-provision",
    VERIFY: "ubuntu-26-samba-ad-dc-verify",
}
SSH_OVERRIDE_PROPERTIES = {
    "rpc_ssh_credential_pk",
    "rpc_ssh_host",
    "rpc_ssh_port",
    "rpc_ssh_known_hosts_entry",
    "rpc_ssh_strict_host_key_checking",
}
EXPECTED_PROVISION_PROPERTIES = {
    "dry_run",
    "domain",
    "netbios",
    "hostname",
    "ip",
    "forwarder",
    "client_networks",
    "ntp_servers",
    "timezone",
    "share_name",
    "share_path",
    "ssh_ports",
    "ssh_networks",
    "ban_exempt_networks",
    "fail2ban_findtime",
    "smb_max_retry",
    "smb_bantime",
    "ssh_max_retry",
    "ssh_bantime",
    "legacy_netbios",
    "freeze_cloud_init",
    "admin_credential_pk",
}
EXPECTED_PROVISION_REQUIRED = {
    "domain",
    "netbios",
    "hostname",
    "ip",
    "forwarder",
    "client_networks",
}
SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "token", "hash", "sha512")
LOG_TAIL_MAX = 65536
RENDERED_CONFIG_MAX = 16384
EVENT_STRING_DEFAULT_LIMIT = 4096


# --------------------------------------------------------------------------- #
# Fixtures and fakes
# --------------------------------------------------------------------------- #


class _ProcedureQuery:
    def __init__(self, manager: "_ProcedureManager", names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def update(self, **fields: Any) -> int:
        matches = [name for name in self.names if name in self.manager.rows]
        for name in matches:
            self.manager.rows[name].update(fields)
        return len(matches)

    def first(self):
        for name in sorted(self.names):
            if name in self.manager.rows:
                return SimpleNamespace(name=name, **self.manager.rows[name])
        return None


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}

    def create(self, *, name: str, **fields: Any):
        self.rows[name] = dict(fields)
        return SimpleNamespace(name=name, **fields)

    def filter(self, *, name__in=None, name=None):
        names = set(name__in) if name__in is not None else {name}
        return _ProcedureQuery(self, names)


class _CommandQuery:
    def __init__(self, manager: "_CommandManager", procedure_name: str) -> None:
        self.manager = manager
        self.procedure_name = procedure_name

    def order_by(self, _field: str):
        return [
            SimpleNamespace(sequence=sequence, **fields)
            for (name, sequence), fields in sorted(self.manager.rows.items())
            if name == self.procedure_name
        ]


class _CommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, Any]] = {}

    def create(self, *, procedure, sequence: int, **fields: Any):
        self.rows[(procedure.name, sequence)] = dict(fields)
        return SimpleNamespace(sequence=sequence, **fields)

    def filter(self, *, procedure):
        return _CommandQuery(self, procedure.name)


def _apps(procedures: _ProcedureManager, commands: _CommandManager):
    def _get_model(app_label: str, model_name: str):
        assert app_label == "netbox_rpc"
        if model_name == "RPCProcedure":
            return SimpleNamespace(objects=procedures)
        assert model_name == "RPCProcedureCommand"
        return SimpleNamespace(objects=commands)

    return SimpleNamespace(get_model=_get_model)


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    migrations = types.ModuleType("django.db.migrations")
    migrations.Migration = type("Migration", (), {})
    migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = migrations
    django.db = django_db
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.migrations", migrations)


@pytest.fixture()
def catalog(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop(SEED_MODULE, None)
    seed = importlib.import_module(SEED_MODULE)
    procedures = _ProcedureManager()
    commands = _CommandManager()
    seed.seed_ubuntu_26_samba_ad_dc_procedures(_apps(procedures, commands), None)
    return seed, procedures, commands


def _walk(schema: Any, path: tuple = ()):
    """Yield ``(path, subschema)`` for every dict inside a JSON schema."""

    if isinstance(schema, dict):
        yield path, schema
        for key, child in schema.items():
            yield from _walk(child, (*path, key))
    elif isinstance(schema, list):
        for index, child in enumerate(schema):
            yield from _walk(child, (*path, index))


def _property_names(schema: Any) -> set[str]:
    names: set[str] = set()
    for _path, node in _walk(schema):
        properties = node.get("properties")
        if isinstance(properties, dict):
            names.update(str(key) for key in properties)
    return names


def _has_type(spec: dict, name: str) -> bool:
    declared = spec.get("type")
    return declared == name or (isinstance(declared, list) and name in declared)


def _load_command_contract():
    spec = importlib.util.spec_from_file_location(
        "samba_ad_dc_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Constants and registration
# --------------------------------------------------------------------------- #


def test_constants_are_complete_capability_gated_and_provision_is_protected() -> None:
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))

    assert constants["UBUNTU_26_SAMBA_AD_DC_PREFLIGHT"] == PREFLIGHT
    assert constants["UBUNTU_26_SAMBA_AD_DC_PROVISION"] == PROVISION
    assert constants["UBUNTU_26_SAMBA_AD_DC_VERIFY"] == VERIFY
    assert constants["UBUNTU_26_SAMBA_AD_DC_PROCEDURE_NAMES"] == frozenset(
        ALL_PROCEDURES
    )
    # The destructive installer must fail closed without an exact backend
    # capability, never degrade to "unknown => proceed".
    assert (
        frozenset(ALL_PROCEDURES)
        <= constants["EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES"]
    )
    # Only the destructive installer is two-person protected; the reads are not.
    protected = constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    assert PROVISION in protected
    assert not {PREFLIGHT, VERIFY} & protected


def test_seed_names_and_handler_ids_equal_the_constants(catalog) -> None:
    _seed, procedures, _commands = catalog
    assert set(procedures.rows) == set(ALL_PROCEDURES)
    for name in ALL_PROCEDURES:
        assert procedures.rows[name]["handler_id"] == name


def test_handlers_are_documented_command_exemptions() -> None:
    command_contract = _load_command_contract()
    assert set(ALL_PROCEDURES) <= command_contract.EXEMPT_HANDLER_IDS
    for name in ALL_PROCEDURES:
        assert len(command_contract.EXEMPT_HANDLER_RATIONALE[name]) > 40


# --------------------------------------------------------------------------- #
# Seed rows
# --------------------------------------------------------------------------- #


def test_seed_gating_is_exactly_the_contract(catalog) -> None:
    _seed, procedures, _commands = catalog

    for name, expected in EXPECTED_GATING.items():
        row = procedures.rows[name]
        assert row["effect"] == expected["effect"]
        assert row["approval_required"] is expected["approval_required"]
        assert row["timeout_seconds"] == expected["timeout_seconds"]
        assert row["version"] == 1
        assert row["target_models"] == ["dcim.device", "virtualization.virtualmachine"]
        assert row["params_schema"]["additionalProperties"] is False


def test_seed_ships_enabled_and_transport_pinned(catalog) -> None:
    _seed, procedures, _commands = catalog

    for name in ALL_PROCEDURES:
        row = procedures.rows[name]
        # Enabled, like the Proxmox OCI pull: the explicit backend-capability
        # requirement (not a second flag) keeps it undispatchable until the
        # paired backend advertises the handler.
        assert row["enabled"] is True
        # The bootstrap program is delivered over AsyncSSH stdin and the firewall
        # proof needs a second AsyncSSH connection; a fallback re-dispatch of the
        # non-rerunnable installer is exactly the hazard pinning prevents.
        assert row["transport_driver"] == "asyncssh"
        assert row["transport_pinned"] is True
        assert row["transport_driver_chain"] == []


def test_seed_has_one_backend_orchestrated_command_per_procedure(catalog) -> None:
    _seed, _procedures, commands = catalog

    assert len(commands.rows) == 3  # exactly one representative row each
    for name in ALL_PROCEDURES:
        command = commands.rows[(name, 1)]
        assert command["step_type"] == "shell_argv"
        assert command["argv"] == ["backend-orchestrated", EXPECTED_COMMAND_SLUGS[name]]
        assert command["render_mode"] == "literal"
        assert command["condition_param"] == ""
        assert command["for_each_param"] == ""
        assert command["continue_on_error"] is False


def test_representative_command_rows_are_structurally_safe(catalog) -> None:
    _seed, _procedures, commands = catalog
    command_contract = _load_command_contract()

    for (name, sequence), row in commands.rows.items():
        assert sequence == 1, name
        for token in row["argv"]:
            assert command_contract.token_is_safe(token), (name, token)
            assert command_contract.token_has_balanced_placeholders(token)
            assert command_contract.extract_placeholders(token) == ()


def test_provision_params_are_the_exact_contract_set(catalog) -> None:
    _seed, procedures, _commands = catalog
    schema = procedures.rows[PROVISION]["params_schema"]

    assert set(schema["properties"]) == EXPECTED_PROVISION_PROPERTIES
    assert set(schema["required"]) == EXPECTED_PROVISION_REQUIRED
    # An approval must bind the object that is executed against.
    assert not SSH_OVERRIDE_PROPERTIES & set(schema["properties"])
    defaults = {
        name: spec["default"]
        for name, spec in schema["properties"].items()
        if "default" in spec
    }
    assert defaults == {
        "dry_run": True,
        "ntp_servers": ["a.ntp.br", "b.ntp.br", "c.ntp.br"],
        "timezone": "America/Sao_Paulo",
        "share_name": "shared",
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


@pytest.mark.parametrize("name", [PREFLIGHT, VERIFY])
def test_read_procedures_accept_only_the_shared_ssh_overrides(catalog, name) -> None:
    _seed, procedures, _commands = catalog
    schema = procedures.rows[name]["params_schema"]
    assert set(schema["properties"]) == SSH_OVERRIDE_PROPERTIES
    assert not schema.get("required")


def test_no_schema_declares_or_returns_anything_password_shaped(catalog) -> None:
    _seed, procedures, _commands = catalog

    for name in ALL_PROCEDURES:
        for schema_key in ("params_schema", "result_schema"):
            names = {
                n.lower() for n in _property_names(procedures.rows[name][schema_key])
            }
            for word in SECRET_WORDS:
                assert not any(word in n for n in names), (name, schema_key, word)
    # The only credential-shaped input is the referenced DeviceCredential id.
    properties = procedures.rows[PROVISION]["params_schema"]["properties"]
    assert properties["admin_credential_pk"]["type"] == "integer"
    assert properties["admin_credential_pk"]["minimum"] == 1


def test_seed_text_never_mentions_a_password_value_or_uses_a_shell() -> None:
    source = (
        ROOT / f"netbox_rpc/migrations/{SEED_MODULE.rsplit('.', 1)[1]}.py"
    ).read_text(encoding="utf-8")
    for forbidden in ("subprocess", "os.system", "shell=True", "pickle"):
        assert forbidden not in source
    called = {
        node.func.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"eval", "exec", "compile", "__import__", "open"}, called
    assert "from netbox_rpc" not in source
    assert "import netbox_rpc" not in source
    assert ".delete(" not in source


def test_seeded_descriptions_fit_the_model_column(catalog) -> None:
    """Every seeded ``description`` must fit ``max_length`` (255).

    The pure-domain fakes enforce no column widths, so an over-long description
    would only fail when a real database applies the migration. This includes the
    property descriptions nested inside the JSON schemas, which the AST scan in
    ``test_migration_seed_field_lengths`` also reads.
    """

    models_source = (ROOT / "netbox_rpc/models.py").read_text()
    limits = {
        int(match)
        for match in re.findall(
            r"description = models\.CharField\(max_length=(\d+)", models_source
        )
    }
    assert limits == {255}, limits

    _seed, procedures, commands = catalog
    for name, row in procedures.rows.items():
        assert len(row["description"]) <= 255, name
        for schema_key in ("params_schema", "result_schema"):
            for _path, node in _walk(row[schema_key]):
                text = node.get("description")
                if isinstance(text, str):
                    assert len(text) <= 255, (name, schema_key, text[:40])
    for key, row in commands.rows.items():
        assert len(row["description"]) <= 255, key


def test_reverse_only_disables_durable_rows(catalog) -> None:
    seed, procedures, commands = catalog
    for row in procedures.rows.values():
        row["enabled"] = True

    seed.unseed_ubuntu_26_samba_ad_dc_procedures(_apps(procedures, commands), None)

    assert set(procedures.rows) == set(ALL_PROCEDURES)
    assert all(row["enabled"] is False for row in procedures.rows.values())
    assert len(commands.rows) == 3


def test_reapply_is_exact_and_existing_drift_fails_closed(catalog) -> None:
    seed, procedures, commands = catalog
    apps = _apps(procedures, commands)
    seed.seed_ubuntu_26_samba_ad_dc_procedures(apps, None)  # exact reapply is a no-op

    procedures.rows[PROVISION]["timeout_seconds"] = 30
    with pytest.raises(RuntimeError, match="timeout_seconds"):
        seed.seed_ubuntu_26_samba_ad_dc_procedures(apps, None)


def test_seed_refuses_an_extra_or_drifted_existing_command(catalog) -> None:
    seed, procedures, commands = catalog
    apps = _apps(procedures, commands)
    commands.rows[(PREFLIGHT, 2)] = dict(commands.rows[(PREFLIGHT, 1)])
    with pytest.raises(RuntimeError, match="exactly one command"):
        seed.seed_ubuntu_26_samba_ad_dc_procedures(apps, None)

    commands.rows.pop((PREFLIGHT, 2))
    commands.rows[(PREFLIGHT, 1)]["argv"] = ["backend-orchestrated", "drifted"]
    with pytest.raises(RuntimeError, match="argv"):
        seed.seed_ubuntu_26_samba_ad_dc_procedures(apps, None)


def test_migration_is_additive_inline_and_ordered(catalog) -> None:
    seed, _procedures, _commands = catalog
    assert seed.Migration.dependencies == [
        ("netbox_rpc", "0102_seed_proxbox_api_image_recovery")
    ]


# --------------------------------------------------------------------------- #
# Params schema behaviour
# --------------------------------------------------------------------------- #

# A 238-character domain: one character over the 237 limit.
DOMAIN_238 = ".".join(["a" * 63, "a" * 63, "a" * 63, "a" * 46])
assert len(DOMAIN_238) == 238

BASE_PARAMS = {
    "domain": "ad.example.com",
    "netbios": "EXAMPLE",
    "hostname": "ad01",
    "ip": "10.0.30.10",
    "forwarder": "10.0.30.1",
    "client_networks": ["10.0.30.0/24"],
}
LIVE_PARAMS = {
    **BASE_PARAMS,
    "dry_run": False,
    "admin_credential_pk": 73,
    "ssh_ports": [22],
    "ssh_networks": ["10.0.50.0/24"],
}


def _provision_schema(catalog) -> dict:
    _seed, procedures, _commands = catalog
    return procedures.rows[PROVISION]["params_schema"]


def test_every_seeded_schema_is_a_valid_draft_2020_12_schema(catalog) -> None:
    _seed, procedures, _commands = catalog
    for name in ALL_PROCEDURES:
        Draft202012Validator.check_schema(procedures.rows[name]["params_schema"])
        Draft202012Validator.check_schema(procedures.rows[name]["result_schema"])


def test_every_seed_pattern_is_anchored_against_the_trailing_newline_bypass(
    catalog,
) -> None:
    """jsonschema applies ``pattern`` with ``re.search``; ``$`` matches before \\n."""

    _seed, procedures, _commands = catalog
    seen = 0
    for name in ALL_PROCEDURES:
        for schema_key in ("params_schema", "result_schema"):
            for _path, node in _walk(procedures.rows[name][schema_key]):
                pattern = node.get("pattern")
                if isinstance(pattern, str):
                    seen += 1
                    assert pattern.endswith(r"(?![\s\S])"), (name, pattern)
                    assert not pattern.endswith("$"), (name, pattern)
    assert seen >= 10


@pytest.mark.parametrize(
    "params",
    [
        dict(BASE_PARAMS),
        dict(LIVE_PARAMS),
        {**BASE_PARAMS, "domain": "AD.Example.COM", "netbios": "example"},
        {
            **BASE_PARAMS,
            "ntp_servers": ["200.160.0.8", "2001:db8::1", "pool"],
            "timezone": "Etc/GMT+3",
            "share_name": "Data_1",
            "share_path": "/srv/.hidden/data",
            "ssh_ports": [22, 2222],
            "ssh_networks": ["10.0.50.5", "2001:db8::/32", "fd00::/8"],
            "ban_exempt_networks": ["10.0.50.5"],
            "fail2ban_findtime": 86400,
            "smb_max_retry": 100,
            "smb_bantime": 60,
            "ssh_max_retry": 3,
            "ssh_bantime": 86400,
            "legacy_netbios": True,
            "freeze_cloud_init": False,
            "admin_credential_pk": 2**31,
        },
        {**BASE_PARAMS, "hostname": "A", "netbios": "A" + "B" * 13 + "C"},
    ],
)
def test_params_schema_accepts_everything_the_installer_accepts(
    catalog, params: dict
) -> None:
    validate(params, _provision_schema(catalog))


@pytest.mark.parametrize(
    "params",
    [
        {},  # required parameters missing
        {**BASE_PARAMS, "unknown_param": 1},
        {**BASE_PARAMS, "password": "x"},  # a password can never be submitted
        {**BASE_PARAMS, "admin_password": "x"},
        {**BASE_PARAMS, "rpc_ssh_host": "10.0.0.9"},
        {**BASE_PARAMS, "rpc_ssh_credential_pk": 1},
        {**BASE_PARAMS, "dry_run": "false"},
        {**BASE_PARAMS, "domain": "ad.example.com\n"},  # trailing-newline bypass
        {**BASE_PARAMS, "domain": "example"},
        {**BASE_PARAMS, "domain": DOMAIN_238},
        {**BASE_PARAMS, "netbios": "1CORP"},
        {**BASE_PARAMS, "netbios": "CORP-"},
        {**BASE_PARAMS, "netbios": "A" * 16},
        {**BASE_PARAMS, "netbios": "EXAMPLE\n"},
        {**BASE_PARAMS, "hostname": "ad_01"},
        {**BASE_PARAMS, "ip": "10.0.30"},
        {**BASE_PARAMS, "ip": "10.0.30.10\n"},
        {**BASE_PARAMS, "forwarder": "dns.example.com"},
        {**BASE_PARAMS, "client_networks": []},
        {**BASE_PARAMS, "client_networks": ["10.0.30.0"]},
        {**BASE_PARAMS, "client_networks": ["10.0.30.0/24", "10.0.30.0/24"]},
        {**BASE_PARAMS, "client_networks": [f"10.{n}.0.0/16" for n in range(17)]},
        {**BASE_PARAMS, "client_networks": ["10.0.30.0/24\n"]},
        {**BASE_PARAMS, "client_networks": ["10.0.0.0/255.255.255.0"]},
        {**BASE_PARAMS, "ntp_servers": []},
        {**BASE_PARAMS, "ntp_servers": ["a b"]},
        {**BASE_PARAMS, "ntp_servers": ["ntp.br;id"]},
        {**BASE_PARAMS, "ntp_servers": [f"n{n}.ntp.br" for n in range(9)]},
        {**BASE_PARAMS, "timezone": "/etc/passwd"},
        {**BASE_PARAMS, "timezone": "America/Sao Paulo"},
        {**BASE_PARAMS, "timezone": "A" * 65},
        {**BASE_PARAMS, "timezone": "UTC\n"},
        {**BASE_PARAMS, "share_name": "1data"},
        {**BASE_PARAMS, "share_name": "da ta"},
        {**BASE_PARAMS, "share_name": "A" * 65},
        {**BASE_PARAMS, "share_name": "data\n"},
        {**BASE_PARAMS, "share_path": "/etc/samba"},
        {**BASE_PARAMS, "share_path": "/srv"},
        {**BASE_PARAMS, "share_path": "/srv/da ta"},
        {**BASE_PARAMS, "share_path": "/srv/data\n"},
        {**BASE_PARAMS, "ssh_ports": list(range(2000, 2017))},
        {**BASE_PARAMS, "ssh_ports": [0]},
        {**BASE_PARAMS, "ssh_ports": [65536]},
        {**BASE_PARAMS, "ssh_ports": [22, 22]},
        {**BASE_PARAMS, "ssh_ports": ["22"]},
        *(
            {**BASE_PARAMS, "ssh_ports": [port]}
            for port in (53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269)
        ),
        {**BASE_PARAMS, "ssh_networks": ["fe80::1%eth0"]},
        {**BASE_PARAMS, "ssh_networks": ["10.0.0.5", "10.0.0.5"]},
        {**BASE_PARAMS, "ssh_networks": [f"10.0.{n}.0/24" for n in range(33)]},
        {**BASE_PARAMS, "ssh_networks": ["10.0.0.5\n"]},
        {**BASE_PARAMS, "ban_exempt_networks": ["none"]},
        {**BASE_PARAMS, "fail2ban_findtime": 59},
        {**BASE_PARAMS, "fail2ban_findtime": 86401},
        {**BASE_PARAMS, "smb_max_retry": 2},
        {**BASE_PARAMS, "smb_max_retry": 101},
        {**BASE_PARAMS, "smb_bantime": 59},
        {**BASE_PARAMS, "ssh_max_retry": 2},
        {**BASE_PARAMS, "ssh_bantime": 86401},
        {**BASE_PARAMS, "smb_max_retry": "10"},
        {**BASE_PARAMS, "legacy_netbios": "no"},
        {**BASE_PARAMS, "freeze_cloud_init": 1},
        {**BASE_PARAMS, "admin_credential_pk": 0},
        {**BASE_PARAMS, "admin_credential_pk": "73"},
        # A live run needs the credential reference and an SSH allowlist.
        {**BASE_PARAMS, "dry_run": False},
        {**LIVE_PARAMS, "admin_credential_pk": None},
        {
            **BASE_PARAMS,
            "dry_run": False,
            "ssh_ports": [22],
            "ssh_networks": ["10.0.50.0/24"],
        },
        {**BASE_PARAMS, "dry_run": False, "admin_credential_pk": 73},
        {**LIVE_PARAMS, "ssh_ports": []},
        {**LIVE_PARAMS, "ssh_networks": []},
    ],
)
def test_params_schema_rejects_what_the_installer_rejects(
    catalog, params: dict
) -> None:
    with pytest.raises(ValidationError):
        validate(params, _provision_schema(catalog))


@pytest.mark.parametrize(
    "params",
    [
        # These belong to the pure-domain normalizer, not to a JSON schema: they
        # need address-class checks, case-folding or cross-field comparisons.
        {**BASE_PARAMS, "domain": "corp.local"},
        {**BASE_PARAMS, "domain": "ad.example.123"},
        {**BASE_PARAMS, "ip": "127.0.0.1"},
        {**BASE_PARAMS, "ip": "224.0.0.1"},
        {**BASE_PARAMS, "forwarder": "10.0.30.10"},
        {**BASE_PARAMS, "hostname": "example"},
        {**BASE_PARAMS, "client_networks": ["0.0.0.0/0"]},
        {**BASE_PARAMS, "client_networks": ["10.0.30.5/24"]},
        {**BASE_PARAMS, "share_name": "sysvol"},
        {**BASE_PARAMS, "share_name": "HOMES"},
        {**BASE_PARAMS, "ntp_servers": ["::1"]},
        {**BASE_PARAMS, "ssh_networks": ["0.0.0.0/0"], "ssh_ports": [22]},
        {**BASE_PARAMS, "ssh_ports": [22]},  # ports without networks
    ],
)
def test_normalizer_only_rules_are_documented_as_beyond_the_schema(
    catalog, params: dict
) -> None:
    """Record which installer rejections the schema deliberately leaves to the
    normalizer, so a future schema-only consumer knows the boundary."""

    validate(params, _provision_schema(catalog))


@pytest.mark.parametrize("name", [PREFLIGHT, VERIFY])
def test_read_schema_accepts_overrides_and_rejects_unknowns(catalog, name) -> None:
    _seed, procedures, _commands = catalog
    schema = procedures.rows[name]["params_schema"]
    validate({}, schema)
    validate(
        {
            "rpc_ssh_credential_pk": 73,
            "rpc_ssh_host": "dc.example.net",
            "rpc_ssh_port": 2222,
            "rpc_ssh_known_hosts_entry": "dc ssh-ed25519 AAAA",
            "rpc_ssh_strict_host_key_checking": True,
        },
        schema,
    )
    for bad in ({"dry_run": True}, {"password": "x"}, {"domain": "ad.example.com"}):
        with pytest.raises(ValidationError):
            validate(bad, schema)


# --------------------------------------------------------------------------- #
# Result schema bounds
# --------------------------------------------------------------------------- #


def _string_nodes(schema: dict):
    for path, node in _walk(schema):
        if _has_type(node, "string"):
            yield path, node


def test_every_result_string_is_explicitly_bounded(catalog) -> None:
    """The event store silently clamps an undeclared string at 4096 characters."""

    _seed, procedures, _commands = catalog
    wide = {"log_tail": LOG_TAIL_MAX}
    for name in ALL_PROCEDURES:
        schema = procedures.rows[name]["result_schema"]
        count = 0
        for path, node in _string_nodes(schema):
            count += 1
            assert "maxLength" in node, (name, path)
            limit = node["maxLength"]
            key = path[-1] if path else ""
            if key in wide:
                assert limit == wide[key], (name, path)
            elif "rendered_configs" in path:
                assert limit == RENDERED_CONFIG_MAX, (name, path)
            else:
                assert 0 < limit <= EVENT_STRING_DEFAULT_LIMIT, (name, path)
        assert count >= 3, name

    provision = procedures.rows[PROVISION]["result_schema"]
    assert provision["properties"]["log_tail"]["maxLength"] == LOG_TAIL_MAX
    assert provision["properties"]["error"]["maxLength"] == 2048


def test_every_result_array_is_bounded(catalog) -> None:
    _seed, procedures, _commands = catalog
    for name in ALL_PROCEDURES:
        for path, node in _walk(procedures.rows[name]["result_schema"]):
            if _has_type(node, "array"):
                assert "maxItems" in node, (name, path)


def _good_check(**overrides: Any) -> dict:
    return {"name": "os_release", "ok": True, "detail": "Ubuntu 26.04", **overrides}


GOOD_RESULTS = {
    PREFLIGHT: {
        "ok": True,
        "verdicts": [_good_check(), _good_check(name="static_ipv4", ok=False)],
        "detected": {
            "interface": "ens18",
            "ipv4": "10.0.30.10",
            "prefixlen": 24,
            "suggested_forwarder": "10.0.30.1",
            "suggested_client_subnet": "10.0.30.0/24",
            "ssh_ports": [22],
            "cloud_init": {"present": True, "status": "done", "freeze_required": True},
        },
    },
    PROVISION: {
        "ok": True,
        "dry_run": False,
        "stage": "complete",
        "error_code": None,
        "error": None,
        "plan": {
            "domain": "ad.example.com",
            "realm": "AD.EXAMPLE.COM",
            "netbios": "EXAMPLE",
            "dc_fqdn": "ad01.ad.example.com",
            "ip": "10.0.30.10",
            "share_unc": "\\\\ad01.ad.example.com\\shared",
            "share_path": "/srv/samba/shared",
            "ntp_servers": ["a.ntp.br"],
            "timezone": "America/Sao_Paulo",
        },
        "checks": [_good_check()],
        "firewall": {"confirmed": True, "rolled_back": False},
        "backup_dir": "/root/samba-preinstall-abc123",
        "installer_sha256": "a" * 64,
        "log_tail": "PASS: DNS, domain checks and encrypted SMB read/write.",
        "rerunnable": False,
    },
    VERIFY: {
        "ok": True,
        "checks": [_good_check(name="dbcheck")],
        "services": {
            "samba_ad_dc": "active",
            "chrony": "active",
            "nftables": "active",
            "fail2ban": "active",
        },
    },
}


@pytest.mark.parametrize("name", ALL_PROCEDURES)
def test_a_contract_shaped_result_validates(catalog, name) -> None:
    _seed, procedures, _commands = catalog
    validate(GOOD_RESULTS[name], procedures.rows[name]["result_schema"])


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        (PROVISION, lambda r: r.pop("stage")),
        (PROVISION, lambda r: r.pop("dry_run")),
        (PROVISION, lambda r: r.update(ok="yes")),
        # A failed run must state that it cannot be retried, and never say it can.
        (PROVISION, lambda r: (r.update(ok=False), r.pop("rerunnable"))),
        (PROVISION, lambda r: r.update(ok=False, rerunnable=True)),
        (PROVISION, lambda r: r.update(rerunnable=True)),
        (PROVISION, lambda r: r.update(log_tail="x" * (LOG_TAIL_MAX + 1))),
        (PROVISION, lambda r: r.update(error="x" * 2049)),
        (PROVISION, lambda r: r.update(installer_sha256="XYZ")),
        (PROVISION, lambda r: r.update(installer_sha256="a" * 64 + "\n")),
        (PROVISION, lambda r: r["checks"].append(_good_check(detail="x" * 1025))),
        (PROVISION, lambda r: r["plan"].update(ip="x" * 16)),
        (PREFLIGHT, lambda r: r.pop("detected")),
        (PREFLIGHT, lambda r: r["verdicts"].append({"ok": True})),
        (PREFLIGHT, lambda r: r["detected"].update(prefixlen=33)),
        (PREFLIGHT, lambda r: r["detected"].update(ssh_ports=[0])),
        (VERIFY, lambda r: r.pop("services")),
        (VERIFY, lambda r: r["services"].update(fail2ban="x" * 65)),
        (VERIFY, lambda r: r["checks"].append(_good_check(name="x" * 65))),
    ],
)
def test_malformed_or_oversized_results_fail_schema_validation(
    catalog, name: str, mutate
) -> None:
    import copy

    _seed, procedures, _commands = catalog
    result = copy.deepcopy(GOOD_RESULTS[name])
    mutate(result)
    with pytest.raises(ValidationError):
        validate(result, procedures.rows[name]["result_schema"])


# --------------------------------------------------------------------------- #
# Result handling through the real event store
# --------------------------------------------------------------------------- #


@pytest.fixture()
def event_store_module(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_db.transaction = SimpleNamespace(atomic=lambda: nullcontext())
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = lambda: None
    django_utils.timezone = django_timezone
    models = types.ModuleType("netbox_rpc.models")
    models.RPCExecution = type("RPCExecution", (), {})
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})
    for module_name, module in (
        ("netbox", netbox),
        ("netbox.plugins", netbox_plugins),
        ("django", django),
        ("django.db", django_db),
        ("django.utils", django_utils),
        ("django.utils.timezone", django_timezone),
        ("netbox_rpc.models", models),
    ):
        monkeypatch.setitem(sys.modules, module_name, module)
    monkeypatch.delitem(sys.modules, "netbox_rpc.event_store", raising=False)
    module = importlib.import_module("netbox_rpc.event_store")
    events: list = []
    monkeypatch.setattr(
        module, "_append_and_project", lambda execution, event: events.append(event)
    )
    yield module, events


def _record(event_store, procedures, result: dict) -> None:
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name=PROVISION, result_schema=procedures.rows[PROVISION]["result_schema"]
        )
    )
    event_store.record_backend_response(execution, {"ok": True, "result": result})


def test_a_finished_provision_result_is_recorded_as_success(
    catalog, event_store_module
) -> None:
    _seed, procedures, _commands = catalog
    event_store, events = event_store_module

    _record(event_store, procedures, dict(GOOD_RESULTS[PROVISION]))

    assert [event.event_name for event in events] == ["ExecutionSucceeded"]


def test_an_oversized_log_tail_is_truncated_within_its_bound_not_failed(
    catalog, event_store_module
) -> None:
    """A finished DC must never be reported as failed just because the log is long."""

    _seed, procedures, _commands = catalog
    event_store, events = event_store_module
    oversized = "y" * (LOG_TAIL_MAX + 5000)

    _record(event_store, procedures, {**GOOD_RESULTS[PROVISION], "log_tail": oversized})

    assert [event.event_name for event in events] == ["ExecutionSucceeded"]
    stored = events[0].result["log_tail"]
    assert stored.endswith(event_store._TRUNCATION_MARKER)
    assert len(stored) <= LOG_TAIL_MAX


def test_an_oversized_check_detail_fails_closed_so_the_handler_must_clamp(
    catalog, event_store_module
) -> None:
    """Nested strings are bounded at 1024 and are NOT relaxed like ``log_tail``.

    The backend handler is contractually required to clamp every ``detail`` below
    the bound; a violation is reported as a schema mismatch, never silently kept.
    """

    _seed, procedures, _commands = catalog
    event_store, events = event_store_module
    result = {
        **GOOD_RESULTS[PROVISION],
        "checks": [_good_check(detail="d" * 1025)],
    }

    _record(event_store, procedures, result)

    assert len(events) == 1
    assert events[0].event_name == "ExecutionFailed"
    assert events[0].code == event_store.RESULT_SCHEMA_MISMATCH_CODE


def test_a_failed_result_without_rerunnable_false_fails_the_schema(catalog) -> None:
    _seed, procedures, _commands = catalog
    failed = {**GOOD_RESULTS[PROVISION], "ok": False}
    failed.pop("rerunnable")
    with pytest.raises(ValidationError):
        validate(failed, procedures.rows[PROVISION]["result_schema"])
    validate(
        {**failed, "rerunnable": False}, procedures.rows[PROVISION]["result_schema"]
    )


def test_a_failed_provision_result_still_projects_when_schema_valid(
    catalog, event_store_module
) -> None:
    _seed, procedures, _commands = catalog
    event_store, events = event_store_module
    failed = {
        **GOOD_RESULTS[PROVISION],
        "ok": False,
        "stage": "firewall",
        "error_code": "FIREWALL_NOT_CONFIRMED",
        "error": "Firewall was not confirmed; rolled back. Restore the VM snapshot.",
        "firewall": {"confirmed": False, "rolled_back": True},
        "rerunnable": False,
    }
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name=PROVISION, result_schema=procedures.rows[PROVISION]["result_schema"]
        )
    )

    event_store.record_backend_response(execution, {"ok": False, "result": failed})

    assert [event.event_name for event in events] == ["ExecutionFailed"]
    assert events[0].code != event_store.RESULT_SCHEMA_MISMATCH_CODE


# --------------------------------------------------------------------------- #
# Protected two-person contract
# --------------------------------------------------------------------------- #


def _load_protected_contract():
    spec = importlib.util.spec_from_file_location(
        "samba_ad_dc_protected_contract_under_test",
        ROOT / "netbox_rpc/samba_ad_dc_protected_contract.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_immutable_contract_matches_the_seeded_catalog(catalog) -> None:
    _seed, procedures, commands = catalog
    contract = _load_protected_contract()
    row = procedures.rows[PROVISION]
    command = {"sequence": 1, **commands.rows[(PROVISION, 1)]}

    assert contract.PARAMS_SCHEMA == row["params_schema"]
    assert contract.RESULT_SCHEMA == row["result_schema"]
    assert contract.COMMAND_CONTRACT == [command]
    expected_policy = {
        key: value
        for key, value in row.items()
        if key not in {"description", "params_schema", "result_schema"}
    }
    expected_policy["command_contract_sha256"] = contract.canonical_sha256([command])
    expected_policy["name"] = PROVISION
    assert contract.PROCEDURE_POLICY == expected_policy
    assert contract.PROCEDURE_POLICY["enabled"] is True
    assert contract.PROCEDURE_POLICY["approval_required"] is True
    assert contract.PROCEDURE_POLICY["effect"] == "destructive"
    assert contract.PROCEDURE_POLICY["timeout_seconds"] == 3600
    assert contract.PROCEDURE_POLICY["transport_pinned"] is True


def test_the_contract_hashes_are_stable_and_distinct() -> None:
    contract = _load_protected_contract()
    hashes = {
        contract.PROCEDURE_POLICY_SHA256,
        contract.COMMAND_CONTRACT_SHA256,
        contract.PARAMS_SCHEMA_SHA256,
        contract.RESULT_SCHEMA_SHA256,
    }
    assert len(hashes) == 4
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
    assert contract.PROCEDURE_POLICY_SHA256 == contract.canonical_sha256(
        contract.PROCEDURE_POLICY
    )


def test_provision_is_registered_in_every_protected_runtime_map() -> None:
    source = (ROOT / "netbox_rpc/application/command_handlers.py").read_text(
        encoding="utf-8"
    )

    assert "UBUNTU_26_SAMBA_AD_DC_PROVISION: samba_ad_dc_protected_contract" in source
    assert (
        "UBUNTU_26_SAMBA_AD_DC_PROVISION: _SAMBA_AD_DC_PROVISION_APPROVAL_REASON"
        in source
    )
    assert (
        "UBUNTU_26_SAMBA_AD_DC_PROVISION: _SAMBA_AD_DC_PROVISION_REJECTION_REASON"
        in source
    )
    assert (
        'UBUNTU_26_SAMBA_AD_DC_PROVISION: "Ubuntu 26.04 Samba AD DC provision"'
        in source
    )
    # Fixed, value-free decision phrases only.
    assert '"Approved audited Ubuntu 26.04 Samba AD DC provision."' in source
    assert '"Rejected audited Ubuntu 26.04 Samba AD DC provision."' in source


def test_the_read_procedures_are_not_registered_as_protected() -> None:
    source = (ROOT / "netbox_rpc/application/command_handlers.py").read_text(
        encoding="utf-8"
    )
    assert "UBUNTU_26_SAMBA_AD_DC_PREFLIGHT:" not in source
    assert "UBUNTU_26_SAMBA_AD_DC_VERIFY:" not in source


def test_a_success_wrapper_around_a_failed_nested_result_is_not_success(
    catalog, event_store_module
) -> None:
    """Protected procedures require the outer and nested ``ok`` to agree."""

    _seed, procedures, _commands = catalog
    event_store, events = event_store_module
    failed = {
        **GOOD_RESULTS[PROVISION],
        "ok": False,
        "stage": "firewall",
        "rerunnable": False,
    }
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name=PROVISION, result_schema=procedures.rows[PROVISION]["result_schema"]
        )
    )

    event_store.record_backend_response(execution, {"ok": True, "result": failed})

    assert [event.event_name for event in events] == ["ExecutionFailed"]
    assert events[0].code == event_store.RESULT_SCHEMA_MISMATCH_CODE


def test_protected_provision_ignores_backend_progress_events(
    catalog, event_store_module
) -> None:
    """No progress-event channel: the durable surface is the validated result."""

    _seed, procedures, _commands = catalog
    event_store, events = event_store_module
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name=PROVISION, result_schema=procedures.rows[PROVISION]["result_schema"]
        )
    )
    response = {
        "ok": True,
        "result": dict(GOOD_RESULTS[PROVISION]),
        "events": [{"event": "leak", "message": "must not be recorded"}],
    }

    event_store.record_backend_response(execution, response)

    assert [event.event_name for event in events] == ["ExecutionSucceeded"]


def _live_success(catalog):
    import copy

    return copy.deepcopy(GOOD_RESULTS[PROVISION])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("stage"),
        lambda r: r.update(stage="firewall"),
        lambda r: r.pop("firewall"),
        lambda r: r.update(firewall={"confirmed": False, "rolled_back": True}),
        lambda r: r.update(firewall={"rolled_back": False}),
        lambda r: r.pop("checks"),
        lambda r: r.update(checks=[]),
        lambda r: r.pop("installer_sha256"),
    ],
)
def test_a_live_success_must_be_verified_complete(catalog, mutate) -> None:
    """ok=true and dry_run=false is accepted only with a completed, verified run."""

    _seed, procedures, _commands = catalog
    schema = procedures.rows[PROVISION]["result_schema"]
    result = _live_success(catalog)
    validate(result, schema)
    mutate(result)
    with pytest.raises(ValidationError):
        validate(result, schema)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("plan"),
        lambda r: r.pop("stage"),
    ],
)
def test_a_dry_run_success_needs_a_plan_and_stage(catalog, mutate) -> None:
    _seed, procedures, _commands = catalog
    schema = procedures.rows[PROVISION]["result_schema"]
    result = {
        "ok": True,
        "dry_run": True,
        "stage": "dry_run",
        "plan": dict(GOOD_RESULTS[PROVISION]["plan"]),
    }
    validate(result, schema)
    mutate(result)
    with pytest.raises(ValidationError):
        validate(result, schema)


def test_a_failure_needs_stage_and_rerunnable_false(catalog) -> None:
    _seed, procedures, _commands = catalog
    schema = procedures.rows[PROVISION]["result_schema"]
    failed = {"ok": False, "dry_run": False, "stage": "firewall", "rerunnable": False}
    validate(failed, schema)
    for bad in (
        {**failed, "rerunnable": True},
        {k: v for k, v in failed.items() if k != "rerunnable"},
    ):
        with pytest.raises(ValidationError):
            validate(bad, schema)


def test_the_concurrency_fence_runs_inside_the_creation_transaction() -> None:
    source = (ROOT / "netbox_rpc/application/command_handlers.py").read_text(
        encoding="utf-8"
    )
    assert (
        "    with transaction.atomic():\n"
        "        _require_no_concurrent_samba_provision(serializer.validated_data, procedure)\n"
    ) in source
