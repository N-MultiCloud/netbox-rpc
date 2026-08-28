"""Ansible-first transport policy: vocabulary, chain resolution, platform map.

Pure-domain tier — no Django, no database. The chain resolver and the platform
map deliberately live in ``netbox_rpc.transport`` / ``domain.normalization`` so
they are testable here rather than only behind a NetBox test database.
"""

from __future__ import annotations

import ast
import importlib
import sys
import types
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY_MIGRATION = ROOT / "netbox_rpc/migrations/0075_seed_ansible_first_policy.py"
SCHEMA_MIGRATION = ROOT / "netbox_rpc/migrations/0074_ansible_transport_policy.py"


def _stub_netbox(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimal Django/NetBox stubs so the domain module imports without a database.

    ``domain.normalization`` imports two model classes at module level, so the
    model module is stubbed rather than loaded — the same convention the other
    pure-domain normalization tests use.
    """

    netbox = types.ModuleType("netbox")
    plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    plugins.PluginConfig = PluginConfig
    netbox.plugins = plugins
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", plugins)

    django = types.ModuleType("django")
    django_conf = types.ModuleType("django.conf")
    django_conf.settings = types.SimpleNamespace(PLUGINS_CONFIG={})
    django.conf = django_conf
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.conf", django_conf)

    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    # netbox_rpc.domain.normalization imports this alongside the service
    # allowlist for netbox.plugin.install (#262); without it every module
    # that stubs netbox_rpc.models fails at import, not just that one.
    models.RPCNetBoxPluginAllowlist = type("RPCNetBoxPluginAllowlist", (), {})
    models.RPCExecution = type(
        "RPCExecution",
        (),
        {"TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY": "_timeout_seconds_snapshot"},
    )
    models.RpcPluginSettings = type("RpcPluginSettings", (), {})
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)


def _purge_plugin_modules() -> None:
    for name in [key for key in sys.modules if key.startswith("netbox_rpc")]:
        sys.modules.pop(name, None)


@pytest.fixture()
def policy(monkeypatch: pytest.MonkeyPatch):
    """The real normalization + constants modules, importable without Django."""

    # Purge first: the stubs below register `netbox_rpc.models` in sys.modules,
    # and purging afterwards would delete the very stub the import needs.
    _purge_plugin_modules()
    _stub_netbox(monkeypatch)
    normalization = importlib.import_module("netbox_rpc.domain.normalization")
    transport = importlib.import_module("netbox_rpc.transport")
    yield types.SimpleNamespace(normalization=normalization, transport=transport)
    _purge_plugin_modules()


class FakePolicy:
    """Stands in for the RpcPluginSettings singleton.

    Delegates the platform lookup to the *real* shared implementation, so this
    stub cannot drift from what the model does.
    """

    def __init__(self, transport: Any, *, linux=(), network=(), platform_map=None) -> None:
        self._transport = transport
        self._linux = list(linux)
        self._network = list(network)
        self.ansible_platform_map = {} if platform_map is None else platform_map

    def default_chain_for(self, capability: str) -> list[str]:
        source = self._network if capability == "network_cli" else self._linux
        return list(source)

    def ansible_context_for_platform(self, platform_slug: str) -> dict:
        return self._transport.ansible_context_from_platform_map(
            self.ansible_platform_map, platform_slug
        )


def procedure(**overrides: Any) -> types.SimpleNamespace:
    base: dict[str, Any] = {
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "transport_pinned": False,
        "output_parser": "none",
        "output_schema": {},
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


# -- vocabulary -----------------------------------------------------------


def test_every_driver_choice_is_classified_into_exactly_one_capability(policy) -> None:
    """The backend only falls back to a capability-matching driver.

    An unclassified or double-classified choice would produce a chain the
    backend silently skips over, so this must fail the moment a driver is added
    to the vocabulary without deciding what it serves.
    """

    c = policy.transport
    names = {value for value, _label in c.TRANSPORT_DRIVER_CHOICES}

    assert names == c.LINUX_SHELL_DRIVERS | c.NETWORK_CLI_DRIVERS
    assert not (c.LINUX_SHELL_DRIVERS & c.NETWORK_CLI_DRIVERS)
    for name in names:
        assert c.driver_capability(name) in {"linux_shell", "network_cli"}


def test_ansible_drivers_are_a_subset_of_the_vocabulary(policy) -> None:
    c = policy.transport
    names = {value for value, _label in c.TRANSPORT_DRIVER_CHOICES}
    assert c.ANSIBLE_DRIVERS <= names
    assert c.ANSIBLE_DRIVERS == {"ansible", "ansible-network"}
    # One Ansible driver per capability, or the raw-fallback safety net below
    # cannot pick a partner for it.
    assert set(c.RAW_CAPABILITY_DEFAULT) == {"linux_shell", "network_cli"}


def test_driver_names_are_normalized_like_the_backend_registry(policy) -> None:
    """The backend lowercases and maps ``_`` to ``-``; a mismatch means a chain
    entry silently fails to resolve there."""

    c = policy.transport
    assert c.driver_capability("Ansible_Network") == "network_cli"
    assert c.driver_capability("  ASYNCSSH  ") == "linux_shell"
    assert c.driver_capability("not-a-driver") == ""
    assert c.driver_capability(None) == ""


def test_driver_name_lengths_fit_the_model_columns(policy) -> None:
    """The pure tier cannot see column widths; assert them explicitly.

    A too-long choice value passes here and fails only when a database applies
    the migration — which for this plugin means the production deploy.
    """

    c = policy.transport
    for value, _label in c.TRANSPORT_DRIVER_CHOICES:
        assert len(value) <= 20, f"{value} exceeds RPCProcedure.transport_driver max_length"
        assert len(value) <= 32, f"{value} exceeds the chain base field max_length"


# -- chain resolution -----------------------------------------------------


def test_operator_defined_chain_wins_verbatim(policy) -> None:
    """An explicit chain is operator intent and must not be reordered."""

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"]
    )
    chain = policy.normalization.resolve_driver_chain(
        procedure(transport_driver_chain=["paramiko", "subprocess"])
    )
    assert chain == ["paramiko", "subprocess"]


def test_estate_default_puts_ansible_first_and_keeps_the_procedure_driver(
    policy,
) -> None:
    """The whole point of the feature: Ansible first, existing driver as fallback."""

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"]
    )
    assert policy.normalization.resolve_driver_chain(procedure()) == [
        "ansible",
        "asyncssh",
    ]
    assert policy.normalization.resolve_driver_chain(
        procedure(transport_driver="paramiko")
    ) == ["ansible", "paramiko"]


def test_network_procedures_use_the_network_default_chain(policy) -> None:
    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"], network=["ansible-network"]
    )
    assert policy.normalization.resolve_driver_chain(
        procedure(transport_driver="scrapli")
    ) == ["ansible-network", "scrapli"]


def test_an_all_ansible_chain_gains_a_raw_fallback(policy) -> None:
    """Ansible must never be left without a raw fallback.

    A chain of only Ansible drivers turns an optional dependency into a hard
    one: if ansible-core is missing, the execution fails outright instead of
    degrading to the driver it used before.
    """

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"], network=["ansible-network"]
    )
    assert policy.normalization.resolve_driver_chain(
        procedure(transport_driver="ansible")
    ) == ["ansible", "asyncssh"]
    assert policy.normalization.resolve_driver_chain(
        procedure(transport_driver="ansible-network")
    ) == ["ansible-network", "scrapli"]


def test_a_chain_that_already_has_a_raw_driver_is_not_padded(policy) -> None:
    """Mutation guard: the safety net must be conditional, not unconditional."""

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"]
    )
    assert policy.normalization.resolve_driver_chain(
        procedure(transport_driver="fabric")
    ) == ["ansible", "fabric"]


def test_pinned_procedures_are_never_touched_by_the_estate_default(policy) -> None:
    """The security-critical exclusion.

    Staging token rotation and the live Ubuntu upgrade both disable transport
    fallback, which truncates the chain to its FIRST entry — so an Ansible-first
    chain would remove their required driver entirely, with no fallback tier.
    """

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"], network=["ansible-network"]
    )
    assert policy.normalization.resolve_driver_chain(procedure(transport_pinned=True)) == []
    assert (
        policy.normalization.resolve_driver_chain(
            procedure(transport_driver="scrapli", transport_pinned=True)
        )
        == []
    )


def test_a_pinned_procedure_may_still_carry_an_explicit_operator_chain(policy) -> None:
    """Pinning blocks the estate default, not a deliberate per-procedure chain."""

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"]
    )
    assert policy.normalization.resolve_driver_chain(
        procedure(transport_pinned=True, transport_driver_chain=["asyncssh", "paramiko"])
    ) == ["asyncssh", "paramiko"]


def test_no_policy_row_means_no_chain(policy) -> None:
    """A fresh install, a mid-migration read, or an unreadable settings row must
    degrade to the pre-existing single-driver behaviour, never break dispatch."""

    policy.normalization._transport_policy = lambda: None
    assert policy.normalization.resolve_driver_chain(procedure()) == []


def test_empty_estate_default_restores_raw_driver_behaviour(policy) -> None:
    """Clearing the setting is the documented rollback — assert it actually works."""

    policy.normalization._transport_policy = lambda: FakePolicy(policy.transport)
    assert policy.normalization.resolve_driver_chain(procedure()) == []


def test_unknown_driver_yields_no_chain_rather_than_a_guess(policy) -> None:
    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"]
    )
    assert policy.normalization.resolve_driver_chain(procedure(transport_driver="magic")) == []
    assert policy.normalization.resolve_driver_chain(procedure(transport_driver="")) == []


# -- platform map ---------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        None,
        "not-a-dict",
        ["junos"],
        42,
        {"junos": "not-a-dict"},
        {"junos": None},
        {"junos": {"network_os": 42, "become": "yes"}},
        {"junos": {}},
    ],
)
def test_a_malformed_platform_map_degrades_instead_of_raising(policy, hostile) -> None:
    """The map is operator-editable JSON on the execution dispatch path.

    Raising here would abort a run a raw driver could have served; returning
    nothing makes the backend fall back instead.
    """

    assert policy.transport.ansible_context_from_platform_map(hostile, "junos") == {}


def test_platform_lookup_is_slug_normalized(policy) -> None:
    mapping = {"junos": {"network_os": "junipernetworks.junos.junos"}}
    assert policy.transport.ansible_context_from_platform_map(mapping, "  JUNOS ") == {
        "network_os": "junipernetworks.junos.junos"
    }
    assert policy.transport.ansible_context_from_platform_map(mapping, "") == {}
    assert policy.transport.ansible_context_from_platform_map(mapping, None) == {}


def test_only_recognised_keys_survive(policy) -> None:
    """Unknown keys are dropped here rather than sent and ignored by the backend."""

    mapping = {
        "ios": {
            "network_os": "cisco.ios.ios",
            "connection": "ansible.netcommon.network_cli",
            "become": True,
            "become_method": "enable",
            "sudo_password": "hunter2",
            "extra": ["nope"],
        }
    }
    assert policy.transport.ansible_context_from_platform_map(mapping, "ios") == {
        "network_os": "cisco.ios.ios",
        "connection": "ansible.netcommon.network_cli",
        "become": True,
        "become_method": "enable",
    }


# -- seeded policy --------------------------------------------------------


def _migration_constant(path: Path, name: str) -> Any:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == name:
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is missing from {path.name}")


def test_seeded_default_chains_are_ansible_first_and_valid(policy) -> None:
    c = policy.transport
    linux = _migration_constant(POLICY_MIGRATION, "DEFAULT_LINUX_CHAIN")
    network = _migration_constant(POLICY_MIGRATION, "DEFAULT_NETWORK_CHAIN")

    assert linux == ["ansible"]
    assert network == ["ansible-network"]
    for chain, capability in ((linux, "linux_shell"), (network, "network_cli")):
        for entry in chain:
            assert c.driver_capability(entry) == capability, entry


def test_seeded_platform_map_entries_are_well_formed(policy) -> None:
    c = policy.transport
    mapping = _migration_constant(POLICY_MIGRATION, "ANSIBLE_PLATFORM_MAP")

    assert mapping, "the platform map seeds nothing"
    for slug, entry in mapping.items():
        assert slug == slug.strip().lower(), slug
        assert set(entry) <= {"network_os", "connection", "become", "become_method"}, slug
        # Every entry must survive the real extractor unchanged — a typo'd key
        # would otherwise be silently dropped at dispatch time.
        assert c.ansible_context_from_platform_map(mapping, slug) == entry, slug
        if entry.get("become"):
            assert entry.get("become_method"), f"{slug} escalates without a method"


def _seeded_handler_ids() -> set[str]:
    """Every ``handler_id`` value seeded by any migration.

    Resolved from the AST rather than by substring matching, for two reasons a
    text search gets wrong: a bare quoted string also matches a procedure's
    ``name`` (so a typo'd handler id would still "match"), and several
    migrations assign the id to a module-level constant first, so the literal
    ``"handler_id": "..."`` pair never appears in the source at all.
    """

    found: set[str] = set()
    for path in sorted((ROOT / "netbox_rpc/migrations").glob("0*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            constants[target.id] = node.value.value
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if not (isinstance(key, ast.Constant) and key.value == "handler_id"):
                    continue
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    found.add(value.value)
                elif isinstance(value, ast.Name) and value.id in constants:
                    found.add(constants[value.id])
    return found


def test_pinned_handler_ids_match_procedures_that_actually_exist() -> None:
    """The exclusion must name real seeded handlers.

    A typo would silently un-pin a procedure whose backend handler depends on
    one specific transport driver — the exact failure this exclusion prevents.
    """

    pinned = _migration_constant(POLICY_MIGRATION, "PINNED_HANDLER_IDS")
    assert pinned, "the exclusion set is empty"

    seeded = _seeded_handler_ids()
    assert seeded, "no handler_id values were found in any migration"
    for handler_id in pinned:
        assert handler_id in seeded, (
            f"{handler_id} is not seeded as a handler_id by any migration"
        )


def test_the_two_no_fallback_procedures_are_pinned() -> None:
    """Both disable transport fallback in the execution backend.

    ``rotate_backend_token`` additionally requires strict credential isolation
    that Ansible cannot reproduce, and the live Ubuntu upgrade must never be
    redispatched onto a second driver.
    """

    pinned = set(_migration_constant(POLICY_MIGRATION, "PINNED_HANDLER_IDS"))
    assert "service.netbox.staging.rotate_backend_token" in pinned
    assert "os.linux.ubuntu.24.upgrade_26.run_upgrade" in pinned


def test_schema_migration_inlines_its_choices(policy) -> None:
    """A migration must keep describing the schema as it was at that point.

    Importing the live model vocabulary would silently rewrite history the next
    time the vocabulary changes.
    """

    source = SCHEMA_MIGRATION.read_text(encoding="utf-8")
    assert "from netbox_rpc" not in source
    assert "import netbox_rpc" not in source

    choices = _migration_constant(SCHEMA_MIGRATION, "TRANSPORT_DRIVER_CHOICES")
    assert [value for value, _label in choices] == [
        value for value, _label in policy.transport.TRANSPORT_DRIVER_CHOICES
    ]


def test_policy_migration_reverse_never_deletes() -> None:
    """Deleting through a historical model invokes Django's deletion collector,
    which raises for a related app with no migrations — and would destroy
    audited history besides."""

    source = POLICY_MIGRATION.read_text(encoding="utf-8")
    assert ".delete()" not in source
    assert "def revert_policy" in source


# -- single-read policy + hostile targets (review round 1) ----------------


def test_the_settings_singleton_is_read_once_per_execution(policy) -> None:
    """The chain and the platform map must come from ONE snapshot.

    Two reads could pair a chain resolved before an operator's edit with a
    platform map read after it, producing a payload that never existed as a
    coherent policy.
    """

    reads: list[int] = []
    fake = FakePolicy(
        policy.transport,
        linux=["ansible"],
        platform_map={"linux": {"connection": "ansible.builtin.ssh"}},
    )

    def counting_policy():
        reads.append(1)
        return fake

    policy.normalization._transport_policy = counting_policy

    execution = types.SimpleNamespace(
        procedure=procedure(),
        assigned_object=types.SimpleNamespace(platform=types.SimpleNamespace(slug="linux")),
    )
    normalized: dict[str, Any] = {"command_fingerprint": {}}
    policy.normalization._apply_driver_pipeline_overrides(execution, normalized)

    assert reads == [1], f"settings read {len(reads)} times"
    assert normalized["transport_driver_chain"] == ["ansible", "asyncssh"]
    assert normalized["_ansible"] == {"connection": "ansible.builtin.ssh"}
    assert normalized["command_fingerprint"]["ansible_context"] == normalized["_ansible"]


def test_non_ansible_chains_leave_the_payload_untouched(policy) -> None:
    """The regression that matters most: every existing procedure keeps a
    byte-for-byte identical normalized payload."""

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, platform_map={"linux": {"connection": "ansible.builtin.ssh"}}
    )
    execution = types.SimpleNamespace(
        procedure=procedure(),
        assigned_object=types.SimpleNamespace(platform=types.SimpleNamespace(slug="linux")),
    )
    normalized: dict[str, Any] = {"command_fingerprint": {}}
    policy.normalization._apply_driver_pipeline_overrides(execution, normalized)

    # Nothing is added at all: an asyncssh procedure with no resolved chain
    # matches what the backend already assumes, so the payload is untouched.
    assert normalized == {"command_fingerprint": {}}

    # Mutation guard: a non-default driver still pins itself, so this test
    # cannot be satisfied by an implementation that injects nothing ever.
    other: dict[str, Any] = {"command_fingerprint": {}}
    policy.normalization._apply_driver_pipeline_overrides(
        types.SimpleNamespace(procedure=procedure(transport_driver="paramiko")), other
    )
    assert other["transport_driver"] == "paramiko"


def test_pinned_procedures_get_no_chain_and_no_ansible_context(policy) -> None:
    """End-to-end form of the exclusion, at the payload level."""

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport,
        linux=["ansible"],
        platform_map={"linux": {"connection": "ansible.builtin.ssh"}},
    )
    execution = types.SimpleNamespace(
        procedure=procedure(transport_pinned=True),
        assigned_object=types.SimpleNamespace(platform=types.SimpleNamespace(slug="linux")),
    )
    normalized: dict[str, Any] = {"command_fingerprint": {}}
    policy.normalization._apply_driver_pipeline_overrides(execution, normalized)

    assert "transport_driver_chain" not in normalized
    assert "_ansible" not in normalized


@pytest.mark.parametrize(
    "target",
    [
        None,
        types.SimpleNamespace(),
        types.SimpleNamespace(platform=None),
        types.SimpleNamespace(platform=types.SimpleNamespace()),
        types.SimpleNamespace(platform=types.SimpleNamespace(slug=None)),
        types.SimpleNamespace(platform=types.SimpleNamespace(slug="")),
        types.SimpleNamespace(platform=types.SimpleNamespace(slug="unmapped-platform")),
    ],
)
def test_a_target_without_a_mapped_platform_injects_nothing(policy, target) -> None:
    """Not every RPC target is a network device, and not every platform is mapped.

    Both are normal, so both must inject nothing rather than raise — the backend
    then falls back to a raw driver instead of guessing a CLI dialect.
    """

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport,
        linux=["ansible"],
        platform_map={"junos": {"network_os": "junipernetworks.junos.junos"}},
    )
    execution = types.SimpleNamespace(procedure=procedure(), assigned_object=target)
    normalized: dict[str, Any] = {"command_fingerprint": {}}
    policy.normalization._apply_driver_pipeline_overrides(execution, normalized)

    assert "_ansible" not in normalized
    # The chain still resolves — only the platform context is absent.
    assert normalized["transport_driver_chain"] == ["ansible", "asyncssh"]


def test_a_target_whose_content_type_is_gone_does_not_break_dispatch(policy) -> None:
    """A generic FK to a removed content type raises rather than returning None."""

    class Exploding:
        @property
        def assigned_object(self):
            raise LookupError("content type 999 does not exist")

        procedure = procedure()

    policy.normalization._transport_policy = lambda: FakePolicy(
        policy.transport, linux=["ansible"], platform_map={"linux": {"become": True}}
    )
    normalized: dict[str, Any] = {"command_fingerprint": {}}
    policy.normalization._apply_driver_pipeline_overrides(Exploding(), normalized)

    assert "_ansible" not in normalized
    assert normalized["transport_driver_chain"] == ["ansible", "asyncssh"]
