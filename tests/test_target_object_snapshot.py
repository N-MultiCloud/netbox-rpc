"""Pure-domain tests for the Jinja target-object context injected by
``netbox_rpc.domain.normalization`` (the ``{{ target.* }}`` render context and
its gating). Django/NetBox are stubbed so the module imports without a database,
mirroring ``tests/test_jobs_systemd_normalization.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import signal
import sys
import time
import types
from collections import UserDict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


_STUB_SECRET_KEY = "pure-tier-test-secret-key"


def _stub_salted_hmac(key_salt, value, secret=None, *, algorithm="sha256"):
    secret = _STUB_SECRET_KEY if secret is None else secret
    key = hashlib.sha256((key_salt + secret).encode()).digest()
    return hmac.new(key, value.encode(), getattr(hashlib, algorithm))


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone
    django_crypto = types.ModuleType("django.utils.crypto")
    django_crypto.salted_hmac = _stub_salted_hmac
    django_utils.crypto = django_crypto

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    # netbox_rpc.domain.normalization imports this alongside the service
    # allowlist for netbox.plugin.install (#262); without it every module
    # that stubs netbox_rpc.models fails at import, not just that one.
    netbox_rpc_models.RPCNetBoxPluginAllowlist = type(
        "RPCNetBoxPluginAllowlist", (), {}
    )
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "django.utils.crypto", django_crypto)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)


@pytest.fixture()
def norm(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.domain.normalization")
    yield module
    sys.modules.pop("netbox_rpc.domain.normalization", None)


class _FakeQS:
    def __init__(self, matched: bool) -> None:
        self._matched = matched

    def exists(self) -> bool:
        return self._matched


class _FakeManager:
    """Mimics a Django related manager for render_mode filtering."""

    def __init__(self, render_modes: list[str]) -> None:
        self._render_modes = render_modes

    def filter(self, **kwargs):
        want = kwargs.get("render_mode")
        return _FakeQS(want in self._render_modes)


class _Target:
    """A stand-in NetBox object whose ``__str__`` is a safe label (its name),
    like real NetBox models — unlike ``SimpleNamespace`` whose repr dumps every
    attribute."""

    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)

    def __str__(self) -> str:
        return str(getattr(self, "name", "") or "")


# ── _build_target_object_snapshot ────────────────────────────────────────────


def test_snapshot_none_target_returns_none(norm) -> None:
    assert norm._build_target_object_snapshot(None) is None


def test_snapshot_serializes_public_fields_and_id(norm) -> None:
    obj = SimpleNamespace(pk=42, name="switch-a", serial="ABC123")
    snap = norm._build_target_object_snapshot(obj)
    assert snap["id"] == 42
    assert snap["name"] == "switch-a"
    assert snap["serial"] == "ABC123"
    assert "display" in snap


def test_snapshot_redacts_sensitive_field_names(norm) -> None:
    obj = _Target(
        pk=1,
        name="host",
        password="topsecret",
        api_key="k",
        ssh_token="t",
        client_secret="s",
        device_credential="c",
        snmp_community="public",
        wireguard_psk="p",
        passphrase="pp",
        aws_access_key="ak",
        encryption_key="ek",
    )
    snap = norm._build_target_object_snapshot(obj)
    for leaked in (
        "password",
        "api_key",
        "ssh_token",
        "client_secret",
        "device_credential",
        "snmp_community",
        "wireguard_psk",
        "passphrase",
        "aws_access_key",
        "encryption_key",
    ):
        assert leaked not in snap, f"{leaked} must be redacted"
    assert "topsecret" not in repr(snap)
    # Non-sensitive fields still pass through.
    assert snap["name"] == "host"


def test_snapshot_caps_long_values(norm) -> None:
    obj = SimpleNamespace(pk=1, name="x", blob="A" * 5000)
    snap = norm._build_target_object_snapshot(obj)
    assert len(snap["blob"]) <= 1024


# ── _has_jinja_command ───────────────────────────────────────────────────────


def test_has_jinja_command_list_path(norm) -> None:
    jinja = SimpleNamespace(commands=[SimpleNamespace(render_mode="jinja")])
    literal = SimpleNamespace(commands=[SimpleNamespace(render_mode="literal")])
    none = SimpleNamespace(name="no-commands-attr")
    assert norm._has_jinja_command(jinja) is True
    assert norm._has_jinja_command(literal) is False
    assert norm._has_jinja_command(none) is False


def test_has_jinja_command_manager_path(norm) -> None:
    with_jinja = SimpleNamespace(commands=_FakeManager(["literal", "jinja"]))
    without = SimpleNamespace(commands=_FakeManager(["literal"]))
    assert norm._has_jinja_command(with_jinja) is True
    assert norm._has_jinja_command(without) is False


# ── _apply_target_object_context ─────────────────────────────────────────────


def _execution(render_modes: list[str], target):
    procedure = SimpleNamespace(
        commands=[SimpleNamespace(render_mode=m) for m in render_modes]
    )
    return SimpleNamespace(procedure=procedure, assigned_object=target)


def test_apply_injects_target_object_for_jinja_procedure(norm) -> None:
    execution = _execution(["literal", "jinja"], SimpleNamespace(pk=7, name="olt-1"))
    normalized = {"target": "olt-1", "command_fingerprint": {"handler_id": "h"}}
    norm._apply_target_object_context(execution, normalized)
    assert normalized["_target_object"]["id"] == 7
    assert normalized["_target_object"]["name"] == "olt-1"
    assert "target_object_sha256" in normalized["command_fingerprint"]


def test_apply_is_noop_for_literal_only_procedure(norm) -> None:
    execution = _execution(["literal"], SimpleNamespace(pk=7, name="olt-1"))
    normalized = {"target": "olt-1", "command_fingerprint": {"handler_id": "h"}}
    before = dict(normalized)
    before_fp = dict(normalized["command_fingerprint"])
    norm._apply_target_object_context(execution, normalized)
    assert "_target_object" not in normalized
    assert normalized["command_fingerprint"] == before_fp
    assert set(normalized) == set(before)


def test_apply_is_noop_when_target_missing(norm) -> None:
    execution = _execution(["jinja"], None)
    normalized = {"command_fingerprint": {"handler_id": "h"}}
    norm._apply_target_object_context(execution, normalized)
    assert "_target_object" not in normalized


_FLAG = "rpc_ssh_strict_host_key_checking"
_CANARY = "opaque-secret-text"


def test_snapshot_keeps_custom_fields_only_as_the_structured_mapping(norm) -> None:
    """The raw custom field data must not be copied as text.

    A stringified dictionary would carry every custom field name and value past
    the key-based redaction that applies to the structured ``custom_fields``
    mapping.
    """

    class _Target:
        """A stand-in whose text form is its name, as a NetBox object is."""

        def __init__(self, **fields: object) -> None:
            self.__dict__.update(fields)

        def __str__(self) -> str:
            return str(self.name)

    obj = _Target(
        pk=42, name="switch-a", custom_field_data={_FLAG: _CANARY, "site": "lab"}
    )

    snap = norm._build_target_object_snapshot(obj)

    assert "custom_field_data" not in snap
    assert not any(isinstance(value, str) and _FLAG in value for value in snap.values())
    assert snap["custom_fields"][_FLAG] == _CANARY


class _NamedTarget:
    """A stand-in whose text form is its name, as a NetBox object is."""

    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)

    def __str__(self) -> str:
        return str(self.name)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("custom_field_data", {"settings": {_FLAG: _CANARY}}, id="custom-nested-object"),
        pytest.param("custom_field_data", {"settings": [{_FLAG: _CANARY}]}, id="custom-list-of-objects"),
        pytest.param("local_context_data", {"settings": {_FLAG: _CANARY}}, id="generic-nested-object"),
    ],
)
def test_nested_custom_field_text_never_reaches_the_ledger_or_projection(
    norm, monkeypatch, field_name, value
) -> None:
    """Snapshot, redaction, and projection together must not persist the canary."""

    from contextlib import nullcontext

    from netbox_rpc.domain import events as domain_events
    from netbox_rpc.domain.projection import ProjectionState, apply

    monkeypatch.setattr(
        sys.modules["django.db"],
        "transaction",
        SimpleNamespace(atomic=lambda: nullcontext()),
        raising=False,
    )
    monkeypatch.delitem(sys.modules, "netbox_rpc.event_store", raising=False)
    event_store = importlib.import_module("netbox_rpc.event_store")

    obj = _NamedTarget(pk=42, name="switch-a", **{field_name: value})
    snap = norm._build_target_object_snapshot(obj)
    if field_name == "custom_field_data":
        assert isinstance(snap["custom_fields"]["settings"], (dict, list))
    else:
        assert isinstance(snap[field_name]["settings"], dict)

    event = domain_events.ParametersNormalized(
        normalized_params={"_target_object": snap},
        resolved_command_hash="a" * 64,
    )
    persisted = event_store.redact_event_data(event.data)
    state = apply(ProjectionState(), domain_events.ParametersNormalized.from_data(persisted))

    assert _CANARY not in repr(persisted)
    assert _CANARY not in repr(state)


def test_json_value_copy_truncates_deep_nesting(norm) -> None:
    deep = {"a": {"b": {"c": {"d": {"secret": "x"}}}}}

    out = norm._json_safe_value(deep)

    assert "[truncated]" in repr(out)
    assert "secret" not in repr(out)


def test_json_value_copy_keeps_tuples_as_lists(norm) -> None:
    assert norm._json_safe_value(("a", "b")) == ["a", "b"]


def test_json_value_copy_turns_other_objects_into_text(norm) -> None:
    class _Opaque:
        def __str__(self) -> str:
            return "opaque-text"

    assert norm._json_safe_value(_Opaque()) == "opaque-text"


def _snapshot_node_count(value: object) -> int:
    if isinstance(value, dict):
        return 1 + sum(_snapshot_node_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(_snapshot_node_count(item) for item in value)
    return 1


def _load_event_store(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delitem(sys.modules, "netbox_rpc.event_store", raising=False)
    return importlib.import_module("netbox_rpc.event_store")


def test_snapshot_budget_bounds_wide_custom_fields(norm) -> None:
    custom_fields = {f"field-{index:03d}": "x" * 1024 for index in range(100)}
    snapshot = norm._build_target_object_snapshot(
        _Target(pk=1, name="wide", custom_field_data=custom_fields)
    )
    serialized = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))

    assert len(serialized.encode()) <= 65536
    assert _snapshot_node_count(snapshot) <= 1000
    assert snapshot["_truncated"] is True


def test_snapshot_budget_bounds_full_shared_fanout_under_two_seconds(norm) -> None:
    leaf = "x" * 1024
    level_1 = [leaf] * 100
    level_2 = [level_1] * 100
    level_3 = [level_2] * 100
    full_fanout = [level_3] * 100
    target = _Target(name="fanout", custom_field_data={"fanout": full_fanout})

    def _deadline(_signum, _frame):
        raise AssertionError("snapshot construction exceeded two seconds")

    previous_handler = signal.signal(signal.SIGALRM, _deadline)
    signal.setitimer(signal.ITIMER_REAL, 2.0)
    started = time.perf_counter()
    try:
        snapshot = norm._build_target_object_snapshot(target)
    finally:
        elapsed = time.perf_counter() - started
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)

    serialized = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    assert elapsed < 2.0
    assert len(serialized.encode()) <= 65536
    assert _snapshot_node_count(snapshot) <= 1000


SECRET_REF = "nms-secret:12345678-1234-4234-8234-123456789abc"


def _nested_secret_target() -> _Target:
    return _Target(
        pk=7,
        name="olt-1",
        custom_field_data={
            "settings": {
                "password": "fake-password",
                "credential": "fake-credential",
                "key": "fake-key",
                "password_sha256": "a" * 64,
                "rpc_ssh_strict_host_key_checking": True,
                "nested": {"rpc_ssh_strict_host_key_checking": "not-a-bool"},
                "operator_secret_ref": SECRET_REF,
            }
        },
    )


def test_target_context_hashes_persisted_and_raw_snapshots(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_store = _load_event_store(monkeypatch)
    target = _nested_secret_target()
    raw_snapshot = norm._build_target_object_snapshot(target)
    normalized = {"command_fingerprint": {"handler_id": "handler"}}

    norm._apply_target_object_context(_execution(["jinja"], target), normalized)

    persisted = normalized["_target_object"]
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["target_object_sha256"] == norm._hash_json(persisted)
    assert "target_object_raw_hmac_sha256" in fingerprint
    raw_digest = fingerprint["target_object_raw_hmac_sha256"]
    assert raw_digest == norm._keyed_target_snapshot_digest(raw_snapshot)
    assert raw_digest != norm._hash_json(raw_snapshot)
    assert len(raw_digest) == 64
    assert event_store.redact_event_value(persisted) == persisted


def test_target_context_redacts_nested_secret_values(norm) -> None:
    target = _nested_secret_target()
    normalized = {"command_fingerprint": {"handler_id": "handler"}}

    norm._apply_target_object_context(_execution(["jinja"], target), normalized)

    persisted = normalized["_target_object"]
    settings = persisted["custom_fields"]["settings"]
    assert settings["password"] == "[REDACTED]"
    assert settings["credential"] == "[REDACTED]"
    assert settings["key"] == "[REDACTED]"
    assert settings["rpc_ssh_strict_host_key_checking"] is True
    assert settings["nested"]["rpc_ssh_strict_host_key_checking"] == "[REDACTED]"
    assert "fake-password" not in repr(persisted)
    assert "fake-credential" not in repr(persisted)
    assert "fake-key" not in repr(persisted)
    assert settings["password_sha256"] == "a" * 64
    assert settings["operator_secret_ref"] == SECRET_REF


def test_event_redaction_traverses_all_supported_sequence_types(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_store = _load_event_store(monkeypatch)
    values = [
        ({"password": "hunter2"},),
        [{"password": "hunter2"}],
        {"password=hunter2"},
        frozenset({"password=hunter2"}),
    ]

    outputs = [event_store.redact_event_value(value) for value in values]

    assert all(isinstance(output, list) for output in outputs)
    assert "hunter2" not in repr(outputs)


def test_event_redaction_traverses_mapping_subclasses(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_store = _load_event_store(monkeypatch)
    output = event_store.redact_event_value(UserDict({"password": "hunter2"}))

    assert output == {"password": "[REDACTED]"}


def test_event_redaction_applies_text_rules_to_other_objects(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_store = _load_event_store(monkeypatch)

    class _Opaque:
        def __str__(self) -> str:
            return "password=hunter2"

    output = event_store.redact_event_value(_Opaque())

    assert "hunter2" not in output


def test_event_redaction_truncates_deep_containers(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_store = _load_event_store(monkeypatch)
    value: object = "leaf"
    for _ in range(40):
        value = {"safe": value}

    output = event_store.redact_event_value(value)

    assert "[truncated]" in repr(output)
    assert "leaf" not in repr(output)


def test_custom_field_keys_are_canonical_and_deterministic(norm) -> None:
    first = norm._build_target_object_snapshot(
        _Target(
            name="keys",
            custom_field_data={
                1: "integer",
                "1": "string",
                "nested": {1: "integer", "1": "string"},
            },
        )
    )
    second = norm._build_target_object_snapshot(
        _Target(
            name="keys",
            custom_field_data={
                "nested": {"1": "string", 1: "integer"},
                "1": "string",
                1: "integer",
            },
        )
    )

    assert first == second
    assert first["custom_fields"] == {
        "1": "integer",
        "nested": {"1": "integer"},
    }
    assert first["_truncated"] is True
    assert norm._hash_json(first) == norm._hash_json(second)


def test_truncated_custom_field_key_collision_keeps_first(norm) -> None:
    prefix = "k" * 1024
    snapshot = norm._build_target_object_snapshot(
        _Target(
            name="keys",
            custom_field_data={f"{prefix}b": "second", f"{prefix}a": "first"},
        )
    )

    assert snapshot["custom_fields"] == {prefix: "first"}
    assert "_truncated" in snapshot
    assert snapshot["_truncated"] is True


def test_custom_field_named_truncated_round_trips(norm) -> None:
    custom_fields = {"_truncated": "ordinary-value"}
    custom_fields.update(
        {f"field-{index:03d}": "x" * 1024 for index in range(100)}
    )
    snapshot = norm._build_target_object_snapshot(
        _Target(name="keys", custom_field_data=custom_fields)
    )

    assert "_truncated" in snapshot
    assert snapshot["_truncated"] is True
    assert snapshot["custom_fields"]["_truncated"] == "ordinary-value"


def test_hash_json_accepts_snapshot_from_non_string_mapping_keys(norm) -> None:
    snapshot = norm._build_target_object_snapshot(
        _Target(name="keys", custom_field_data={1: "integer"})
    )

    assert all(isinstance(key, str) for key in snapshot["custom_fields"])
    assert isinstance(norm._hash_json(snapshot), str)


def test_raw_digest_sees_secret_only_changes_and_depends_on_the_key(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _digests(note: str) -> tuple[str, str]:
        target = _Target(pk=9, name="olt-2", custom_field_data={"notes": note})
        normalized = {"command_fingerprint": {"handler_id": "handler"}}
        norm._apply_target_object_context(_execution(["jinja"], target), normalized)
        fingerprint = normalized["command_fingerprint"]
        return (
            fingerprint["target_object_sha256"],
            fingerprint["target_object_raw_hmac_sha256"],
        )

    first_persisted, first_raw = _digests("password=alpha-one")
    second_persisted, second_raw = _digests("password=beta-two")
    # Both values redact to the same persisted copy, so only the raw digest differs.
    assert first_persisted == second_persisted
    assert first_raw != second_raw

    monkeypatch.setattr(sys.modules[__name__], "_STUB_SECRET_KEY", "rotated-secret")
    _, rotated_raw = _digests("password=alpha-one")
    assert rotated_raw != first_raw


def test_persisted_copy_stays_within_budget_when_redaction_expands_values(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_store = _load_event_store(monkeypatch)
    # Large plain strings fill most of the raw budget. Single-character secrets
    # then expand to "[REDACTED]" in the persisted copy.
    bulk = ["x" * 1000 for _ in range(50)]
    secrets = {
        f"group-{group:02d}": {
            f"password{index:02d}": "x" for index in range(90)
        }
        for group in range(9)
    }
    target = _Target(
        pk=11, name="expand", custom_field_data={"bulk": bulk, **secrets}
    )
    normalized = {"command_fingerprint": {"handler_id": "handler"}}

    norm._apply_target_object_context(_execution(["jinja"], target), normalized)

    persisted = normalized["_target_object"]
    size = len(json.dumps(persisted, sort_keys=True, separators=(",", ":")).encode())
    assert size <= 65536
    assert persisted["_truncated"] is True
    assert event_store.redact_event_value(persisted) == persisted
    assert normalized["command_fingerprint"]["target_object_sha256"] == (
        norm._hash_json(persisted)
    )


class _CountingMapping(dict):
    visited = 0

    def items(self):
        for pair in super().items():
            self.visited += 1
            yield pair


class _CountingSet(set):
    visited = 0

    def __iter__(self):
        for item in super().__iter__():
            self.visited += 1
            yield item


def test_event_redaction_visits_at_most_one_entry_past_each_limit(
    norm, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_store = _load_event_store(monkeypatch)
    limit = event_store.MAX_EVENT_DICT_ITEMS
    mapping = _CountingMapping({f"k{index:06d}": index for index in range(10_000)})
    output = event_store.redact_event_value(mapping)
    assert mapping.visited <= limit + 1
    assert len(output) == limit + 1
    assert output["_truncated"] is True

    unordered = _CountingSet(f"item-{index:06d}" for index in range(10_000))
    kept = event_store.redact_event_value(unordered)
    assert unordered.visited <= event_store.MAX_EVENT_LIST_ITEMS + 1
    assert kept[-1] == {"_truncated": True, "remaining": 10_000 - 50}
    assert len(kept) == event_store.MAX_EVENT_LIST_ITEMS + 1
