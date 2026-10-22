"""Pure-domain tests for the Jinja target-object context injected by
``netbox_rpc.domain.normalization`` (the ``{{ target.* }}`` render context and
its gating). Django/NetBox are stubbed so the module imports without a database,
mirroring ``tests/test_jobs_systemd_normalization.py``.
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
