"""Pure-domain tests for the persisted secret-content pattern (issue 399 forms)."""

from __future__ import annotations

import importlib
import importlib.util
import sys
import time
from pathlib import Path

import pytest

_SIBLING = Path(__file__).with_name("test_target_object_snapshot.py")
_PEM_BEGIN = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
_PEM_END = "-----END " + "OPENSSH PRIVATE KEY-----"
_POINTER = "nms-secret:12345678-1234-4234-8234-123456789abc"


@pytest.fixture
def event_store(monkeypatch: pytest.MonkeyPatch):
    spec = importlib.util.spec_from_file_location("_snapshot_stub_helpers", _SIBLING)
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    helpers._install_import_stubs(monkeypatch)
    monkeypatch.delitem(sys.modules, "netbox_rpc.event_store", raising=False)
    return importlib.import_module("netbox_rpc.event_store")


def _redact(event_store, text: str) -> str:
    return event_store._SECRET_CONTENT_RE.sub("[REDACTED]", text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("SSH failed with password=fake-inline-value", "SSH failed with [REDACTED]"),
        ('password="fake quoted value" tail', "[REDACTED] tail"),
        ("password='fake single value' tail", "[REDACTED] tail"),
        ('password="fake \\" escaped value" tail', "[REDACTED] tail"),
        ("password='fake it''s value' tail", "[REDACTED] tail"),
        ('password="fake ""sensitive remainder" tail', "[REDACTED] tail"),
        ('password="fake line one\nfake line two" tail', "[REDACTED] tail"),
        ('password="fake open value\nnext', "[REDACTED]"),
        ("password=correct horse battery staple", "[REDACTED]"),
        # A block scalar body is redacted for CR LF, bare CR, and LF line breaks, and for a list item.
        ("password: |\r\n  CRLF-SECRET\r\nafter: public\r\n", "[REDACTED]\r\nafter: public\r\n"),
        ("password: |\r\n  A-SECRET\r\n\r\n  B-SECRET\r\nafter\r\n", "[REDACTED]\r\nafter\r\n"),
        ("password: |\r  BARE-SECRET\nafter\n", "[REDACTED]\nafter\n"),
        ("- password: |\n  LIST-SECRET\nafter\n", "[REDACTED]\nafter\n"),
        ('password="fake-terminal\\', "[REDACTED]"),
        ("password='fake-terminal\\", "[REDACTED]"),
        (f"{_PEM_BEGIN}\nAAAA-fake-body\n{_PEM_END}\nafter", "[REDACTED]\nafter"),
        (f"prefix {_PEM_BEGIN}\nAAAA-fake-body", "prefix [REDACTED]"),
        # The separator before a key is consumed, as the base pattern consumed it.
        # An unquoted value runs to the end of its line.
        ("user=bob, password=abc, host=h1", "user=bob[REDACTED]"),
    ],
)
def test_reproduced_secret_forms_are_redacted(event_store, text, expected) -> None:
    assert _redact(event_store, text) == expected
    assert event_store._bounded_event_message(text) == expected


def test_mismatched_pem_footer_is_body_and_the_matching_footer_ends_the_block(
    event_store,
) -> None:
    begin = "-----BEGIN RSA PRIVATE KEY-----"
    end = "-----END RSA PRIVATE KEY-----"
    text = (
        f"{begin}\nLEAKED-PRIVATE-MATERIAL\n"
        "-----END EC PRIVATE KEY-----\nafter\n"
        f"{end}\ntail"
    )
    redacted = _redact(event_store, text)
    assert "LEAKED-PRIVATE-MATERIAL" not in redacted
    assert redacted == "[REDACTED]\ntail"


@pytest.mark.parametrize(
    "text",
    [
        "password rotation completed",
        "the service restarted at 10:00",
    ],
)
def test_text_without_a_secret_assignment_is_unchanged(event_store, text) -> None:
    assert _redact(event_store, text) == text


def test_exact_pointer_value_is_persisted_in_every_position(event_store) -> None:
    # A pointer that is the whole value is a reference, not secret material. Stored
    # data keeps it so that the backend can read the approved reference back.
    assert event_store._redact_secret_text(_POINTER) == _POINTER
    assert event_store._bounded_event_message(_POINTER) == _POINTER
    assert event_store.redact_event_data({"note": _POINTER}) == {"note": _POINTER}
    assert event_store.redact_event_data({"admin_secret_ref": _POINTER}) == {
        "admin_secret_ref": _POINTER
    }


@pytest.mark.parametrize(
    "text",
    [
        _POINTER + "=fake-tail-value",
        '"' + _POINTER + '"=fake-tail-value',
        "reference " + _POINTER + " then password=fake-inline-value",
    ],
)
def test_pointer_with_extra_text_keeps_no_secret(event_store, text) -> None:
    redacted = event_store._redact_secret_text(text)
    assert "fake-tail-value" not in redacted
    assert "fake-inline-value" not in redacted


def test_redaction_is_idempotent_for_each_form(event_store) -> None:
    samples = [
        "SSH failed with password=fake-inline-value",
        'password="fake quoted value" tail',
        f"{_PEM_BEGIN}\nAAAA-fake-body\n{_PEM_END}\nafter",
        "password=correct horse battery staple",
    ]
    for text in samples:
        once = _redact(event_store, text)
        assert _redact(event_store, once) == once


@pytest.mark.parametrize(
    "text",
    [
        "a" * 1_000_000,
        "password" * 125_000,
        "a." * 500_000,
        "a." * 500_000 + "://",
        "-----BEGIN " * 83_333,
        "-----BEGIN " + "PRIVATE KEY " * 85_000,
        "-----BEGIN " + "A" * 1_000_000,
        "-----BEGIN RSA PRIVATE KEY-----" + "-----END RSA " * 90_000,
        "password=" * 111_111,
        '"' * 1_000_000,
        "password: |\r\n" + "  x\r\n" * 200_000,
        "password: |\r" + "\r" * 1_000_000,
        'password="' + '""' * 500_000,
        'password="' + "\\" * 999_999,
        "password='" + "\\" * 999_999,
        "'" * 1_000_000,
        '"fake \\' * 125_000,
        "password" + " " * 1_000_000,
        "password=" + "x" * 1_000_000,
        "x" * 1_000_000 + "password",
        "password:\n" + "  x\n" * 250_000,
        "authorization:" * 71_428,
        "token" * 200_000,
    ],
)
def test_adversarial_megabyte_inputs_run_in_linear_time(event_store, text) -> None:
    started = time.perf_counter()
    _redact(event_store, text)
    # The measured worst case on a development host is well under one second. The bound
    # is generous so that a slow runner does not fail the suite; a quadratic pattern
    # takes minutes on these inputs.
    assert time.perf_counter() - started < 10.0
