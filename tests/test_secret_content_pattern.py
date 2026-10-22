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
        # Header forms of the YAML block scalar pattern (issue 415), and long prefixes
        # before a key: each must stay linear, not retry the prefix at every length.
        '"' + "a" * 1_000_000,
        '"' + " " * 1_000_000 + "x",
        "password" + " " * 1_000_000 + "x",
        "- " * 500_000 + "x",
        "- " * 500_000 + "password",
        " " * 1_000_000 + "password",
        "\t" * 1_000_000 + "token",
        "\ufeff" + " " * 1_000_000 + "password",
        "password: &" + "a " * 500_000,
        "password: " + "&a " * 300_000,
        "'" + "''" * 500_000 + "x",
        "\ufeff" * 1_000_000,
        "\ufeffa:" * 500_000,
        "? password #" + " " * 1_000_000 + "\n: x",
        "a\ufeffa:" * 500_000,
        "- " * 500_000 + "password: |\n",
        "? password" + " " * 1_000_000 + "\n: |\n" + "  x\n" * 100_000,
        '"pass\\"' * 200_000 + ": |",
    ],
)
def test_adversarial_megabyte_inputs_run_in_linear_time(event_store, text) -> None:
    started = time.perf_counter()
    event_store._redact_secret_text(text)
    # The measured worst case on a development host is well under one second. The bound
    # is generous so that a slow runner does not fail the suite; a quadratic pattern
    # takes minutes on these inputs.
    assert time.perf_counter() - started < 10.0


# Issue 415: a YAML block scalar body is redacted through its last indented line for every
# valid key form. Each input is a fixed literal; the body line is SECRET-BODY. The new
# forms go through _redact_secret_text, which exists on the base and on this change.
_BLOCK_BODY = "  SECRET-BODY\nafter: public\n"
_BLOCK_REDACTED = "[REDACTED]\nafter: public\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('"my password": |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
        ("'my password': |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ('- "my password": |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
        ("? password\n: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("password: &value |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("password: !!str |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("\ufeffpassword: |\n" + _BLOCK_BODY, "\ufeff" + _BLOCK_REDACTED),
        ("\ufeff\ufeffpassword: |\n" + _BLOCK_BODY, "\ufeff\ufeff" + _BLOCK_REDACTED),
        ("a\ufeff\ufeffpassword: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ('"pass\\"word": |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
        ('"pass\\u0077ord": |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
        ('"my password: label": |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
        ("? password # comment\n: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("? \"my password: label\"\n: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("? \"\\u0070assword\"\n: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ('? "my password: label" # comment\n: |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
        ('? "\\u0070assword: label" # comment\n: |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
        ("my_password#x: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("api#key: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("password=label: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ("? password=label # comment\n: |\n" + _BLOCK_BODY, _BLOCK_REDACTED),
        ('"My Password": |\n' + _BLOCK_BODY, _BLOCK_REDACTED),
    ],
    ids=[
        "double-quoted-key-with-space",
        "single-quoted-key-with-space",
        "quoted-key-in-list-item",
        "explicit-mapping-key",
        "anchor-before-indicator",
        "tag-before-indicator",
        "byte-order-mark-before-key",
        "byte-order-mark-run-before-key",
        "byte-order-marks-inside-key",
        "quoted-key-with-escaped-quote",
        "quoted-key-with-escaped-letter",
        "quoted-key-with-colon",
        "explicit-key-with-comment",
        "explicit-quoted-key-with-colon",
        "explicit-quoted-key-with-unicode-escape",
        "explicit-quoted-key-with-colon-and-comment",
        "explicit-quoted-key-with-escape-and-comment",
        "plain-key-with-hash-in-name",
        "plain-key-with-hash-in-name-second",
        "plain-key-with-equals-sign",
        "explicit-plain-key-with-equals-and-comment",
        "quoted-key-with-capital-letters",
    ],
)
def test_block_scalar_body_is_redacted_for_each_yaml_key_form(
    event_store, text, expected
) -> None:
    redacted = event_store._redact_secret_text(text)
    assert "SECRET-BODY" not in redacted
    assert redacted == expected
    assert event_store._bounded_event_message(text) == expected


@pytest.mark.parametrize(
    "header",
    [
        '"my password": |',
        "? password\n: |",
        "password: &value |",
        "\ufeffpassword: |",
        '? "my password: label"\n: |',
        '? "\\u0070assword"\n: |',
        '? "my password: label" # comment\n: |',
    ],
)
@pytest.mark.parametrize("line_break", ["\r\n", "\r", "\n"])
def test_block_scalar_key_forms_redact_under_every_line_break(
    event_store, header, line_break
) -> None:
    text = header.replace("\n", line_break) + line_break + "  SECRET-BODY" + line_break
    text += "after: public" + line_break
    redacted = event_store.redact_event_data({"note": text})["note"]
    assert "SECRET-BODY" not in redacted
    assert redacted.endswith("after: public" + line_break)
    assert "after: public" in event_store._bounded_event_message(text)


@pytest.mark.parametrize(
    "text",
    [
        "description: |\n  ok\nafter: public\n",
        '"my notes": |\n  ok\nafter: public\n',
        "? name\n: |\n  ok\nafter: public\n",
        "\ufeffname: |\n  ok\nafter: public\n",
    ],
)
def test_block_scalar_with_a_non_secret_key_is_unchanged(event_store, text) -> None:
    assert event_store._redact_secret_text(text) == text


def test_block_scalar_redaction_survives_a_one_megabyte_body(event_store) -> None:
    body = "  " + "x" * 1_000_000 + "\n"
    for header in ('"my password": |\n', "? password\n: |\n", "password: &a !!str |\n"):
        started = time.perf_counter()
        redacted = event_store._redact_secret_text(header + body + "after: public\n")
        assert time.perf_counter() - started < 10.0
        assert redacted == _BLOCK_REDACTED
