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


# A block scalar body is redacted for CR LF, bare CR, and LF line breaks, and for a list item.
# The base pattern alone ends the span at the body; the persistence helpers redact a block
# scalar under a sensitive key to the end of the text (issue 428).
@pytest.mark.parametrize(
    ("text", "base_expected"),
    [
        ("password: |\r\n  CRLF-SECRET\r\nafter: public\r\n", "[REDACTED]\r\nafter: public\r\n"),
        ("password: |\r\n  A-SECRET\r\n\r\n  B-SECRET\r\nafter\r\n", "[REDACTED]\r\nafter\r\n"),
        ("password: |\r  BARE-SECRET\nafter\n", "[REDACTED]\nafter\n"),
        ("- password: |\n  LIST-SECRET\nafter\n", "[REDACTED]\nafter\n"),
    ],
)
def test_block_scalar_forms_are_redacted(event_store, text, base_expected) -> None:
    assert _redact(event_store, text) == base_expected
    assert event_store._bounded_event_message(text) == "[REDACTED]"


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
    ids=[
        "repeated-word",
        "repeated-password-key",
        "repeated-dotted-prefix",
        "dotted-prefix-url-suffix",
        "repeated-pem-header-prefix",
        "repeated-private-key-prefix",
        "pem-header-long-key-material",
        "rsa-header-repeated-incomplete-footer",
        "repeated-password-assignment",
        "repeated-double-quote",
        "yaml-block-crlf-body",
        "yaml-block-lone-carriage-returns",
        "password-repeated-double-quotes",
        "double-quoted-password-backslashes",
        "single-quoted-password-backslashes",
        "repeated-single-quote",
        "repeated-escaped-quoted-fragments",
        "password-key-trailing-spaces",
        "password-long-value",
        "long-prefix-before-password-key",
        "yaml-block-newline-body",
        "repeated-authorization-key",
        "repeated-token-key",
        "opening-quote-long-word",
        "opening-quote-long-space-prefix",
        "password-space-prefix-before-word",
        "yaml-dash-prefix-before-word",
        "yaml-dash-prefix-before-password-key",
        "yaml-space-prefix-before-password-key",
        "yaml-tab-prefix-before-token-key",
        "yaml-bom-space-prefix-before-key",
        "yaml-anchor-long-suffix",
        "yaml-repeated-anchor-tokens",
        "yaml-doubled-single-quotes",
        "repeated-byte-order-mark",
        "yaml-repeated-bom-mapping",
        "yaml-explicit-key-comment-padding",
        "yaml-repeated-embedded-bom-mapping",
        "yaml-dash-prefix-before-block-header",
        "yaml-explicit-key-space-prefix-block",
        "quoted-escaped-key-fragments",
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
# Issue 428: a block scalar under a sensitive key is redacted to the end of the text.
_BLOCK_TAIL = "[REDACTED]"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('"my password": |\n' + _BLOCK_BODY, _BLOCK_TAIL),
        ("'my password': |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ('- "my password": |\n' + _BLOCK_BODY, _BLOCK_TAIL),
        ("? password\n: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("password: &value |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("password: !!str |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("\ufeffpassword: |\n" + _BLOCK_BODY, "\ufeff" + _BLOCK_TAIL),
        ("\ufeff\ufeffpassword: |\n" + _BLOCK_BODY, "\ufeff\ufeff" + _BLOCK_TAIL),
        ("a\ufeff\ufeffpassword: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ('"pass\\"word": |\n' + _BLOCK_BODY, _BLOCK_TAIL),
        ('"pass\\u0077ord": |\n' + _BLOCK_BODY, _BLOCK_TAIL),
        ('"my password: label": |\n' + _BLOCK_BODY, _BLOCK_TAIL),
        ("? password # comment\n: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("? \"my password: label\"\n: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("? \"\\u0070assword\"\n: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ('? "my password: label" # comment\n: |\n' + _BLOCK_BODY, _BLOCK_TAIL),
        ('? "\\u0070assword: label" # comment\n: |\n' + _BLOCK_BODY, _BLOCK_TAIL),
        ("my_password#x: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("api#key: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("password=label: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ("? password=label # comment\n: |\n" + _BLOCK_BODY, _BLOCK_TAIL),
        ('"My Password": |\n' + _BLOCK_BODY, _BLOCK_TAIL),
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
    # Issue 428: a block scalar under a sensitive key is redacted to the end of the text.
    assert redacted.endswith("[REDACTED]")
    assert "SECRET-BODY" not in event_store._bounded_event_message(text)


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
        assert redacted == _BLOCK_TAIL


# Neutral canary: a body word that does not itself match the secret-word pattern, so a
# rule that redacts from the first secret word cannot hide a leak by matching the canary.
_CANARY_BODY = "  CANARY-BODY\nafter: public\n"


# Issue 428: the remaining valid YAML layouts that carry a sensitive key, handled by the
# structural value rule. Each input is a fixed literal; the body line is CANARY-BODY, then
# "after: public". The expected outputs are fixed literals: the key line keeps the
# redaction the base patterns give it. A value that starts on the key line has its deeper
# lines redacted; a value that starts on a later line is redacted to the end of the text.
_LAYOUTS_428 = [
    pytest.param(
        "my password:label: |\n" + _CANARY_BODY,
        "my [REDACTED]\n[REDACTED]",
        id="colon-inside-plain-key",
    ),
    pytest.param(
        '"my password":\n  &value |\n' + _CANARY_BODY,
        '"my [REDACTED]',
        id="newline-before-anchor",
    ),
    pytest.param(
        '"my password":\n  !!str |\n' + _CANARY_BODY,
        '"my [REDACTED]',
        id="newline-before-tag",
    ),
    pytest.param(
        '? "my password"\n# comment\n: |\n' + _CANARY_BODY,
        '? "my password"\n[REDACTED]',
        id="comment-line-between-explicit-key-and-value",
    ),
    pytest.param(
        '? "my\n  password"\n: |\n' + _CANARY_BODY,
        '? "my\n[REDACTED]',
        id="folded-explicit-quoted-key",
    ),
    # Review and security-review reproducers.
    pytest.param(
        "password:\n  !<tag:yaml.org,2002:str> |\n" + _CANARY_BODY,
        "[REDACTED]",
        id="verbatim-tag-with-colons-on-next-line",
    ),
    pytest.param(
        "password:\n  !e!tag:x |\n" + _CANARY_BODY,
        "[REDACTED]",
        id="shorthand-tag-with-colon-on-next-line",
    ),
    pytest.param(
        "my password:|label: |\n" + _CANARY_BODY,
        "my [REDACTED]\n[REDACTED]",
        id="plain-key-colon-before-pipe",
    ),
    pytest.param(
        "my password:>label: |\n" + _CANARY_BODY,
        "my [REDACTED]\n[REDACTED]",
        id="plain-key-colon-before-greater-than",
    ),
    pytest.param(
        '"my password": \n  &value |\n' + _CANARY_BODY,
        '"my [REDACTED]',
        id="trailing-space-after-key",
    ),
    pytest.param(
        '"my password":\n  &value \n  !!str |\n' + _CANARY_BODY,
        '"my [REDACTED]',
        id="properties-on-two-lines",
    ),
    pytest.param(
        '"my password":\n\n  &value |\n' + _CANARY_BODY,
        '"my [REDACTED]',
        id="blank-line-before-property",
    ),
    pytest.param(
        '"my password":\n# c\n  |\n' + _CANARY_BODY,
        '"my [REDACTED]',
        id="comment-line-between-implicit-key-and-value",
    ),
    pytest.param(
        '"my password": &a # c\n  |\n' + _CANARY_BODY,
        '"my [REDACTED]\n[REDACTED]',
        id="comment-after-property",
    ),
    pytest.param(
        "? my\n  password\n: |\n" + _CANARY_BODY,
        "? my\n[REDACTED]",
        id="folded-explicit-plain-key",
    ),
    pytest.param(
        "  ? 'my\n\"my password\": |\n   x'\n : |\n" + _CANARY_BODY,
        "  ? 'my\n[REDACTED]",
        id="base-span-inside-a-multiline-explicit-key",
    ),
    pytest.param(
        "password:\n- a\n- CANARY-BODY\nafter: public\n",
        "[REDACTED]",
        id="block-sequence-at-key-indentation",
    ),
    pytest.param(
        "password:\n- |\n" + _CANARY_BODY,
        "[REDACTED]",
        id="block-scalar-in-a-sequence-at-key-indentation",
    ),
    pytest.param(
        "?\n  password\n: |\n" + _CANARY_BODY,
        "?\n[REDACTED]",
        id="bare-explicit-key-marker",
    ),
    pytest.param(
        '?\n  "password"\n: |\n' + _CANARY_BODY,
        "?\n[REDACTED]",
        id="bare-explicit-key-marker-with-quoted-key",
    ),
    pytest.param(
        '"\\u0070assword":\n  &value |\n' + _CANARY_BODY,
        '[REDACTED]',
        id="escaped-quoted-key-with-later-line-value",
    ),
    pytest.param(
        '? "my\n: | password"\n: |\n' + _CANARY_BODY,
        '? "my\n[REDACTED]',
        id="quoted-explicit-key-holding-a-header-lookalike",
    ),
    pytest.param(
        "password: [a,\nCANARY-BODY]\nafter: public\n",
        '[REDACTED]',
        id="open-flow-sequence-at-key-indentation",
    ),
    pytest.param(
        "password: {a: 1,\nb: CANARY-BODY}\nafter: public\n",
        '[REDACTED]',
        id="open-flow-mapping-at-key-indentation",
    ),
    pytest.param(
        "password: &f [a,\nCANARY-BODY]\nafter: public\n",
        '[REDACTED]',
        id="open-flow-sequence-after-a-property",
    ),
    # Flow context: a value is not bounded by lines or indentation.
    pytest.param(
        "x: [\n password: abc\n def CANARY-BODY\n]\nafter: public\n",
        'x: [\n[REDACTED]',
        id="plain-value-continued-inside-a-flow-sequence",
    ),
    pytest.param(
        "x: {password: [a,\nCANARY-BODY]}\nafter: public\n",
        'x: [REDACTED]',
        id="sensitive-key-inside-a-flow-mapping",
    ),
    pytest.param(
        "x: [password: abc\n   CANARY-BODY]\nafter: public\n",
        'x: [[REDACTED]',
        id="flow-pair-continued-on-the-next-line",
    ),
    # Review round 2 reproducers.
    pytest.param(
        "{password: first\nCANARY-BODY\n}\nafter: public\n",
        '[REDACTED]',
        id="plain-value-continued-at-key-indentation-in-a-flow-mapping",
    ),
    pytest.param(
        '&a "my: password": |\n' + _CANARY_BODY,
        '&a "my: [REDACTED]\n[REDACTED]',
        id="anchor-before-a-quoted-key-with-a-colon",
    ),
    pytest.param(
        '!!str "my: password": |\n' + _CANARY_BODY,
        '!!str "my: [REDACTED]\n[REDACTED]',
        id="tag-before-a-quoted-key-with-a-colon",
    ),
    pytest.param(
        '&a "pass\\u0077ord": |\n' + _CANARY_BODY,
        '[REDACTED]',
        id="anchor-before-an-escaped-quoted-key",
    ),
    pytest.param(
        "? &a\n\n  password\n: |\n" + _CANARY_BODY,
        "? &a\n[REDACTED]",
        id="explicit-key-after-a-blank-line",
    ),
    pytest.param(
        "? my\n\n  password\n: |\n" + _CANARY_BODY,
        "? my\n[REDACTED]",
        id="explicit-key-folded-after-a-blank-line",
    ),
    pytest.param(
        "x: [REDACTEDx,\n password: abc\n def CANARY-BODY\n]\nafter: public\n",
        'x: [REDACTEDx[REDACTED]',
        id="flow-item-that-starts-like-the-marker",
    ),
    # Review round 3 reproducers.
    pytest.param(
        '{"password":first\nCANARY-BODY\n}\nafter: public\n',
        "[REDACTED]",
        id="flow-quoted-key-without-a-blank-after-the-colon",
    ),
    pytest.param(
        "{? password\n: first\nCANARY-BODY\n}\nafter: public\n",
        "{? [REDACTED]",
        id="flow-explicit-key",
    ),
    pytest.param(
        '{\n"pass\\u0077ord": first\nCANARY-BODY\n}\nafter: public\n',
        "{\n[REDACTED]",
        id="flow-escaped-quoted-key",
    ),
    pytest.param(
        '"pass\\u0077ord": CANARY-BODY\nafter: public\n',
        "[REDACTED]",
        id="escaped-quoted-key-with-an-inline-value",
    ),
    pytest.param(
        '&a "pass\\u0077ord": CANARY-BODY\nafter: public\n',
        "[REDACTED]",
        id="anchor-before-an-escaped-key-with-an-inline-value",
    ),
]


@pytest.mark.parametrize(("text", "expected"), _LAYOUTS_428)
def test_issue_428_layouts_redact_the_value(event_store, text, expected) -> None:
    redacted = event_store._redact_secret_text(text)
    assert "CANARY-BODY" not in redacted
    assert redacted == expected
    assert event_store._bounded_event_message(text) == expected
    assert event_store.redact_event_data({"note": text}) == {"note": expected}


@pytest.mark.parametrize(("text", "expected"), _LAYOUTS_428)
@pytest.mark.parametrize("line_break", ["\r\n", "\r"], ids=["crlf", "cr"])
def test_issue_428_layouts_redact_under_every_line_break(
    event_store, text, expected, line_break
) -> None:
    converted = text.replace("\n", line_break)
    wanted = expected.replace("\n", line_break)
    redacted = event_store.redact_event_data({"note": converted})["note"]
    assert "CANARY-BODY" not in redacted
    assert "CANARY-BODY" not in event_store._bounded_event_message(converted)
    if "[" in text or "{" in text:
        # The base pattern reads a bare CR differently on a flow line; the secret check
        # above is the property, the exact form is pinned for LF.
        return
    assert redacted == wanted
    assert event_store._bounded_event_message(converted) == wanted


@pytest.mark.parametrize(
    "text",
    [
        "my notes:label: |\n  ok\nafter: public\n",
        '"my notes":\n  &value |\n  ok\nafter: public\n',
        "description: rotate the password\n  ok\nafter: public\n",
        "name: x\n  user: bob\nafter: public\n",
    ],
)
def test_issue_428_layouts_with_a_non_secret_key_are_unchanged(event_store, text) -> None:
    assert event_store._redact_secret_text(text) == text


def test_an_unresolved_explicit_key_is_redacted_whatever_its_name(event_store) -> None:
    # An explicit key not directly followed by its ":" line is not resolved, so its value is
    # redacted to the end of the text even when the key names no secret (fail-closed).
    text = '? "my notes"\n# comment\n: |\n  ok\nafter: public\n'
    assert event_store._redact_secret_text(text) == '? "my notes"\n[REDACTED]'


@pytest.mark.parametrize(
    "text",
    [
        "password" + ":a" * 500_000,
        "my password:" * 90_000 + " |",
        '"my password":' + "\n  &a" * 300_000,
        '"my password":\n' * 70_000,
        "password:\n  &a\n" * 90_000,
        '? "my password"' + "\n# c" * 300_000,
        "? password\n# c\n" * 90_000,
        "# password:\n" * 90_000,
        '? "my' + "\n  x" * 300_000,
        '? "' + "\n" * 1_000_000 + "password",
        '? "a\n' * 200_000,
        '? "x\\\n' * 200_000,
        "? a\n  b\n" * 120_000,
        "&password:\n" * 100_000,
        "!password:\n" * 100_000,
        "  &password:\n" * 100_000,
        "password:\n  !" + "<" * 1_000_000 + "\n",
        "".join(" " * (i % 200) + "password:\n" for i in range(20_000)),
        '"password' * 120_000 + "\n",
        "? password\n" + ": x\n" * 200_000,
        '"\\x' * 300_000 + '":\n',
        '"\\":\n' * 150_000,
        "[password\n" * 100_000,
        "{\n" + "password word\n" * 100_000,
        "[\n" + "x: password\n" * 100_000,
        "&a " * 300_000 + "password: |\n  x\n",
        "? a\n" * 200_000,
        "? a\n: b\n" * 150_000,
        "? a" + " b" * 400_000 + "\n: c\n",
        "? a" + " " * 100_000 + "\nnot-colon\n",
        '"a\\' * 300_000,
        '"\\"' * 300_000,
        "{" + '"\\a"' * 200_000,
        '\\x"\n' * 200_000,
        "password: a\n  b\n" * 100_000,
        "password: a\n  token=b\n" * 100_000,
        ("password: plain\n  -----BEGIN PRIVATE KEY-----\n  k\n  -----END PRIVATE KEY-----token=\"\nC\"\n")
        * 10_000,
    ],
    ids=lambda text: f"{len(text)}-chars-{text[:12]!r}",
)
def test_issue_428_layouts_run_in_linear_time(event_store, text) -> None:
    started = time.perf_counter()
    event_store._redact_secret_text(text)
    # A quadratic scan of these inputs takes minutes; the linear patterns take well under a
    # second on a development host.
    assert time.perf_counter() - started < 10.0


@pytest.mark.parametrize(
    "unit",
    [
        "? a" + " " * 50 + "\nnot-colon\n",
        '"a\\',
        '"\\"',
        "&password:\n",
        "!password:\n",
        "&a password:\n  &b\n",
        "password:\n  !<" + "<" * 50 + "\n",
        "? a\n  b\n",
        "# password:\n",
    ],
)
def test_value_rule_scales_linearly(event_store, unit) -> None:
    # Ten times the input must take about ten times as long, not a hundred.
    def elapsed(count: int) -> float:
        text = unit * count
        started = time.perf_counter()
        event_store._redact_secret_text(text)
        return time.perf_counter() - started

    elapsed(1_000)
    small = elapsed(10_000)
    large = elapsed(100_000)
    assert large < 10.0
    assert large < max(small, 0.01) * 40


@pytest.mark.parametrize(
    "header",
    [
        "my password:label: |\n",
        '"my password":\n  &value |\n',
        '? "my password"\n# comment\n: |\n',
        '? "my\n  password"\n: |\n',
    ],
)
def test_issue_428_layouts_survive_a_one_megabyte_body(event_store, header) -> None:
    body = "  " + "x" * 1_000_000 + "\n"
    started = time.perf_counter()
    redacted = event_store._redact_secret_text(header + body + "after: public\n")
    assert time.perf_counter() - started < 10.0
    assert "x" * 100 not in redacted
    assert "[REDACTED]" in redacted


# Generated layouts: random valid YAML documents that put CANARY-VALUE under a sensitive key
# in many layouts. Each document is parsed with PyYAML first, and only documents whose parsed
# value under the sensitive key holds the secret are used, so the check is against real YAML.
_SENSITIVE_KEYS = [
    "password",
    '&a "my: password"',
    '!!str "pass\\u0077ord"',
    '"my password"',
    "'my password'",
    "my password:label",
    "api_key",
    '"pass\\u0077ord"',
]
_AFTER_COLON = ["", " ", " &a", " !!str", " # note", " &a !!str", " !<tag:yaml.org,2002:str>"]
_GAPS = ["", "\n", "\n# comment", "\n  # comment", "\n\n"]


def _sensitive_value(rng, indent: str) -> tuple[str, bool]:
    """Return a value layout and whether it starts on the key line."""
    deeper = indent + "  "
    gap = rng.choice(_GAPS)
    layouts = [
        (" |\n" + deeper + "CANARY-VALUE", True),
        (" >-\n" + deeper + "line one\n" + deeper + "CANARY-VALUE", True),
        (gap + "\n" + deeper + "&v |\n" + deeper + "CANARY-VALUE", False),
        (gap + "\n" + indent + "- a\n" + indent + "- CANARY-VALUE", False),
        (gap + "\n" + indent + "- |\n" + deeper + "CANARY-VALUE", False),
        (gap + "\n" + deeper + "inner: CANARY-VALUE", False),
        (gap + "\n" + deeper + "CANARY-VALUE", False),
        (" plain start\n" + deeper + "CANARY-VALUE", True),
        (" [a,\n" + deeper + "CANARY-VALUE]", True),
        (" [a,\n" + indent + "CANARY-VALUE]", True),
        (" {x: a,\n" + indent + "y: CANARY-VALUE}", True),
        (" &f [a,\n" + rng.choice([indent, deeper]) + "CANARY-VALUE]", True),
        (' "start\n' + deeper + 'CANARY-VALUE"', True),
        (gap + "\n" + deeper + "- CANARY-VALUE", False),
        (" >\n\n" + deeper + "CANARY-VALUE", True),
    ]
    return rng.choice(layouts)


def _explicit_entry(rng, indent: str) -> str:
    deeper = indent + "  "
    key = rng.choice(
        [
            "? password",
            '? "my password"',
            '? "my\n' + deeper + 'password"',
            "?\n" + deeper + "password",
            "? password # note",
            '? "my\n' + indent + ': | password"',
            "? 'my\n" + deeper + "password'",
            "? &a\n\n" + deeper + "password",
            "? my\n\n" + deeper + "password",
        ]
    )
    gap = rng.choice(["", "\n# comment"])
    value = rng.choice([" |\n" + deeper + "CANARY-VALUE", "\n" + deeper + "CANARY-VALUE"])
    return indent + key.replace("? ", "? ", 1) + gap + "\n" + indent + ":" + value


def _flow_document(rng) -> str:
    opener, closer = rng.choice([("[", "]"), ("{", "}")])
    key = rng.choice(
        ["password", '"password"', "api_key", '"my: password"', '"pass\\u0077ord"', "? password\n"]
    )
    separator = ":" if key.startswith('"') and rng.random() < 0.5 else ": "
    value = rng.choice(
        [
            "abc\n def CANARY-VALUE",
            "abc\nCANARY-VALUE",
            "\n  CANARY-VALUE",
            "[a,\nCANARY-VALUE]",
            '"start\n CANARY-VALUE"',
        ]
    )
    if rng.random() < 0.5:
        return "{" + key + separator + value + "\n}\n"
    return "before: public\nx: " + opener + "\n " + key + separator + value + "\n" + closer + "\n"


def _generated_document(rng) -> str:
    if rng.random() < 0.15:
        return _flow_document(rng)
    indent = rng.choice(["", "  "])
    lines = ["root:"] if indent else []
    lines.append(indent + "before: public")
    if rng.random() < 0.25:
        lines.append(_explicit_entry(rng, indent))
    else:
        value, inline = _sensitive_value(rng, indent)
        after = rng.choice(_AFTER_COLON) if not inline else ""
        if inline and value.startswith(" |"):
            after = rng.choice(["", " &a", " !!str"])
        lines.append(indent + rng.choice(_SENSITIVE_KEYS) + ":" + after + value)
    lines.append(indent + "after: public")
    return "\n".join(lines) + "\n"


def _holds_secret(node) -> bool:
    if isinstance(node, dict):
        return any(_holds_secret(k) or _holds_secret(v) for k, v in node.items())
    if isinstance(node, list):
        return any(_holds_secret(item) for item in node)
    return "CANARY-VALUE" in str(node)


def test_generated_yaml_layouts_never_keep_the_secret(event_store) -> None:
    import random

    import yaml
    rng = random.Random(428)
    checked = 0
    for _ in range(4000):
        document = _generated_document(rng)
        line_break = rng.choice(["\n", "\r\n", "\r"])
        document = document.replace("\n", line_break)
        try:
            parsed = yaml.safe_load(document)
        except yaml.YAMLError:
            continue
        if not _holds_secret(parsed):
            continue
        checked += 1
        for redacted in (
            event_store._redact_secret_text(document),
            event_store._bounded_event_message(document),
            event_store.redact_event_data({"note": document})["note"],
        ):
            assert "CANARY-VALUE" not in redacted, repr(document)
    # Most generated documents are valid YAML; the check must have real coverage.
    assert checked >= 2000, checked


# Composition: the structural rules are applied after the base fixed point, to the characters
# the base pipeline kept, so they can only remove more. A structural span that removed the
# start of a construct (here the token=" prefix that the PEM redaction exposes) would leave the
# rest of that construct for no later pass to find.
_PEM_THEN_TOKEN = (
    "password: plain\n  " + _PEM_BEGIN.replace("OPENSSH ", "") + "\n  key-body\n  "
    + _PEM_END.replace("OPENSSH ", "") + 'token="\nCANARY-VALUE"\n'
)


@pytest.mark.parametrize("line_break", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])
def test_structural_rules_keep_the_base_fixed_point(event_store, line_break) -> None:
    text = _PEM_THEN_TOKEN.replace("\n", line_break)
    expected = "[REDACTED]" + line_break + "[REDACTED]" + line_break
    assert event_store._redact_secret_text(text) == expected
    assert event_store._bounded_event_message(text) == expected
    assert event_store.redact_event_data({"note": text}) == {"note": expected}


def _is_subsequence(small: str, big: str) -> bool:
    remaining = iter(big)
    return all(character in remaining for character in small)


def test_structural_rules_only_remove_what_the_base_pipeline_keeps(event_store) -> None:
    import random

    tokens = [
        "password", "token", " ", ":", ": ", "=", '"', "\\", "|", "- ", "? ", "#", "&a",
        "\n", "\r\n", "\r", "x", "{", "[", "]", ",", _PEM_BEGIN, _PEM_END, "﻿",
    ]
    rng = random.Random(428)
    for _ in range(3000):
        text = "".join(rng.choice(tokens) for _ in range(rng.randint(1, 30)))
        base = event_store._base_fixed_point(text, lambda value: value)
        assert base is not None
        kept_by_base = base[0].replace("[REDACTED]", "")
        kept_by_head = event_store._redact_secret_text(text).replace("[REDACTED]", "")
        assert _is_subsequence(kept_by_head, kept_by_base), repr(text)
