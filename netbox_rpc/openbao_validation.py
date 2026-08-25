"""Pre-persistence secret-ingress validation for the OpenBao catalogue.

The OpenBao backend has its own recursive request scanner, but an execution's
raw ``params`` are stored before that backend is contacted.  This module is the
single family-wide admission control that scans the complete caller-supplied
params object before ``RPCExecution`` persistence.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import json
import math
import re
from typing import Any


OPENBAO_PROCEDURE_PREFIX = "service.openbao.1."
OPENBAO_MAX_STRING_BYTES = 1024 * 1024


class OpenBaoSecretIngressError(ValueError):
    """Raised when OpenBao params contain material that must not be stored."""


_SENSITIVE_FIELD_COMPONENTS = frozenset(
    {
        "authorization",
        "credential",
        "credentials",
        "passphrase",
        "passwd",
        "password",
        "pin",
        "secret",
        "secrets",
        "token",
        "tokens",
        "unseal",
    }
)
_SENSITIVE_KEY_PREFIXES = frozenset(
    {
        "access",
        "account",
        "api",
        "client",
        "current",
        "previous",
        "private",
        "root",
        "shared",
    }
)
_NON_SECRET_FIELD_NAMES = frozenset(
    {"key_id", "key_label", "key_name", "tls_key_file", "token_label"}
)
_IDENTIFIER_FIELD_NAMES = frozenset(
    {"mount_path", "peer_id", "policy_name", "snapshot_name"}
)
# Operational identifiers are schema-bounded to 128 characters. A long run of
# base64-alphabet characters is not enough evidence that one is a credential:
# realistic hyphenated names and timestamped snapshots have exactly that shape.
# High-entropy base64/base64url remains forbidden in these fields, while all
# other strings retain the full match-on-shape behavior.
_BASE64_IDENTIFIER_MIN_ENTROPY_BITS = 4.5
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9_.-])"
    r"(?P<key>[\"']?[A-Za-z0-9_.-]+[\"']?)\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|"
    r"Bearer\s+[^\s,}\]]+|[^\s,}\]]+)"
)
_ESCAPED_ASSIGNMENT_KEY_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9_.-]|\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}))+"
    r"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2})"
    r"(?:[A-Za-z0-9_.-]|\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}))*"
    r"\s*[:=]"
)
_QUOTED_STRING_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)
_TOKEN_LITERAL_RE = re.compile(r"(?i)\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{8,}\b")
_BASE64_MATERIAL_RE = re.compile(
    r"(?<![A-Za-z0-9+/_=-])"
    r"(?=[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_=-]))"
    r"(?=[A-Za-z0-9+/_-]*[G-Zg-z+/_-])"
    r"[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_=-])"
)
_HEX_MATERIAL_RE = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}(?![0-9A-Fa-f])"
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AUTHORIZATION_RE = re.compile(
    r"(?im)\b(?:authorization|bearer)\s*[:=]\s*[^\r\n]+?(?=\r?$)"
)
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"
)
_KEY_MATERIAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:unseal\s+key(?:\s+\d+)?|initial\s+root\s+token|"
    r"root\s+token)\s*[=:]\s*.*$"
)
_SECRET_SHAPE_PATTERNS = (
    _PRIVATE_KEY_RE,
    _AUTHORIZATION_RE,
    _URL_CREDENTIAL_RE,
    _TOKEN_LITERAL_RE,
    _HEX_MATERIAL_RE,
    _KEY_MATERIAL_LINE_RE,
)
_SIMPLE_HCL_ESCAPES = {
    '"': '"',
    "'": "'",
    "\\": "\\",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def validate_openbao_params_for_persistence(
    procedure_name: str,
    params: object,
) -> None:
    """Reject secret ingress anywhere in an OpenBao params object.

    Dictionary keys and values are both scanned recursively. String values are
    checked by secret shape; schema-declared identifier fields apply the narrow
    entropy distinction documented below. Accepted JSON documents are decoded
    and walked, while HCL-style quoted strings are lexically decoded before
    assignment classification so escaped field names and values cannot hide
    from the scanner.

    Non-OpenBao procedures return immediately and retain their existing
    admission behavior.
    """

    if not procedure_name.startswith(OPENBAO_PROCEDURE_PREFIX):
        return
    if not isinstance(params, Mapping):
        raise OpenBaoSecretIngressError("OpenBao params must be an object.")
    _scan_value(params, decode_documents=True, allow_identifier_fields=True)


def _scan_value(
    value: object,
    *,
    decode_documents: bool,
    identifier_field: str | None = None,
    allow_identifier_fields: bool = False,
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                _scan_text(key, decode_documents=decode_documents)
                if _sensitive_field_name(key):
                    _raise_secret_ingress()
            _scan_value(
                child,
                decode_documents=decode_documents,
                identifier_field=(
                    key
                    if allow_identifier_fields
                    and isinstance(key, str)
                    and key in _IDENTIFIER_FIELD_NAMES
                    else None
                ),
            )
        return
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        for child in value:
            _scan_value(child, decode_documents=decode_documents)
        return
    if isinstance(value, str):
        _scan_text(
            value,
            decode_documents=decode_documents,
            identifier_field=identifier_field,
        )


def _scan_text(
    value: str,
    *,
    decode_documents: bool,
    identifier_field: str | None = None,
) -> None:
    if len(value.encode("utf-8")) > OPENBAO_MAX_STRING_BYTES:
        raise OpenBaoSecretIngressError(
            "OpenBao params contain a string exceeding the 1 MiB UTF-8 byte limit."
        )
    _reject_secret_shapes(value, identifier_field=identifier_field)
    _reject_sensitive_assignments(value)

    if decode_documents:
        try:
            decoded_json: Any = json.loads(value)
        except (json.JSONDecodeError, TypeError, ValueError):
            decoded_json = None
        else:
            _scan_value(decoded_json, decode_documents=False)

    decoded_hcl, decoded_literals = _decode_hcl_quoted_strings(value)
    for literal in decoded_literals:
        _reject_secret_shapes(literal)
        _scan_decoded_json_literal(literal)
    if decoded_hcl != value:
        _reject_secret_shapes(decoded_hcl)
        _reject_sensitive_assignments(decoded_hcl)

    # HCL identifiers cannot contain backslash escapes. Reject them on an
    # assignment's left-hand side rather than allowing a future parser or
    # syntax extension to reinterpret a field name the classifier saw raw.
    if _ESCAPED_ASSIGNMENT_KEY_RE.search(value):
        _raise_secret_ingress()


def _scan_decoded_json_literal(value: str) -> None:
    try:
        decoded: Any = json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return
    _scan_value(decoded, decode_documents=False)


def _decode_hcl_quoted_strings(value: str) -> tuple[str, tuple[str, ...]]:
    decoded_literals: list[str] = []

    def replace(match: re.Match[str]) -> str:
        body = match.group(0)[1:-1]
        try:
            decoded = _decode_hcl_escapes(body)
        except ValueError:
            return match.group(0)
        decoded_literals.append(decoded)
        # Quotes are unnecessary for the assignment-name classifier, and
        # omitting them avoids a decoded quote changing lexical boundaries.
        return decoded

    decoded = _QUOTED_STRING_RE.sub(replace, value)
    decoded = decoded.replace("\u2028", "\n").replace("\u2029", "\n")
    return decoded, tuple(decoded_literals)


def _decode_hcl_escapes(value: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            decoded.append(character)
            index += 1
            continue
        if index + 1 >= len(value):
            raise ValueError("unterminated HCL escape")
        escape = value[index + 1]
        if escape in _SIMPLE_HCL_ESCAPES:
            decoded.append(_SIMPLE_HCL_ESCAPES[escape])
            index += 2
            continue
        if escape in {"u", "U"}:
            width = 4 if escape == "u" else 8
            start = index + 2
            end = start + width
            digits = value[start:end]
            if len(digits) != width or not all(
                character in "0123456789abcdefABCDEF" for character in digits
            ):
                raise ValueError("invalid HCL unicode escape")
            try:
                decoded.append(chr(int(digits, 16)))
            except ValueError as exc:
                raise ValueError("invalid HCL unicode code point") from exc
            index = end
            continue
        raise ValueError("unsupported HCL escape")
    return "".join(decoded)


def _reject_secret_shapes(
    value: str,
    *,
    identifier_field: str | None = None,
) -> None:
    if any(pattern.search(value) for pattern in _SECRET_SHAPE_PATTERNS):
        _raise_secret_ingress()
    base64_matches = tuple(_BASE64_MATERIAL_RE.finditer(value))
    if not base64_matches:
        return
    if identifier_field in _IDENTIFIER_FIELD_NAMES and all(
        match.span() == (0, len(value))
        and _shannon_entropy_bits(match.group(0).rstrip("="))
        < _BASE64_IDENTIFIER_MIN_ENTROPY_BITS
        for match in base64_matches
    ):
        return
    _raise_secret_ingress()


def _shannon_entropy_bits(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


def _reject_sensitive_assignments(value: str) -> None:
    if any(
        _sensitive_field_name(match.group("key"))
        for match in _ASSIGNMENT_RE.finditer(value)
    ):
        _raise_secret_ingress()


def _sensitive_field_name(value: str) -> bool:
    normalized = re.sub(r"[.-]+", "_", value.strip("\"'").lower())
    if normalized in _NON_SECRET_FIELD_NAMES:
        return False
    components = tuple(part for part in normalized.split("_") if part)
    if not components:
        return False
    if any(part in _SENSITIVE_FIELD_COMPONENTS for part in components):
        return True
    if normalized in {
        "auth_info",
        "connection_string",
        "connection_url",
        "key",
        "keys",
    }:
        return True
    return any(
        components[index] in _SENSITIVE_KEY_PREFIXES
        and components[index + 1] in {"key", "keys"}
        for index in range(len(components) - 1)
    )


def _raise_secret_ingress() -> None:
    raise OpenBaoSecretIngressError(
        "OpenBao params contain secret-shaped material and cannot be persisted."
    )
