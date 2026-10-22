from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from itertools import islice
from typing import Any

import jsonschema
from django.db import IntegrityError
from django.utils import timezone

from .constants import (
    AKVORADO_BOOTSTRAP_DEBIAN13_PROCEDURE_NAMES,
    GITEA_PRODUCTION_UPGRADE_1_27_1,
    INFLUXDB3_DEBIAN13_PROCEDURE_NAMES,
    NETBOX_STAGING_DEPLOY_DNS_PAIR,
    NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
    NMS_SECRET_REFERENCE_RE,
    PROTECTED_APPROVAL_PROCEDURE_NAMES,
)
from .domain import events as domain_events
from .domain.projection import ProjectionState, apply, rebuild
from .models import RPCExecution, RPCExecutionEvent

try:
    from django.db import transaction
except ImportError:

    class _TransactionShim:
        @staticmethod
        def atomic():
            return nullcontext()

    transaction = _TransactionShim()

SENSITIVE_KEY_FRAGMENTS = (
    "auth",
    "community",
    "credential",
    "key",
    "password",
    "private",
    "secret",
    "token",
)
SAFE_REFERENCE_KEYS = {
    "credential_pk",
    "guest_credential_pk",
    # Public SSH server identity returned by observation-only Akvorado
    # preflight. These are bounded by the procedure result schema and are the
    # operator input needed to enable strict host-key checking; neither is
    # authentication material.
    "host_key_fingerprint",
    "host_key_pinned",
    "known_hosts_entry",
    "key_id",
    "key_version",
    # Samba identity creation scrubs the raw password before persistence and
    # deliberately retains only this non-plaintext audit fingerprint.  Keep
    # these two fields reconstructable when the live projection is folded from
    # the redacted event ledger; a bare ``password`` key remains sensitive.
    "password_bytes",
    "password_sha256",
    "restconf_credential_pk",
    "rpc_ssh_credential_pk",
    # The strict host-key policy flag is a non-secret boolean chosen by the
    # operator. The backend needs it as a real boolean, so it must persist as
    # one rather than as "[REDACTED]".
    "rpc_ssh_strict_host_key_checking",
}
# Policy flags that are stored as booleans. A non-boolean value under one of these
# names is redacted at every depth, even though the name is also a safe reference key.
_BOOLEAN_POLICY_KEYS = frozenset({"rpc_ssh_strict_host_key_checking"})
MAX_EVENT_STRING_LENGTH = 4096
MAX_EVENT_LIST_ITEMS = 50
MAX_EVENT_DICT_ITEMS = 100
MAX_BACKEND_EVENTS = 50
_BACKEND_EVENT_PREFIX = "Backend::"
# A secret-bearing mapping name is persisted as a keyed placeholder. The salt is
# purpose-specific: it keys this digest only, so no other keyed digest can be
# replayed as a mapping-name placeholder.
_EVENT_MAPPING_NAME_SALT = "netbox_rpc.event_mapping_name.v1"
_MAPPING_NAME_PLACEHOLDER_PREFIX = "[REDACTED-NAME:"
# Levels the model stores (RPCExecutionEvent.LEVEL_CHOICES; a DB-tier test keeps the
# two in step). Any other level is recorded as info.
_EVENT_LEVELS = frozenset({"debug", "info", "warning", "error"})
# Keep in sync with the Akvorado and InfluxDB normalization-layer content limits.
_LARGE_NORMALIZED_CONTENT_FIELDS = ("config_content", "content")
_LARGE_NORMALIZED_CONTENT_LIMIT = 1024 * 1024
RESULT_SCHEMA_MISMATCH_CODE = "RPC_RESULT_SCHEMA_MISMATCH"
# Catalog error codes are upper snake case. The RPCExecution.error_code column
# is CharField(max_length=100), so only a code of this shape may be persisted as
# the execution error. See _persistable_failure_event().
_BACKEND_ERROR_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,99}")
MAX_SCHEMA_MISMATCH_MESSAGE_LENGTH = 512
# Appended by redact_event_value() to any string it truncates. A single named
# constant so _result_schema_string_limits() (#215 round 3) can reserve
# exactly this much room out of a schema-declared maxLength, guaranteeing a
# persisted truncated value (content + marker) never exceeds its own schema
# bound.
_TRUNCATION_MARKER = "...[truncated]"
_MAX_REDACTION_DEPTH = 32
StringLimitPath = tuple[str, ...]
# Secret-content patterns for persisted text. Every alternative is linear in the input
# length: key runs are possessive, and each keyed alternative starts only at a token
# boundary (lookbehind). A complete PEM block is consumed through its END line; an
# unclosed block runs to the end of the text. Quoted values run to the closing quote
# (escapes and doubled quotes included) or to the end of the input; an unquoted value
# runs to the end of its line. An exact nms-secret pointer is exempted at the value
# level (see _redact_secret_text), never inside the pattern.
_SECRET_KEY_FRAGMENT = (
    r"(?:token|password|passphrase|secret|authorization|api[-_#]?key|"
    r"access[-_]?key|private[-_]?key|credential)"
)
_SECRET_KEY_RUN = r"[A-Za-z0-9_.-]*+"
_SECRET_CONTENT_RE = re.compile(
    # The END label must equal the BEGIN label; a different PRIVATE KEY footer is body.
    r"-----BEGIN (?P<pem>(?=[A-Z0-9 ]*?PRIVATE KEY)[A-Z0-9 ]{1,128}+)-----"
    r"[\s\S]*?(?:-----END (?P=pem)-----|\Z)"
    # A label longer than the bound redacts to the end of the text.
    r"|-----BEGIN (?=[A-Z0-9 ]*?PRIVATE KEY)[A-Z0-9 ]*+-----[\s\S]*"
    # A line break is CR LF, CR, or LF; a block scalar body may follow a header with any of them.
    r"|(?<![^\r\n])(?P<yaml_indent>[ \t]*)(?:-[ \t]+)*"
    r"(?=[\"']?[A-Za-z0-9_.-]*?" + _SECRET_KEY_FRAGMENT + r")"
    r"[\"']?" + _SECRET_KEY_RUN + r"[\"']?\s*:\s*[|>]"
    r"(?:[1-9][+-]?|[+-][1-9]?)?[ \t]*(?:#[^\r\n]*)?(?=\r|\n|\Z)"
    r"(?:(?:\r\n|\r(?!\n)|\n)(?:(?P=yaml_indent)[ \t][^\r\n]*|[ \t]*(?=\r|\n|\Z)))*"
    r"|(?im:\b(?:authorization|bearer)\s*[:=]\s*[^\r\n]+?(?=\r?$))"
    r"|(?im:(?:^[ \t]*|[,{]\s*|-\s+)?(?<![A-Za-z0-9_.-])"
    r"(?=[\"']?[A-Za-z0-9_.-]*?" + _SECRET_KEY_FRAGMENT + r")"
    r"[\"']?" + _SECRET_KEY_RUN + r"[\"']?\s*+[:=]\s*+"
    r"(?:\"(?:\"\"|\\(?:[\s\S]|\Z)|[^\"\\])*\"?"
    r"|'(?:''|\\(?:[\s\S]|\Z)|[^'\\])*'?"
    r"|[^\r\n]+))"
    r"|(?i:(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]*+://[^\s/:@]+:[^\s/@]+@)"
)

# YAML block scalar headers that _SECRET_CONTENT_RE does not cover: a quoted key with spaces
# or escapes, an explicit "? key" line whose ": |" indicator follows on the next line, a key
# after a byte-order mark, and anchor or tag properties before the indicator. The body rules
# are those of the base pattern. Keys are read up to their colon, and every quantifier is
# possessive or bounded by the line, so the match stays linear in the input length.
_YAML_BLOCK_SCALAR_HEADER_RE = re.compile(
    r"(?<![^\r\n])\ufeff*+(?P<yaml_indent>[ \t]*+)(?:-[ \t]++)*+(?:\?[ \t]++)?+"
    r"(?=[^\r\n]*?(?i:" + _SECRET_KEY_FRAGMENT + r")|[\"'][^\r\n]*?\\)"
    r"(?:\"(?:\\[^\r\n]|[^\"\\\r\n])*+\"|'(?:''|[^'\r\n])*+'|(?:[^\r\n:#]|(?<![ \t])#)*+)"
    r"(?:[ \t]*+#[^\r\n]*+)?"
    r"\s*:(?:[ \t]+[&!][^ \t\r\n]*)*+\s*[|>]"
    r"(?:[1-9][+-]?|[+-][1-9]?)?[ \t]*(?:#[^\r\n]*)?(?=\r|\n|\Z)"
    r"(?:(?:\r\n|\r(?!\n)|\n)(?:(?P=yaml_indent)[ \t][^\r\n]*|[ \t]*(?=\r|\n|\Z)))*"
)


def _secret_spans(text: str) -> list[tuple[int, int]]:
    """Return the sorted, non-overlapping spans to redact in text.

    The union of the base pattern's matches and the YAML header matches is taken. A header
    match that overlaps a base match is merged with it, so every span the base pattern
    redacts is still redacted, whatever the header match covers. Spans that do not overlap
    anything are left exactly as the base pattern found them.
    """
    spans = [match.span() for match in _SECRET_CONTENT_RE.finditer(text)]
    extra = [match.span() for match in _YAML_BLOCK_SCALAR_HEADER_RE.finditer(text)]
    if not extra:
        return spans
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans + extra):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _redact_secret_spans(text: str) -> str:
    """Replace each secret span of text with the redaction marker."""
    pieces: list[str] = []
    last = 0
    for start, end in _secret_spans(text):
        pieces.append(text[last:start])
        # A header match consumes the byte-order marks at its line start; keep them.
        span = text[start:end]
        pieces.append(span[: len(span) - len(span.lstrip("\ufeff"))])
        pieces.append("[REDACTED]")
        last = end
    pieces.append(text[last:])
    return "".join(pieces)


# One substitution can expose a new assignment: a PEM block replaced by its marker
# can leave a secret assignment that the same pass did not match. Persisted text is
# therefore redacted to a fixed point. The passes are bounded, so the cost stays
# linear, and text that still changes after them is replaced whole.
_SECRET_TEXT_PASSES = 4


def _redact_bounded(text: str, bound: Callable[[str], str]) -> str:
    """Redact secret content and bound the text, repeating until the result is stable.

    Each pass substitutes secret content and then applies the bound, as the base
    pipeline did when it redacted and truncated a value twice. The bound stays inside
    the loop, so content beyond it is dropped before a later pass can move it inside
    the bound. An nms-secret pointer that is the entire text is a reference, not secret
    material, so it is returned unchanged. Text still changing after the bounded
    passes is replaced whole.
    """
    if NMS_SECRET_REFERENCE_RE.fullmatch(text):
        return text
    current = text
    for _ in range(_SECRET_TEXT_PASSES):
        bounded = bound(_redact_secret_spans(current))
        if bounded == current:
            return current
        current = bounded
    return "[REDACTED]"


def _redact_secret_text(text: str) -> str:
    """Redact secret content in persisted text to a fixed point, without a length bound."""
    return _redact_bounded(text, lambda value: value)


class RPCEventStoreError(RuntimeError):
    """Raised when the RPC execution event ledger cannot append an event."""


def _json_dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _stable_hash(value: object) -> str:
    return hashlib.sha256(_json_dump(value).encode("utf-8")).hexdigest()


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    if normalized in SAFE_REFERENCE_KEYS or normalized.endswith("_credential_pk"):
        return False
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def _is_vaulted_secret_reference(value: object) -> bool:
    """True only for an exact ``nms-secret:<uuid>`` pointer.

    A reference is not secret material -- redeeming it requires the execution
    backend's own credentials -- so it is safe to persist, and it MUST be
    persisted: the pull-based backend reads the approved reference back out of
    ``normalized_params``, and ``resolved_command_hash`` and the dispatch lease
    are computed from the unredacted fingerprint, so redacting it here would
    both strand the backend and desynchronise those hashes.

    Matched by value rather than by key name on purpose. Every reference
    parameter in the catalog (``admin_secret_ref``, ``operator_token_secret_ref``,
    ``registration_token_secret_ref``, ...) trips the key-name rule, while a raw
    or malformed value under those same keys must still be redacted.
    """

    return isinstance(value, str) and bool(NMS_SECRET_REFERENCE_RE.fullmatch(value))


def contains_secret_text(text: str) -> bool:
    """True when the shared pattern would change ``text``.

    An exact nms-secret reference is a reference, not secret content, so it is
    reported as clean. The check runs on the complete text the caller holds.
    """
    return _redact_secret_text(text) != text


def _redact_event_text(
    value: object,
    string_limits: dict[StringLimitPath, int] | None,
    path: StringLimitPath,
) -> str:
    max_length = (string_limits or {}).get(path, MAX_EVENT_STRING_LENGTH)

    def bound(text: str) -> str:
        if len(text) > max_length:
            return f"{text[:max_length]}{_TRUNCATION_MARKER}"
        return text

    return _redact_bounded(str(value), bound)


def _redact_event_mapping(
    value: Mapping[object, object],
    *,
    string_limits: dict[StringLimitPath, int] | None,
    path: StringLimitPath,
    depth: int,
) -> dict[str, object]:
    # A mapping that the ledger already bounded holds the data limit of entries
    # and the marker, in any key order: the database may return its keys in a
    # different order. Its data entries are kept and the marker is kept, so
    # redacting a stored mapping returns the same form.
    if len(value) == MAX_EVENT_DICT_ITEMS + 1 and value.get("_truncated") is True:
        entries = [pair for pair in value.items() if pair[0] != "_truncated"]
        truncated = True
    else:
        # Visit at most one entry past the limit, so an oversized mapping costs
        # bounded work. The kept entries are the first ones in insertion order.
        window = list(islice(value.items(), MAX_EVENT_DICT_ITEMS + 1))
        entries = window[:MAX_EVENT_DICT_ITEMS]
        truncated = len(window) > MAX_EVENT_DICT_ITEMS
    # Sensitivity checks and string limits read each name as written; only the
    # persisted key changes, to a keyed placeholder for a secret-bearing name.
    redacted: dict[str, object] = {}
    for persisted, name, item in _persisted_mapping_entries(entries):
        redacted[persisted] = redact_event_value(
            item,
            parent_key=name,
            string_limits=string_limits,
            path=(*path, name),
            depth=depth + 1,
        )
    if truncated:
        redacted["_truncated"] = True
    return redacted


def _persisted_mapping_entries(
    entries: list[tuple[object, object]],
) -> list[tuple[str, str, object]]:
    """Return ``(persisted name, name as written, value)`` in name order.

    A secret-bearing name is persisted as a keyed placeholder that neither collides
    with a non-secret name of the mapping nor with another placeholder, so no value
    is dropped and no non-secret key is overwritten.
    """
    named = [(str(key), item) for key, item in entries]
    secret_names = {name for name, _item in named if _mapping_name_is_secret_bearing(name)}
    taken = {name for name, _item in named if name not in secret_names}
    resolved: list[tuple[str, str, object]] = []
    for name, item in sorted(named, key=lambda entry: entry[0]):
        if name in secret_names:
            persisted = _unused_placeholder(name, taken)
            taken.add(persisted)
        else:
            persisted = name
        resolved.append((persisted, name, item))
    return resolved


def _mapping_name_is_secret_bearing(name: str) -> bool:
    """True when a mapping name holds secret content the ledger must not store."""
    return _redact_secret_text(name) != name


def _keyed_mapping_name(name: str) -> str:
    """Return the keyed placeholder for a secret-bearing mapping name.

    The digest is salted_hmac over the complete name, keyed with the deployment
    secret and a purpose-specific salt. The stored copy therefore does not reveal
    the name, and an unkeyed guess cannot be checked offline. The placeholder does
    not match the shared pattern, so redaction keeps it unchanged on later passes.
    """
    from django.utils.crypto import salted_hmac

    digest = salted_hmac(_EVENT_MAPPING_NAME_SALT, name, algorithm="sha256")
    return f"{_MAPPING_NAME_PLACEHOLDER_PREFIX}{digest.hexdigest()}]"


def _unused_placeholder(name: str, taken: set[str]) -> str:
    """Return the placeholder for ``name`` that no persisted name in the mapping uses.

    The loop runs at most once per taken name, so its cost is bounded by the
    mapping window, not by the size of the names.
    """
    placeholder = _keyed_mapping_name(name)
    candidate = placeholder
    suffix = 1
    while candidate in taken:
        suffix += 1
        candidate = f"{placeholder}#{suffix}"
    return candidate


def _event_level(value: object) -> str:
    """Return the level the ledger stores: a supported model level, otherwise info."""
    if isinstance(value, str) and value in _EVENT_LEVELS:
        return value
    return "info"


def _is_truncation_marker(item: object) -> bool:
    """True for the marker that a bounded list ends with: ``_truncated`` and an integer ``remaining``."""
    return (
        isinstance(item, Mapping)
        and set(item) == {"_truncated", "remaining"}
        and item["_truncated"] is True
        and type(item["remaining"]) is int
    )


def _redact_event_sequence(
    value: list[object] | tuple[object, ...] | set[object] | frozenset[object],
    *,
    parent_key: str,
    string_limits: dict[StringLimitPath, int] | None,
    path: StringLimitPath,
    depth: int,
) -> list[object]:
    # Visit at most one entry past the limit. Unordered containers sort only
    # the visited window, so the kept subset is deterministic for sets of up to
    # the limit and bounded work for larger sets.
    marker: object = None
    if (
        isinstance(value, (list, tuple))
        and len(value) == MAX_EVENT_LIST_ITEMS + 1
        and _is_truncation_marker(value[-1])
    ):
        # A list that the ledger already bounded keeps its marker, so redacting
        # the stored form again returns the same form.
        window = list(value[:-1])
        marker = dict(value[-1])
    else:
        window = list(islice(value, MAX_EVENT_LIST_ITEMS + 1))
        if isinstance(value, (set, frozenset)):
            window.sort(key=repr)
        if len(value) > MAX_EVENT_LIST_ITEMS:
            marker = {
                "_truncated": True,
                "remaining": len(value) - MAX_EVENT_LIST_ITEMS,
            }
    items = [
        redact_event_value(
            item,
            parent_key=parent_key,
            string_limits=string_limits,
            path=(*path, "*"),
            depth=depth + 1,
        )
        for item in window[:MAX_EVENT_LIST_ITEMS]
    ]
    if marker is not None:
        items.append(marker)
    return items


def _redact_sensitive_value(value: object, parent_key: str) -> object:
    if isinstance(value, bool):
        # A boolean cannot carry secret material. Replacing it with a string
        # would break the typed field that consumes it.
        return value
    from .credential_contract import public_credential_metadata

    public_metadata = public_credential_metadata(value, parent_key)
    if public_metadata is not None:
        return public_metadata
    if _is_vaulted_secret_reference(value):
        return value
    return "[REDACTED]"


def redact_event_value(
    value: object,
    *,
    parent_key: str = "",
    string_limits: dict[StringLimitPath, int] | None = None,
    path: StringLimitPath = (),
    depth: int = 0,
) -> object:
    if parent_key and parent_key.lower() in _BOOLEAN_POLICY_KEYS:
        # This check precedes safe-key and container handling at every depth.
        return value if isinstance(value, bool) else "[REDACTED]"
    if parent_key and _is_sensitive_key(parent_key):
        return _redact_sensitive_value(value, parent_key)
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        if depth > _MAX_REDACTION_DEPTH:
            return "[truncated]"
        if isinstance(value, Mapping):
            return _redact_event_mapping(
                value, string_limits=string_limits, path=path, depth=depth
            )
        return _redact_event_sequence(
            value,
            parent_key=parent_key,
            string_limits=string_limits,
            path=path,
            depth=depth,
        )
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return _redact_event_text(value, string_limits, path)


def redact_event_data(
    data: dict[str, Any] | None,
    *,
    string_limits: dict[StringLimitPath, int] | None = None,
) -> dict[str, Any]:
    redacted = redact_event_value(data or {}, string_limits=string_limits)
    return redacted if isinstance(redacted, dict) else {}


def _bounded_event_message(message: object) -> str:
    """Redact and hard-cap an event message independently of event data."""
    content_limit = max(MAX_EVENT_STRING_LENGTH - len(_TRUNCATION_MARKER), 0)

    def bound(text: str) -> str:
        if len(text) <= MAX_EVENT_STRING_LENGTH:
            return text
        return f"{text[:content_limit]}{_TRUNCATION_MARKER}"

    return _redact_bounded(str(message or ""), bound)


def _next_event_sequence(execution: RPCExecution) -> int:
    latest = (
        execution.events.order_by("-sequence")
        .values_list("sequence", flat=True)
        .first()
    )
    return int(latest or 0) + 1


def append_execution_event(
    execution: RPCExecution,
    level: str,
    event: str,
    message: str,
    data: dict[str, Any] | None = None,
    *,
    string_limits: dict[StringLimitPath, int] | None = None,
) -> RPCExecutionEvent:
    """Append one durable execution event with per-execution sequence ordering."""
    sequence = _next_event_sequence(execution)
    level = _event_level(level)
    event_data = redact_event_data(data, string_limits=string_limits)
    redacted_message = _bounded_event_message(message)
    payload_hash = _stable_hash(
        {
            "level": level,
            "event": event,
            "message": redacted_message,
            "data": event_data,
        }
    )
    for _ in range(3):
        try:
            with transaction.atomic():
                return RPCExecutionEvent.objects.create(
                    execution=execution,
                    sequence=sequence,
                    level=level,
                    event=event,
                    message=redacted_message,
                    data=event_data,
                    payload_hash=payload_hash,
                )
        except IntegrityError:
            sequence = _next_event_sequence(execution)
    raise RPCEventStoreError(
        "RPCExecutionEvent sequence collision exhausted retries for execution "
        f"{execution.pk} (event={event!r})."
    )


def _normalized_params_string_limits() -> dict[StringLimitPath, int]:
    return {
        ("normalized_params", field_name): _LARGE_NORMALIZED_CONTENT_LIMIT
        for field_name in _LARGE_NORMALIZED_CONTENT_FIELDS
    }


def ledger_normalized_params(normalized_params: dict[str, Any]) -> dict[str, Any]:
    """Return normalized parameters in the form the ledger stores and projects.

    The ledger redacts and bounds the ParametersNormalized event before it
    projects the parameters onto the execution. The approval hash is computed
    over this same form, so the request-time hash and the lease-time check agree.
    """
    redacted = redact_event_data(
        {"normalized_params": dict(normalized_params or {})},
        string_limits=_normalized_params_string_limits(),
    )
    return dict(redacted.get("normalized_params") or {})


_EXECUTION_FAILED_CODE = "RPC_EXECUTION_FAILED"
_ENQUEUE_FAILED_CODE = "RPC_ENQUEUE_FAILED"


def _is_catalog_error_code(code: object) -> bool:
    """True only for a code that fits RPCExecution.error_code: catalog shape and column width."""
    return isinstance(code, str) and _BACKEND_ERROR_CODE_RE.fullmatch(code) is not None


def _persistable_failure_event(
    event: domain_events.DomainEvent,
) -> domain_events.DomainEvent:
    """Return a failure event whose code is safe to project onto the execution.

    The projection writes ``code`` to ``RPCExecution.error_code``. Every failure
    event passes through ``_append_and_project``, so bounding the code here covers
    every writer. A code that is not catalog-shaped, or that is longer than the
    column, is replaced by the fixed fallback. The raw value is not kept: no
    legitimate backend code fails the shape, and echoing unchecked backend text
    into the ledger would add a leak channel.
    """
    if isinstance(event, domain_events.ExecutionFailed):
        fallback = _EXECUTION_FAILED_CODE
    elif isinstance(event, domain_events.ExecutionEnqueueFailed):
        fallback = _ENQUEUE_FAILED_CODE
    else:
        return event
    if _is_catalog_error_code(event.code):
        return event
    return dataclasses.replace(event, code=fallback)


def _append_and_project(
    execution: RPCExecution,
    event: domain_events.DomainEvent,
) -> RPCExecutionEvent:
    event = _persistable_failure_event(event)
    string_limits = None
    if isinstance(
        event,
        (domain_events.ExecutionSucceeded, domain_events.ExecutionFailed),
    ):
        string_limits = {
            ("result", *path): limit
            for path, limit in _result_schema_string_limits(execution).items()
        }
    elif isinstance(event, domain_events.ParametersNormalized):
        string_limits = _normalized_params_string_limits()
    record = append_execution_event(
        execution,
        event.level,
        event.event_name,
        event.message,
        event.data,
        string_limits=string_limits,
    )
    redacted_event = type(event).from_data(record.data)
    projected = apply(ProjectionState.from_execution(execution), redacted_event)
    _write_projection(execution, projected)
    return record


def _write_projection(execution: RPCExecution, state: ProjectionState) -> None:
    update_fields = []
    for field_name, value in state.as_update_dict().items():
        if getattr(execution, field_name) != value:
            setattr(execution, field_name, value)
            update_fields.append(field_name)
    if update_fields:
        execution.save(update_fields=update_fields)


def record_execution_queued(execution: RPCExecution) -> None:
    requested_by = getattr(execution, "requested_by", None)
    requested_by_id = getattr(requested_by, "pk", None) or getattr(
        execution,
        "requested_by_id",
        None,
    )
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionQueued(requested_by_id=requested_by_id),
        )


def record_execution_enqueued(execution: RPCExecution, job_id: object) -> None:
    with transaction.atomic():
        _append_and_project(execution, domain_events.JobEnqueued(job_id=job_id))


def mark_execution_running(execution: RPCExecution) -> None:
    now = timezone.now()
    with transaction.atomic():
        _append_and_project(execution, domain_events.ExecutionStarted(started_at=now))


def record_dispatch_lease_issued(
    execution: RPCExecution,
    *,
    nonce: str,
    key_id: str,
    key_version: int,
    stream_version: int,
    audience: str,
    expires_at: Any,
    envelope_version: int,
) -> None:
    """Append the audit event for a minted signed dispatch lease (#168).

    References only — the nonce, key lineage, stream version, audience, and
    expiry. Never the signature or any secret; ``redact_event_data`` bounds the
    payload like every other ledger event.
    """
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.DispatchLeaseIssued(
                nonce=nonce,
                key_id=key_id,
                key_version=key_version,
                stream_version=stream_version,
                audience=audience,
                expires_at=expires_at,
                envelope_version=envelope_version,
            ),
        )


def mark_execution_failed(
    execution: RPCExecution,
    message: str,
    code: str,
    *,
    event_name: str = "ExecutionFailed",
) -> None:
    now = timezone.now()
    if event_name == domain_events.ExecutionEnqueueFailed.EVENT_NAME:
        event: domain_events.DomainEvent = domain_events.ExecutionEnqueueFailed(
            error_message=message,
            code=code,
            finished_at=now,
        )
    else:
        event = domain_events.ExecutionFailed(
            error_message=message,
            code=code,
            finished_at=now,
        )
    with transaction.atomic():
        _append_and_project(execution, event)


def record_execution_normalized(
    execution: RPCExecution,
    normalized_params: dict[str, Any],
    resolved_command_hash: str,
) -> None:
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ParametersNormalized(
                normalized_params=normalized_params,
                resolved_command_hash=resolved_command_hash,
            ),
        )


def record_execution_succeeded(
    execution: RPCExecution,
    result: dict[str, Any],
) -> None:
    finished_at = timezone.now()
    with transaction.atomic():
        # _append_and_project redacts the result once, with the result's schema limits.
        _append_and_project(
            execution,
            domain_events.ExecutionSucceeded(result=result, finished_at=finished_at),
        )


def record_execution_cancelled(
    execution: RPCExecution,
    *,
    user: object | None = None,
    reason: str = "",
) -> None:
    finished_at = timezone.now()
    cancelled_by_id = getattr(user, "pk", None)
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionCancelled(
                finished_at=finished_at,
                cancelled_by_id=cancelled_by_id,
                reason=reason,
            ),
        )


def record_execution_requested(
    execution: RPCExecution,
    *,
    requested_by_id: object | None = None,
) -> None:
    if requested_by_id is None:
        requested_by = getattr(execution, "requested_by", None)
        requested_by_id = getattr(requested_by, "pk", None) or getattr(
            execution, "requested_by_id", None
        )
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionRequested(requested_by_id=requested_by_id),
        )


def record_approval_requested(
    execution: RPCExecution,
    *,
    snapshot_hash: str,
    expires_at: object | None = None,
    requested_by_id: object | None = None,
) -> None:
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ApprovalRequested(
                snapshot_hash=snapshot_hash,
                expires_at=expires_at,
                requested_by_id=requested_by_id,
            ),
        )


def record_execution_approved(
    execution: RPCExecution,
    *,
    approved_by_id: object,
    snapshot_hash: str,
    reason: str = "",
) -> None:
    decided_at = timezone.now()
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionApproved(
                approved_by_id=approved_by_id,
                snapshot_hash=snapshot_hash,
                decided_at=decided_at,
                reason=reason,
            ),
        )


def record_execution_rejected(
    execution: RPCExecution,
    *,
    rejected_by_id: object,
    reason: str = "",
) -> None:
    decided_at = timezone.now()
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionRejected(
                rejected_by_id=rejected_by_id,
                decided_at=decided_at,
                reason=reason,
            ),
        )


def record_execution_expired(
    execution: RPCExecution,
    *,
    reason: str = "",
) -> None:
    expired_at = timezone.now()
    with transaction.atomic():
        _append_and_project(
            execution,
            domain_events.ExecutionExpired(expired_at=expired_at, reason=reason),
        )


def _skips_result_validation(
    *,
    ok: object,
    result_present: bool,
    raw_result: object,
    error_code: object,
    has_dedicated_validation: bool,
) -> bool:
    """Return True for a failure whose backend error code is the real cause.

    The response must be a failure: ``ok`` is exactly ``False``. Its ``result``
    must be absent or exactly ``{}``. Its ``error_code`` must be catalog-shaped.
    Such a failure has no result to validate, and a schema mismatch would hide
    the backend code behind RPC_RESULT_SCHEMA_MISMATCH. Every other shape keeps
    the existing validation rules, including successes; a missing, null, or non-boolean ``ok``; an explicit
    ``null`` result; any other result value, including ``[]``, ``""``, ``0``
    and ``False``; a missing or non-catalog code; and protected or special
    procedures with a dedicated closed result contract.
    """
    if has_dedicated_validation or ok is not False:
        return False
    if result_present and not (isinstance(raw_result, dict) and not raw_result):
        return False
    return _is_catalog_error_code(error_code)


@dataclasses.dataclass(frozen=True)
class _ResponseContract:
    """The validation contract that applies to one procedure's backend response."""

    is_staging_rotation: bool
    is_dns_staging_deploy: bool
    is_protected: bool
    is_gitea_upgrade: bool
    requires_envelope_state_match: bool

    @property
    def has_dedicated_validation(self) -> bool:
        return (
            self.is_gitea_upgrade
            or self.is_staging_rotation
            or self.is_dns_staging_deploy
            or self.requires_envelope_state_match
        )


@dataclasses.dataclass(frozen=True)
class _BackendOutcome:
    """The backend response fields that decide the terminal ledger event."""

    ok: bool
    result: dict[str, Any]
    has_nested_result: bool
    error_code: str
    error_message: str
    skip_result_validation: bool


def _response_contract(procedure_name: str) -> _ResponseContract:
    is_protected = procedure_name in PROTECTED_APPROVAL_PROCEDURE_NAMES
    # Protected procedures and the InfluxDB installers carry a closed oneOf
    # success envelope in their result_schema, which only constrains the nested
    # object. Requiring outer/nested agreement prevents an ok=true wrapper around
    # a failed operation from being recorded as success.
    requires_envelope_state_match = (
        is_protected
        or procedure_name in AKVORADO_BOOTSTRAP_DEBIAN13_PROCEDURE_NAMES
        or procedure_name in INFLUXDB3_DEBIAN13_PROCEDURE_NAMES
    )
    return _ResponseContract(
        is_staging_rotation=procedure_name == NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
        is_dns_staging_deploy=procedure_name == NETBOX_STAGING_DEPLOY_DNS_PAIR,
        is_protected=is_protected,
        is_gitea_upgrade=procedure_name == GITEA_PRODUCTION_UPGRADE_1_27_1,
        requires_envelope_state_match=requires_envelope_state_match,
    )


def _backend_failure_fields(
    response: dict[str, Any],
    raw_result: object,
    contract: _ResponseContract,
) -> tuple[str, str]:
    """Return the failure code and message. Gitea diagnostics come from its own catalog."""
    if contract.is_gitea_upgrade and isinstance(raw_result, dict):
        from .gitea_upgrade_contract import result_diagnostics

        return result_diagnostics(raw_result)
    return (
        str(response.get("error_code") or ""),
        str(response.get("error_message") or ""),
    )


def _dns_staging_response_mismatch(
    execution: RPCExecution,
    response: dict[str, Any],
    raw_result: object,
) -> str:
    schema_mismatch = _protected_backend_response_mismatch(response, raw_result)
    expected_commit = (
        execution.params.get("commit_sha") if isinstance(execution.params, dict) else None
    )
    if (
        not schema_mismatch
        and isinstance(raw_result, dict)
        and raw_result.get("commit_sha") != expected_commit
    ):
        return "Backend result schema mismatch at commit_sha."
    return schema_mismatch


def _envelope_response_mismatch(
    execution: RPCExecution,
    contract: _ResponseContract,
    response: dict[str, Any],
    raw_result: object,
) -> str:
    """Return the envelope mismatch that the procedure's closed contract requires, or ""."""
    if contract.is_gitea_upgrade:
        return _gitea_backend_response_mismatch(response, raw_result)
    if contract.is_staging_rotation:
        return _staging_backend_response_mismatch(response, raw_result)
    if contract.is_dns_staging_deploy:
        return _dns_staging_response_mismatch(execution, response, raw_result)
    if contract.requires_envelope_state_match:
        return _envelope_ok_state_mismatch(response, raw_result)
    return ""


def _response_schema_mismatch(
    execution: RPCExecution,
    contract: _ResponseContract,
    response: dict[str, Any],
    raw_result: object,
    result: dict[str, Any],
    string_limits: dict[StringLimitPath, int],
    should_validate: bool,
) -> str:
    """Return the first schema mismatch for the response, or an empty string.

    #215 round 3: validate the raw, untouched backend result -- not a
    length-clamped copy. A schema property only ends up in string_limits
    when its maxLength was deliberately widened above MAX_EVENT_STRING_LENGTH
    (see _collect_schema_string_limits) -- i.e. it was opted into holding
    large diagnostic content (a log tail, a config dump) specifically so it
    would NOT be silently truncated. Clamping the value *before* validating
    it (the round-2 approach) could hide a genuine pattern/enum/type
    violation that only appears in the truncated tail, and the persisted
    value (content + "...[truncated]") could itself exceed the schema's own
    maxLength -- a record marked ExecutionSucceeded storing a value that
    would fail the schema it was validated against. Instead,
    _backend_result_schema_mismatch() validates the complete raw value
    against a schema copy with maxLength removed only at these specific
    wide-override paths (_relax_schema_string_lengths) -- every other
    validator (pattern/enum/type/required/...) still runs at full fidelity
    against the untouched string, everywhere in the schema. The
    persisted/redacted `result` is separately clamped to fit its
    schema bound by _result_schema_string_limits() reserving room for the
    truncation marker, so what is validated and what is persisted can never
    disagree about whether a wide field is oversized.

    The second pass validates the redacted, truncated value against the
    unrelaxed schema, because the raw value passing the relaxed schema does not
    guarantee that the persisted value passes it. The truncation marker is not
    necessarily inside a field's pattern, so a truncated value can break a pattern
    that the raw value satisfied. Keep this pass.
    """
    schema_mismatch = _envelope_response_mismatch(execution, contract, response, raw_result)
    if not should_validate or schema_mismatch:
        return schema_mismatch
    schema_mismatch = _backend_result_schema_mismatch(
        execution,
        raw_result,
        string_limits=string_limits,
    )
    if schema_mismatch:
        return schema_mismatch
    return _backend_result_schema_mismatch(execution, result)


def _backend_progress_event(item: dict[str, Any]) -> domain_events.BackendEventRecorded:
    # The name is redacted and bounded in the same passes, so a secret that straddles
    # the bound cannot survive as its clear prefix.
    raw_name = str(item.get("event") or "BackendEventRecorded")
    name_limit = 100 - len(_BACKEND_EVENT_PREFIX)
    backend_name = _BACKEND_EVENT_PREFIX + _redact_bounded(
        raw_name, lambda text: text[:name_limit]
    )
    data = item.get("data")
    return domain_events.BackendEventRecorded(
        event_level=_event_level(item.get("level")),
        backend_event=backend_name,
        event_message=str(item.get("message") or ""),
        backend_data=data if isinstance(data, dict) else {},
    )


def _record_backend_progress_events(execution: RPCExecution, response: dict[str, Any]) -> None:
    raw_events = response.get("events") or []
    backend_events = raw_events[:MAX_BACKEND_EVENTS] if isinstance(raw_events, list) else []
    for item in backend_events:
        if isinstance(item, dict):
            _append_and_project(execution, _backend_progress_event(item))


def _record_backend_terminal_event(
    execution: RPCExecution,
    outcome: _BackendOutcome,
    schema_mismatch: str,
    finished_at: Any,
) -> None:
    if outcome.ok and not schema_mismatch:
        _append_and_project(
            execution,
            domain_events.ExecutionSucceeded(result=outcome.result, finished_at=finished_at),
        )
        return
    error_code, error_message = outcome.error_code, outcome.error_message
    if schema_mismatch:
        error_code, error_message = RESULT_SCHEMA_MISMATCH_CODE, schema_mismatch
    elif outcome.skip_result_validation:
        # Free text from this kind of failure is not retained. The catalog code
        # is the whole diagnostic.
        error_message = f"Backend reported {error_code}."
    keep_result = outcome.has_nested_result and not schema_mismatch
    _append_and_project(
        execution,
        domain_events.ExecutionFailed(
            error_message=_bounded_event_message(error_message) or "RPC execution failed.",
            code=error_code or "RPC_EXECUTION_FAILED",
            finished_at=finished_at,
            result=outcome.result if keep_result else {},
        ),
    )


def _ledger_result(
    result: dict[str, Any],
    string_limits: dict[StringLimitPath, int],
) -> dict[str, Any]:
    """Return ``result`` as the ledger stores it under an execution event.

    _append_and_project redacts the event data once, with the result's paths prefixed
    by "result". This is that same computation, so the value validated here is the
    value stored there. A second redaction is not a no-op for a secret-bearing name
    whose schema limit has moved to its placeholder, so the terminal event carries the
    raw result and is redacted exactly once.
    """
    prefixed = {("result", *path): limit for path, limit in string_limits.items()}
    return redact_event_data({"result": result}, string_limits=prefixed)["result"]


def record_backend_response(execution: RPCExecution, response: dict[str, Any]) -> None:
    procedure_name = str(getattr(getattr(execution, "procedure", None), "name", "") or "")
    contract = _response_contract(procedure_name)
    ok = bool(response.get("ok"))
    raw_result = response.get("result")
    string_limits = _result_schema_string_limits(execution)
    persisted_result = raw_result if isinstance(raw_result, dict) else {}
    ledger_result = _ledger_result(persisted_result, string_limits)
    error_code, error_message = _backend_failure_fields(response, raw_result, contract)
    result_is_present = "result" in response
    skip_result_validation = _skips_result_validation(
        ok=response.get("ok"),
        result_present=result_is_present,
        raw_result=raw_result,
        error_code=response.get("error_code"),
        has_dedicated_validation=contract.has_dedicated_validation,
    )
    should_validate = not skip_result_validation and (
        ok or result_is_present or contract.requires_envelope_state_match
    )
    schema_mismatch = _response_schema_mismatch(
        execution,
        contract,
        response,
        raw_result,
        ledger_result,
        string_limits,
        should_validate,
    )
    finished_at = timezone.now()
    outcome = _BackendOutcome(
        ok=ok,
        result=persisted_result,
        has_nested_result=isinstance(raw_result, dict),
        error_code=error_code,
        error_message=error_message,
        skip_result_validation=skip_result_validation,
    )
    with transaction.atomic():
        # The privileged staging rotation contract permits no backend events.
        # Its entire durable result surface is the closed five-field tuple;
        # accepting arbitrary progress events would create an unnecessary
        # secret-leak and database-amplification channel before the response
        # itself is accepted. Other procedures retain their existing event
        # behavior. A failure on the catalog-code path records no backend
        # progress events either: their free text can carry credentials, and
        # the catalog code is the whole diagnostic for that failure.
        if not contract.is_protected and not skip_result_validation:
            _record_backend_progress_events(execution, response)
        _record_backend_terminal_event(execution, outcome, schema_mismatch, finished_at)


def _envelope_ok_state_mismatch(
    response: dict[str, Any],
    raw_result: object,
) -> str:
    """Require the outer response ``ok`` and the nested ``result.ok`` to agree.

    The terminal event is derived from the OUTER ``ok``, and a procedure's
    ``result_schema`` can only constrain the nested object — so without this check
    a backend response of ``ok=true`` wrapping a nested ``ok=false`` result is
    schema-valid and still records ``ExecutionSucceeded``. For a privileged or
    approval-gated procedure that means a failed or partial run reported as a
    success, which an operator could act on. Both values must be strict booleans:
    a truthy non-boolean would otherwise pass ``bool()`` coercion silently.
    """

    if type(response.get("ok")) is not bool:
        return "Backend result schema mismatch at response.ok: boolean required."
    if "result" not in response:
        return "Backend result schema mismatch at result: required validation failed."
    if not isinstance(raw_result, dict):
        return "Backend result schema mismatch at result: object validation failed."
    nested_ok = raw_result.get("ok")
    if type(nested_ok) is not bool or nested_ok is not response["ok"]:
        return "Backend result schema mismatch at result.ok: envelope state mismatch."
    return ""


def _gitea_backend_response_mismatch(
    response: dict[str, Any],
    raw_result: object,
) -> str:
    """Require the diagnostic-free catalog projection of the Gitea envelope."""

    if set(response) != {"ok", "result"}:
        return "Backend result schema mismatch at response: unexpected property."
    return _protected_backend_response_mismatch(response, raw_result)


def _protected_backend_response_mismatch(
    response: dict[str, Any],
    raw_result: object,
) -> str:
    """Validate a closed protected envelope before persisting any content."""

    envelope_mismatch = _envelope_ok_state_mismatch(response, raw_result)
    if envelope_mismatch:
        return envelope_mismatch
    backend_events = response.get("events")
    if backend_events not in (None, []):
        return (
            "Backend result schema mismatch at events: protected events are forbidden."
        )
    return ""


def _staging_backend_response_mismatch(
    response: dict[str, Any],
    raw_result: object,
) -> str:
    """Validate the closed staging envelope before persisting any content."""

    return _protected_backend_response_mismatch(response, raw_result)


def _result_schema_string_limits(
    execution: RPCExecution,
) -> dict[StringLimitPath, int]:
    schema = getattr(getattr(execution, "procedure", None), "result_schema", None)
    if not isinstance(schema, dict):
        return {}
    limits: dict[StringLimitPath, int] = {}
    _collect_schema_string_limits(schema, path=(), limits=limits)
    # #215 round 3: reserve room for the "...[truncated]" marker
    # redact_event_value() appends to a clamped string, so the persisted
    # truncated value (content[:limit] + marker) never exceeds the schema's
    # own declared maxLength -- a record marked ExecutionSucceeded must never
    # store a value that would itself fail the schema it was validated
    # against. Scoped to these schema-derived wide overrides only; it does
    # not touch the MAX_EVENT_STRING_LENGTH default or any string_limits a
    # caller builds directly (e.g. the ParametersNormalized large-content
    # limits below).
    marker_length = len(_TRUNCATION_MARKER)
    return {path: max(limit - marker_length, 0) for path, limit in limits.items()}


def _collect_schema_string_limits(
    schema: dict[str, Any],
    *,
    path: StringLimitPath,
    limits: dict[StringLimitPath, int],
) -> None:
    max_length = schema.get("maxLength")
    if isinstance(max_length, int) and max_length > MAX_EVENT_STRING_LENGTH:
        limits[path] = max_length

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for key, child_schema in properties.items():
            if isinstance(child_schema, dict):
                _collect_schema_string_limits(
                    child_schema,
                    path=(*path, str(key)),
                    limits=limits,
                )

    items = schema.get("items")
    if isinstance(items, dict):
        _collect_schema_string_limits(
            items,
            path=(*path, "*"),
            limits=limits,
        )


def _strip_max_length_at_paths(
    schema: dict[str, Any],
    *,
    string_limits: dict[StringLimitPath, int],
    path: StringLimitPath,
) -> None:
    """Recursively pop ``maxLength`` from ``schema`` at paths in ``string_limits``.

    Mirrors ``_collect_schema_string_limits``'s own ``properties``/``items``
    traversal so the two stay in lockstep -- every path this function can
    reach is exactly the set of paths that function could have registered a
    wide override for. Mutates ``schema`` in place; callers must pass a copy.
    """
    if path in string_limits:
        schema.pop("maxLength", None)

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for key, child_schema in properties.items():
            if isinstance(child_schema, dict):
                _strip_max_length_at_paths(
                    child_schema,
                    string_limits=string_limits,
                    path=(*path, str(key)),
                )

    items = schema.get("items")
    if isinstance(items, dict):
        _strip_max_length_at_paths(
            items,
            string_limits=string_limits,
            path=(*path, "*"),
        )


def _relax_schema_string_lengths(
    schema: dict[str, Any],
    *,
    string_limits: dict[StringLimitPath, int],
) -> dict[str, Any]:
    """Return a deep copy of ``schema`` with ``maxLength`` removed at wide paths.

    Used so a backend result's complete, untouched value can be validated
    against every other validator (``pattern``/``enum``/``type``/``required``/
    ...) at full fidelity, without failing purely because a field that was
    deliberately widened above the default event-string limit (#215) is
    longer than its own declared ``maxLength`` -- the persisted/redacted copy
    is separately clamped to fit that same bound by
    ``_result_schema_string_limits``. Only paths present in ``string_limits``
    are touched; every other constraint in the schema is left byte-for-byte
    unchanged.
    """
    relaxed = copy.deepcopy(schema)
    _strip_max_length_at_paths(relaxed, string_limits=string_limits, path=())
    return relaxed


def _backend_result_schema_mismatch(
    execution: RPCExecution,
    raw_result: object,
    *,
    string_limits: dict[StringLimitPath, int] | None = None,
) -> str:
    schema = getattr(getattr(execution, "procedure", None), "result_schema", None)
    if not schema:
        return ""
    validation_schema = (
        _relax_schema_string_lengths(schema, string_limits=string_limits)
        if string_limits
        else schema
    )
    try:
        jsonschema.validate(raw_result, validation_schema)
    except (jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        path = ".".join(str(part)[:64] for part in exc.absolute_path)
        location = f"result.{path}" if path else "result"
        validator = str(getattr(exc, "validator", None) or "schema")[:64]
        message = (
            f"Backend result schema mismatch at {location}: "
            f"{validator} validation failed."
        )
        return message[:MAX_SCHEMA_MISMATCH_MESSAGE_LENGTH]
    return ""


def rebuild_projection(execution: RPCExecution) -> ProjectionState:
    events = (
        domain_events.from_record(record.event, record.data or {})
        for record in execution.events.all().order_by("sequence", "created")
    )
    return rebuild(events)


def reproject(execution: RPCExecution) -> ProjectionState:
    state = rebuild_projection(execution)
    with transaction.atomic():
        _write_projection(execution, state)
    return state
