from __future__ import annotations

import copy
import hashlib
import json
import re
from contextlib import nullcontext
from typing import Any

import jsonschema
from django.db import IntegrityError
from django.utils import timezone

from .constants import (
    GITEA_PRODUCTION_UPGRADE_1_27_1,
    INFLUXDB3_DEBIAN13_PROCEDURE_NAMES,
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
}
MAX_EVENT_STRING_LENGTH = 4096
MAX_EVENT_LIST_ITEMS = 50
MAX_EVENT_DICT_ITEMS = 100
MAX_BACKEND_EVENTS = 50
_BACKEND_EVENT_PREFIX = "Backend::"
# Keep in sync with the Akvorado and InfluxDB normalization-layer content limits.
_LARGE_NORMALIZED_CONTENT_FIELDS = ("config_content", "content")
_LARGE_NORMALIZED_CONTENT_LIMIT = 1024 * 1024
RESULT_SCHEMA_MISMATCH_CODE = "RPC_RESULT_SCHEMA_MISMATCH"
MAX_SCHEMA_MISMATCH_MESSAGE_LENGTH = 512
# Appended by redact_event_value() to any string it truncates. A single named
# constant so _result_schema_string_limits() (#215 round 3) can reserve
# exactly this much room out of a schema-declared maxLength, guaranteeing a
# persisted truncated value (content + marker) never exceeds its own schema
# bound.
_TRUNCATION_MARKER = "...[truncated]"
StringLimitPath = tuple[str, ...]
_SECRET_CONTENT_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?m:^([ \t]*)[\"']?[A-Za-z0-9_.-]*"
    r"(?:token|password|passphrase|secret|authorization|api[-_]?key|"
    r"access[-_]?key|private[-_]?key|credential)"
    r"[A-Za-z0-9_.-]*[\"']?\s*:\s*[|>]"
    r"(?:[1-9][+-]?|[+-][1-9]?)?[ \t]*(?:#[^\r\n]*)?"
    r"$(?:\n(?:\1[ \t].*|[ \t]*$))*)"
    r"|(?im:\b(?:authorization|bearer)\s*[:=]\s*[^\r\n]+?(?=\r?$))"
    r"|(?im:(?:^[ \t]*|[,{]\s*|-\s+)[\"']?[A-Za-z0-9_.-]*"
    r"(?:token|password|passphrase|secret|authorization|api[-_]?key|"
    r"access[-_]?key|private[-_]?key|credential)"
    r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?[^\s\"']+)"
    r"|(?i:\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@)"
)


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


def redact_event_value(
    value: object,
    *,
    parent_key: str = "",
    string_limits: dict[StringLimitPath, int] | None = None,
    path: StringLimitPath = (),
) -> object:
    if parent_key and _is_sensitive_key(parent_key):
        if _is_vaulted_secret_reference(value):
            return value
        return "[REDACTED]"
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        items = sorted(value.items(), key=lambda pair: str(pair[0]))
        for index, (key, item) in enumerate(items):
            if index >= MAX_EVENT_DICT_ITEMS:
                redacted["_truncated"] = True
                break
            key_text = str(key)
            redacted[key_text] = redact_event_value(
                item,
                parent_key=key_text,
                string_limits=string_limits,
                path=(*path, key_text),
            )
        return redacted
    if isinstance(value, list):
        items = [
            redact_event_value(
                item,
                parent_key=parent_key,
                string_limits=string_limits,
                path=(*path, "*"),
            )
            for item in value[:MAX_EVENT_LIST_ITEMS]
        ]
        if len(value) > MAX_EVENT_LIST_ITEMS:
            items.append(
                {"_truncated": True, "remaining": len(value) - MAX_EVENT_LIST_ITEMS}
            )
        return items
    if isinstance(value, str):
        limits = string_limits or {}
        max_length = limits.get(path, MAX_EVENT_STRING_LENGTH)
        value = _SECRET_CONTENT_RE.sub("[REDACTED]", value)
        if len(value) > max_length:
            return f"{value[:max_length]}{_TRUNCATION_MARKER}"
        return value
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)


def redact_event_data(
    data: dict[str, Any] | None,
    *,
    string_limits: dict[StringLimitPath, int] | None = None,
) -> dict[str, Any]:
    redacted = redact_event_value(data or {}, string_limits=string_limits)
    return redacted if isinstance(redacted, dict) else {}


def _bounded_event_message(message: object) -> str:
    """Redact and hard-cap an event message independently of event data."""
    redacted = _SECRET_CONTENT_RE.sub("[REDACTED]", str(message or ""))
    if len(redacted) <= MAX_EVENT_STRING_LENGTH:
        return redacted
    content_limit = max(MAX_EVENT_STRING_LENGTH - len(_TRUNCATION_MARKER), 0)
    return f"{redacted[:content_limit]}{_TRUNCATION_MARKER}"


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


def _append_and_project(
    execution: RPCExecution,
    event: domain_events.DomainEvent,
) -> RPCExecutionEvent:
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
        string_limits = {
            ("normalized_params", field_name): _LARGE_NORMALIZED_CONTENT_LIMIT
            for field_name in _LARGE_NORMALIZED_CONTENT_FIELDS
        }
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
        _append_and_project(
            execution,
            domain_events.ExecutionSucceeded(
                result=redact_event_data(
                    result,
                    string_limits=_result_schema_string_limits(execution),
                ),
                finished_at=finished_at,
            ),
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


def record_backend_response(execution: RPCExecution, response: dict[str, Any]) -> None:
    procedure_name = str(
        getattr(getattr(execution, "procedure", None), "name", "") or ""
    )
    is_staging_rotation = procedure_name == NETBOX_STAGING_ROTATE_BACKEND_TOKEN
    is_protected_procedure = procedure_name in PROTECTED_APPROVAL_PROCEDURE_NAMES
    is_gitea_upgrade = procedure_name == GITEA_PRODUCTION_UPGRADE_1_27_1
    # Protected procedures and the InfluxDB installers carry a closed oneOf
    # success envelope in their result_schema, which only constrains the nested
    # object. Requiring outer/nested agreement prevents an ok=true wrapper around
    # a failed operation from being recorded as success.
    requires_envelope_state_match = (
        is_protected_procedure or procedure_name in INFLUXDB3_DEBIAN13_PROCEDURE_NAMES
    )
    ok = bool(response.get("ok"))
    raw_result = response.get("result")
    string_limits = _result_schema_string_limits(execution)
    result = redact_event_data(
        raw_result if isinstance(raw_result, dict) else {},
        string_limits=string_limits,
    )
    if is_gitea_upgrade and isinstance(raw_result, dict):
        from .gitea_upgrade_contract import result_diagnostics

        error_code, error_message = result_diagnostics(raw_result)
    else:
        error_code = str(response.get("error_code") or "")
        error_message = str(response.get("error_message") or "")
    # #215 round 3: validate the raw, untouched backend result -- not a
    # length-clamped copy. A schema property only ends up in string_limits
    # when its maxLength was deliberately widened above MAX_EVENT_STRING_LENGTH
    # (see _collect_schema_string_limits) -- i.e. it was opted into holding
    # large diagnostic content (a log tail, a config dump) specifically so it
    # would NOT be silently truncated. Clamping the value *before* validating
    # it (the round-2 approach) could hide a genuine pattern/enum/type
    # violation that only appears in the truncated tail, and the persisted
    # value (content + "...[truncated]") could itself exceed the schema's own
    # maxLength -- a record marked ExecutionSucceeded storing a value that
    # would fail the schema it was validated against. Instead,
    # _backend_result_schema_mismatch() validates the complete raw value
    # against a schema copy with maxLength removed only at these specific
    # wide-override paths (_relax_schema_string_lengths) -- every other
    # validator (pattern/enum/type/required/...) still runs at full fidelity
    # against the untouched string, everywhere in the schema. The
    # persisted/redacted `result` above is separately clamped to fit its
    # schema bound by _result_schema_string_limits() reserving room for the
    # truncation marker, so what is validated and what is persisted can never
    # disagree about whether a wide field is oversized.
    has_nested_result = isinstance(raw_result, dict)
    result_is_present = "result" in response
    should_validate_result = ok or result_is_present or requires_envelope_state_match
    schema_mismatch = ""
    if is_gitea_upgrade:
        schema_mismatch = _gitea_backend_response_mismatch(response, raw_result)
    elif is_staging_rotation:
        schema_mismatch = _staging_backend_response_mismatch(response, raw_result)
    elif requires_envelope_state_match:
        schema_mismatch = _envelope_ok_state_mismatch(response, raw_result)
    if should_validate_result and not schema_mismatch:
        schema_mismatch = _backend_result_schema_mismatch(
            execution,
            raw_result,
            string_limits=string_limits,
        )
    if should_validate_result and not schema_mismatch:
        # #215 round 3 follow-up (adversarial review): the raw value passing
        # the relaxed schema does not guarantee the *persisted* value does.
        # redact_event_value() truncates any string longer than its limit by
        # appending "...[truncated]" -- for a field with a `pattern` (or other
        # non-length constraint) alongside its maxLength, a raw value that
        # satisfies `pattern` can stop satisfying it once the marker is
        # appended (e.g. pattern "^a+$" matches "aaaa...a" but not
        # "aaaa...a...[truncated]"). This applies to any string field that
        # gets truncated -- both the deliberately-widened paths in
        # string_limits AND any field truncated only by the
        # MAX_EVENT_STRING_LENGTH default -- not just the #215 wide-override
        # case. Re-validate the truncated/redacted `result` against the real,
        # unrelaxed schema: `_result_schema_string_limits()` already reserved
        # marker headroom so a truncated value never exceeds its own
        # maxLength, so this second pass only re-checks pattern/enum/type/...
        # against what will actually be stored. A record must never be marked
        # ExecutionSucceeded while storing data that fails the schema it
        # claims to satisfy.
        schema_mismatch = _backend_result_schema_mismatch(execution, result)
    finished_at = timezone.now()
    with transaction.atomic():
        # The privileged staging rotation contract permits no backend events.
        # Its entire durable result surface is the closed five-field tuple;
        # accepting arbitrary progress events would create an unnecessary
        # secret-leak and database-amplification channel before the response
        # itself is accepted. Other procedures retain their existing event
        # behavior.
        if not is_protected_procedure:
            raw_backend_events = response.get("events") or []
            backend_events = (
                raw_backend_events[:MAX_BACKEND_EVENTS]
                if isinstance(raw_backend_events, list)
                else []
            )
            for item in backend_events:
                if not isinstance(item, dict):
                    continue
                raw_backend_name = str(item.get("event") or "BackendEventRecorded")
                backend_name = (
                    _BACKEND_EVENT_PREFIX
                    + raw_backend_name[: 100 - len(_BACKEND_EVENT_PREFIX)]
                )
                _append_and_project(
                    execution,
                    domain_events.BackendEventRecorded(
                        event_level=str(item.get("level") or "info"),
                        backend_event=backend_name,
                        event_message=str(item.get("message") or ""),
                        backend_data=item.get("data")
                        if isinstance(item.get("data"), dict)
                        else {},
                    ),
                )
        if ok and not schema_mismatch:
            _append_and_project(
                execution,
                domain_events.ExecutionSucceeded(
                    result=result,
                    finished_at=finished_at,
                ),
            )
        else:
            if schema_mismatch:
                error_code = RESULT_SCHEMA_MISMATCH_CODE
                error_message = schema_mismatch
            _append_and_project(
                execution,
                domain_events.ExecutionFailed(
                    error_message=error_message or "RPC execution failed.",
                    code=error_code or "RPC_EXECUTION_FAILED",
                    finished_at=finished_at,
                    result=(
                        result if has_nested_result and not schema_mismatch else {}
                    ),
                ),
            )


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
