from __future__ import annotations

import hashlib
import json
from typing import Any

import jsonschema
from django.db import transaction
from rest_framework import serializers as drf_serializers
from rest_framework.exceptions import PermissionDenied

from ..backends import resolve_backend
from ..constants import (
    AKVORADO_1_PROCEDURE_NAMES,
    GITEA_PRODUCTION_UPGRADE_1_27_1,
    INFLUXDB3_DEBIAN13_PROCEDURE_NAMES,
    NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
    PROTECTED_APPROVAL_PROCEDURE_NAMES,
)
from ..domain.aggregate import RPCExecutionAggregate, RPCExecutionAggregateError
from ..domain.normalization import (
    RPCExecutionError,
    code_gate_unavailable_reason,
    normalize_execution_params,
    validate_gitea_upgrade_target,
    validate_akvorado_content_params,
)
from ..event_store import mark_execution_failed
from ..openbao_validation import (
    OpenBaoSecretIngressError,
    validate_openbao_params_for_persistence,
)
from .. import staging_rotation_contract as staging_contract
from .. import gitea_upgrade_contract as gitea_contract

# Handler IDs whose params_schema declares a "password" property (issue #160:
# service.samba.1.user_create / user_set_password). The raw password must
# never reach a persisted RPCExecution row: _scrub_password_param() replaces
# it with a sha256+byte-count fingerprint before serializer.save() writes the
# row, so params/normalized_params/result/events never contain the plaintext.
_PASSWORD_BEARING_HANDLER_IDS = frozenset(
    {
        "service.samba_1.user_create",
        "service.samba_1.user_set_password",
    }
)

# Procedure families whose SSH target is derived exclusively from the execution's
# assigned NetBox object, so the object must exist AND be viewable by the
# requester at admission time. Neither family accepts an rpc_ssh_* override, which
# is exactly why the assigned object has to be authorization-checked here.
_ASSIGNED_OBJECT_SCOPED_PROCEDURE_NAMES = frozenset(
    AKVORADO_1_PROCEDURE_NAMES | INFLUXDB3_DEBIAN13_PROCEDURE_NAMES
)
_OPENBAO_PROCEDURE_PREFIX = "service.openbao.1."

# #215: RPCExecutionJob.enqueue() used to fall back to a flat 600s RQ
# job_timeout for every procedure, regardless of the dispatched procedure's
# own timeout_seconds. A procedure whose backend call can legitimately run
# longer than 600s (e.g. qemu_vm_lifecycle at 3600s, or the Ubuntu 24->26
# run_upgrade at 7200s) would have its RQ worker killed mid-run, stranding
# the execution in RUNNING forever with no automatic reconciliation. The RQ
# job_timeout must always exceed the _call_backend() HTTP read timeout
# (max(timeout_seconds + 10, 30), see jobs.py) or the worker gets killed
# before the HTTP call it is blocked on can even return cleanly.
_RPC_JOB_TIMEOUT_HEADROOM_SECONDS = 60
_RPC_JOB_TIMEOUT_FLOOR_SECONDS = 600

_STAGING_ROTATION_CREATE_FIELDS = frozenset(
    {"procedure_id", "assigned_object_type", "assigned_object_id", "params"}
)
_STAGING_ROTATION_APPROVAL_REASON = (
    "Approved audited staging backend token rotation."
)
_STAGING_ROTATION_REJECTION_REASON = (
    "Rejected audited staging backend token rotation."
)
_GITEA_UPGRADE_APPROVAL_REASON = (
    "Approved audited production Gitea 1.27.1 upgrade."
)
_GITEA_UPGRADE_REJECTION_REASON = (
    "Rejected audited production Gitea 1.27.1 upgrade."
)

_PROTECTED_APPROVAL_REASON = {
    NETBOX_STAGING_ROTATE_BACKEND_TOKEN: _STAGING_ROTATION_APPROVAL_REASON,
    GITEA_PRODUCTION_UPGRADE_1_27_1: _GITEA_UPGRADE_APPROVAL_REASON,
}
_PROTECTED_REJECTION_REASON = {
    NETBOX_STAGING_ROTATE_BACKEND_TOKEN: _STAGING_ROTATION_REJECTION_REASON,
    GITEA_PRODUCTION_UPGRADE_1_27_1: _GITEA_UPGRADE_REJECTION_REASON,
}


def _protected_contract(procedure_name: str):
    if procedure_name == NETBOX_STAGING_ROTATE_BACKEND_TOKEN:
        return staging_contract
    if procedure_name == GITEA_PRODUCTION_UPGRADE_1_27_1:
        return gitea_contract
    raise ValueError(f"{procedure_name!r} is not a protected approval procedure")


def _protected_label(procedure_name: str) -> str:
    if procedure_name == NETBOX_STAGING_ROTATE_BACKEND_TOKEN:
        return "Staging token rotation"
    if procedure_name == GITEA_PRODUCTION_UPGRADE_1_27_1:
        return "Production Gitea upgrade"
    return "Protected RPC procedure"


def _execution_job_timeout(timeout_seconds: object) -> int:
    """Derive the RQ ``job_timeout`` from a frozen ``timeout_seconds`` value.

    Scales with the procedure's ``timeout_seconds`` (plus headroom over the
    _call_backend() HTTP timeout) instead of a flat constant, while keeping
    the historical 600s floor for short procedures so existing behavior is
    unchanged for anything that was already comfortably within it.

    Takes the raw seconds value, not a procedure object: the caller must pass
    the SAME frozen value it also stamps into
    ``RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY`` (see
    create_execution()), so this RQ deadline and jobs._call_backend()'s later
    HTTP timeout are always derived from one immutable number and can never
    diverge if an operator edits procedure.timeout_seconds while the
    execution sits queued.
    """
    return max(
        int(timeout_seconds or 0) + _RPC_JOB_TIMEOUT_HEADROOM_SECONDS,
        _RPC_JOB_TIMEOUT_FLOOR_SECONDS,
    )


def _scrub_password_param(params: dict[str, Any]) -> None:
    """Replace an in-place ``password`` param with a non-reversible fingerprint.

    Mutates ``params`` (the same dict object DRF will persist via
    ``serializer.save()``) so the raw password value is never written to the
    database, not even transiently. Downstream normalization only ever sees
    ``password_sha256`` / ``password_bytes``.
    """
    if "password" not in params:
        return
    raw_password = params.pop("password")
    password_bytes = str(raw_password).encode("utf-8")
    params["password_sha256"] = hashlib.sha256(password_bytes).hexdigest()
    params["password_bytes"] = len(password_bytes)


def _require_enabled_and_authoritative_backend(user: object) -> object | None:
    """Enforce the authoritative RPC opt-in + selected backend (issue #166).

    The ``RpcPluginSettings`` singleton is the authority for both the opt-in
    gate and the selected backend at command-creation time. Rejects new work
    when the integration is disabled or no backend is resolvable, and returns
    the authoritative backend id (``None`` = defer to the settings resolver
    chain) that the requester's ``backend_id`` must NOT override.
    """
    from ..models import RpcPluginSettings

    settings_row = RpcPluginSettings.get_solo()
    if not settings_row.enabled:
        raise PermissionDenied(
            "The netbox-rpc integration is disabled. Enable it in RPC settings "
            "before creating executions."
        )
    if settings_row.resolved_backend_target() is None:
        raise drf_serializers.ValidationError(
            {
                "backend": (
                    "No RPC backend is configured. Select a backend in RPC "
                    "settings before creating executions."
                )
            }
        )
    return settings_row.backend_id


def _require_concrete_staging_backend_id(backend_id: object) -> int:
    """Require one immutable backend row for approval and worker dispatch."""

    return _require_concrete_protected_backend_id(
        backend_id,
        NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
    )


def _require_concrete_protected_backend_id(
    backend_id: object,
    procedure_name: str,
) -> int:
    """Require one immutable backend row for a protected approval flow."""

    try:
        concrete_backend_id = int(backend_id)
    except (TypeError, ValueError) as exc:
        raise drf_serializers.ValidationError(
            {
                "backend": (
                    f"{_protected_label(procedure_name)} requires an explicitly selected "
                    "authoritative RPC backend."
                )
            }
        ) from exc
    if concrete_backend_id <= 0:
        raise drf_serializers.ValidationError(
            {
                "backend": (
                    f"{_protected_label(procedure_name)} requires an explicitly selected "
                    "authoritative RPC backend."
                )
            }
        )
    contract = _protected_contract(procedure_name)
    expected_backend_id = getattr(contract, "BACKEND_ID", None)
    if (
        expected_backend_id is not None
        and concrete_backend_id != expected_backend_id
    ):
        raise drf_serializers.ValidationError(
            {
                "backend": (
                    f"{_protected_label(procedure_name)} requires authoritative "
                    f"RPC backend {expected_backend_id}."
                )
            }
        )
    return concrete_backend_id


def _verify_backend_capability(
    procedure: object,
    *,
    backend_target: object | None = None,
    use_cache: bool = True,
) -> None:
    """Fail closed before enqueue on a backend capability mismatch (issue #167).

    Fetches the selected backend's capability manifest and verifies the
    procedure's handler/version/effect/contract-hash/envelope against it. A
    ``MISMATCH`` (advertised but incompatible) is rejected (400). Legacy
    procedures retain graceful ``UNKNOWN`` handling; the production Gitea
    upgrade requires an explicit compatible manifest at admission and claim.
    """
    from .. import capabilities
    from ..models import RpcPluginSettings

    target = backend_target or RpcPluginSettings.get_solo().resolved_backend_target()
    manifest = capabilities.fetch_backend_capabilities(target, use_cache=use_cache)
    status = capabilities.verify_procedure_capability(procedure, manifest)
    requires_explicit_capability = (
        getattr(procedure, "name", "") == GITEA_PRODUCTION_UPGRADE_1_27_1
    )
    if status is capabilities.CapabilityStatus.MISMATCH or (
        requires_explicit_capability
        and status is not capabilities.CapabilityStatus.COMPATIBLE
    ):
        raise drf_serializers.ValidationError(
            {
                "procedure_id": (
                    "The selected backend does not advertise a compatible "
                    "capability for this procedure (handler/version/effect/"
                    "contract mismatch)."
                )
            }
        )


def _resolve_validated_protected_backend_target(
    backend_id: object,
    procedure_name: str,
    *,
    backend_target: object | None = None,
) -> object:
    """Resolve and validate one protected target before authenticated I/O.

    Capability discovery and dispatch both carry the backend authentication
    token.  A mutable backend row must therefore match the immutable reviewed
    URL/TLS binding before either operation can use it.  Returning the same
    object lets admission, approval, lease validation, and dispatch avoid a
    second resolver read and its associated time-of-check/time-of-use gap.
    """

    concrete_backend_id = _require_concrete_protected_backend_id(
        backend_id,
        procedure_name,
    )
    target = backend_target or resolve_backend(concrete_backend_id)
    _protected_backend_target_sha256(
        concrete_backend_id,
        procedure_name=procedure_name,
        backend_target=target,
    )
    return target


def create_execution(
    *,
    serializer: Any,
    user: object,
    source_intent: object | None = None,
) -> object:
    if not user.has_perm("netbox_rpc.execute_rpcprocedure"):
        raise PermissionDenied("execute_rpcprocedure permission is required.")
    serializer.is_valid(raise_exception=True)

    # #166: opt-in + selected backend are authoritative at creation time.
    authoritative_backend_id = _require_enabled_and_authoritative_backend(user)

    procedure = serializer.validated_data["procedure"]
    if not procedure.enabled:
        raise drf_serializers.ValidationError(
            {"procedure_id": "This procedure is disabled."}
        )
    # Hard-coded fail-closed gates (see code_gate_unavailable_reason) sit
    # below RPCProcedure.enabled: an operator could flip that mutable flag
    # without knowing a gate is still closed, so this admission-time check
    # is the primary enforcement point, checked before an RPCExecution row
    # can even be created. The identical check inside normalize_execution_params
    # remains as defense in depth for a worker claiming a pre-existing row.
    gate_reason = code_gate_unavailable_reason(procedure.name)
    if gate_reason is not None:
        raise drf_serializers.ValidationError({"procedure_id": gate_reason})
    protected_backend_target: object | None = None
    if procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
        authoritative_backend_id = _require_concrete_protected_backend_id(
            authoritative_backend_id,
            procedure.name,
        )
        _require_protected_procedure_policy(procedure)
        _require_protected_procedure_scope(procedure, user, "execute")
        _require_protected_creation_shape(serializer, procedure.name)
        protected_backend_target = _resolve_validated_protected_backend_target(
            authoritative_backend_id,
            procedure.name,
        )
    elif procedure.approval_required:
        if not user.has_perm("netbox_rpc.approve_rpcprocedure"):
            raise PermissionDenied(
                "This procedure requires approval (approve_rpcprocedure permission)."
            )
    params = serializer.validated_data.get("params") or {}
    # #215 round 3: ``.get("params") or {}`` builds a brand-new, unlinked dict
    # when the caller's original ``params`` was falsy (``None``/``{}`` --
    # common for procedures with no/optional params). Re-assign it back onto
    # ``validated_data`` immediately so every later in-place mutation of this
    # local ``params`` (the password scrub below, the timeout-snapshot stamp
    # further down) is guaranteed visible to ``serializer.save()`` regardless
    # of whether the original value was falsy -- this same gap silently
    # existed in ``_scrub_password_param()`` already, currently masked only
    # because both password-bearing handlers require "password", so their
    # params is never falsy in practice.
    serializer.validated_data["params"] = params
    if procedure.params_schema:
        try:
            jsonschema.validate(params, procedure.params_schema)
        except jsonschema.ValidationError as exc:
            raise drf_serializers.ValidationError({"params": exc.message}) from exc

    # Reject caller-supplied OpenBao secret material before target lookups or
    # capability work. A second scan immediately before persistence below
    # covers the complete payload after platform-owned stamps.
    try:
        validate_openbao_params_for_persistence(procedure.name, params)
    except OpenBaoSecretIngressError as exc:
        raise drf_serializers.ValidationError({"params": str(exc)}) from exc

    _require_viewable_assigned_object(serializer.validated_data, procedure, user)
    _require_staging_rotation_assigned_object(
        serializer.validated_data,
        procedure,
        user,
    )
    _require_gitea_upgrade_assigned_object(
        serializer.validated_data,
        procedure,
        user,
    )
    try:
        validate_akvorado_content_params(procedure.name, params)
    except RPCExecutionError as exc:
        raise drf_serializers.ValidationError({"params": str(exc)}) from exc

    # #160: scrub a raw password to a fingerprint AFTER schema validation (so
    # the caller-visible validation error still names "password") and BEFORE
    # anything is persisted, so the plaintext value is never written to the
    # database even transiently.
    if procedure.handler_id in _PASSWORD_BEARING_HANDLER_IDS:
        _scrub_password_param(params)

    # #167: fail closed before enqueue on a backend capability mismatch.
    _verify_backend_capability(
        procedure,
        backend_target=protected_backend_target,
    )

    # #215 round 3: stamp the procedure's timeout_seconds onto `params`
    # BEFORE serializer.save(), not via a second post-save write. The
    # original #215 fix wrote this snapshot with a *second*, unguarded
    # `execution.save(update_fields=["params"])` call sitting outside both
    # this transaction and the RQ-enqueue try/except below -- a failure in
    # that second write (a DB hiccup, a signal handler, anything) orphaned an
    # already-committed `queued` execution with no job and no failure event.
    # Folding the stamp into the SAME `params` dict serializer.save() persists
    # means either the whole execution + snapshot commits together in this one
    # atomic block, or nothing does -- mirrors how _scrub_password_param()
    # already mutates `params` in place before save. Stamped after
    # params_schema validation above, so a schema declaring
    # additionalProperties: false never rejects the injected key.
    # ``source_intent`` attribution is a separate model relation and never
    # enters this schema-governed payload.
    # RPCExecutionJob.enqueue() below and jobs._call_backend() at dispatch
    # time both read this SAME frozen value, so a later edit to
    # procedure.timeout_seconds while this execution sits queued can never let
    # the RQ deadline and the backend HTTP timeout diverge.
    from ..models import RPCExecution

    timeout_seconds_snapshot = procedure.timeout_seconds
    params[RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY] = timeout_seconds_snapshot

    # Scan the COMPLETE final object immediately before the atomic insert,
    # after every platform-owned params mutation. RPCExecution.save() repeats
    # this family-scoped check at the ORM boundary so script/job-created rows
    # cannot bypass it. The intent relation is persisted separately below.
    try:
        validate_openbao_params_for_persistence(procedure.name, params)
    except OpenBaoSecretIngressError as exc:
        raise drf_serializers.ValidationError({"params": str(exc)}) from exc

    with transaction.atomic():
        # #166: a normal requester cannot select an arbitrary backend — the
        # authoritative selected backend from RPC settings always wins over any
        # client-supplied ``backend_id``.
        execution = serializer.save(
            requested_by=user,
            backend=authoritative_backend_id,
            source_intent=source_intent,
        )
        aggregate = RPCExecutionAggregate(execution)
        if procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
            try:
                normalized = normalize_execution_params(execution)
            except RPCExecutionError as exc:
                raise drf_serializers.ValidationError({"params": str(exc)}) from exc
            aggregate.request(requested_by_id=user.pk)
            approval_request = _create_approval_request(
                execution,
                normalized,
                backend_target=protected_backend_target,
            )
            aggregate.request_approval(
                snapshot_hash=approval_request.payload_hash,
                requested_by_id=user.pk,
            )
        else:
            aggregate.queue()

    if procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
        return execution

    _enqueue_execution_job(
        execution,
        user=user,
        timeout_seconds_snapshot=timeout_seconds_snapshot,
    )
    return execution


def _enqueue_execution_job(
    execution: object,
    *,
    user: object,
    timeout_seconds_snapshot: object,
) -> None:
    """Enqueue one already-queued execution and audit the resulting job id."""

    try:
        from ..jobs import RPCExecutionJob

        job = RPCExecutionJob.enqueue(
            user=user,
            name=f"RPC Execution: {execution.procedure.name}",
            backend_pk=execution.backend_id,
            execution_pk=execution.pk,
            job_timeout=_execution_job_timeout(timeout_seconds_snapshot),
        )
    except Exception:
        mark_execution_failed(
            execution,
            "Failed to enqueue RPC job. Check RQ/Redis connectivity.",
            "RPC_ENQUEUE_FAILED",
            event_name="ExecutionEnqueueFailed",
        )
        raise

    RPCExecutionAggregate(execution).enqueue(job.pk)


def _hash_approval_value(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _approval_protected_payload(
    execution: object,
    normalized: dict[str, Any],
    *,
    backend_target: object | None = None,
) -> dict[str, object]:
    """Build an immutable, non-secret protected approval decision surface."""
    procedure = execution.procedure
    contract = _protected_contract(procedure.name)
    fingerprint = normalized.get("command_fingerprint")
    target_snapshot = {
        "target_type_id": execution.assigned_object_type_id,
        "target_id": execution.assigned_object_id,
        "target_model_label": execution.target_model_label,
        "target_display": execution.target_display,
    }
    return {
        "procedure_id": procedure.pk,
        "procedure_version": str(procedure.version),
        "procedure_policy_sha256": contract.canonical_sha256(
            _protected_procedure_policy(procedure)
        ),
        "params_schema_sha256": contract.canonical_sha256(
            procedure.params_schema
        ),
        "result_schema_sha256": contract.canonical_sha256(
            procedure.result_schema
        ),
        "effect": procedure.effect,
        "target_type_id": execution.assigned_object_type_id,
        "target_id": execution.assigned_object_id,
        "target_snapshot_hash": _hash_approval_value(target_snapshot),
        "normalized_params": normalized,
        "command_fingerprint": (
            dict(fingerprint) if isinstance(fingerprint, dict) else {}
        ),
        "backend_id": execution.backend_id,
        "backend_target_sha256": _protected_backend_target_sha256(
            execution.backend_id,
            procedure_name=procedure.name,
            backend_target=backend_target,
        ),
        "credential_policy_ref": _credential_policy_reference(normalized, execution),
        "requested_by_id": execution.requested_by_id,
    }


def _create_approval_request(
    execution: object,
    normalized: dict[str, Any],
    *,
    backend_target: object | None = None,
) -> object:
    """Persist a protected snapshot after ExecutionRequested is recorded."""
    from ..models import RPCApprovalRequest

    return RPCApprovalRequest.objects.create(
        execution=execution,
        stream_version=_current_stream_version(execution),
        **_approval_protected_payload(
            execution,
            normalized,
            backend_target=backend_target,
        ),
    )


def _require_viewable_assigned_object(
    validated_data: dict[str, Any],
    procedure: object,
    user: object,
) -> None:
    """Fail creation when the target is absent or not viewable by the requester.

    RPCExecution stores a GenericForeignKey, so a syntactically valid content
    type + object ID can otherwise point at no object. Applies to every procedure
    family whose SSH targeting is derived *exclusively* from the assigned object:
    such a procedure must never bypass NetBox object restrictions or fall back to
    a dangling display value. The requester chooses ``assigned_object_id``, so
    without this the requester could aim a privileged run at a device or VM they
    cannot even view — which matters most for the approval-gated Debian 13
    InfluxDB 3 Core installer.
    """

    procedure_name = getattr(procedure, "name", "")
    if (
        procedure_name not in _ASSIGNED_OBJECT_SCOPED_PROCEDURE_NAMES
        and not procedure_name.startswith(_OPENBAO_PROCEDURE_PREFIX)
    ):
        return
    content_type = validated_data.get("assigned_object_type")
    object_id = validated_data.get("assigned_object_id")
    if content_type is None or object_id is None:
        raise drf_serializers.ValidationError(
            {"assigned_object_id": "An assigned NetBox object is required."},
            code="required",
        )
    try:
        model_class = content_type.model_class()
        assigned_object = (
            model_class.objects.restrict(user, "view").filter(pk=object_id).first()
        )
    except (AttributeError, TypeError, ValueError):
        assigned_object = None
    if assigned_object is None:
        raise drf_serializers.ValidationError(
            {"assigned_object_id": "The assigned NetBox object does not exist."},
            code="does_not_exist",
        )


def _require_staging_rotation_assigned_object(
    validated_data: dict[str, Any],
    procedure: object,
    user: object,
) -> None:
    """Pin token rotation to the existing, viewable nms-front-door device."""
    if getattr(procedure, "name", "") != NETBOX_STAGING_ROTATE_BACKEND_TOKEN:
        return
    content_type = validated_data.get("assigned_object_type")
    object_id = validated_data.get("assigned_object_id")
    if (
        content_type is None
        or object_id is None
        or getattr(content_type, "app_label", "") != "dcim"
        or getattr(content_type, "model", "") != "device"
    ):
        raise drf_serializers.ValidationError(
            {"assigned_object_id": "The nms-front-door device is required."},
            code="required",
        )
    try:
        model_class = content_type.model_class()
        assigned_object = (
            model_class.objects.restrict(user, "view").filter(pk=object_id).first()
        )
    except (AttributeError, TypeError, ValueError):
        assigned_object = None
    if (
        assigned_object is None
        or getattr(assigned_object, "name", "") != "nms-front-door"
    ):
        raise drf_serializers.ValidationError(
            {"assigned_object_id": "The nms-front-door device does not exist."},
            code="does_not_exist",
        )


def _require_gitea_upgrade_assigned_object(
    validated_data: dict[str, Any],
    procedure: object,
    user: object,
) -> None:
    """Pin the upgrade to the exact existing, viewable production Gitea VM."""
    if getattr(procedure, "name", "") != GITEA_PRODUCTION_UPGRADE_1_27_1:
        return
    content_type = validated_data.get("assigned_object_type")
    object_id = validated_data.get("assigned_object_id")
    type_label = (
        f"{getattr(content_type, 'app_label', '')}."
        f"{getattr(content_type, 'model', '')}"
    )
    if type_label != "virtualization.virtualmachine" or object_id != 170:
        raise drf_serializers.ValidationError(
            {"assigned_object_id": "Production Gitea VM PK 170 is required."},
            code="required",
        )
    try:
        model_class = content_type.model_class()
        assigned_object = (
            model_class.objects.restrict(user, "view").filter(pk=object_id).first()
        )
    except (AttributeError, TypeError, ValueError):
        assigned_object = None
    try:
        validate_gitea_upgrade_target(
            assigned_object,
            target_model_label=type_label,
            assigned_object_id=object_id,
            target_display=getattr(assigned_object, "name", None),
        )
    except RPCExecutionError as exc:
        raise drf_serializers.ValidationError(
            {"assigned_object_id": str(exc)},
            code="does_not_exist",
        ) from exc


def _require_staging_rotation_procedure_policy(procedure: object) -> None:
    """Fail closed if mutable catalog policy weakens staging rotation."""
    _require_protected_procedure_policy(
        procedure,
        expected_name=NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
    )


def _require_protected_procedure_policy(
    procedure: object,
    *,
    expected_name: str | None = None,
) -> None:
    """Fail closed if mutable catalog policy weakens a protected procedure."""
    procedure_name = str(getattr(procedure, "name", "") or "")
    contract_name = expected_name or procedure_name
    contract = _protected_contract(contract_name)
    actual_policy = _protected_procedure_policy(
        procedure,
        contract_name=contract_name,
    )
    if (
        actual_policy != contract.PROCEDURE_POLICY
        or getattr(procedure, "params_schema", None)
        != contract.PARAMS_SCHEMA
        or getattr(procedure, "result_schema", None)
        != contract.RESULT_SCHEMA
    ):
        raise drf_serializers.ValidationError(
            {
                "procedure_id": (
                    f"{_protected_label(procedure_name)} catalog policy does not match the "
                    "immutable reviewed contract."
                )
            }
        )


def _staging_rotation_procedure_policy(procedure: object) -> dict[str, object]:
    return _protected_procedure_policy(procedure)


def _protected_procedure_policy(
    procedure: object,
    *,
    contract_name: str | None = None,
) -> dict[str, object]:
    contract = _protected_contract(
        contract_name or str(getattr(procedure, "name", "") or "")
    )
    command_contract = []
    commands = getattr(procedure, "commands", None)
    if commands is not None:
        command_contract = [
            {
                "sequence": command.sequence,
                "step_type": command.step_type,
                "device_cli_mode": command.device_cli_mode,
                "argv": command.argv,
                "description": command.description,
                "condition_param": command.condition_param,
                "condition_negate": command.condition_negate,
                "for_each_param": command.for_each_param,
                "continue_on_error": command.continue_on_error,
                "render_mode": command.render_mode,
                "produces_var": command.produces_var,
                "capture_kind": command.capture_kind,
                "capture_expression": command.capture_expression,
            }
            for command in commands.all().order_by("sequence")
        ]
    policy = {
        "name": getattr(procedure, "name", None),
        "handler_id": getattr(procedure, "handler_id", None),
        "version": getattr(procedure, "version", None),
        "enabled": getattr(procedure, "enabled", None),
        "target_models": getattr(procedure, "target_models", None),
        "effect": getattr(procedure, "effect", None),
        "timeout_seconds": getattr(procedure, "timeout_seconds", None),
        "approval_required": getattr(procedure, "approval_required", None),
        "transport_driver": getattr(procedure, "transport_driver", None),
        "transport_driver_chain": getattr(
            procedure, "transport_driver_chain", None
        ),
        "output_parser": getattr(procedure, "output_parser", None),
        "output_schema": getattr(procedure, "output_schema", None),
        "command_contract_sha256": contract.canonical_sha256(
            command_contract
        ),
    }
    semantic_contract_sha256 = getattr(
        contract,
        "SEMANTIC_CAPABILITY_SHA256",
        None,
    )
    if semantic_contract_sha256 is not None:
        policy["semantic_contract_sha256"] = semantic_contract_sha256
    return policy


def _staging_backend_target_sha256(
    backend_id: object,
    *,
    backend_target: object | None = None,
) -> str:
    return _protected_backend_target_sha256(
        backend_id,
        procedure_name=NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
        backend_target=backend_target,
    )


def _protected_backend_target_sha256(
    backend_id: object,
    *,
    procedure_name: str,
    backend_target: object | None = None,
) -> str:
    contract = _protected_contract(procedure_name)
    concrete_backend_id = _require_concrete_protected_backend_id(
        backend_id,
        procedure_name,
    )
    target = backend_target or resolve_backend(concrete_backend_id)
    if target is None:
        raise drf_serializers.ValidationError(
            {
                "backend": (
                    f"{_protected_label(procedure_name)} authoritative backend is unavailable."
                )
            }
        )
    expected_backend_url = getattr(contract, "BACKEND_BASE_URL", None)
    expected_verify_ssl = getattr(contract, "BACKEND_VERIFY_SSL", None)
    if expected_backend_url is not None and (
        str(getattr(target, "url", "") or "") != expected_backend_url
        or bool(getattr(target, "verify_ssl", False)) is not expected_verify_ssl
    ):
        raise drf_serializers.ValidationError(
            {
                "backend": (
                    f"{_protected_label(procedure_name)} authoritative backend "
                    "URL/TLS policy does not match the immutable reviewed contract."
                )
            }
        )
    return contract.canonical_sha256(
        {
            "backend_id": concrete_backend_id,
            "url": str(getattr(target, "url", "") or ""),
            "verify_ssl": bool(getattr(target, "verify_ssl", False)),
        }
    )


def _require_staging_rotation_creation_shape(serializer: object) -> None:
    """Reject all caller metadata outside the exact secret-silent request."""
    _require_protected_creation_shape(
        serializer,
        NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
    )


def _require_protected_creation_shape(
    serializer: object,
    procedure_name: str,
) -> None:
    """Reject caller metadata outside an exact protected request."""
    initial_data = getattr(serializer, "initial_data", {})
    supplied_fields = set(initial_data.keys()) if hasattr(initial_data, "keys") else set()
    unexpected = sorted(supplied_fields - _STAGING_ROTATION_CREATE_FIELDS)
    if unexpected:
        raise drf_serializers.ValidationError(
            {
                "non_field_errors": (
                    f"{_protected_label(procedure_name)} accepts only procedure_id, assigned "
                    "object, and empty params; request metadata is forbidden."
                )
            }
        )


def _require_staging_rotation_procedure_scope(
    procedure: object,
    user: object,
    action: str,
) -> None:
    """Preserve concrete-procedure constraints for this destructive command."""
    _require_protected_procedure_scope(procedure, user, action)


def _require_protected_procedure_scope(
    procedure: object,
    user: object,
    action: str,
) -> None:
    """Preserve concrete-procedure constraints for protected commands."""
    from ..models import RPCProcedure

    if not RPCProcedure.objects.restrict(user, action).filter(pk=procedure.pk).exists():
        raise PermissionDenied(
            f"Object-scoped {action}_rpcprocedure permission is required for "
            f"{_protected_label(getattr(procedure, 'name', ''))}."
        )


def _transition_locked(execution: object, transition) -> object:
    """Run a status-guarded transition while holding a row lock on the execution.

    Concurrent QUEUED transitions (e.g. an API cancel racing the RQ worker's
    start) would otherwise both read ``status == "queued"`` and each append an
    event, producing an inconsistent stream. Re-fetching the row with
    ``select_for_update`` inside the transaction serializes them: the first
    writer commits its terminal/running transition, and the second re-reads the
    new status and is cleanly rejected by the aggregate invariant.
    """
    from django.db import transaction

    from ..models import RPCExecution

    with transaction.atomic():
        locked = RPCExecution.objects.select_for_update().get(pk=execution.pk)
        transition(RPCExecutionAggregate(locked))
        return locked


def _claim_if_procedure_enabled(agg: RPCExecutionAggregate) -> None:
    """Atomically claim queued work only while its procedure remains enabled."""

    from ..models import RPCExecution, RPCProcedure

    execution = agg.execution
    if agg.status != RPCExecution.STATUS_QUEUED:
        raise RPCExecutionAggregateError(
            "Only a queued execution can be claimed by a worker."
        )
    procedure = RPCProcedure.objects.select_for_update().get(pk=execution.procedure_id)
    if not procedure.enabled:
        agg.fail(
            "The RPC procedure for this execution has been disabled; "
            "execution not dispatched.",
            "RPC_PROCEDURE_DISABLED",
        )
        return
    if procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
        try:
            _require_protected_procedure_policy(procedure)
        except drf_serializers.ValidationError:
            agg.fail(
                f"{_protected_label(procedure.name)} catalog policy changed after approval.",
                "RPC_APPROVAL_INVALIDATED",
            )
            return
        requested_by_id = getattr(execution, "requested_by_id", None)
        approved_by_id = getattr(execution, "approved_by_id", None)
        if (
            requested_by_id is None
            or approved_by_id is None
            or str(requested_by_id) == str(approved_by_id)
        ):
            agg.fail(
                f"{_protected_label(procedure.name)} requires a destructive, approval-required "
                "procedure and distinct requester/approver identities.",
                "RPC_APPROVAL_REQUIRED",
            )
            return
    agg.start()


def run_execution(execution: object, *, backend_pk: object | None = None) -> None:
    # #166: the opt-in is authoritative at the worker claim too — a claim on a
    # disabled integration must fail closed rather than dispatch.
    from ..models import RpcPluginSettings

    if not RpcPluginSettings.get_solo().enabled:
        try:
            RPCExecutionAggregate(execution).fail(
                "The netbox-rpc integration is disabled; execution not dispatched.",
                "RPC_INTEGRATION_DISABLED",
            )
        except RPCExecutionAggregateError:
            pass
        return

    try:
        execution = _transition_locked(execution, _claim_if_procedure_enabled)
    except RPCExecutionAggregateError:
        # Lost the race to a cancel (or already terminal): nothing to run.
        return
    if execution.status != execution.STATUS_RUNNING:
        # The locked claim failed closed because the procedure was disabled.
        return
    aggregate = RPCExecutionAggregate(execution)

    if execution.procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
        try:
            bound_backend_id = _require_concrete_protected_backend_id(
                execution.backend_id,
                execution.procedure.name,
            )
            if (
                backend_pk is not None
                and int(backend_pk) != bound_backend_id
            ):
                raise ValueError("worker backend does not match approval binding")
        except (TypeError, ValueError, drf_serializers.ValidationError) as exc:
            aggregate.fail(
                f"{_protected_label(execution.procedure.name)} backend binding is invalid.",
                "RPC_BACKEND_BINDING_INVALID",
            )
            raise RPCExecutionError(
                f"{_protected_label(execution.procedure.name)} backend binding is invalid.",
                code="RPC_BACKEND_BINDING_INVALID",
            ) from exc
        backend_selector: object = bound_backend_id
    else:
        backend_selector = (
            backend_pk if backend_pk is not None else execution.backend_id
        )

    try:
        from .. import jobs

        try:
            target = resolve_backend(backend_selector)
        except Exception as exc:
            # Resolver implementations may import deployment-owned code or
            # consult mutable configuration. Once the queued execution has
            # been claimed, every such failure must append a bounded terminal
            # event rather than leaking exception text or stranding ``running``.
            raise RPCExecutionError(
                "RPC backend resolution failed; execution not dispatched.",
                code="RPC_BACKEND_RESOLUTION_FAILED",
            ) from exc
        if target is None:
            raise RPCExecutionError(
                "No NMSBackend configured for RPC execution.",
                code="RPC_BACKEND_NOT_CONFIGURED",
            )

        if execution.procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
            try:
                target = _resolve_validated_protected_backend_target(
                    bound_backend_id,
                    execution.procedure.name,
                    backend_target=target,
                )
            except drf_serializers.ValidationError as exc:
                raise RPCExecutionError(
                    f"{_protected_label(execution.procedure.name)} backend binding is invalid.",
                    code="RPC_BACKEND_BINDING_INVALID",
                ) from exc
        if execution.procedure.name == GITEA_PRODUCTION_UPGRADE_1_27_1:
            _verify_backend_capability(
                execution.procedure,
                backend_target=target,
                use_cache=False,
            )
        normalized = normalize_execution_params(execution)
        if execution.procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
            _require_current_protected_approval(
                execution,
                normalized,
                backend_target=target,
            )
        aggregate.normalize(
            normalized,
            jobs._hash_json(normalized.get("command_fingerprint")),
        )

        # #168: mint a one-time signed dispatch lease bound to this just-claimed
        # execution + current stream version. Graceful: ``None`` when no signing
        # key is configured, so dispatch stays ID-only (byte-for-byte as before).
        lease = _issue_dispatch_lease(execution, aggregate, normalized)
        if (
            execution.procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES
            and lease is None
        ):
            raise RPCExecutionError(
                f"{_protected_label(execution.procedure.name)} requires a signed one-time dispatch lease.",
                code="RPC_DISPATCH_LEASE_REQUIRED",
            )

        response = jobs._call_backend(target, execution, lease=lease)
        aggregate.record_backend_response(response)
    except Exception as exc:
        code = getattr(exc, "code", "RPC_EXECUTION_FAILED")
        try:
            aggregate.fail(str(exc), code)
        except RPCExecutionAggregateError:
            pass
        raise


def _require_current_staging_approval(
    execution: object,
    normalized: dict[str, Any],
    *,
    backend_target: object,
) -> None:
    """Revalidate the approved snapshot immediately before lease issuance."""
    _require_current_protected_approval(
        execution,
        normalized,
        backend_target=backend_target,
    )


def _require_current_protected_approval(
    execution: object,
    normalized: dict[str, Any],
    *,
    backend_target: object,
) -> None:
    """Revalidate a protected approved snapshot before lease issuance."""
    procedure_name = execution.procedure.name
    try:
        _require_protected_procedure_policy(execution.procedure)
    except drf_serializers.ValidationError as exc:
        raise RPCExecutionError(
            f"{_protected_label(procedure_name)} procedure policy changed after approval.",
            code="RPC_APPROVAL_INVALIDATED",
        ) from exc

    requested_by_id = getattr(execution, "requested_by_id", None)
    approved_by_id = getattr(execution, "approved_by_id", None)
    if (
        requested_by_id is None
        or approved_by_id is None
        or str(requested_by_id) == str(approved_by_id)
    ):
        raise RPCExecutionError(
            f"{_protected_label(procedure_name)} requires distinct requester and approver identities.",
            code="RPC_APPROVAL_REQUIRED",
        )

    snapshot = getattr(execution, "approval_request", None)
    current = _approval_protected_payload(
        execution,
        normalized,
        backend_target=backend_target,
    )
    if snapshot is None or not snapshot.matches_current(current):
        raise RPCExecutionError(
            f"{_protected_label(procedure_name)} approval no longer matches the execution.",
            code="RPC_APPROVAL_INVALIDATED",
        )


def _current_stream_version(execution: object) -> int:
    """The event-stream version at issuance — the sequence of the most recent
    (pre-lease) event. Bounds the lease to a specific point in the stream so a
    replay against an advanced stream is caught."""
    events = getattr(execution, "events", None)
    if events is None:
        return 0
    latest = events.order_by("-sequence").values_list("sequence", flat=True).first()
    return int(latest or 0)


def _credential_policy_reference(normalized: dict, execution: object) -> str:
    """A bounded, non-secret reference describing the credential policy in force
    (a DeviceCredential PK reference or the procedure effect) — never a secret."""
    explicit_policy = (normalized or {}).get("ssh_policy_ref")
    if isinstance(explicit_policy, str):
        explicit_policy = explicit_policy.strip()
        if (
            explicit_policy
            and len(explicit_policy) <= 200
            and not any(ord(character) < 32 or ord(character) == 127 for character in explicit_policy)
        ):
            return explicit_policy
    cred_pk = (normalized or {}).get("rpc_ssh_credential_pk")
    if cred_pk is not None:
        return f"device_credential:{cred_pk}"[:255]
    procedure = getattr(execution, "procedure", None)
    effect = str(getattr(procedure, "effect", "") or "")
    return f"procedure_effect:{effect}"[:255]


def _issue_dispatch_lease(
    execution: object, aggregate: object, normalized: dict
) -> object | None:
    """Mint + audit a signed dispatch lease for a just-claimed execution (#168).

    Returns the signed lease, or ``None`` when no signing key is configured
    (graceful ID-only dispatch). Issuance sits behind the atomic ``start()``
    transition, so at most one lease is ever minted per claim.
    """
    from django.utils import timezone

    from .. import dispatch_lease as dl

    stream_version = _current_stream_version(execution)
    lease = dl.issue_dispatch_lease(
        execution,
        stream_version=stream_version,
        normalized_params=normalized,
        now=timezone.now(),
        credential_policy=_credential_policy_reference(normalized, execution),
    )
    if lease is None:
        return None
    aggregate.record_dispatch_lease_issued(
        nonce=lease.claims.nonce,
        key_id=lease.claims.key_id,
        key_version=lease.claims.key_version,
        stream_version=lease.claims.stream_version,
        audience=lease.claims.audience,
        expires_at=lease.claims.expires_at,
        envelope_version=lease.claims.envelope_version,
    )
    return lease


def cancel_execution(execution: object, user: object) -> object:
    if not user.has_perm("netbox_rpc.execute_rpcprocedure"):
        raise PermissionDenied("execute_rpcprocedure permission is required.")
    try:
        execution = _transition_locked(execution, lambda agg: agg.cancel(user=user))
    except RPCExecutionAggregateError as exc:
        raise drf_serializers.ValidationError({"status": str(exc)}) from exc
    return execution


def _require_approval_authorization(execution: object, user: object) -> None:
    """Gate an approve/reject decision (issue #165).

    Layered on top of the aggregate's segregation-of-duties + concurrency
    guards (#164): the actor must hold ``approve_rpcprocedure`` AND have
    object-scoped view access to the execution's procedure, so an object-
    restricted actor cannot decide a procedure outside their scope. The
    execution row itself is already object-restricted by the viewset's
    ``get_object()`` (a non-viewer 404s before reaching here).
    """
    if not user.has_perm("netbox_rpc.approve_rpcprocedure"):
        raise PermissionDenied("approve_rpcprocedure permission is required.")

    from ..models import RPCProcedure

    procedure_id = getattr(execution, "procedure_id", None)
    if (
        procedure_id is not None
        and not RPCProcedure.objects.restrict(user, "view")
        .filter(pk=procedure_id)
        .exists()
    ):
        raise PermissionDenied(
            "You do not have object-scoped access to this procedure."
        )


def approve_execution(execution: object, user: object, *, reason: str = "") -> object:
    """Second-actor approval command (POST). Never mutates state via CRUD.

    Authorization is enforced here; the aggregate enforces segregation of
    duties, the pending-approval status guard, and single-decision concurrency
    (``select_for_update`` + status recheck).
    """
    _require_approval_authorization(execution, user)
    if execution.procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
        procedure_name = execution.procedure.name
        if reason:
            raise drf_serializers.ValidationError(
                {"reason": f"{_protected_label(procedure_name)} does not accept operator notes."}
            )
        _require_protected_procedure_scope(execution.procedure, user, "approve")
        return _approve_protected_execution(execution, user)
    try:
        RPCExecutionAggregate(execution).approve(approver_id=user.pk, reason=reason)
    except RPCExecutionAggregateError as exc:
        raise drf_serializers.ValidationError({"status": str(exc)}) from exc
    execution.refresh_from_db()
    return execution


def _approve_staging_rotation(
    execution: object,
    user: object,
) -> object:
    """Approve, queue, and enqueue staging rotation after snapshot validation."""
    return _approve_protected_execution(execution, user)


def _approve_protected_execution(
    execution: object,
    user: object,
) -> object:
    """Approve, queue, and enqueue after protected snapshot validation."""
    from ..models import RPCExecution

    try:
        with transaction.atomic():
            locked = (
                RPCExecution.objects.select_for_update(of=("self", "procedure"))
                .select_related(
                    "procedure",
                    "assigned_object_type",
                    "requested_by",
                    "approved_by",
                )
                .get(pk=execution.pk)
            )
            _require_protected_procedure_policy(locked.procedure)
            backend_target = _resolve_validated_protected_backend_target(
                locked.backend_id,
                locked.procedure.name,
            )
            _verify_backend_capability(
                locked.procedure,
                backend_target=backend_target,
                use_cache=False,
            )
            normalized = normalize_execution_params(locked)
            current_protected = _approval_protected_payload(
                locked,
                normalized,
                backend_target=backend_target,
            )
            RPCExecutionAggregate(locked).approve(
                approver_id=user.pk,
                current_protected=current_protected,
                reason=_PROTECTED_APPROVAL_REASON[locked.procedure.name],
                queue_after_approval=True,
            )
    except RPCExecutionError as exc:
        raise drf_serializers.ValidationError({"params": str(exc)}) from exc
    except RPCExecutionAggregateError as exc:
        raise drf_serializers.ValidationError({"status": str(exc)}) from exc

    timeout_seconds_snapshot = (locked.params or {}).get(
        RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY,
        locked.procedure.timeout_seconds,
    )
    _enqueue_execution_job(
        locked,
        user=user,
        timeout_seconds_snapshot=timeout_seconds_snapshot,
    )
    locked.refresh_from_db()
    return locked


def reject_execution(execution: object, user: object, *, reason: str = "") -> object:
    """Terminal rejection command (POST) by a distinct second actor."""
    _require_approval_authorization(execution, user)
    if execution.procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES:
        procedure_name = execution.procedure.name
        if reason:
            raise drf_serializers.ValidationError(
                {"reason": f"{_protected_label(procedure_name)} does not accept operator notes."}
            )
        _require_protected_procedure_scope(execution.procedure, user, "approve")
        reason = _PROTECTED_REJECTION_REASON[procedure_name]
    try:
        RPCExecutionAggregate(execution).reject(rejecter_id=user.pk, reason=reason)
    except RPCExecutionAggregateError as exc:
        raise drf_serializers.ValidationError({"status": str(exc)}) from exc
    execution.refresh_from_db()
    return execution


def execute_intent(
    intent: object,
    user: object,
    *,
    assigned_object_type: object,
    assigned_object_id: int,
    params: dict | None = None,
) -> list[object]:
    """Fan out one child ``RPCExecution`` per grouped procedure (issue #130).

    Every child is created through :func:`create_execution` — the exact same
    event-sourced command path a direct ``RPCExecution`` POST uses. Nothing
    here duplicates, weakens, or short-circuits any of that path's gates: each
    child independently re-runs the ``execute_rpcprocedure`` permission check,
    the #166 authoritative opt-in + selected-backend enforcement,
    ``procedure.enabled``, the procedure's approval policy, ``params_schema``
    validation, and the #167 backend capability check. Most legacy
    ``approval_required`` procedures retain the requester permission gate;
    staging token rotation instead creates a pending request that only a
    distinct approver may queue — exactly as a direct create would.

    This function never bypasses approval/destructive gating: it does not
    catch or suppress any exception raised by ``create_execution()``. The
    first child that fails any gate raises immediately out of this function,
    aborting the run (no partial silent continuation past a refused child).
    Any earlier children already created in this call remain as independently
    committed ``RPCExecution`` rows — there is no shared outer transaction
    across children, because wrapping multiple ``create_execution()`` calls in
    one outer transaction would risk leaving RQ jobs dangling against rows
    rolled back by a later sibling's failure. Cancel an unwanted stray child
    individually via the existing ``cancel`` command.

    Ordering: children are created in ascending ``RPCIntentProcedure.sequence``
    order (``RPCIntent.ordered_intent_procedures`` is already sorted that way)
    regardless of ``execution_mode``. v1 note: today, both ``sequential`` and
    ``parallel`` intents create their children synchronously, in that order,
    within this one call — see ``docs/intents.md`` "Execution modes" for the
    documented scope of what the mode currently affects (fail-fast abort
    behaviour is identical for both; true concurrent/chained dispatch is a
    future enhancement, not required for the safety contract in issue #130).

    Origin attribution: ``create_execution()`` persists a structured
    ``source_intent`` foreign-key reference in the child's original insert.
    Intent names never enter ``params``, and there is no post-creation params
    mutation. This preserves closed ``params_schema`` validation while the
    Runs tab can still render ``Intent: <name>`` through the relation.
    """
    if not user.has_perm("netbox_rpc.execute_rpcintent"):
        raise PermissionDenied("execute_rpcintent permission is required.")
    if not intent.enabled:
        raise drf_serializers.ValidationError({"intent": "This intent is disabled."})

    # ``params`` is a bare JSONField on RPCIntentRunSerializer, so a caller can
    # POST a non-object value (e.g. ``{"params": 5}``). Fail closed with a clean
    # 400 rather than letting ``dict(params or {})`` below raise an uncaught 500.
    if params is not None and not isinstance(params, dict):
        raise drf_serializers.ValidationError(
            {"params": "params must be a JSON object (mapping of param name to value)."}
        )

    ordered = list(intent.ordered_intent_procedures)
    if not ordered:
        raise drf_serializers.ValidationError(
            {"intent": "This intent has no grouped procedures to run."}
        )

    from ..api.serializers import RPCExecutionSerializer

    # RPCExecutionSerializer.assigned_object_type is a ContentTypeField, which
    # deserializes the wire string form "<app_label>.<model>" (see
    # netbox.api.fields.ContentTypeField.to_internal_value). assigned_object_type
    # arrives here as an already-resolved ContentType instance, so it must be
    # re-encoded to that string form before being fed back into a fresh
    # serializer's `data=` -- passing the instance through directly would break
    # `.split('.')` inside to_internal_value().
    target_type_label = f"{assigned_object_type.app_label}.{assigned_object_type.model}"

    base_params = dict(params or {})
    children: list[object] = []
    for intent_procedure in ordered:
        procedure = intent_procedure.procedure
        serializer = RPCExecutionSerializer(
            data={
                "procedure_id": procedure.pk,
                "assigned_object_type": target_type_label,
                "assigned_object_id": assigned_object_id,
                "params": dict(base_params),
            }
        )
        # No try/except: any gate failure here (PermissionDenied for
        # approval_required, ValidationError for params/capability/etc.)
        # propagates unmodified out of execute_intent(), exactly as it would
        # from a direct RPCExecution create — this IS the no-bypass proof.
        execution = create_execution(
            serializer=serializer,
            user=user,
            source_intent=intent,
        )
        children.append(execution)

    return children
