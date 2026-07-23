from __future__ import annotations

from typing import Any

import jsonschema
from django.db import transaction
from rest_framework import serializers as drf_serializers
from rest_framework.exceptions import PermissionDenied

from ..backends import resolve_backend
from ..domain.aggregate import RPCExecutionAggregate, RPCExecutionAggregateError
from ..domain.normalization import RPCExecutionError, normalize_execution_params
from ..event_store import mark_execution_failed


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


def _verify_backend_capability(procedure: object) -> None:
    """Fail closed before enqueue on a backend capability mismatch (issue #167).

    Fetches the selected backend's capability manifest and verifies the
    procedure's handler/version/effect/contract-hash/envelope against it. A
    ``MISMATCH`` (advertised but incompatible) is rejected (400); ``UNKNOWN``
    (the backend advertises nothing) proceeds — capability enforcement is inert
    until the paired backend advertises.
    """
    from .. import capabilities
    from ..models import RpcPluginSettings

    target = RpcPluginSettings.get_solo().resolved_backend_target()
    manifest = capabilities.fetch_backend_capabilities(target)
    status = capabilities.verify_procedure_capability(procedure, manifest)
    if status is capabilities.CapabilityStatus.MISMATCH:
        raise drf_serializers.ValidationError(
            {
                "procedure_id": (
                    "The selected backend does not advertise a compatible "
                    "capability for this procedure (handler/version/effect/"
                    "contract mismatch)."
                )
            }
        )


def create_execution(*, serializer: Any, user: object) -> object:
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
    if procedure.approval_required:
        if not user.has_perm("netbox_rpc.approve_rpcprocedure"):
            raise PermissionDenied(
                "This procedure requires approval (approve_rpcprocedure permission)."
            )
    params = serializer.validated_data.get("params") or {}
    if procedure.params_schema:
        try:
            jsonschema.validate(params, procedure.params_schema)
        except jsonschema.ValidationError as exc:
            raise drf_serializers.ValidationError({"params": exc.message}) from exc

    # #167: fail closed before enqueue on a backend capability mismatch.
    _verify_backend_capability(procedure)

    with transaction.atomic():
        # #166: a normal requester cannot select an arbitrary backend — the
        # authoritative selected backend from RPC settings always wins over any
        # client-supplied ``backend_id``.
        execution = serializer.save(requested_by=user, backend=authoritative_backend_id)
        RPCExecutionAggregate(execution).queue()

    try:
        from ..jobs import RPCExecutionJob

        job = RPCExecutionJob.enqueue(
            user=user,
            name=f"RPC Execution: {execution.procedure.name}",
            backend_pk=execution.backend_id,
            execution_pk=execution.pk,
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
    return execution


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
        execution = _transition_locked(execution, lambda agg: agg.start())
    except RPCExecutionAggregateError:
        # Lost the race to a cancel (or already terminal): nothing to run.
        return
    aggregate = RPCExecutionAggregate(execution)

    target = resolve_backend(
        backend_pk if backend_pk is not None else execution.backend_id
    )
    if target is None:
        aggregate.fail(
            "No NMSBackend configured for RPC execution.",
            "RPC_BACKEND_NOT_CONFIGURED",
        )
        raise RPCExecutionError(
            "No NMSBackend configured for RPC execution.",
            code="RPC_BACKEND_NOT_CONFIGURED",
        )

    try:
        from .. import jobs

        normalized = normalize_execution_params(execution)
        aggregate.normalize(
            normalized,
            jobs._hash_json(normalized.get("command_fingerprint")),
        )

        response = jobs._call_backend(target, execution)
        aggregate.record_backend_response(response)
    except Exception as exc:
        code = getattr(exc, "code", "RPC_EXECUTION_FAILED")
        try:
            aggregate.fail(str(exc), code)
        except RPCExecutionAggregateError:
            pass
        raise


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
    try:
        RPCExecutionAggregate(execution).approve(approver_id=user.pk, reason=reason)
    except RPCExecutionAggregateError as exc:
        raise drf_serializers.ValidationError({"status": str(exc)}) from exc
    execution.refresh_from_db()
    return execution


def reject_execution(execution: object, user: object, *, reason: str = "") -> object:
    """Terminal rejection command (POST) by a distinct second actor."""
    _require_approval_authorization(execution, user)
    try:
        RPCExecutionAggregate(execution).reject(rejecter_id=user.pk, reason=reason)
    except RPCExecutionAggregateError as exc:
        raise drf_serializers.ValidationError({"status": str(exc)}) from exc
    execution.refresh_from_db()
    return execution
