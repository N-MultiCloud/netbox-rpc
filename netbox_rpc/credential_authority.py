"""Execution-owned authority for optional credential providers.

No function in this module reveals secrets or consumes a backend dispatch nonce.
The provider reserves a separate reveal receipt before its first secret read.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied

from .credential_contract import (
    MAX_REFERENCE_LEASE_SECONDS,
    CredentialContractError,
    CredentialReferenceV1,
    canonical_hash,
    validate_named_references,
)


class SecretResolutionDenied(PermissionDenied):
    default_detail = "Credential resolution is not authorized for this execution."
    default_code = "rpc_credential_resolution_denied"


@dataclass(frozen=True)
class SecretResolutionAuthorization:
    initiating_actor: object
    executor_id: int
    execution_id: int
    stream_version: int
    target_object: object
    reference: CredentialReferenceV1
    reference_name: str
    step_id: str
    dispatch_nonce: str
    correlation_id: str
    approval_snapshot_hash: str
    reason: str
    provider_identity: dict[str, object]
    expires_at: datetime
    procedure_id: int
    backend_id: int
    approved_by_id: int | None
    intent_run_id: int | None = None


def _require(condition: object) -> None:
    if not condition:
        raise SecretResolutionDenied()


def _viewable(model: object, user: object, pk: int) -> object:
    obj = _lock_in_transaction(
        model.objects.restrict(user, "view").filter(pk=pk)
    ).first()
    _require(obj is not None)
    return obj


def _lock_in_transaction(queryset: object, *, no_key: bool = False) -> object:
    from django.db import connection

    if connection.in_atomic_block:
        return queryset.select_for_update(no_key=no_key)
    return queryset


def _active_actor(actor: object, permission: str) -> None:
    _require(actor is not None and actor.is_active)
    _require(actor.has_perm(permission))


def _fresh_rpc_actor(actor_id: int, procedure_id: int, action: str) -> object:
    """Reload the user so NetBox permission constraints cannot come from a cache."""
    from django.contrib.auth import get_user_model

    from .models import RPCProcedure

    actor = get_user_model().objects.get(pk=actor_id)
    _active_actor(actor, f"netbox_rpc.{action}_rpcprocedure")
    _require(RPCProcedure.objects.restrict(actor, action).filter(pk=procedure_id).exists())
    _require(RPCProcedure.objects.restrict(actor, "view").filter(pk=procedure_id).exists())
    return actor


def _fresh_execution_permissions(
    *, requester_id: int, approved_by_id: int | None, procedure_id: int,
    backend_id: int, target_model: object, target_id: int,
) -> None:
    """Read current permissions only; never acquire authority or provider row locks."""
    from .models import RPCBackend

    actor = _fresh_rpc_actor(requester_id, procedure_id, "execute")
    _require(RPCBackend.objects.restrict(actor, "view").filter(pk=backend_id).exists())
    _require(target_model.objects.restrict(actor, "view").filter(pk=target_id).exists())
    if approved_by_id is not None:
        approver = _fresh_rpc_actor(approved_by_id, procedure_id, "approve")
        _require(target_model.objects.restrict(approver, "view").filter(pk=target_id).exists())


def _check_execution_permissions(execution: object) -> None:
    _fresh_execution_permissions(
        requester_id=execution.requested_by_id,
        approved_by_id=execution.approved_by_id,
        procedure_id=execution.procedure_id,
        backend_id=execution.backend_id,
        target_model=execution.assigned_object_type.model_class(),
        target_id=execution.assigned_object_id,
    )


def check_authorization_permissions(authorization: SecretResolutionAuthorization) -> None:
    """Refresh RPC permissions after provider waits and before material delivery.

    Accept only the already verified in-process result, never caller input. This
    check deliberately takes no row locks, resolves no backend and calls no
    provider, so it cannot reverse the established authority/provider lock order.
    It establishes permissions at the check, not a lock on future policy edits.
    """
    from django.contrib.auth import get_user_model

    try:
        _require(isinstance(authorization, SecretResolutionAuthorization))
        executor = get_user_model().objects.get(pk=authorization.executor_id)
        _require(executor.is_active and executor.is_authenticated)
        _fresh_execution_permissions(
            requester_id=authorization.initiating_actor.pk,
            approved_by_id=authorization.approved_by_id,
            procedure_id=authorization.procedure_id,
            backend_id=authorization.backend_id,
            target_model=type(authorization.target_object),
            target_id=authorization.target_object.pk,
        )
    except Exception:  # noqa: BLE001 -- Permission/ORM diagnostics are not public authority.
        raise SecretResolutionDenied() from None


def _reference_context(execution: object, actor: object) -> tuple[object, object]:
    from .models import RPCBackend, RpcPluginSettings, RPCProcedure

    _active_actor(actor, "netbox_rpc.execute_rpcprocedure")
    procedure = _viewable(RPCProcedure, actor, execution.procedure_id)
    _require(procedure.enabled)
    execution.procedure = procedure
    _require(
        RPCProcedure.objects.restrict(actor, "execute").filter(pk=procedure.pk).exists()
    )
    backend = _viewable(RPCBackend, actor, execution.backend_id)
    _require(backend.executor_identity_id and backend.executor_identity.is_active)
    settings_row = _lock_in_transaction(RpcPluginSettings.objects.all()).get(
        pk=RpcPluginSettings.get_solo().pk
    )
    _require(settings_row.enabled and settings_row.backend_id == backend.pk)
    target = _viewable(
        execution.assigned_object_type.model_class(),
        actor,
        execution.assigned_object_id,
    )
    _require(execution.target_model_label in procedure.target_models)
    return backend, target


def _snapshot_payload(
    execution: object, actor: object, backend: object, target: object
) -> dict:
    from .capabilities import _base_command_contract_payload

    procedure = execution.procedure
    # Child command updates do not necessarily lock their parent procedure.
    # Hold existing command rows for the provider's whole reveal transaction.
    list(_lock_in_transaction(procedure.commands.all()))
    references = validate_named_references(execution.credential_references)
    for value in references.values():
        _require(
            value["target"]
            == {
                "object_type": execution.target_model_label,
                "object_id": target.pk,
            }
        )
    return {
        "schema_version": 1,
        "references": references,
        "requested_by_id": actor.pk,
        "backend_id": backend.pk,
        "executor_id": backend.executor_identity_id,
        "backend_identity": {
            "url": backend.backend_url,
            "verify_ssl": backend.verify_ssl,
            "auth_header_name": backend.auth_header_name,
            "revision": str(backend.last_updated),
        },
        "target": {
            "object_type": execution.target_model_label,
            "object_id": target.pk,
            "revision": str(target.last_updated),
        },
        "procedure_id": procedure.pk,
        "procedure_policy_sha256": canonical_hash(
            {
                "contract": _base_command_contract_payload(procedure),
                "name": procedure.name,
                "params_schema": procedure.params_schema,
                "result_schema": procedure.result_schema,
                "target_models": procedure.target_models,
                "approval_required": procedure.approval_required,
                "timeout_seconds": procedure.timeout_seconds,
                "transport_policy": {
                    key: getattr(procedure, key, None)
                    for key in (
                        "transport_driver",
                        "transport_driver_chain",
                        "transport_pinned",
                        "output_parser",
                        "output_schema",
                    )
                },
            }
        ),
        "params_sha256": canonical_hash(execution.params),
    }


def prepare_reference_execution(
    serializer: object, actor: object, backend_id: int | None
) -> None:
    """Freeze metadata in the original execution insert, before any enqueue."""
    from types import SimpleNamespace

    data = serializer.validated_data
    references = data.get("credential_references", {})
    if not references:
        return
    references = validate_named_references(references)
    content_type = data["assigned_object_type"]
    execution = SimpleNamespace(
        procedure=data["procedure"],
        procedure_id=data["procedure"].pk,
        credential_references=references,
        backend_id=backend_id,
        assigned_object_type=content_type,
        assigned_object_id=data["assigned_object_id"],
        target_model_label=f"{content_type.app_label}.{content_type.model}",
        params=data["params"],
    )
    backend, target = _reference_context(execution, actor)
    snapshot = _snapshot_payload(execution, actor, backend, target)
    snapshot["correlation_id"] = str(uuid4())
    snapshot["provider_identities"] = _capture_provider_identities(
        references, actor, target, execution.procedure
    )
    _fresh_execution_permissions(
        requester_id=actor.pk, approved_by_id=None, procedure_id=execution.procedure_id,
        backend_id=backend_id, target_model=type(target), target_id=target.pk,
    )
    data["credential_references"] = references
    data["credential_authority"] = snapshot


def _reference_reason(procedure: object, reference: CredentialReferenceV1) -> str:
    return (
        f"Execute {procedure.name} using the assigned {reference.purpose} credential."
    )


def _capture_provider_identities(
    references: dict, actor: object, target: object, procedure: object
) -> dict:
    try:
        from netbox_openbao.automation import capture_reference_identity

        identities = {}
        for name, value in references.items():
            reference = CredentialReferenceV1.from_mapping(value)
            identity = capture_reference_identity(
                reference=reference,
                initiating_actor=actor,
                target_object=target,
                reason=_reference_reason(procedure, reference),
            )
            identities[name] = _validated_provider_identity(identity, reference)
        return identities
    except Exception:  # noqa: BLE001 -- Optional-provider failures never disclose provider state.
        raise SecretResolutionDenied() from None


def _validated_provider_identity(
    value: object, reference: CredentialReferenceV1
) -> dict:
    """Reject unexpected provider fields before they enter durable execution state."""
    keys = {
        "credential_uuid",
        "assignment_id",
        "target",
        "purpose",
        "username",
        "fingerprint",
        "credential_type",
        "policy_id",
        "engine_id",
        "engine_identity_sha256",
        "schema_sha256",
    }
    _require(isinstance(value, dict) and set(value) == keys)
    _require(value["target"] == reference.to_mapping()["target"])
    _require(type(value["target"]["object_id"]) is int)
    _require(value["purpose"] == reference.purpose)
    for key in ("assignment_id", "policy_id", "engine_id"):
        _require(type(value[key]) is int and 0 < value[key] <= 9007199254740991)
    for key in ("username", "fingerprint", "credential_type"):
        _require(isinstance(value[key], str) and len(value[key]) <= 1024)
    for key in ("engine_identity_sha256", "schema_sha256"):
        _require(
            isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{64}", value[key])
        )
    _require(str(UUID(value["credential_uuid"])) == value["credential_uuid"])
    _require(reference.assignment_id in (None, value["assignment_id"]))
    _require(reference.credential_uuid in (None, value["credential_uuid"]))
    return deepcopy(value)


def validate_immutable_reference_fields(execution: object) -> None:
    """ORM defense in depth; PostgreSQL protects updates below model methods."""
    references = getattr(execution, "credential_references", {})
    authority = getattr(execution, "credential_authority", {})
    if references:
        try:
            _require(
                validate_named_references(references) == authority.get("references")
            )
        except (CredentialContractError, SecretResolutionDenied):
            raise ValidationError("Invalid credential authority snapshot.") from None
    if execution._state.adding:
        _require(bool(references) == bool(authority))
        return
    original = (
        type(execution)
        .objects.filter(pk=execution.pk)
        .values(
            "credential_references",
            "credential_authority",
        )
        .first()
    )
    if original and original != {
        "credential_references": references,
        "credential_authority": authority,
    }:
        raise ValidationError("Execution credential references are immutable.")


def _current_reference_snapshot(execution: object) -> tuple[object, object, object]:
    actor = execution.requested_by
    backend, target = _reference_context(execution, actor)
    current = _snapshot_payload(execution, actor, backend, target)
    saved = dict(execution.credential_authority)
    correlation_id = saved.pop("correlation_id", None)
    provider_identities = saved.pop("provider_identities", None)
    _require(
        isinstance(provider_identities, dict)
        and set(provider_identities) == set(current["references"])
    )
    _require(
        isinstance(correlation_id, str) and str(UUID(correlation_id)) == correlation_id
    )
    for name, value in current["references"].items():
        _validated_provider_identity(
            provider_identities[name], CredentialReferenceV1.from_mapping(value)
        )
    _require(saved == current)
    _check_execution_permissions(execution)
    return actor, backend, target


def require_reference_backend(execution: object, backend_selector: object) -> None:
    if not getattr(execution, "credential_references", None):
        return
    _require(backend_selector == execution.credential_authority.get("backend_id"))
    _current_reference_snapshot(execution)


def require_reference_dispatch_ready(execution: object, backend_target: object) -> None:
    if not getattr(execution, "credential_references", None):
        return
    from . import capabilities, dispatch_lease

    _, backend, _ = _current_reference_snapshot(execution)
    _require(backend_target.url == backend.backend_url)
    _require(backend_target.verify_ssl == backend.verify_ssl)
    manifest = capabilities.fetch_backend_capabilities(backend_target, use_cache=False)
    _require(manifest is not None)
    _require(
        capabilities.verify_procedure_capability(execution.procedure, manifest)
        is capabilities.CapabilityStatus.COMPATIBLE
    )
    _require(1 in manifest.credential_reference_versions)
    _require(1 in manifest.credential_provider_versions.get("netbox-openbao", []))
    _require(1 in manifest.dispatch_lease_versions)
    _require(dispatch_lease.load_active_signing_key() is not None)
    _check_execution_permissions(execution)


def _approval_backend_target(execution: object, backend_target: object | None) -> object:
    if backend_target is not None:
        return backend_target
    from .backends import resolve_backend

    try:
        return resolve_backend(execution.backend_id)
    except Exception:  # noqa: BLE001 -- Resolver diagnostics are never public authority.
        raise SecretResolutionDenied() from None


def _current_approval(
    execution: object, normalized: dict, *, backend_target: object | None = None,
) -> str:
    procedure = execution.procedure
    if not procedure.approval_required and procedure.effect != "destructive":
        _require(execution.approved_by_id is None)
        _check_execution_permissions(execution)
        return ""
    from .application.command_handlers import (
        PROTECTED_APPROVAL_PROCEDURE_NAMES,
        _require_current_protected_approval,
        _require_protected_procedure_scope,
    )

    # Legacy permission-only approvals are not sufficient evidence.
    _require(procedure.name in PROTECTED_APPROVAL_PROCEDURE_NAMES)
    _require(execution.approved_by_id != execution.requested_by_id)
    _active_actor(execution.approved_by, "netbox_rpc.approve_rpcprocedure")
    _require_protected_procedure_scope(procedure, execution.approved_by, "approve")
    _viewable(type(procedure), execution.approved_by, procedure.pk)
    _viewable(
        execution.assigned_object_type.model_class(),
        execution.approved_by,
        execution.assigned_object_id,
    )
    _require_current_protected_approval(
        execution,
        normalized,
        backend_target=_approval_backend_target(execution, backend_target),
    )
    _check_execution_permissions(execution)
    return execution.approval_request.payload_hash


def require_reference_approval(
    execution: object, normalized: dict, *, backend_target: object | None = None,
) -> None:
    if getattr(execution, "credential_references", None):
        try:
            _current_approval(execution, normalized, backend_target=backend_target)
        except Exception:  # noqa: BLE001 -- Worker failures enter immutable public history.
            raise SecretResolutionDenied() from None


def _lease_times(claims: object, now: datetime) -> None:
    try:
        issued = datetime.fromisoformat(claims.issued_at)
        expires = datetime.fromisoformat(claims.expires_at)
        _require(issued.utcoffset() is not None and expires.utcoffset() is not None)
        _require(issued <= now < expires)
        _require(
            timedelta(0) < expires - issued
            <= timedelta(seconds=MAX_REFERENCE_LEASE_SECONDS)
        )
    except (ValueError, TypeError, AttributeError):
        raise SecretResolutionDenied() from None


def check_authorization_lifetime(
    authorization: SecretResolutionAuthorization, *, now: datetime | None = None,
) -> None:
    """Recheck a verified result after provider waits, without acquiring locks."""
    current = timezone.now() if now is None else now
    try:
        _require(authorization.expires_at.utcoffset() is not None)
        _require(current.utcoffset() is not None)
        _require(current < authorization.expires_at)
    except (AttributeError, TypeError, ValueError):
        raise SecretResolutionDenied() from None


def _issuance_event(execution: object, claims: object) -> object:
    events = execution.events.order_by("sequence")
    event = events.filter(event="DispatchLeaseIssued", data__nonce=claims.nonce).first()
    _require(event is not None)
    expected = {
        "nonce": claims.nonce,
        "key_id": claims.key_id,
        "key_version": claims.key_version,
        "stream_version": claims.stream_version,
        "audience": claims.audience,
        "expires_at": claims.expires_at,
        "envelope_version": claims.envelope_version,
    }
    _require(event.data == expected)
    _require(event.sequence == claims.stream_version + 1)
    _require(not events.filter(sequence__gt=event.sequence).exists())
    _require(
        events.filter(
            sequence=claims.stream_version, event="ParametersNormalized"
        ).exists()
    )
    return event


def _verify_lease(
    execution: object, lease: object, event: object, now: datetime
) -> None:
    from . import dispatch_lease as dl
    from .capabilities import derive_command_contract_hash

    normalized = execution.normalized_params
    fingerprint = normalized.get("command_fingerprint", {})
    authority = execution.credential_authority
    _require(
        fingerprint.get("credential_authority_sha256") == canonical_hash(authority)
    )
    _require(normalized.get("credential_references") == authority["references"])
    _require(lease.claims.approved_by_id == execution.approved_by_id)
    _require(lease.claims.trace_id == authority["correlation_id"])
    result = dl.verify_dispatch_lease(
        lease,
        public_keys=dl.load_verifier_public_keys(),
        audience=str(dl._plugin_setting(dl._AUDIENCE_SETTING) or dl.DEFAULT_AUDIENCE),
        now=now,
        expected_execution_id=execution.pk,
        expected_stream_version=event.sequence - 1,
        expected_contract_hash=derive_command_contract_hash(execution.procedure),
        expected_handler_id=execution.procedure.handler_id,
        expected_handler_version=execution.procedure.version,
        expected_effect=execution.procedure.effect,
        expected_target_snapshot_hash=str(
            fingerprint.get("target_object_sha256") or ""
        ),
        expected_params_fingerprint=canonical_hash(fingerprint),
        expected_credential_policy="credential-authority:" + canonical_hash(authority),
        expected_requested_by_id=execution.requested_by_id,
        expected_approved_by_id=execution.approved_by_id,
    )
    _require(result.is_valid)


def validate_secret_resolution_dispatch(
    *,
    execution: object,
    dispatch_lease: Mapping[str, object],
    authenticated_executor: object,
    reference_name: str,
    step_id: str | None = None,
) -> SecretResolutionAuthorization:
    """Derive fresh execution authority; never trust an API-supplied actor/ref.

    Providers must invoke again inside their reveal transaction after reserving
    a durable receipt. A receipt is not authorization and cannot bypass this check.
    """
    from .dispatch_lease import SignedDispatchLease
    from .models import RPCExecution

    try:
        _require(
            step_id in (None, "")
        )  # Named intent runs are a later additive contract.
        fresh = _lock_in_transaction(RPCExecution.objects.all()).get(pk=execution.pk)
        from django.contrib.auth import get_user_model

        actors = get_user_model().objects.all()
        # Actor UPDATE/DELETE must remain blocked, while audit rows may take
        # FK KEY SHARE locks without inverting provider material-write locks.
        fresh.requested_by = _lock_in_transaction(actors, no_key=True).get(pk=fresh.requested_by_id)
        if fresh.approved_by_id:
            fresh.approved_by = _lock_in_transaction(actors, no_key=True).get(
                pk=fresh.approved_by_id
            )
        authenticated_executor = _lock_in_transaction(actors, no_key=True).get(
            pk=authenticated_executor.pk
        )
        _require(fresh.status == fresh.STATUS_RUNNING)
        actor, backend, target = _current_reference_snapshot(fresh)
        _require(
            authenticated_executor.is_authenticated and authenticated_executor.is_active
        )
        _require(authenticated_executor.pk == backend.executor_identity_id)
        _require(authenticated_executor.pk != actor.pk)
        reference = CredentialReferenceV1.from_mapping(
            fresh.credential_references[reference_name]
        )
        lease = SignedDispatchLease.model_validate(dict(dispatch_lease))
        now = timezone.now()
        _lease_times(lease.claims, now)
        event = _issuance_event(fresh, lease.claims)
        _verify_lease(fresh, lease, event, now)
        approval_hash = _current_approval(fresh, fresh.normalized_params)
        authorization = SecretResolutionAuthorization(
            initiating_actor=actor,
            executor_id=backend.executor_identity_id,
            execution_id=fresh.pk,
            stream_version=lease.claims.stream_version,
            target_object=target,
            reference=reference,
            reference_name=reference_name,
            step_id="",
            dispatch_nonce=lease.claims.nonce,
            correlation_id=fresh.credential_authority["correlation_id"],
            approval_snapshot_hash=approval_hash,
            reason=_reference_reason(fresh.procedure, reference),
            provider_identity=fresh.credential_authority["provider_identities"][
                reference_name
            ],
            expires_at=datetime.fromisoformat(lease.claims.expires_at),
            procedure_id=fresh.procedure_id,
            backend_id=fresh.backend_id,
            approved_by_id=fresh.approved_by_id,
        )
        check_authorization_permissions(authorization)
        check_authorization_lifetime(authorization)
        return authorization
    except Exception:  # noqa: BLE001 -- Never disclose provider, ORM, or cryptographic error values.
        raise SecretResolutionDenied() from None
