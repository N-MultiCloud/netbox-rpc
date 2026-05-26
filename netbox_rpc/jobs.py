from __future__ import annotations

import hashlib
import json
from typing import Any

import requests
from django.utils import timezone
from netbox.constants import RQ_QUEUE_DEFAULT
from netbox.jobs import JobRunner

from netbox_nms.backend import get_backend

from .constants import HUAWEI_MA5800_R024_START_ONT, UBUNTU_24_RESTART_SERVICE
from .models import RPCLinuxServiceAllowlist, RPCExecution, RPCExecutionEvent

RPC_QUEUE_NAME = RQ_QUEUE_DEFAULT
RPC_JOB_TIMEOUT = 600


class RPCExecutionError(RuntimeError):
    def __init__(self, message: str, *, code: str = "RPC_EXECUTION_FAILED") -> None:
        super().__init__(message)
        self.code = code


class RPCExecutionJob(JobRunner):
    class Meta:
        name = "RPC Execution"

    @classmethod
    def enqueue(cls, *args, **kwargs):
        backend_pk = kwargs.pop("backend_pk", None)
        kwargs.setdefault("queue_name", RPC_QUEUE_NAME)
        kwargs.setdefault("job_timeout", RPC_JOB_TIMEOUT)
        job = super().enqueue(*args, **kwargs)
        data = job.data or {}
        if backend_pk:
            data["backend_pk"] = backend_pk
        job.data = data
        job.save(update_fields=["data"])
        return job

    def run(self, *args: object, **kwargs: object) -> None:
        execution = self._get_execution()
        self._mark_running(execution)
        backend_pk = (self.job.data or {}).get("backend_pk") or execution.backend_id
        backend = get_backend(backend_pk)
        if backend is None:
            self._mark_failed(
                execution,
                "No NMSBackend configured for RPC execution.",
                "RPC_BACKEND_NOT_CONFIGURED",
            )
            raise RPCExecutionError(
                "No NMSBackend configured for RPC execution.",
                code="RPC_BACKEND_NOT_CONFIGURED",
            )

        try:
            normalized = normalize_execution_params(execution)
            execution.normalized_params = normalized
            execution.resolved_command_hash = _hash_json(normalized.get("command_fingerprint"))
            execution.save(update_fields=["normalized_params", "resolved_command_hash"])
            _event(execution, "info", "normalized", "Execution parameters normalized by NetBox.")

            response = _call_backend(backend, execution)
            _store_backend_response(execution, response)
        except Exception as exc:
            code = getattr(exc, "code", "RPC_EXECUTION_FAILED")
            self._mark_failed(execution, str(exc), code)
            raise

    def _get_execution(self) -> RPCExecution:
        if not self.job.object_id:
            raise RuntimeError("RPCExecutionJob requires an RPCExecution instance.")
        return RPCExecution.objects.select_related(
            "procedure",
            "assigned_object_type",
            "backend",
        ).get(pk=self.job.object_id)

    def _mark_running(self, execution: RPCExecution) -> None:
        execution.status = RPCExecution.STATUS_RUNNING
        execution.started_at = timezone.now()
        execution.save(update_fields=["status", "started_at"])
        _event(execution, "info", "started", "RPC execution started.")

    def _mark_failed(self, execution: RPCExecution, message: str, code: str) -> None:
        execution.status = RPCExecution.STATUS_FAILED
        execution.error_code = code
        execution.error_message = message
        execution.finished_at = timezone.now()
        execution.save(update_fields=["status", "error_code", "error_message", "finished_at"])
        _event(execution, "error", "failed", message, {"code": code})


def normalize_execution_params(execution: RPCExecution) -> dict[str, Any]:
    procedure_name = execution.procedure.name
    target = execution.target_display

    if procedure_name == UBUNTU_24_RESTART_SERVICE:
        slug = str((execution.params or {}).get("service_slug") or "").strip()
        allow = RPCLinuxServiceAllowlist.objects.filter(slug=slug, enabled=True).first()
        if allow is None:
            raise RPCExecutionError(
                f"Linux service {slug!r} is not allowlisted.",
                code="RPC_LINUX_SERVICE_NOT_ALLOWLISTED",
            )
        target_models = set(allow.target_models or [])
        if target_models and execution.target_model_label not in target_models:
            raise RPCExecutionError(
                f"Linux service {slug!r} is not allowed for {execution.target_model_label}.",
                code="RPC_LINUX_SERVICE_TARGET_DENIED",
            )
        unit = allow.systemd_unit
        return {
            "target": target,
            "service_slug": slug,
            "systemd_unit": unit,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "systemd_unit": unit,
            },
        }

    if procedure_name == HUAWEI_MA5800_R024_START_ONT:
        params = execution.params or {}
        normalized = {
            "target": target,
            "frame": _int_range(params, "frame", 0, None),
            "slot": _int_range(params, "slot", 1, 17),
            "port": _int_range(params, "port", 0, 15),
            "ont_id": _int_range(params, "ont_id", 0, 127),
        }
        normalized["command_fingerprint"] = {
            "handler_id": execution.procedure.handler_id,
            "frame": normalized["frame"],
            "slot": normalized["slot"],
            "port": normalized["port"],
            "ont_id": normalized["ont_id"],
        }
        return normalized

    raise RPCExecutionError(
        f"Procedure {procedure_name!r} has no NetBox normalizer.",
        code="RPC_PROCEDURE_NOT_NORMALIZABLE",
    )


def _int_range(params: dict[str, Any], key: str, minimum: int, maximum: int | None) -> int:
    try:
        value = int(params[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise RPCExecutionError(f"{key} must be an integer.", code="RPC_PARAM_INVALID") from exc
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" and <= {maximum}" if maximum is not None else ""
        raise RPCExecutionError(
            f"{key} must be >= {minimum}{suffix}.",
            code="RPC_PARAM_OUT_OF_RANGE",
        )
    return value


def _call_backend(backend, execution: RPCExecution) -> dict[str, Any]:
    url = f"{backend.backend_url.rstrip('/')}/rpc/executions/{execution.pk}/run"
    timeout = (10, max(execution.procedure.timeout_seconds + 10, 30))
    resp = requests.post(
        url,
        headers=backend.get_auth_headers(),
        json={},
        verify=backend.verify_ssl,
        timeout=timeout,
    )
    if resp.status_code == 401:
        raise RPCExecutionError(
            "nms-backend returned 401 Unauthorized.",
            code="RPC_BACKEND_UNAUTHORIZED",
        )
    try:
        data = resp.json()
    except ValueError as exc:
        raise RPCExecutionError(
            f"nms-backend returned non-JSON response: HTTP {resp.status_code}",
            code="RPC_BACKEND_BAD_RESPONSE",
        ) from exc
    if resp.status_code >= 400:
        detail = data.get("detail") if isinstance(data, dict) else None
        message = detail if isinstance(detail, str) else data.get("error", f"HTTP {resp.status_code}")
        raise RPCExecutionError(str(message), code=str(data.get("code") or "RPC_BACKEND_ERROR"))
    return data


def _store_backend_response(execution: RPCExecution, response: dict[str, Any]) -> None:
    ok = bool(response.get("ok"))
    execution.result = response.get("result") or {}
    execution.error_code = str(response.get("error_code") or "")
    execution.error_message = str(response.get("error_message") or "")
    execution.status = RPCExecution.STATUS_SUCCEEDED if ok else RPCExecution.STATUS_FAILED
    execution.finished_at = timezone.now()
    execution.save(update_fields=["result", "error_code", "error_message", "status", "finished_at"])
    for item in response.get("events") or []:
        _event(
            execution,
            str(item.get("level") or "info"),
            str(item.get("event") or "backend"),
            str(item.get("message") or ""),
            item.get("data") if isinstance(item.get("data"), dict) else {},
        )
    if ok:
        _event(execution, "info", "completed", "RPC execution completed.")
    else:
        _event(execution, "error", "failed", execution.error_message or "RPC execution failed.")


def _event(
    execution: RPCExecution,
    level: str,
    event: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    last = execution.events.order_by("-sequence").first()
    sequence = 1 if last is None else last.sequence + 1
    RPCExecutionEvent.objects.create(
        execution=execution,
        sequence=sequence,
        level=level,
        event=event,
        message=message,
        data=data or {},
    )


def _hash_json(value: object) -> str:
    if value is None:
        return ""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
