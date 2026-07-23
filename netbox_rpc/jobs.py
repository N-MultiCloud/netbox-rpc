from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

import requests
from netbox.constants import RQ_QUEUE_DEFAULT
from netbox.jobs import JobRunner

from .backends import BackendTarget
from .domain.normalization import (
    RPCLinuxServiceAllowlist,
    RPCExecutionError,
    _apply_driver_pipeline_overrides,
    _dispatch_normalize_execution_params,
    normalize_execution_params,
)
from .event_store import (
    append_execution_event,
    mark_execution_failed,
    mark_execution_running,
    record_backend_response,
)
from .models import RPCExecution

if TYPE_CHECKING:
    from rq.job import Job

logger = logging.getLogger(__name__)

RPC_QUEUE_NAME = RQ_QUEUE_DEFAULT
RPC_JOB_TIMEOUT = 600

__all__ = (
    "BackendTarget",
    "RPCLinuxServiceAllowlist",
    "RPCExecutionError",
    "RPCExecutionJob",
    "_apply_driver_pipeline_overrides",
    "_call_backend",
    "_dispatch_normalize_execution_params",
    "_event",
    "_hash_json",
    "_store_backend_response",
    "normalize_execution_params",
    "requests",
)


class RPCExecutionJob(JobRunner):
    class Meta:
        name = "RPC Execution"

    @classmethod
    def enqueue(cls, *args: Any, **kwargs: Any) -> Job:
        backend_pk = kwargs.pop("backend_pk", None)
        execution_pk = kwargs.get("execution_pk")
        kwargs.setdefault("queue_name", RPC_QUEUE_NAME)
        kwargs.setdefault("job_timeout", RPC_JOB_TIMEOUT)
        # Embed identifiers in job data before enqueueing so workers can read
        # them without a race between super().enqueue() and a subsequent save.
        if backend_pk is not None or execution_pk is not None:
            data = dict(kwargs.get("data") or {})
            if backend_pk is not None:
                data["backend_pk"] = backend_pk
            if execution_pk is not None:
                data["execution_pk"] = execution_pk
            kwargs["data"] = data
        job = super().enqueue(*args, **kwargs)
        # Persist as a safety fallback in case super().enqueue() ignored the data kwarg.
        needs_data_save = False
        job.data = dict(job.data or {})
        if backend_pk is not None and job.data.get("backend_pk") != backend_pk:
            job.data["backend_pk"] = backend_pk
            needs_data_save = True
        if execution_pk is not None and job.data.get("execution_pk") != execution_pk:
            job.data["execution_pk"] = execution_pk
            needs_data_save = True
        if needs_data_save:
            job.save(update_fields=["data"])
        return job

    def run(self, *args: object, **kwargs: object) -> None:
        runtime_data = (
            kwargs.get("data") if isinstance(kwargs.get("data"), dict) else {}
        )
        execution = self._get_execution(
            execution_pk=kwargs.get("execution_pk") or runtime_data.get("execution_pk")
        )
        backend_pk = (
            runtime_data.get("backend_pk")
            or (self.job.data or {}).get("backend_pk")
            or execution.backend_id
        )
        from .application.command_handlers import run_execution

        run_execution(execution, backend_pk=backend_pk)

    def _get_execution(self, execution_pk: object | None = None) -> RPCExecution:
        raw_pk = execution_pk
        if raw_pk is None:
            raw_pk = (self.job.data or {}).get("execution_pk")
        if raw_pk is None:
            # Legacy fallback for jobs queued before RPC executions stopped
            # using NetBox's attached-object fields.
            raw_pk = self.job.object_id
        if raw_pk is None:
            raise RuntimeError("RPCExecutionJob requires an RPCExecution primary key.")
        try:
            pk = int(raw_pk)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "RPCExecutionJob received an invalid RPCExecution primary key."
            ) from exc
        return RPCExecution.objects.select_related(
            "procedure",
            "assigned_object_type",
        ).get(pk=pk)

    def _mark_running(self, execution: RPCExecution) -> None:
        mark_execution_running(execution)

    def _mark_failed(self, execution: RPCExecution, message: str, code: str) -> None:
        mark_execution_failed(execution, message, code)


def _call_backend(
    target: BackendTarget,
    execution: RPCExecution,
    *,
    lease: Any = None,
) -> dict[str, Any]:
    url = f"{target.url.rstrip('/')}/rpc/executions/{execution.pk}/run"
    timeout = (10, max(execution.procedure.timeout_seconds + 10, 30))
    # #168: when a signed dispatch lease was minted, hand it to the backend in
    # the body. Prod-safe: with no signing key configured the lease is None and
    # the body stays ``{}`` byte-for-byte, exactly as before.
    body: dict[str, Any] = {}
    if lease is not None:
        body["dispatch_lease"] = lease.to_body()
    try:
        resp = requests.post(
            url,
            headers=target.headers,
            json=body,
            verify=target.verify_ssl,
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        raise RPCExecutionError(
            f"nms-backend is unreachable: {exc}",
            code="RPC_BACKEND_UNREACHABLE",
        ) from exc
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
        if not isinstance(data, dict):
            raise RPCExecutionError(
                f"nms-backend returned HTTP {resp.status_code}",
                code="RPC_BACKEND_ERROR",
            )
        detail = data.get("detail")
        message = (
            detail
            if isinstance(detail, str)
            else data.get("error", f"HTTP {resp.status_code}")
        )
        raise RPCExecutionError(
            str(message), code=str(data.get("code") or "RPC_BACKEND_ERROR")
        )
    return data


def _store_backend_response(execution: RPCExecution, response: dict[str, Any]) -> None:
    record_backend_response(execution, response)


def _event(
    execution: RPCExecution,
    level: str,
    event: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    append_execution_event(execution, level, event, message, data)


def _hash_json(value: object) -> str:
    if value is None:
        return ""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
