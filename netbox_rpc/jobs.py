from __future__ import annotations

import hashlib
import json
import logging
import signal
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import jsonschema
import requests
from netbox.constants import RQ_QUEUE_DEFAULT
from netbox.jobs import JobRunner
from urllib3.util import Timeout as Urllib3Timeout

from .backends import BackendTarget
from .constants import AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL
from .domain.normalization import (
    RPCExecutionError,
    RPCLinuxServiceAllowlist,
    RPCNetBoxPluginAllowlist,
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


class _ProtectedBackendResponseError(ValueError):
    """Raised when a protected backend response exceeds its closed contract."""


class _ProtectedBackendWallClockError(TimeoutError):
    """Raised when a protected request exceeds its request-absolute budget."""


@contextmanager
def _protected_backend_wall_clock(deadline: float):
    """Bound DNS, connect, send, and response headers on the worker main thread."""
    if threading.current_thread() is not threading.main_thread():
        raise _ProtectedBackendWallClockError(
            "protected backend request requires the worker main thread"
        )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _ProtectedBackendWallClockError(
            "protected backend request exceeded its total deadline"
        )
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_remaining, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    if previous_remaining > 0 and previous_remaining <= remaining:
        # The worker's outer death penalty is already the tighter boundary.
        # Leave both its handler and timer untouched so its exception cannot be
        # consumed and projected as an ordinary protected-transport failure.
        yield
        if time.monotonic() >= deadline:
            raise _ProtectedBackendWallClockError(
                "protected backend request exceeded its total deadline"
            )
        return
    started = deadline - remaining
    ended: float | None = None

    def _deadline_exceeded(_signum, _frame) -> None:
        raise _ProtectedBackendWallClockError(
            "protected backend request exceeded its total deadline"
        )

    signal.signal(signal.SIGALRM, _deadline_exceeded)
    signal.setitimer(
        signal.ITIMER_REAL,
        remaining,
    )
    try:
        yield
        ended = time.monotonic()
        if ended >= deadline:
            raise _ProtectedBackendWallClockError(
                "protected backend request exceeded its total deadline"
            )
    finally:
        if ended is None:
            ended = time.monotonic()
        elapsed = ended - started
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_remaining > elapsed:
            signal.setitimer(
                signal.ITIMER_REAL,
                previous_remaining - elapsed,
                previous_interval,
            )


def _set_protected_response_socket_deadline(
    response: requests.Response,
    *,
    deadline: float,
) -> None:
    """Apply the remaining total budget to the next one-byte socket read."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _ProtectedBackendResponseError(
            "protected backend response exceeded its total deadline"
        )
    raw = getattr(response, "raw", None)
    connection = getattr(raw, "_connection", None)
    sock = getattr(connection, "sock", None)
    if sock is None:
        raw_fp = getattr(raw, "_fp", None)
        buffered = getattr(raw_fp, "fp", None)
        socket_io = getattr(buffered, "raw", None)
        sock = getattr(socket_io, "_sock", None)
    settimeout = getattr(sock, "settimeout", None)
    if not callable(settimeout):
        raise _ProtectedBackendResponseError(
            "protected backend response socket is unavailable"
        )
    try:
        settimeout(remaining)
    except OSError as exc:
        raise _ProtectedBackendResponseError(
            "protected backend response deadline could not be applied"
        ) from exc


def _read_bounded_json_response(
    response: requests.Response,
    *,
    deadline: float,
    max_bytes: int,
) -> object:
    """Read one identity-encoded JSON body under byte and monotonic bounds."""
    content_encoding = str(response.headers.get("Content-Encoding") or "").lower()
    if content_encoding not in {"", "identity"}:
        raise _ProtectedBackendResponseError(
            "protected backend response content encoding is forbidden"
        )

    content_length_header = response.headers.get("Content-Length")
    expected_length: int | None = None
    if content_length_header is not None:
        raw_length = str(content_length_header)
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise _ProtectedBackendResponseError(
                "protected backend response Content-Length is invalid"
            )
        expected_length = int(raw_length)
        if expected_length > max_bytes:
            raise _ProtectedBackendResponseError(
                "protected backend response exceeds the byte limit"
            )

    body = bytearray()
    try:
        chunks = iter(response.iter_content(chunk_size=1, decode_unicode=False))
        while expected_length is None or len(body) < expected_length:
            _set_protected_response_socket_deadline(response, deadline=deadline)
            try:
                chunk = next(chunks)
            except StopIteration:
                break
            if not chunk:
                continue
            if not isinstance(chunk, bytes):
                raise _ProtectedBackendResponseError(
                    "protected backend response yielded a non-byte chunk"
                )
            if len(body) + len(chunk) > max_bytes:
                raise _ProtectedBackendResponseError(
                    "protected backend response exceeds the byte limit"
                )
            body.extend(chunk)
            if expected_length is None and len(body) == max_bytes:
                _set_protected_response_socket_deadline(response, deadline=deadline)
                try:
                    extra = next(chunks)
                except StopIteration:
                    extra = b""
                if extra:
                    raise _ProtectedBackendResponseError(
                        "protected backend response exceeds the byte limit"
                    )
                break
        if expected_length is not None and len(body) != expected_length:
            raise _ProtectedBackendResponseError(
                "protected backend response ended before Content-Length"
            )
        if not body:
            raise _ProtectedBackendResponseError(
                "protected backend response body is empty"
            )
        return json.loads(body)
    finally:
        for index in range(len(body)):
            body[index] = 0


__all__ = (
    "BackendTarget",
    "RPCLinuxServiceAllowlist",
    "RPCNetBoxPluginAllowlist",
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


class _BackendTransportKind(Enum):
    GENERIC = "generic"
    GITEA_UPGRADE = "gitea-upgrade"
    GITEA_RUNNER = "gitea-runner"
    GITEA_ORG_CI_RUNNER = "gitea-org-ci-runner"
    DNS_STAGING_DEPLOY = "dns-staging-deploy"
    AKVORADO_INSTALL = "akvorado-install"


_PROCEDURE_TRANSPORT_KINDS = {
    "service.gitea.production.upgrade_1_27_1": (_BackendTransportKind.GITEA_UPGRADE),
    "service.gitea.runner.register": _BackendTransportKind.GITEA_RUNNER,
    "service.gitea.actions_runner.provision_org_ci_runner": (
        _BackendTransportKind.GITEA_ORG_CI_RUNNER
    ),
    "service.netbox.staging.deploy_dns_pair": (
        _BackendTransportKind.DNS_STAGING_DEPLOY
    ),
    AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL: _BackendTransportKind.AKVORADO_INSTALL,
}
_SECRET_PROTECTED_TRANSPORTS = frozenset(
    {
        _BackendTransportKind.GITEA_UPGRADE,
        _BackendTransportKind.GITEA_RUNNER,
        _BackendTransportKind.GITEA_ORG_CI_RUNNER,
        _BackendTransportKind.DNS_STAGING_DEPLOY,
    }
)
_STREAMED_TRANSPORTS = frozenset(
    {
        _BackendTransportKind.GITEA_RUNNER,
        _BackendTransportKind.GITEA_ORG_CI_RUNNER,
        _BackendTransportKind.DNS_STAGING_DEPLOY,
        _BackendTransportKind.AKVORADO_INSTALL,
    }
)
_CONNECT_FAILURE_STAGES = {
    _BackendTransportKind.GITEA_UPGRADE: "execute",
    _BackendTransportKind.GITEA_RUNNER: "generate_token",
    _BackendTransportKind.GITEA_ORG_CI_RUNNER: "preconditions",
    _BackendTransportKind.DNS_STAGING_DEPLOY: "execute",
}


@dataclass(frozen=True)
class _BackendTransportPolicy:
    kind: _BackendTransportKind
    timeout_seconds: int | float
    params: dict[str, Any]
    normalized: dict[str, Any]
    execution: RPCExecution

    @property
    def secret_protected(self) -> bool:
        return self.kind in _SECRET_PROTECTED_TRANSPORTS

    @property
    def streamed(self) -> bool:
        return self.kind in _STREAMED_TRANSPORTS

    @property
    def target_display(self) -> str:
        return str(getattr(self.execution, "target_display", ""))

    @property
    def operation(self) -> str:
        return str(self.params.get("operation") or "register")

    @property
    def runner_scope(self) -> str:
        return str(self.params.get("scope") or "")

    @property
    def org_runner_scope(self) -> str:
        return str(self.normalized.get("scope") or "")

    @property
    def org_runner_lane(self) -> str:
        return str(self.params.get("lane") or "")

    @property
    def dns_commit_sha(self) -> str:
        return str(self.params.get("commit_sha") or "")

    @property
    def fence_digest(self) -> object:
        return self.normalized.get("fence_expected_sha256")

    @property
    def fence_execution_id(self) -> object:
        return self.normalized.get("fence_execution_id")

    @property
    def fence_generation(self) -> object:
        return self.normalized.get("fence_generation")


@dataclass(frozen=True)
class _BackendRequestPlan:
    url: str
    kwargs: dict[str, Any]
    response_deadline: float | None
    response_max_bytes: int | None


@dataclass(frozen=True)
class _BackendRequestResult:
    response: requests.Response | None = None
    failure: dict[str, Any] | None = None


@dataclass(frozen=True)
class _BackendReadResult:
    data: object = None
    failure: dict[str, Any] | None = None


def _resolve_backend_timeout_seconds(
    execution: RPCExecution,
    params: dict[str, Any],
) -> int | float:
    timeout_seconds = params.get(RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY)
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        return execution.procedure.timeout_seconds
    return timeout_seconds


def _resolve_backend_transport_policy(
    execution: RPCExecution,
) -> _BackendTransportPolicy:
    params = execution.params if isinstance(execution.params, dict) else {}
    normalized = getattr(execution, "normalized_params", None)
    procedure_name = str(getattr(execution.procedure, "name", "") or "")
    return _BackendTransportPolicy(
        kind=_PROCEDURE_TRANSPORT_KINDS.get(
            procedure_name,
            _BackendTransportKind.GENERIC,
        ),
        timeout_seconds=_resolve_backend_timeout_seconds(execution, params),
        params=params,
        normalized=normalized if isinstance(normalized, dict) else {},
        execution=execution,
    )


def _protected_response_limits(
    policy: _BackendTransportPolicy,
) -> tuple[float, int] | None:
    if policy.kind is _BackendTransportKind.GITEA_ORG_CI_RUNNER:
        from . import gitea_org_ci_runner_contract as contract
    elif policy.kind is _BackendTransportKind.GITEA_RUNNER:
        from . import gitea_runner_contract as contract
    elif policy.kind is _BackendTransportKind.DNS_STAGING_DEPLOY:
        from . import dns_staging_deploy_contract as contract
    elif policy.kind is _BackendTransportKind.AKVORADO_INSTALL:
        from . import akvorado_bootstrap_contract as contract

        return (
            max(float(policy.timeout_seconds) + 10, 30),
            contract.BACKEND_RESPONSE_MAX_BYTES,
        )
    else:
        return None
    return contract.ROUTE_BUDGET_SECONDS, contract.BACKEND_RESPONSE_MAX_BYTES


def _build_backend_request_plan(
    target: BackendTarget,
    execution: RPCExecution,
    policy: _BackendTransportPolicy,
    lease: Any,
) -> _BackendRequestPlan:
    body: dict[str, Any] = {}
    if lease is not None:
        body["dispatch_lease"] = lease.to_body()
    request_kwargs: dict[str, Any] = {
        "headers": target.headers,
        "json": body,
        "verify": target.verify_ssl,
        "timeout": (10, max(policy.timeout_seconds + 10, 30)),
    }
    if policy.secret_protected or policy.kind is _BackendTransportKind.AKVORADO_INSTALL:
        request_kwargs["allow_redirects"] = False
    limits = _protected_response_limits(policy)
    if limits is None:
        return _BackendRequestPlan(
            url=f"{target.url.rstrip('/')}/rpc/executions/{execution.pk}/run",
            kwargs=request_kwargs,
            response_deadline=None,
            response_max_bytes=None,
        )
    route_budget_seconds, response_max_bytes = limits
    response_deadline = time.monotonic() + route_budget_seconds
    connect_timeout = min(10, route_budget_seconds)
    request_kwargs.update(
        {
            "stream": True,
            "timeout": Urllib3Timeout(
                total=route_budget_seconds,
                connect=connect_timeout,
                read=max(1, route_budget_seconds - connect_timeout),
            ),
        }
    )
    return _BackendRequestPlan(
        url=f"{target.url.rstrip('/')}/rpc/executions/{execution.pk}/run",
        kwargs=request_kwargs,
        response_deadline=response_deadline,
        response_max_bytes=response_max_bytes,
    )


def _closed_backend_transport_failure(
    policy: _BackendTransportPolicy,
    *,
    stage: str,
) -> dict[str, Any]:
    if policy.kind is _BackendTransportKind.AKVORADO_INSTALL:
        return _akvorado_transport_failure_response(policy.target_display)
    if policy.kind is _BackendTransportKind.GITEA_ORG_CI_RUNNER:
        return _gitea_org_ci_runner_transport_failure_response(
            stage=stage,
            operation=policy.operation,
            lane=policy.org_runner_lane,
            scope=policy.org_runner_scope,
            fence_digest=policy.fence_digest,
            fence_execution_id=policy.fence_execution_id,
            fence_generation=policy.fence_generation,
        )
    if policy.kind is _BackendTransportKind.GITEA_RUNNER:
        return _gitea_runner_transport_failure_response(
            stage=stage,
            operation=policy.operation,
            fence_digest=policy.fence_digest,
            fence_execution_id=policy.fence_execution_id,
            fence_generation=policy.fence_generation,
            scope=policy.runner_scope,
        )
    if policy.kind is _BackendTransportKind.DNS_STAGING_DEPLOY:
        return _dns_staging_transport_failure_response(
            commit_sha=policy.dns_commit_sha,
            stage=stage,
        )
    if policy.kind is _BackendTransportKind.GITEA_UPGRADE:
        return _gitea_transport_failure_response(stage=stage)
    raise RuntimeError("generic backend transport has no closed failure envelope")


def _classify_backend_request_failure(
    policy: _BackendTransportPolicy,
    exc: BaseException,
) -> dict[str, Any]:
    if isinstance(exc, _ProtectedBackendWallClockError):
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    if policy.kind is _BackendTransportKind.AKVORADO_INSTALL:
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    if policy.secret_protected:
        connect_timeout = getattr(requests.exceptions, "ConnectTimeout", ())
        stage = (
            _CONNECT_FAILURE_STAGES[policy.kind]
            if isinstance(exc, connect_timeout)
            else "indeterminate"
        )
        return _closed_backend_transport_failure(policy, stage=stage)
    raise RPCExecutionError(
        f"nms-backend is unreachable: {exc}",
        code="RPC_BACKEND_UNREACHABLE",
    ) from exc


def _perform_backend_request(
    plan: _BackendRequestPlan,
    policy: _BackendTransportPolicy,
) -> _BackendRequestResult:
    response: requests.Response | None = None
    try:
        if plan.response_deadline is None:
            response = requests.post(plan.url, **plan.kwargs)
        else:
            with _protected_backend_wall_clock(plan.response_deadline):
                response = requests.post(plan.url, **plan.kwargs)
        return _BackendRequestResult(response=response)
    except _ProtectedBackendWallClockError as exc:
        if response is not None:
            response.close()
        return _BackendRequestResult(
            failure=_classify_backend_request_failure(policy, exc)
        )
    except requests.exceptions.RequestException as exc:
        return _BackendRequestResult(
            failure=_classify_backend_request_failure(policy, exc)
        )


def _classify_backend_http_response(
    policy: _BackendTransportPolicy,
    response: requests.Response,
) -> dict[str, Any] | None:
    if response.status_code == 401 and not policy.secret_protected:
        if policy.kind is _BackendTransportKind.AKVORADO_INSTALL:
            response.close()
        raise RPCExecutionError(
            "nms-backend returned 401 Unauthorized.",
            code="RPC_BACKEND_UNAUTHORIZED",
        )
    if policy.secret_protected and 300 <= response.status_code < 400:
        if policy.streamed:
            response.close()
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    if (
        policy.kind is _BackendTransportKind.AKVORADO_INSTALL
        and 300 <= response.status_code < 400
    ):
        response.close()
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    return None


def _read_backend_response(
    plan: _BackendRequestPlan,
    policy: _BackendTransportPolicy,
    response: requests.Response,
) -> _BackendReadResult:
    try:
        if policy.streamed:
            if plan.response_deadline is None or plan.response_max_bytes is None:
                raise _ProtectedBackendResponseError(
                    "protected backend response deadline is unavailable"
                )
            data = _read_bounded_json_response(
                response,
                deadline=plan.response_deadline,
                max_bytes=plan.response_max_bytes,
            )
        else:
            data = response.json()
    except (ValueError, requests.exceptions.RequestException) as exc:
        if (
            policy.secret_protected
            or policy.kind is _BackendTransportKind.AKVORADO_INSTALL
        ):
            return _BackendReadResult(
                failure=_closed_backend_transport_failure(
                    policy,
                    stage="indeterminate",
                )
            )
        raise RPCExecutionError(
            f"nms-backend returned non-JSON response: HTTP {response.status_code}",
            code="RPC_BACKEND_BAD_RESPONSE",
        ) from exc
    finally:
        if policy.streamed:
            response.close()
    return _BackendReadResult(data=data)


def _closed_response_matches_http_status(
    response: requests.Response,
    normalized: dict[str, Any],
) -> bool:
    return 200 <= response.status_code < 300 or normalized["ok"] is False


def _normalize_gitea_upgrade_backend_response(
    policy: _BackendTransportPolicy,
    response: requests.Response,
    data: object,
) -> dict[str, Any]:
    normalized = _normalize_gitea_closed_response(data)
    if normalized is None or not _closed_response_matches_http_status(
        response,
        normalized,
    ):
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    return normalized


def _normalize_gitea_org_ci_runner_backend_response(
    policy: _BackendTransportPolicy,
    response: requests.Response,
    data: object,
) -> dict[str, Any]:
    normalized = _normalize_gitea_org_ci_runner_closed_response(
        data,
        operation=policy.operation,
        lane=policy.org_runner_lane,
        scope=policy.org_runner_scope,
        fence_execution_id=policy.fence_execution_id,
        fence_generation=policy.fence_generation,
    )
    if normalized is None or not _closed_response_matches_http_status(
        response,
        normalized,
    ):
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    return normalized


def _normalize_gitea_runner_backend_response(
    policy: _BackendTransportPolicy,
    response: requests.Response,
    data: object,
) -> dict[str, Any]:
    normalized = _normalize_gitea_runner_closed_response(
        data,
        operation=policy.operation,
        scope=policy.runner_scope,
        fence_execution_id=policy.fence_execution_id,
        fence_generation=policy.fence_generation,
    )
    if normalized is None or not _closed_response_matches_http_status(
        response,
        normalized,
    ):
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    return normalized


def _normalize_dns_staging_backend_response(
    policy: _BackendTransportPolicy,
    response: requests.Response,
    data: object,
) -> dict[str, Any]:
    normalized = _normalize_dns_staging_closed_response(
        data,
        commit_sha=policy.dns_commit_sha,
    )
    if normalized is None or not _closed_response_matches_http_status(
        response,
        normalized,
    ):
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    return normalized


def _normalize_generic_backend_response(
    response: requests.Response,
    data: object,
) -> Any:
    if response.status_code < 400:
        return data
    if not isinstance(data, dict):
        raise RPCExecutionError(
            f"nms-backend returned HTTP {response.status_code}",
            code="RPC_BACKEND_ERROR",
        )
    detail = data.get("detail")
    message = (
        detail
        if isinstance(detail, str)
        else data.get("error", f"HTTP {response.status_code}")
    )
    raise RPCExecutionError(
        str(message),
        code=str(data.get("code") or "RPC_BACKEND_ERROR"),
    )


def _normalize_akvorado_backend_response(
    policy: _BackendTransportPolicy,
    execution: RPCExecution,
    response: requests.Response,
    data: object,
) -> Any:
    if response.status_code in {408, 504} or response.status_code >= 500:
        return _closed_backend_transport_failure(policy, stage="indeterminate")
    if 200 <= response.status_code < 300:
        normalized = _normalize_akvorado_install_closed_response(execution, data)
        if normalized is None:
            return _closed_backend_transport_failure(policy, stage="indeterminate")
        return normalized
    return _normalize_generic_backend_response(response, data)


def _normalize_backend_response(
    policy: _BackendTransportPolicy,
    execution: RPCExecution,
    response: requests.Response,
    data: object,
) -> Any:
    if policy.kind is _BackendTransportKind.GITEA_UPGRADE:
        return _normalize_gitea_upgrade_backend_response(policy, response, data)
    if policy.kind is _BackendTransportKind.GITEA_ORG_CI_RUNNER:
        return _normalize_gitea_org_ci_runner_backend_response(policy, response, data)
    if policy.kind is _BackendTransportKind.GITEA_RUNNER:
        return _normalize_gitea_runner_backend_response(policy, response, data)
    if policy.kind is _BackendTransportKind.DNS_STAGING_DEPLOY:
        return _normalize_dns_staging_backend_response(policy, response, data)
    if policy.kind is _BackendTransportKind.AKVORADO_INSTALL:
        return _normalize_akvorado_backend_response(
            policy,
            execution,
            response,
            data,
        )
    return _normalize_generic_backend_response(response, data)


def _call_backend(
    target: BackendTarget,
    execution: RPCExecution,
    *,
    lease: Any = None,
) -> dict[str, Any]:
    policy = _resolve_backend_transport_policy(execution)
    plan = _build_backend_request_plan(target, execution, policy, lease)
    request_result = _perform_backend_request(plan, policy)
    if request_result.failure is not None:
        return request_result.failure
    resp = request_result.response
    if resp is None:
        raise RPCExecutionError(
            "nms-backend returned no response.",
            code="RPC_BACKEND_BAD_RESPONSE",
        )
    early_failure = _classify_backend_http_response(policy, resp)
    if early_failure is not None:
        return early_failure
    read_result = _read_backend_response(plan, policy, resp)
    if read_result.failure is not None:
        return read_result.failure
    data = read_result.data
    return _normalize_backend_response(policy, execution, resp, data)


def _akvorado_transport_failure_response(target: object) -> dict[str, Any]:
    """Return the closed reconciliation-required Akvorado install result."""
    services = [
        "clickhouse",
        "console",
        "inlet",
        "kafka",
        "orchestrator",
        "outlet",
        "redis",
    ]
    return {
        "ok": False,
        "result": {
            "ok": False,
            "procedure": AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL,
            "target": str(target)[:255],
            "installed": None,
            "changed": None,
            "config_created": None,
            "docker_package_version": "",
            "compose_package_version": "",
            "docker_version": "",
            "compose_version": "",
            "compose_path": "/opt/nmulticloud/deploy/compose/akvorado/docker-compose.yml",
            "config_path": "/opt/nmulticloud/deploy/compose/akvorado/akvorado.yaml",
            "stack_healthy": False,
            "services_expected": services,
            "services_running": [],
            "services_healthy": [],
            "console_ready": False,
            "ingress_ports_ready": False,
            "ready": False,
            "stage": "outcome_unknown",
            "warnings": ["Run Akvorado bootstrap preflight before retrying."],
            "error": "Backend transport outcome is indeterminate.",
        },
    }


def _normalize_akvorado_install_closed_response(
    execution: Any,
    data: object,
) -> dict[str, Any] | None:
    """Validate the complete install wire envelope before persisting certainty."""
    if not isinstance(data, dict) or set(data) != {
        "ok",
        "result",
        "events",
        "error_code",
        "error_message",
    }:
        return None
    if type(data.get("ok")) is not bool:
        return None
    result = data.get("result")
    if not isinstance(result, dict) or result.get("ok") is not data["ok"]:
        return None
    if not isinstance(data.get("events"), list):
        return None
    if not isinstance(data.get("error_code"), str) or not isinstance(
        data.get("error_message"), str
    ):
        return None
    if data["ok"] and (data["error_code"] or data["error_message"]):
        return None
    if result.get("target") != str(getattr(execution, "target_display", ""))[:255]:
        return None
    result_schema = getattr(
        getattr(execution, "procedure", None), "result_schema", None
    )
    if not isinstance(result_schema, dict) or not result_schema:
        return None
    try:
        jsonschema.validate(result, result_schema)
    except jsonschema.ValidationError:
        return None
    return data


def _gitea_transport_failure_response(*, stage: str) -> dict[str, Any]:
    """Return the exact closed failure tuple for a protected transport outcome."""
    from . import gitea_upgrade_contract as contract

    is_indeterminate = stage == "indeterminate"
    return {
        "ok": False,
        "result": {
            "ok": False,
            "procedure": contract.PROCEDURE_NAME,
            "target": contract.TARGET_NAME,
            "changed": None if is_indeterminate else False,
            "healthy": None if is_indeterminate else False,
            "stage": stage,
        },
    }


def _dns_staging_transport_failure_response(
    *,
    commit_sha: str,
    stage: str,
) -> dict[str, Any]:
    """Return the conservative exact-SHA result for a transport failure."""
    from . import dns_staging_deploy_contract as contract

    safe_commit = (
        commit_sha
        if len(commit_sha) == 40
        and all(character in "0123456789abcdef" for character in commit_sha)
        else "0" * 40
    )
    indeterminate = stage == "indeterminate"
    return {
        "ok": False,
        "result": {
            "ok": False,
            "procedure": contract.PROCEDURE_NAME,
            "target": contract.TARGET,
            "commit_sha": safe_commit,
            "deployed": None if indeterminate else False,
            "stage": stage,
        },
    }


def _normalize_dns_staging_closed_response(
    data: object,
    *,
    commit_sha: str,
) -> dict[str, Any] | None:
    """Validate the output-free DNS deploy envelope and exact commit binding."""
    from . import dns_staging_deploy_contract as contract

    if not isinstance(data, dict) or set(data) != {
        "ok",
        "result",
        "events",
        "error_code",
        "error_message",
    }:
        return None
    result = data.get("result")
    if (
        type(data.get("ok")) is not bool
        or not isinstance(result, dict)
        or result.get("ok") is not data["ok"]
        or result.get("commit_sha") != commit_sha
        or data.get("events") != []
        or not isinstance(data.get("error_code"), str)
        or not isinstance(data.get("error_message"), str)
        or (data["ok"] and (data["error_code"] or data["error_message"]))
    ):
        return None
    try:
        jsonschema.validate(result, contract.RESULT_SCHEMA)
    except jsonschema.ValidationError:
        return None
    return {"ok": data["ok"], "result": result}


def _gitea_runner_transport_failure_response(
    *,
    stage: str,
    operation: str,
    fence_digest: object,
    fence_execution_id: object,
    fence_generation: object,
    scope: str,
) -> dict[str, Any]:
    """Return a closed conservative result for a registration transport failure."""
    from . import gitea_runner_contract as contract

    safe_operation = operation if operation in contract.OPERATIONS else "register"
    if safe_operation == "reconcile":
        stage = "reconcile" if stage == "generate_token" else stage
    indeterminate = stage == "indeterminate"
    safe_scope = scope if scope in contract.SCOPES else contract.SCOPES[0]
    safe_fence_execution_id = (
        fence_execution_id
        if isinstance(fence_execution_id, int)
        and not isinstance(fence_execution_id, bool)
        and 0 < fence_execution_id <= contract.JS_SAFE_INTEGER_MAX
        else None
    )
    safe_fence_generation = (
        fence_generation
        if isinstance(fence_generation, int)
        and not isinstance(fence_generation, bool)
        and 0 < fence_generation <= contract.JS_SAFE_INTEGER_MAX
        else 1
    )
    if (
        not isinstance(fence_digest, str)
        or len(fence_digest) != 64
        or any(character not in "0123456789abcdef" for character in fence_digest)
    ):
        fence_digest = contract.FENCE_UNKNOWN_SHA256
    if safe_operation == "reconcile":
        result = {
            "ok": False,
            "procedure": contract.PROCEDURE_NAME,
            "target": contract.RUNNER_TARGET_NAME,
            "operation": safe_operation,
            "scope": safe_scope,
            "fence_execution_id": safe_fence_execution_id,
            "fence_generation": safe_fence_generation,
            "registered": None,
            "reconciled": False,
            "token_invalidated": False,
            "token_reset_required": True,
            "token_sha256": fence_digest,
            "reset_state": "indeterminate",
            "prior_token_id": None,
            "prior_active_sha256": None,
            "replacement_token_id": None,
            "stage": stage,
        }
        return {"ok": False, "result": result}
    return {
        "ok": False,
        "result": {
            "ok": False,
            "procedure": contract.PROCEDURE_NAME,
            "target": contract.RUNNER_TARGET_NAME,
            "operation": safe_operation,
            "scope": safe_scope,
            "fence_execution_id": safe_fence_execution_id,
            "fence_generation": safe_fence_generation,
            "registered": None if indeterminate else False,
            "reconciled": None,
            "token_invalidated": False,
            "token_reset_required": indeterminate,
            "token_sha256": None,
            "reset_state": "indeterminate" if indeterminate else "not_started",
            "prior_token_id": None,
            "prior_active_sha256": None,
            "replacement_token_id": None,
            "stage": stage,
        },
    }


def _normalize_gitea_runner_closed_response(
    data: object,
    *,
    operation: str,
    scope: str,
    fence_execution_id: object,
    fence_generation: object,
) -> dict[str, Any] | None:
    """Validate the secret-silent runner response envelope and result schema."""
    import jsonschema

    from . import gitea_runner_contract as contract

    if not isinstance(data, dict) or set(data) != {
        "ok",
        "result",
        "events",
        "error_code",
        "error_message",
    }:
        return None
    result = data.get("result")
    if (
        type(data.get("ok")) is not bool
        or not isinstance(result, dict)
        or result.get("ok") is not data["ok"]
        or result.get("operation") != operation
        or result.get("scope") != scope
        or result.get("fence_execution_id") != fence_execution_id
        or result.get("fence_generation") != fence_generation
        or data.get("events") != []
        or not isinstance(data.get("error_code"), str)
        or not isinstance(data.get("error_message"), str)
        or (data["ok"] and (data["error_code"] or data["error_message"]))
    ):
        return None
    try:
        jsonschema.validate(result, contract.RESULT_SCHEMA)
    except jsonschema.ValidationError:
        return None
    return {
        "ok": data["ok"],
        "result": result,
    }


def _gitea_org_ci_runner_transport_failure_response(
    *,
    stage: str,
    operation: str,
    lane: str,
    scope: str,
    fence_digest: object,
    fence_execution_id: object,
    fence_generation: object,
) -> dict[str, Any]:
    """Return a secret-silent, schema-valid conservative org-runner result."""
    from . import gitea_org_ci_runner_contract as contract

    safe_operation = operation if operation in contract.OPERATIONS else "provision"
    safe_lane = lane if lane in contract.LANES else "root-python312"
    expected_scope = contract.SCOPE_BY_LANE[safe_lane]
    safe_scope = scope if scope == expected_scope else expected_scope
    safe_fence_execution_id = (
        fence_execution_id
        if isinstance(fence_execution_id, int)
        and not isinstance(fence_execution_id, bool)
        and 0 < fence_execution_id <= 9_007_199_254_740_991
        else None
    )
    safe_fence_generation = (
        fence_generation
        if isinstance(fence_generation, int)
        and not isinstance(fence_generation, bool)
        and 0 < fence_generation <= contract.JS_SAFE_INTEGER_MAX
        else 1
    )
    valid_digest = bool(
        isinstance(fence_digest, str)
        and len(fence_digest) == 64
        and all(character in "0123456789abcdef" for character in fence_digest)
    )
    safe_digest = fence_digest if valid_digest else contract.FENCE_UNKNOWN_SHA256
    common = {
        "ok": False,
        "procedure": contract.PROCEDURE_NAME,
        "target": contract.TARGET_NAME,
        "operation": safe_operation,
        "scope": safe_scope,
        "lane": safe_lane,
        "fence_execution_id": safe_fence_execution_id,
        "fence_generation": safe_fence_generation,
        "organization": contract.DEFAULT_ORGANIZATION,
        "gitea_instance_url": contract.DEFAULT_GITEA_INSTANCE_URL,
        "prior_token_id": None,
        "prior_active_sha256": None,
        "replacement_token_id": None,
        **contract.LANES[safe_lane],
    }
    if safe_operation == "reconcile":
        result = {
            **common,
            "provisioned": None,
            "registered": None,
            "reconciled": False,
            "stage": "reconcile" if stage != "indeterminate" else stage,
            "token_invalidated": False,
            "token_reset_required": True,
            "token_sha256": safe_digest,
            "reset_state": "indeterminate",
        }
    else:
        indeterminate = stage == "indeterminate"
        result = {
            **common,
            "provisioned": None if indeterminate else False,
            "registered": None if indeterminate else False,
            "reconciled": None,
            "stage": stage,
            "token_invalidated": False,
            "token_reset_required": indeterminate,
            "token_sha256": None,
            "reset_state": "indeterminate" if indeterminate else "not_started",
        }
    return {"ok": False, "result": result}


def _normalize_gitea_org_ci_runner_closed_response(
    data: object,
    *,
    operation: str,
    lane: str,
    scope: str,
    fence_execution_id: object,
    fence_generation: object,
) -> dict[str, Any] | None:
    """Validate the five-key org-runner envelope and discard diagnostics."""
    import jsonschema

    from . import gitea_org_ci_runner_contract as contract

    if not isinstance(data, dict) or set(data) != {
        "ok",
        "result",
        "events",
        "error_code",
        "error_message",
    }:
        return None
    result = data.get("result")
    if (
        type(data.get("ok")) is not bool
        or not isinstance(result, dict)
        or result.get("ok") is not data["ok"]
        or result.get("operation") != operation
        or result.get("lane") != lane
        or result.get("scope") != scope
        or result.get("fence_execution_id") != fence_execution_id
        or result.get("fence_generation") != fence_generation
        or data.get("events") != []
        or not isinstance(data.get("error_code"), str)
        or not isinstance(data.get("error_message"), str)
        or (data["ok"] and (data["error_code"] or data["error_message"]))
    ):
        return None
    try:
        jsonschema.validate(result, contract.RESULT_SCHEMA)
    except jsonschema.ValidationError:
        return None
    return {"ok": data["ok"], "result": result}


def _normalize_gitea_closed_response(data: object) -> dict[str, Any] | None:
    """Validate the five-key backend wire envelope and discard diagnostics."""
    from . import gitea_upgrade_contract as contract

    if not isinstance(data, dict) or set(data) != {
        "ok",
        "result",
        "events",
        "error_code",
        "error_message",
    }:
        return None
    if type(data.get("ok")) is not bool:
        return None
    result = data.get("result")
    if not isinstance(result, dict) or result.get("ok") is not data["ok"]:
        return None
    if data.get("events") != []:
        return None
    if not isinstance(data.get("error_code"), str) or not isinstance(
        data.get("error_message"), str
    ):
        return None
    if data["ok"] and (data["error_code"] or data["error_message"]):
        return None
    try:
        jsonschema.validate(result, contract.RESULT_SCHEMA)
    except jsonschema.ValidationError:
        return None
    # Never carry backend-controlled diagnostics into the event store.  It
    # derives bounded static values solely from this validated result tuple.
    return {"ok": data["ok"], "result": result}


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
