from __future__ import annotations

import hashlib
import json
import logging
import signal
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import jsonschema
import requests
from netbox.constants import RQ_QUEUE_DEFAULT
from netbox.jobs import JobRunner
from urllib3.util import Timeout as Urllib3Timeout

from .backends import BackendTarget
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
    started = deadline - remaining
    ended: float | None = None

    def _deadline_exceeded(_signum, _frame) -> None:
        raise _ProtectedBackendWallClockError(
            "protected backend request exceeded its total deadline"
        )

    signal.signal(signal.SIGALRM, _deadline_exceeded)
    signal.setitimer(
        signal.ITIMER_REAL,
        min(remaining, previous_remaining) if previous_remaining > 0 else remaining,
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


def _call_backend(
    target: BackendTarget,
    execution: RPCExecution,
    *,
    lease: Any = None,
) -> dict[str, Any]:
    url = f"{target.url.rstrip('/')}/rpc/executions/{execution.pk}/run"
    # #215: prefer the timeout_seconds snapshot command_handlers.create_execution()
    # stamped into params at enqueue time over the (mutable) procedure's
    # *current* timeout_seconds, so this HTTP read timeout and the RQ
    # job_timeout already committed at enqueue are always derived from the
    # same frozen value and can never diverge if an operator edited
    # procedure.timeout_seconds while this execution sat queued. Executions
    # created before this fix (or missing the snapshot for any other reason)
    # fall back to the live procedure value, unchanged from prior behavior.
    params = execution.params if isinstance(execution.params, dict) else {}
    timeout_seconds = params.get(RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY)
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        timeout_seconds = execution.procedure.timeout_seconds
    timeout = (10, max(timeout_seconds + 10, 30))
    # #168: when a signed dispatch lease was minted, hand it to the backend in
    # the body. Prod-safe: with no signing key configured the lease is None and
    # the body stays ``{}`` byte-for-byte, exactly as before.
    body: dict[str, Any] = {}
    if lease is not None:
        body["dispatch_lease"] = lease.to_body()
    is_gitea_upgrade = (
        str(getattr(execution.procedure, "name", "") or "")
        == "service.gitea.production.upgrade_1_27_1"
    )
    is_gitea_runner = (
        str(getattr(execution.procedure, "name", "") or "")
        == "service.gitea.runner.register"
    )
    is_dns_staging_deploy = (
        str(getattr(execution.procedure, "name", "") or "")
        == "service.netbox.staging.deploy_dns_pair"
    )
    dns_commit_sha = str(params.get("commit_sha") or "")
    gitea_runner_scope = str(params.get("scope") or "")
    gitea_runner_operation = str(params.get("operation") or "register")
    execution_normalized = getattr(execution, "normalized_params", None)
    gitea_runner_fence_digest = (
        execution_normalized.get("fence_expected_sha256")
        if isinstance(execution_normalized, dict)
        else None
    )
    is_secret_protected = is_gitea_upgrade or is_gitea_runner or is_dns_staging_deploy
    # The org CI runner provisioning procedure resolves a vaulted registration
    # token, so its backend response must be handled on the secret-protected
    # path -- redirect-free, byte-bounded, reduced to a closed envelope with
    # backend diagnostics discarded, exactly as the two procedures above are.
    # That closed envelope does not exist yet; it belongs with the paired
    # netbox-rpc-backend handler, which is out of scope here.
    #
    # Until then, refuse to dispatch rather than fall through to the GENERIC
    # path, which follows redirects, calls unbounded resp.json(), and copies
    # backend-controlled diagnostics (error_message, error, warnings,
    # container_state, service_state) into the event ledger. An opaque
    # registration credential in any of those fields is not recognised by the
    # regex redactor and would reach the audit log.
    #
    # The catalog row is seeded disabled and _GITEA_ORG_CI_RUNNER_AVAILABLE is
    # False, so this is unreachable today; it is here so that opening those
    # gates alone cannot silently expose the leak path. See netbox-rpc #280.
    if (
        str(getattr(execution.procedure, "name", "") or "")
        == "service.gitea.actions_runner.provision_org_ci_runner"
    ):
        raise RPCExecutionError(
            "service.gitea.actions_runner.provision_org_ci_runner has no "
            "secret-protected backend transport yet; it must not be dispatched "
            "through the generic response path.",
            code="RPC_PROCEDURE_NOT_AVAILABLE",
        )
    runner_response_deadline: float | None = None
    request_kwargs: dict[str, Any] = {
        "headers": target.headers,
        "json": body,
        "verify": target.verify_ssl,
        "timeout": timeout,
    }
    if is_secret_protected:
        # The protected Gitea lease is approved for one concrete backend
        # destination and must never be replayed by requests across a redirect.
        # Legacy procedure calls keep their byte-for-byte request behavior.
        request_kwargs["allow_redirects"] = False
    if is_gitea_runner or is_dns_staging_deploy:
        if is_gitea_runner:
            from . import gitea_runner_contract as response_contract
        else:
            from . import dns_staging_deploy_contract as response_contract

        runner_response_deadline = (
            time.monotonic() + response_contract.ROUTE_BUDGET_SECONDS
        )
        request_kwargs["stream"] = True
        connect_timeout = min(10, response_contract.ROUTE_BUDGET_SECONDS)
        request_kwargs["timeout"] = Urllib3Timeout(
            total=response_contract.ROUTE_BUDGET_SECONDS,
            connect=connect_timeout,
            read=max(
                1,
                response_contract.ROUTE_BUDGET_SECONDS - connect_timeout,
            ),
        )
    resp: requests.Response | None = None
    try:
        if runner_response_deadline is None:
            resp = requests.post(url, **request_kwargs)
        else:
            with _protected_backend_wall_clock(runner_response_deadline):
                resp = requests.post(url, **request_kwargs)
    except _ProtectedBackendWallClockError:
        if resp is not None:
            resp.close()
        if is_gitea_runner:
            return _gitea_runner_transport_failure_response(
                stage="indeterminate",
                operation=gitea_runner_operation,
                fence_digest=gitea_runner_fence_digest,
                scope=gitea_runner_scope,
            )
        return _dns_staging_transport_failure_response(
            commit_sha=dns_commit_sha,
            stage="indeterminate",
        )
    except requests.exceptions.RequestException as exc:
        if is_secret_protected:
            connect_timeout = getattr(requests.exceptions, "ConnectTimeout", ())
            if isinstance(exc, connect_timeout):
                if is_gitea_runner:
                    return _gitea_runner_transport_failure_response(
                        stage="generate_token",
                        operation=gitea_runner_operation,
                        fence_digest=gitea_runner_fence_digest,
                        scope=gitea_runner_scope,
                    )
                if is_dns_staging_deploy:
                    return _dns_staging_transport_failure_response(
                        commit_sha=dns_commit_sha,
                        stage="execute",
                    )
                return _gitea_transport_failure_response(stage="execute")
            if is_gitea_runner:
                return _gitea_runner_transport_failure_response(
                    stage="indeterminate",
                    operation=gitea_runner_operation,
                    fence_digest=gitea_runner_fence_digest,
                    scope=gitea_runner_scope,
                )
            if is_dns_staging_deploy:
                return _dns_staging_transport_failure_response(
                    commit_sha=dns_commit_sha,
                    stage="indeterminate",
                )
            return _gitea_transport_failure_response(stage="indeterminate")
        raise RPCExecutionError(
            f"nms-backend is unreachable: {exc}",
            code="RPC_BACKEND_UNREACHABLE",
        ) from exc
    if resp is None:
        raise RPCExecutionError(
            "nms-backend returned no response.",
            code="RPC_BACKEND_BAD_RESPONSE",
        )
    if resp.status_code == 401 and not is_secret_protected:
        raise RPCExecutionError(
            "nms-backend returned 401 Unauthorized.",
            code="RPC_BACKEND_UNAUTHORIZED",
        )
    if is_secret_protected and 300 <= resp.status_code < 400:
        # The request reached the approved origin but a redirect response says
        # nothing trustworthy about whether that origin dispatched work.  Do
        # not parse or follow it; persist the exact ambiguous outcome.
        if is_gitea_runner:
            resp.close()
            return _gitea_runner_transport_failure_response(
                stage="indeterminate",
                operation=gitea_runner_operation,
                fence_digest=gitea_runner_fence_digest,
                scope=gitea_runner_scope,
            )
        if is_dns_staging_deploy:
            resp.close()
            return _dns_staging_transport_failure_response(
                commit_sha=dns_commit_sha,
                stage="indeterminate",
            )
        return _gitea_transport_failure_response(stage="indeterminate")
    try:
        if is_gitea_runner or is_dns_staging_deploy:
            if is_gitea_runner:
                from . import gitea_runner_contract as response_contract
            else:
                from . import dns_staging_deploy_contract as response_contract

            if runner_response_deadline is None:
                raise _ProtectedBackendResponseError(
                    "protected backend response deadline is unavailable"
                )
            data = _read_bounded_json_response(
                resp,
                deadline=runner_response_deadline,
                max_bytes=response_contract.BACKEND_RESPONSE_MAX_BYTES,
            )
        else:
            data = resp.json()
    except (ValueError, requests.exceptions.RequestException) as exc:
        if is_secret_protected:
            if is_gitea_runner:
                return _gitea_runner_transport_failure_response(
                    stage="indeterminate",
                    operation=gitea_runner_operation,
                    fence_digest=gitea_runner_fence_digest,
                    scope=gitea_runner_scope,
                )
            if is_dns_staging_deploy:
                return _dns_staging_transport_failure_response(
                    commit_sha=dns_commit_sha,
                    stage="indeterminate",
                )
            return _gitea_transport_failure_response(stage="indeterminate")
        raise RPCExecutionError(
            f"nms-backend returned non-JSON response: HTTP {resp.status_code}",
            code="RPC_BACKEND_BAD_RESPONSE",
        ) from exc
    finally:
        if is_gitea_runner or is_dns_staging_deploy:
            resp.close()
    if is_gitea_upgrade:
        normalized = _normalize_gitea_closed_response(data)
        if normalized is None:
            return _gitea_transport_failure_response(stage="indeterminate")
        if not 200 <= resp.status_code < 300 and normalized["ok"] is not False:
            return _gitea_transport_failure_response(stage="indeterminate")
        return normalized
    if is_gitea_runner:
        normalized = _normalize_gitea_runner_closed_response(data)
        if normalized is None:
            return _gitea_runner_transport_failure_response(
                stage="indeterminate",
                operation=gitea_runner_operation,
                fence_digest=gitea_runner_fence_digest,
                scope=gitea_runner_scope,
            )
        if not 200 <= resp.status_code < 300 and normalized["ok"] is not False:
            return _gitea_runner_transport_failure_response(
                stage="indeterminate",
                operation=gitea_runner_operation,
                fence_digest=gitea_runner_fence_digest,
                scope=gitea_runner_scope,
            )
        return normalized
    if is_dns_staging_deploy:
        normalized = _normalize_dns_staging_closed_response(
            data,
            commit_sha=dns_commit_sha,
        )
        if normalized is None:
            return _dns_staging_transport_failure_response(
                commit_sha=dns_commit_sha,
                stage="indeterminate",
            )
        if not 200 <= resp.status_code < 300 and normalized["ok"] is not False:
            return _dns_staging_transport_failure_response(
                commit_sha=dns_commit_sha,
                stage="indeterminate",
            )
        return normalized
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
    scope: str,
) -> dict[str, Any]:
    """Return a closed conservative result for a registration transport failure."""
    from . import gitea_runner_contract as contract

    safe_operation = operation if operation in contract.OPERATIONS else "register"
    if safe_operation == "reconcile":
        stage = "reconcile" if stage == "generate_token" else stage
    indeterminate = stage == "indeterminate"
    safe_scope = scope if scope in contract.SCOPES else contract.SCOPES[0]
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


def _normalize_gitea_runner_closed_response(data: object) -> dict[str, Any] | None:
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
