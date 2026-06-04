from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import TYPE_CHECKING, Any

import requests
from django.db import IntegrityError
from django.utils import timezone
from netbox.constants import RQ_QUEUE_DEFAULT
from netbox.jobs import JobRunner

from netbox_nms.backend import get_backend

from .constants import (
    HUAWEI_MA5800_R024_START_ONT,
    LINUX_INSTALL_SSH_KEY,
    NGINX_1_CONFIG_DEPLOY,
    NGINX_1_CONFIG_TEST,
    NGINX_1_RELOAD,
    NGINX_1_ROLLBACK,
    UBUNTU_24_DAEMON_RELOAD,
    UBUNTU_24_DISABLE_SERVICE,
    UBUNTU_24_ENABLE_SERVICE,
    UBUNTU_24_JOURNAL_TAIL,
    UBUNTU_24_RELOAD_SERVICE,
    UBUNTU_24_RESTART_SERVICE,
    UBUNTU_24_START_SERVICE,
    UBUNTU_24_STATUS_SERVICE,
    UBUNTU_24_STOP_SERVICE,
)
from .models import RPCLinuxServiceAllowlist, RPCExecution, RPCExecutionEvent

if TYPE_CHECKING:
    from netbox_nms.models import NMSBackend
    from rq.job import Job

logger = logging.getLogger(__name__)

RPC_QUEUE_NAME = RQ_QUEUE_DEFAULT
RPC_JOB_TIMEOUT = 600
_POSIX_USERNAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}$")


class RPCExecutionError(RuntimeError):
    def __init__(self, message: str, *, code: str = "RPC_EXECUTION_FAILED") -> None:
        super().__init__(message)
        self.code = code


class RPCExecutionJob(JobRunner):
    class Meta:
        name = "RPC Execution"

    @classmethod
    def enqueue(cls, *args: Any, **kwargs: Any) -> Job:
        backend_pk = kwargs.pop("backend_pk", None)
        kwargs.setdefault("queue_name", RPC_QUEUE_NAME)
        kwargs.setdefault("job_timeout", RPC_JOB_TIMEOUT)
        # Embed backend_pk in job data before enqueueing so workers can read it
        # without a race between super().enqueue() and a subsequent job.save().
        if backend_pk:
            data = dict(kwargs.get("data") or {})
            data["backend_pk"] = backend_pk
            kwargs["data"] = data
        job = super().enqueue(*args, **kwargs)
        # Persist as a safety fallback in case super().enqueue() ignored the data kwarg.
        if backend_pk and not (job.data or {}).get("backend_pk"):
            job.data = dict(job.data or {})
            job.data["backend_pk"] = backend_pk
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

    if procedure_name in {
        UBUNTU_24_RESTART_SERVICE,
        UBUNTU_24_STATUS_SERVICE,
        UBUNTU_24_START_SERVICE,
        UBUNTU_24_STOP_SERVICE,
        UBUNTU_24_RELOAD_SERVICE,
        UBUNTU_24_ENABLE_SERVICE,
        UBUNTU_24_DISABLE_SERVICE,
        UBUNTU_24_JOURNAL_TAIL,
    }:
        normalized = _normalize_linux_service_execution(execution, target)
        if procedure_name == UBUNTU_24_JOURNAL_TAIL:
            lines = int((execution.params or {}).get("lines", 100))
            normalized["lines"] = lines
        return normalized

    if procedure_name == UBUNTU_24_DAEMON_RELOAD:
        return {
            "target": target,
            "command_fingerprint": {"handler_id": execution.procedure.handler_id},
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

    if procedure_name == LINUX_INSTALL_SSH_KEY:
        return _normalize_ssh_install_key_execution(execution, target)

    if procedure_name == NGINX_1_CONFIG_TEST:
        return _normalize_nginx_node_execution(execution, target, extra_params={})

    if procedure_name == NGINX_1_CONFIG_DEPLOY:
        params = execution.params or {}
        config_content = str(params.get("config_content") or "").strip()
        if not config_content:
            raise RPCExecutionError("config_content must be a non-empty string.", code="RPC_PARAM_INVALID")
        deployment_id = _int_range(params, "deployment_id", 1, None)
        extra: dict[str, Any] = {
            "config_content": config_content,
            "deployment_id": deployment_id,
        }
        config_path = str(params.get("config_path") or "").strip()
        if config_path:
            extra["config_path"] = config_path
        return _normalize_nginx_node_execution(execution, target, extra_params=extra)

    if procedure_name == NGINX_1_RELOAD:
        return _normalize_nginx_node_execution(execution, target, extra_params={})

    if procedure_name == NGINX_1_ROLLBACK:
        params = execution.params or {}
        deployment_id = _int_range(params, "deployment_id", 1, None)
        previous_config = str(params.get("previous_config") or "").strip()
        if not previous_config:
            raise RPCExecutionError(
                "previous_config must be a non-empty string.", code="RPC_PARAM_INVALID"
            )
        extra = {"deployment_id": deployment_id, "previous_config": previous_config}
        return _normalize_nginx_node_execution(execution, target, extra_params=extra)

    raise RPCExecutionError(
        f"Procedure {procedure_name!r} has no NetBox normalizer.",
        code="RPC_PROCEDURE_NOT_NORMALIZABLE",
    )


def _normalize_nginx_node_execution(
    execution: RPCExecution,
    target: str,
    extra_params: dict[str, Any],
) -> dict[str, Any]:
    params = execution.params or {}
    node_id = _int_range(params, "node_id", 1, None)
    result: dict[str, Any] = {
        "target": target,
        "node_id": node_id,
        **extra_params,
    }
    result["command_fingerprint"] = {
        "handler_id": execution.procedure.handler_id,
        "node_id": node_id,
    }
    return result


def _normalize_linux_service_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
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
    result = {
        "target": target,
        "service_slug": slug,
        "systemd_unit": unit,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "systemd_unit": unit,
        },
    }
    if allow.ssh_credential_override_id is not None:
        result["rpc_ssh_credential_pk"] = allow.ssh_credential_override_id
    return result


def _normalize_ssh_install_key_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for os.linux.ubuntu.24.install_ssh_key.

    Validates that public_key is a single-line OpenSSH key (no newlines),
    extracts the optional username, and builds the normalized dict for
    nms-backend to execute the authorized_keys append via SSH.
    """
    params = execution.params or {}
    public_key = str(params.get("public_key") or "").strip()
    if not public_key:
        raise RPCExecutionError("public_key is required.", code="RPC_PARAM_INVALID")
    if "\n" in public_key or "\r" in public_key:
        raise RPCExecutionError(
            "public_key must be a single line without newlines.",
            code="RPC_PARAM_INVALID",
        )
    if not any(
        public_key.startswith(prefix)
        for prefix in ("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")
    ):
        raise RPCExecutionError(
            "public_key must start with a supported key type prefix.",
            code="RPC_PARAM_INVALID",
        )
    # Strip any comment field — only key-type + base64-blob is forwarded to nms-backend.
    # This eliminates comment-field characters from the authorized_keys append path.
    key_parts = public_key.split(None, 2)
    public_key = " ".join(key_parts[:2]) if len(key_parts) >= 2 else public_key

    result: dict[str, Any] = {
        "target": target,
        "public_key": public_key,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "public_key_prefix": public_key[:64],
        },
    }

    username = str(params.get("username") or "").strip()
    if username:
        if not _POSIX_USERNAME_RE.fullmatch(username):
            raise RPCExecutionError(
                "username must be a valid POSIX username "
                "(lowercase letters, digits, _ or -; starts with letter or _; max 32 chars).",
                code="RPC_PARAM_INVALID",
            )
        result["username"] = username

    return result


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


def _call_backend(backend: NMSBackend, execution: RPCExecution) -> dict[str, Any]:
    url = f"{backend.backend_url.rstrip('/')}/rpc/executions/{execution.pk}/run"
    timeout = (10, max(execution.procedure.timeout_seconds + 10, 30))
    try:
        resp = requests.post(
            url,
            headers=backend.get_auth_headers(),
            json={},
            verify=backend.verify_ssl,
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
    from django.db.models import Max
    from django.db.models.functions import Coalesce

    max_seq = execution.events.aggregate(m=Coalesce(Max("sequence"), 0))["m"]
    # Retry up to 3 times on sequence collisions from concurrent RQ workers.
    # Always attempt max_seq+1 after re-reading — never add the loop counter,
    # which would skip valid sequence numbers on re-reads.
    for _ in range(3):
        try:
            RPCExecutionEvent.objects.create(
                execution=execution,
                sequence=max_seq + 1,
                level=level,
                event=event,
                message=message,
                data=data or {},
            )
            return
        except IntegrityError:
            max_seq = execution.events.aggregate(m=Coalesce(Max("sequence"), 0))["m"]
    # Final attempt after exhausting retries; log instead of propagating if this
    # also collides, so an event loss under extreme concurrency doesn't abort the job.
    try:
        RPCExecutionEvent.objects.create(
            execution=execution,
            sequence=max_seq + 1,
            level=level,
            event=event,
            message=message,
            data=data or {},
        )
    except IntegrityError:
        logger.warning(
            "RPCExecutionEvent sequence collision exhausted retries for execution %s "
            "(event=%r). Event dropped.",
            execution.pk,
            event,
        )


def _hash_json(value: object) -> str:
    if value is None:
        return ""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
