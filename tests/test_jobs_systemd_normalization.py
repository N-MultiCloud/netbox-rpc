from __future__ import annotations

import importlib
import json
import sys
import types
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SERVICE_PROCEDURES = (
    ("os.linux.ubuntu.24.status_service", "os.linux_ubuntu_24.status_service"),
    ("os.linux.ubuntu.24.start_service", "os.linux_ubuntu_24.start_service"),
    ("os.linux.ubuntu.24.stop_service", "os.linux_ubuntu_24.stop_service"),
    ("os.linux.ubuntu.24.reload_service", "os.linux_ubuntu_24.reload_service"),
    ("os.linux.ubuntu.24.enable_service", "os.linux_ubuntu_24.enable_service"),
    ("os.linux.ubuntu.24.disable_service", "os.linux_ubuntu_24.disable_service"),
    ("os.linux.ubuntu.24.journal_tail", "os.linux_ubuntu_24.journal_tail"),
)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.mark.parametrize(("procedure_name", "handler_id"), SERVICE_PROCEDURES)
def test_systemd_service_procedures_normalize_allowlisted_service(
    jobs_module,
    procedure_name: str,
    handler_id: str,
) -> None:
    allow = SimpleNamespace(systemd_unit="nginx.service", target_models=["dcim.device"])
    filter_mock = _mock_allowlist(jobs_module, allow)
    execution = _execution(
        procedure_name,
        handler_id,
        {"service_slug": " nginx "},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "edge-01"
    assert normalized["service_slug"] == "nginx"
    assert normalized["systemd_unit"] == "nginx.service"
    assert normalized["command_fingerprint"]["handler_id"] == handler_id
    assert normalized["command_fingerprint"]["systemd_unit"] == "nginx.service"
    if procedure_name == "os.linux.ubuntu.24.journal_tail":
        assert normalized["lines"] == 100
    filter_mock.assert_called_once_with(slug="nginx", enabled=True)


@pytest.mark.parametrize(("procedure_name", "handler_id"), SERVICE_PROCEDURES)
def test_systemd_service_procedures_reject_not_allowlisted_service(
    jobs_module,
    procedure_name: str,
    handler_id: str,
) -> None:
    filter_mock = _mock_allowlist(jobs_module, None)
    execution = _execution(procedure_name, handler_id, {"service_slug": "missing"})

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_LINUX_SERVICE_NOT_ALLOWLISTED"
    assert "missing" in str(exc_info.value)
    filter_mock.assert_called_once_with(slug="missing", enabled=True)


def test_daemon_reload_skips_allowlist_lookup(jobs_module) -> None:
    filter_mock = MagicMock()
    jobs_module.RPCLinuxServiceAllowlist.objects = SimpleNamespace(filter=filter_mock)
    execution = _execution(
        "os.linux.ubuntu.24.daemon_reload",
        "os.linux_ubuntu_24.daemon_reload",
        {},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized == {
        "target": "edge-01",
        "command_fingerprint": {"handler_id": "os.linux_ubuntu_24.daemon_reload"},
    }
    filter_mock.assert_not_called()


@pytest.mark.parametrize(
    ("params", "expected_lines"), [({}, 100), ({"lines": 250}, 250)]
)
def test_journal_tail_normalizes_lines(
    jobs_module,
    params: dict[str, int],
    expected_lines: int,
) -> None:
    allow = SimpleNamespace(systemd_unit="nginx.service", target_models=["dcim.device"])
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        "os.linux.ubuntu.24.journal_tail",
        "os.linux_ubuntu_24.journal_tail",
        {"service_slug": "nginx", **params},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["lines"] == expected_lines


def test_linux_service_normalization_includes_ssh_credential_override_pk(
    jobs_module,
) -> None:
    allow = SimpleNamespace(
        systemd_unit="nginx.service",
        target_models=["dcim.device"],
        ssh_credential_override_id=42,
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        "os.linux.ubuntu.24.status_service",
        "os.linux_ubuntu_24.status_service",
        {"service_slug": "nginx"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 42


def test_linux_service_normalization_omits_ssh_credential_override_pk_when_unset(
    jobs_module,
) -> None:
    allow = SimpleNamespace(
        systemd_unit="nginx.service",
        target_models=["dcim.device"],
        ssh_credential_override_id=None,
    )
    _mock_allowlist(jobs_module, allow)
    execution = _execution(
        "os.linux.ubuntu.24.status_service",
        "os.linux_ubuntu_24.status_service",
        {"service_slug": "nginx"},
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert "rpc_ssh_credential_pk" not in normalized


def test_call_backend_wraps_request_errors_as_backend_unreachable(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = jobs_module.BackendTarget(
        url="http://nms-backend.example",
        headers={"Authorization": "Token test"},
        verify_ssl=True,
    )
    # #215: _call_backend() reads execution.params for the frozen
    # TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY snapshot before falling back to
    # procedure.timeout_seconds; params={} exercises that fallback path.
    execution = SimpleNamespace(
        pk=123, procedure=SimpleNamespace(timeout_seconds=20), params={}
    )
    post_mock = MagicMock(
        side_effect=jobs_module.requests.exceptions.ConnectionError(
            "connection refused"
        )
    )
    monkeypatch.setattr(jobs_module.requests, "post", post_mock)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module._call_backend(target, execution)

    assert exc_info.value.code == "RPC_BACKEND_UNREACHABLE"
    post_mock.assert_called_once_with(
        "http://nms-backend.example/rpc/executions/123/run",
        headers={"Authorization": "Token test"},
        json={},
        verify=True,
        timeout=(10, 30),
    )


def _streaming_response(status_code: int, payload: object) -> MagicMock:
    encoded = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    response = MagicMock(status_code=status_code)
    response.headers = {"Content-Length": str(len(encoded))}
    response.iter_content.return_value = iter(
        encoded[index : index + 1] for index in range(len(encoded))
    )
    return response


@pytest.mark.parametrize(
    "failure_kind",
    [
        "request-error",
        "redirect",
        "server-error",
        "http-408-json",
        "http-408-non-json",
        "non-json",
        "wrong-json-shape",
        "dict-missing-result",
        "dict-invalid-result",
        "dict-envelope-extra",
        "dict-ok-mismatch",
    ],
)
def test_akvorado_install_transport_ambiguity_requires_reconciliation(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    target = jobs_module.BackendTarget(
        url="http://nms-backend.example",
        headers={"Authorization": "Token test"},
        verify_ssl=True,
    )
    execution = SimpleNamespace(
        pk=264,
        procedure=SimpleNamespace(
            name="os.linux.debian.13.install_akvorado",
            timeout_seconds=1200,
            result_schema={
                "type": "object",
                "required": ["ok", "target", "stage"],
                "properties": {
                    "ok": {"type": "boolean"},
                    "target": {"type": "string"},
                    "stage": {"type": "string"},
                },
            },
        ),
        params={},
        target_display="akvorado01",
    )
    if failure_kind == "request-error":
        post_mock = MagicMock(
            side_effect=jobs_module.requests.exceptions.ConnectionError("timed out")
        )
    else:
        status_code = {
            "redirect": 307,
            "server-error": 502,
            "http-408-json": 408,
            "http-408-non-json": 408,
            "non-json": 200,
            "wrong-json-shape": 200,
            "dict-missing-result": 200,
            "dict-invalid-result": 200,
            "dict-envelope-extra": 200,
            "dict-ok-mismatch": 200,
        }[failure_kind]
        if failure_kind in {"non-json", "http-408-non-json"}:
            payload = b"not JSON"
        elif failure_kind == "wrong-json-shape":
            payload = []
        elif failure_kind == "dict-missing-result":
            payload = {
                "ok": True,
                "events": [],
                "error_code": "",
                "error_message": "",
            }
        elif failure_kind == "dict-invalid-result":
            payload = {
                "ok": True,
                "result": {"ok": True, "target": "akvorado01"},
                "events": [],
                "error_code": "",
                "error_message": "",
            }
        elif failure_kind == "dict-envelope-extra":
            payload = {
                "ok": True,
                "result": {
                    "ok": True,
                    "target": "akvorado01",
                    "stage": "complete",
                },
                "events": [],
                "error_code": "",
                "error_message": "",
                "unexpected": True,
            }
        elif failure_kind == "dict-ok-mismatch":
            payload = {
                "ok": True,
                "result": {
                    "ok": False,
                    "target": "akvorado01",
                    "stage": "verify",
                },
                "events": [],
                "error_code": "",
                "error_message": "",
            }
        else:
            payload = {"detail": "ambiguous"}
        response = _streaming_response(status_code, payload)
        post_mock = MagicMock(return_value=response)
    monkeypatch.setattr(jobs_module.requests, "post", post_mock)

    outcome = jobs_module._call_backend(target, execution)

    assert outcome["ok"] is False
    result = outcome["result"]
    assert result["procedure"] == "os.linux.debian.13.install_akvorado"
    assert result["target"] == "akvorado01"
    assert result["stage"] == "outcome_unknown"
    assert result["installed"] is None
    assert result["changed"] is None
    assert result["config_created"] is None
    assert "preflight" in result["warnings"][0]
    assert post_mock.call_args.kwargs["allow_redirects"] is False
    assert post_mock.call_args.kwargs["stream"] is True
    if failure_kind != "request-error":
        response.close.assert_called_once_with()


def test_akvorado_install_validated_2xx_envelope_preserves_known_result(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = jobs_module.BackendTarget(
        url="http://nms-backend.example",
        headers={},
        verify_ssl=True,
    )
    result = jobs_module._akvorado_transport_failure_response("akvorado01")["result"]
    result = {**result, "stage": "verify", "installed": True, "changed": True}
    result_schema = {
        "type": "object",
        "required": ["ok", "target", "stage", "installed", "changed"],
        "properties": {
            "ok": {"const": False},
            "target": {"const": "akvorado01"},
            "stage": {"const": "verify"},
            "installed": {"const": True},
            "changed": {"const": True},
        },
    }
    execution = SimpleNamespace(
        pk=265,
        procedure=SimpleNamespace(
            name="os.linux.debian.13.install_akvorado",
            timeout_seconds=1200,
            result_schema=result_schema,
        ),
        params={},
        target_display="akvorado01",
    )
    wire = {
        "ok": False,
        "result": result,
        "events": [],
        "error_code": "",
        "error_message": "",
    }
    response = _streaming_response(200, wire)
    monkeypatch.setattr(jobs_module.requests, "post", MagicMock(return_value=response))

    assert jobs_module._call_backend(target, execution) == wire
    response.close.assert_called_once_with()


def test_akvorado_install_http_401_closes_stream_before_error(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = jobs_module.BackendTarget(
        url="http://nms-backend.example",
        headers={},
        verify_ssl=True,
    )
    execution = SimpleNamespace(
        pk=267,
        procedure=SimpleNamespace(
            name="os.linux.debian.13.install_akvorado",
            timeout_seconds=1200,
            result_schema={"type": "object"},
        ),
        params={},
        target_display="akvorado01",
    )
    response = _streaming_response(401, {"detail": "unauthorized"})
    monkeypatch.setattr(
        jobs_module.requests,
        "post",
        MagicMock(return_value=response),
    )

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module._call_backend(target, execution)

    assert excinfo.value.code == "RPC_BACKEND_UNAUTHORIZED"
    response.close.assert_called_once_with()


@pytest.mark.parametrize(
    "failure_kind",
    ("oversized", "compressed", "truncated", "deadline"),
)
def test_akvorado_install_stream_is_bounded_and_deadline_closed(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    target = jobs_module.BackendTarget(
        url="http://nms-backend.example",
        headers={},
        verify_ssl=True,
    )
    execution = SimpleNamespace(
        pk=266,
        procedure=SimpleNamespace(
            name="os.linux.debian.13.install_akvorado",
            timeout_seconds=1200,
            result_schema={"type": "object"},
        ),
        params={},
        target_display="akvorado01",
    )
    response = _streaming_response(200, {"ok": True})
    if failure_kind == "oversized":
        response.headers["Content-Length"] = str(64 * 1024 + 1)
    elif failure_kind == "compressed":
        response.headers["Content-Encoding"] = "gzip"
    elif failure_kind == "truncated":
        response.headers["Content-Length"] = str(
            int(response.headers["Content-Length"]) + 1
        )
    else:
        monotonic_values = iter((0.0, 1211.0))
        monkeypatch.setattr(
            jobs_module.time,
            "monotonic",
            lambda: next(monotonic_values),
        )
        monkeypatch.setattr(
            jobs_module,
            "_protected_backend_wall_clock",
            lambda _deadline: nullcontext(),
        )
    post_mock = MagicMock(return_value=response)
    monkeypatch.setattr(jobs_module.requests, "post", post_mock)

    result = jobs_module._call_backend(target, execution)

    assert result["ok"] is False
    assert result["result"]["stage"] == "outcome_unknown"
    assert post_mock.call_args.kwargs["stream"] is True
    response.close.assert_called_once_with()


def _execution(procedure_name: str, handler_id: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=handler_id),
        params=params,
        target_display="edge-01",
        target_model_label="dcim.device",
    )


def _mock_allowlist(jobs_module, allow):
    if allow is not None and not hasattr(allow, "ssh_credential_override_id"):
        allow.ssh_credential_override_id = None
    query = SimpleNamespace(first=MagicMock(return_value=allow))
    filter_mock = MagicMock(return_value=query)
    jobs_module.RPCLinuxServiceAllowlist.objects = SimpleNamespace(filter=filter_mock)
    return filter_mock


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig

    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"

    netbox_jobs = types.ModuleType("netbox.jobs")

    class JobRunner:
        @classmethod
        def enqueue(cls, *args, **kwargs):
            return None

    netbox_jobs.JobRunner = JobRunner

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    # #262: the netbox.plugin.install normalizer imports this alongside the
    # service allowlist, so the shared stub must define it or every pure-domain
    # test that imports netbox_rpc.jobs fails at import time, not just the
    # plugin-install ones.
    netbox_rpc_models.RPCNetBoxPluginAllowlist = type(
        "RPCNetBoxPluginAllowlist", (), {}
    )
    # #215: jobs._call_backend() reads this class attribute as the params key
    # for the frozen timeout_seconds snapshot; the stub must define it too.
    netbox_rpc_models.RPCExecution = type(
        "RPCExecution",
        (),
        {"TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY": "_timeout_seconds_snapshot"},
    )
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    # Stub requests so jobs.py can be imported without the package installed.
    # Include a requests.exceptions namespace so _call_backend's
    # `except requests.exceptions.RequestException` path is exercisable even when
    # the real requests package is installed (CI installs requests, which would
    # otherwise be shadowed by this bare stub and lack .exceptions).
    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")

    class _RequestException(Exception):
        pass

    class _ConnectionError(_RequestException):
        pass

    requests_exceptions.RequestException = _RequestException
    requests_exceptions.ConnectionError = _ConnectionError
    requests_mod.exceptions = requests_exceptions

    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
