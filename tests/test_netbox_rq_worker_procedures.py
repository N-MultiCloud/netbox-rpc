"""Contracts for the production NetBox Compose RQ worker procedures."""

from __future__ import annotations

import importlib
import importlib.util
import socketserver
import sys
import threading
import time
import types
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import MagicMock

import jsonschema
import pytest
import requests as real_requests

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = (
    ROOT
    / "netbox_rpc/migrations/0110_seed_netbox_production_rq_worker_procedures.py"
)
NETBOX_PRODUCTION_STATUS_RQ_WORKER = "service.netbox.production.status_rq_worker"
NETBOX_PRODUCTION_RESTART_RQ_WORKER = "service.netbox.production.restart_rq_worker"
NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES = frozenset(
    {
        NETBOX_PRODUCTION_STATUS_RQ_WORKER,
        NETBOX_PRODUCTION_RESTART_RQ_WORKER,
    }
)


class _Query:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows

    def first(self):
        return self.rows[0] if self.rows else None

    def order_by(self, _field: str):
        return self

    def update(self, **values: object) -> int:
        for row in self.rows:
            for key, value in values.items():
                setattr(row, key, value)
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)


class _Manager:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.rows: list[object] = []

    def filter(self, **values: object) -> _Query:
        if "name__in" in values:
            names = values["name__in"]
            return _Query([row for row in self.rows if row.name in names])
        return _Query(
            [
                row
                for row in self.rows
                if all(getattr(row, key) == value for key, value in values.items())
            ]
        )

    def create(self, **values: object):
        row = SimpleNamespace(pk=len(self.rows) + 1, **values)
        self.rows.append(row)
        return row


def _load_migration():
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")

    class Migration:
        pass

    django_db.migrations = SimpleNamespace(
        Migration=Migration,
        RunPython=lambda *args, **kwargs: None,
    )
    django_db.transaction = SimpleNamespace(atomic=nullcontext)
    previous = {name: sys.modules.get(name) for name in ("django", "django.db")}
    sys.modules["django"] = django
    sys.modules["django.db"] = django_db
    try:
        spec = importlib.util.spec_from_file_location(
            "netbox_rq_migration", MIGRATION_PATH
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


def _load_contract():
    package = types.ModuleType("netbox_rpc")
    package.__path__ = [str(ROOT / "netbox_rpc")]
    previous = {
        name: sys.modules.get(name)
        for name in (
            "netbox_rpc",
            "netbox_rpc.constants",
            "netbox_rpc.netbox_rq_worker_contract",
        )
    }
    sys.modules["netbox_rpc"] = package
    try:
        constants_spec = importlib.util.spec_from_file_location(
            "netbox_rpc.constants", ROOT / "netbox_rpc/constants.py"
        )
        assert constants_spec is not None and constants_spec.loader is not None
        constants = importlib.util.module_from_spec(constants_spec)
        sys.modules["netbox_rpc.constants"] = constants
        constants_spec.loader.exec_module(constants)
        contract_spec = importlib.util.spec_from_file_location(
            "netbox_rpc.netbox_rq_worker_contract",
            ROOT / "netbox_rpc/netbox_rq_worker_contract.py",
        )
        assert contract_spec is not None and contract_spec.loader is not None
        contract_module = importlib.util.module_from_spec(contract_spec)
        sys.modules["netbox_rpc.netbox_rq_worker_contract"] = contract_module
        contract_spec.loader.exec_module(contract_module)
        return contract_module, constants
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


def _migration_state(*, include_allowlist: bool = True):
    migration = _load_migration()
    procedures = _Manager("procedure")
    commands = _Manager("command")
    allowlist = _Manager("allowlist")
    allowlist_row = SimpleNamespace(
        slug="netbox-rq",
        enabled=True,
        comments="Legacy worker unit.",
    )
    allowlist_row.save = MagicMock()
    if include_allowlist:
        allowlist.rows.append(allowlist_row)

    class Apps:
        @staticmethod
        def get_model(_app: str, model: str):
            managers = {
                "RPCProcedure": procedures,
                "RPCProcedureCommand": commands,
                "RPCLinuxServiceAllowlist": allowlist,
            }
            return SimpleNamespace(objects=managers[model])

    return migration, Apps(), procedures, commands, allowlist_row


def test_seed_creates_exact_procedures_and_disables_legacy_allowlist() -> None:
    migration, apps, procedures, commands, allowlist = _migration_state()

    migration.seed(apps, None)
    migration.seed(apps, None)

    assert {row.name for row in procedures.rows} == set(
        NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES
    )
    assert len(commands.rows) == 2
    by_name = {row.name: row for row in procedures.rows}
    assert by_name[NETBOX_PRODUCTION_STATUS_RQ_WORKER].effect == "read"
    assert by_name[NETBOX_PRODUCTION_STATUS_RQ_WORKER].approval_required is False
    assert by_name[NETBOX_PRODUCTION_RESTART_RQ_WORKER].effect == "write"
    assert by_name[NETBOX_PRODUCTION_RESTART_RQ_WORKER].approval_required is True
    assert all(row.enabled is True for row in procedures.rows)
    assert {
        tuple(row.argv) for row in commands.rows
    } == {
        ("backend-orchestrated", "netbox-production-status-rq-worker"),
        ("backend-orchestrated", "netbox-production-restart-rq-worker"),
    }
    assert allowlist.enabled is False
    assert NETBOX_PRODUCTION_STATUS_RQ_WORKER in allowlist.comments
    assert NETBOX_PRODUCTION_RESTART_RQ_WORKER in allowlist.comments
    assert allowlist.comments.count("Retired legacy host unit.") == 1
    allowlist.save.assert_called_with(update_fields=["enabled", "comments"])


def test_seed_contract_matches_runtime_and_refuses_all_caller_params() -> None:
    migration = _load_migration()
    contract, _constants = _load_contract()
    rows = {
        NETBOX_PRODUCTION_STATUS_RQ_WORKER: migration._STATUS_DEFAULTS,
        NETBOX_PRODUCTION_RESTART_RQ_WORKER: migration._RESTART_DEFAULTS,
    }
    for name, defaults in rows.items():
        policy = contract.PROCEDURE_POLICIES[name]
        assert defaults["handler_id"] == name
        assert defaults["version"] == 1
        assert defaults["enabled"] is True
        assert {
            key: defaults[key] for key in policy if key != "name"
        } == {key: value for key, value in policy.items() if key != "name"}
        jsonschema.validate({}, defaults["params_schema"])
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"service": "other"}, defaults["params_schema"])


def test_seed_refuses_contract_drift_and_reverse_never_revives_host_unit() -> None:
    migration, apps, procedures, _commands, allowlist = _migration_state()
    migration.seed(apps, None)
    procedures.rows[0].timeout_seconds = 1
    with pytest.raises(RuntimeError, match="Refusing to overwrite"):
        migration.seed(apps, None)

    procedures.rows[0].timeout_seconds = 45
    migration.reverse(apps, None)
    assert all(row.enabled is False for row in procedures.rows)
    assert allowlist.enabled is False


def test_seed_and_reverse_succeed_when_legacy_allowlist_is_absent() -> None:
    migration, apps, procedures, commands, _allowlist = _migration_state(
        include_allowlist=False
    )

    migration.seed(apps, None)
    migration.reverse(apps, None)

    assert len(procedures.rows) == 2
    assert len(commands.rows) == 2
    assert all(row.enabled is False for row in procedures.rows)


def test_procedures_are_explicitly_capability_gated_and_orchestrated() -> None:
    _contract, constants = _load_contract()
    command_contract_spec = importlib.util.spec_from_file_location(
        "netbox_rq_command_contract", ROOT / "netbox_rpc/command_contract.py"
    )
    assert command_contract_spec is not None and command_contract_spec.loader is not None
    command_contract = importlib.util.module_from_spec(command_contract_spec)
    command_contract_spec.loader.exec_module(command_contract)

    assert NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES <= (
        constants.EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES
    )
    assert NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES <= set(
        command_contract.EXEMPT_HANDLER_RATIONALE
    )
    assert (
        NETBOX_PRODUCTION_RESTART_RQ_WORKER
        in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    )


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.mark.parametrize("procedure_name", NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES)
def test_normalization_binds_device_44_and_refuses_params(
    jobs_module,
    procedure_name: str,
) -> None:
    execution = _execution(procedure_name, {})
    assert jobs_module.normalize_execution_params(execution) == {
        "target": "nmc-prod-207",
        "target_object": {"content_type": "dcim.device", "object_id": 44},
        "command_fingerprint": {
            "handler_id": procedure_name,
            "procedure": procedure_name,
            "target_object": {"content_type": "dcim.device", "object_id": 44},
        },
    }

    execution.params = {"service": "other"}
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)
    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("assigned_object_id", 45),
        ("assigned_object", SimpleNamespace(pk=44, name="other-host")),
        ("target_display", "other-host"),
        ("target_model_label", "virtualization.virtualmachine"),
    ],
)
def test_normalization_refuses_every_nonproduction_target(
    jobs_module,
    field: str,
    value: object,
) -> None:
    execution = _execution(NETBOX_PRODUCTION_STATUS_RQ_WORKER, {})
    setattr(execution, field, value)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_TARGET_INVALID"


def _execution(procedure_name: str, params: dict[str, object]):
    return SimpleNamespace(
        pk=812,
        procedure=SimpleNamespace(
            name=procedure_name,
            handler_id=procedure_name,
            timeout_seconds=(150 if "restart" in procedure_name else 45),
        ),
        params=params,
        normalized_params={},
        assigned_object=SimpleNamespace(pk=44, name="nmc-prod-207"),
        assigned_object_type=SimpleNamespace(app_label="dcim", model="device"),
        assigned_object_id=44,
        target_display="nmc-prod-207",
        target_model_label="dcim.device",
    )


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"
    netbox_jobs = types.ModuleType("netbox.jobs")

    def system_job(*, interval: int):
        def decorate(cls):
            cls.system_job_interval = interval
            return cls

        return decorate

    class JobRunner:
        last_enqueue_kwargs: ClassVar[dict[str, object]] = {}

        @classmethod
        def enqueue(cls, *args, **kwargs):
            cls.last_enqueue_kwargs = dict(kwargs)
            return SimpleNamespace(data={}, save=MagicMock())

    netbox_jobs.JobRunner = JobRunner
    netbox_jobs.system_job = system_job
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone
    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCNetBoxPluginAllowlist = type("RPCNetBoxPluginAllowlist", (), {})
    models.RPCExecution = type(
        "RPCExecution",
        (),
        {"TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY": "_timeout_seconds_snapshot"},
    )
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})
    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")
    requests_exceptions.RequestException = type("RequestException", (Exception,), {})
    requests_exceptions.ConnectionError = type(
        "ConnectionError", (requests_exceptions.RequestException,), {}
    )
    requests_exceptions.ConnectTimeout = type(
        "ConnectTimeout", (requests_exceptions.RequestException,), {}
    )
    requests_exceptions.ReadTimeout = type(
        "ReadTimeout", (requests_exceptions.RequestException,), {}
    )
    requests_mod.exceptions = requests_exceptions
    for name, module in {
        "netbox": netbox,
        "netbox.plugins": netbox_plugins,
        "netbox.constants": netbox_constants,
        "netbox.jobs": netbox_jobs,
        "django": django,
        "django.db": django_db,
        "django.utils": django_utils,
        "django.utils.timezone": django_timezone,
        "requests": requests_mod,
        "requests.exceptions": requests_exceptions,
        "netbox_rpc.models": models,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)


def test_restart_uses_independent_control_queue(jobs_module) -> None:
    job = jobs_module.RPCExecutionJob.enqueue(
        execution_pk=812,
        backend_pk=7,
        procedure_name=NETBOX_PRODUCTION_RESTART_RQ_WORKER,
    )

    assert job.data == {"backend_pk": 7, "execution_pk": 812}
    assert (
        jobs_module.RPCExecutionJob.last_enqueue_kwargs["queue_name"]
        == "netbox_rpc.control"
    )


def test_status_uses_independent_control_queue_during_default_worker_outage(
    jobs_module,
) -> None:
    jobs_module.RPCExecutionJob.enqueue(
        execution_pk=813,
        backend_pk=7,
        procedure_name=NETBOX_PRODUCTION_STATUS_RQ_WORKER,
    )

    assert (
        jobs_module.RPCExecutionJob.last_enqueue_kwargs["queue_name"]
        == "netbox_rpc.control"
    )


def test_expiry_audit_job_uses_only_independent_control_queue(jobs_module) -> None:
    jobs_module.RPCExecutionQueueExpiryJob.enqueue(
        execution_pk=812,
        schedule_at=object(),
    )

    assert (
        jobs_module.RPCExecutionQueueExpiryJob.last_enqueue_kwargs["queue_name"]
        == "netbox_rpc.control"
    )


def _install_worker_registry_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    workers: list[object],
) -> object:
    queue = SimpleNamespace(connection=object())
    django_rq = types.ModuleType("django_rq")
    django_rq.get_queue = MagicMock(return_value=queue)
    rq = types.ModuleType("rq")

    class Worker:
        @classmethod
        def all(cls, *, queue):
            assert queue is django_rq.get_queue.return_value
            return workers

    rq.Worker = Worker
    rq_suspension = types.ModuleType("rq.suspension")
    rq_suspension.is_suspended = MagicMock(return_value=False)
    monkeypatch.setitem(sys.modules, "django_rq", django_rq)
    monkeypatch.setitem(sys.modules, "rq", rq)
    monkeypatch.setitem(sys.modules, "rq.suspension", rq_suspension)
    django_rq.is_suspended = rq_suspension.is_suspended
    return django_rq


def test_control_queue_refuses_absent_and_stopped_consumers(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped = SimpleNamespace(
        get_state=lambda: "stopped",
        last_heartbeat=datetime.now(UTC),
    )

    django_rq = _install_worker_registry_stubs(monkeypatch, workers=[])
    assert jobs_module.control_queue_has_live_worker() is False
    django_rq.get_queue.assert_called_once_with("netbox_rpc.control")

    django_rq = _install_worker_registry_stubs(monkeypatch, workers=[stopped])
    assert jobs_module.control_queue_has_live_worker() is False
    django_rq.get_queue.assert_called_once_with("netbox_rpc.control")


def test_control_queue_accepts_only_live_exact_queue_consumer(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = SimpleNamespace(
        get_state=lambda: "idle",
        last_heartbeat=datetime.now(UTC),
    )
    django_rq = _install_worker_registry_stubs(monkeypatch, workers=[live])

    assert jobs_module.control_queue_has_live_worker() is True
    django_rq.get_queue.assert_called_once_with("netbox_rpc.control")


def test_control_queue_refuses_stale_worker_registration(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = SimpleNamespace(
        get_state=lambda: "idle",
        last_heartbeat=datetime.now(UTC) - timedelta(seconds=121),
    )
    _install_worker_registry_stubs(monkeypatch, workers=[stale])

    assert jobs_module.control_queue_has_live_worker() is False


def test_control_worker_ttl_keeps_idle_heartbeat_inside_admission_gate(
    jobs_module,
) -> None:
    contract = importlib.import_module("netbox_rpc.netbox_rq_worker_contract")
    now = datetime.now(UTC)
    configured_idle_cadence = contract.CONTROL_WORKER_TTL_SECONDS - 15
    default_idle_cadence = 420 - 15

    assert contract.CONTROL_WORKER_TTL_SECONDS == 90
    configured = SimpleNamespace(
        get_state=lambda: "idle",
        last_heartbeat=now - timedelta(seconds=configured_idle_cadence),
    )
    default = SimpleNamespace(
        get_state=lambda: "idle",
        last_heartbeat=now - timedelta(seconds=default_idle_cadence),
    )

    assert configured_idle_cadence == 75
    assert jobs_module._worker_is_live(configured, now=now) is True
    assert default_idle_cadence == 405
    assert jobs_module._worker_is_live(default, now=now) is False


def test_control_queue_refuses_busy_worker_while_rq_is_suspended(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    busy = SimpleNamespace(
        get_state=lambda: "busy",
        last_heartbeat=datetime.now(UTC),
    )
    django_rq = _install_worker_registry_stubs(monkeypatch, workers=[busy])
    django_rq.is_suspended.return_value = True

    assert jobs_module.control_queue_has_live_worker() is False


def test_periodic_expiry_sweep_uses_default_queue_independently(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sys.modules.pop("netbox_rpc.system_jobs", None)
    system_jobs = importlib.import_module("netbox_rpc.system_jobs")
    system_jobs.RPCExecutionQueueExpirySweepJob.enqueue()

    assert system_jobs.RPCExecutionQueueExpirySweepJob.system_job_interval == 1
    assert (
        system_jobs.RPCExecutionQueueExpirySweepJob.last_enqueue_kwargs["queue_name"]
        == "default"
    )


def test_control_queue_registry_failure_fails_closed(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    django_rq = types.ModuleType("django_rq")
    django_rq.get_queue = MagicMock(side_effect=RuntimeError("redis unavailable"))
    rq = types.ModuleType("rq")
    rq.Worker = object
    rq_suspension = types.ModuleType("rq.suspension")
    rq_suspension.is_suspended = MagicMock(return_value=False)
    monkeypatch.setitem(sys.modules, "django_rq", django_rq)
    monkeypatch.setitem(sys.modules, "rq", rq)
    monkeypatch.setitem(sys.modules, "rq.suspension", rq_suspension)

    assert jobs_module.control_queue_has_live_worker() is False
    django_rq.get_queue.assert_called_once_with("netbox_rpc.control")


def _backend_target(jobs_module):
    return jobs_module.BackendTarget(
        url="https://backend.example.invalid",
        headers={"Authorization": "redacted"},
        verify_ssl=True,
    )


def _streaming_response(*, status_code: int, body: bytes):
    socket = SimpleNamespace(settimeout=MagicMock())
    response = MagicMock()
    response.status_code = status_code
    response.headers = {
        "Content-Encoding": "identity",
        "Content-Length": str(len(body)),
    }
    response.raw = SimpleNamespace(_connection=SimpleNamespace(sock=socket))
    response.iter_content.return_value = iter([body])
    return response


@pytest.mark.parametrize(
    "framing",
    ("chunk-extension", "trailer"),
)
def test_worker_absolute_deadline_bounds_chunked_framing_and_closes_response(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
    framing: str,
) -> None:
    contract = importlib.import_module("netbox_rpc.netbox_rq_worker_contract")
    monkeypatch.setitem(
        contract.BACKEND_ROUTE_BUDGET_SECONDS,
        NETBOX_PRODUCTION_STATUS_RQ_WORKER,
        0.05,
    )
    captured: dict[str, real_requests.Response] = {}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.rfile.read(1)
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            )
            if framing == "chunk-extension":
                self.wfile.write(b"1;")
            else:
                self.wfile.write(b"2\r\n{}\r\n0\r\nX-Control: ")
            self.wfile.flush()
            time.sleep(0.2)
            try:
                self.wfile.write(b"slow\r\n\r\n")
                self.wfile.flush()
            except OSError:
                pass

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(url: str, **kwargs):
        response = real_requests.post(url, **kwargs)
        response.close = MagicMock(wraps=response.close)
        captured["response"] = response
        return response

    monkeypatch.setattr(jobs_module.requests, "post", post)
    monkeypatch.setattr(jobs_module.requests, "exceptions", real_requests.exceptions)
    target = jobs_module.BackendTarget(
        url=f"http://127.0.0.1:{server.server_address[1]}",
        headers={},
        verify_ssl=True,
    )
    started = time.monotonic()
    try:
        result = jobs_module._call_backend(
            target,
            _execution(NETBOX_PRODUCTION_STATUS_RQ_WORKER, {}),
        )
        elapsed = time.monotonic() - started
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert elapsed < 0.5
    assert result["ok"] is False
    assert result["error_code"] == "RPC_BACKEND_OUTCOME_UNKNOWN"
    assert result["result"]["status"] == "indeterminate"
    assert result["result"]["retry_requires_status_check"] is True
    captured["response"].close.assert_called_once_with()


@pytest.mark.parametrize("procedure_name", NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES)
def test_worker_procedures_use_bounded_redirect_free_http_transport(
    jobs_module,
    procedure_name: str,
) -> None:
    execution = _execution(procedure_name, {})
    policy = jobs_module._resolve_backend_transport_policy(execution)
    plan = jobs_module._build_backend_request_plan(
        _backend_target(jobs_module), execution, policy, None
    )

    assert policy.kind is jobs_module._BackendTransportKind.NETBOX_RQ_WORKER
    assert policy.streamed is True
    assert plan.kwargs["stream"] is True
    assert plan.kwargs["allow_redirects"] is False
    assert plan.response_max_bytes == 16384
    assert plan.kwargs["timeout"].total == (160 if "restart" in procedure_name else 55)


@pytest.mark.parametrize(
    "failure",
    ["lost-response", "http-error", "decode-error", "oversized-response"],
)
@pytest.mark.parametrize("procedure_name", NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES)
def test_worker_http_ambiguity_returns_reconciliation_required_result(
    jobs_module,
    failure: str,
    procedure_name: str,
) -> None:
    execution = _execution(procedure_name, {})
    post = jobs_module.requests.post
    if failure == "lost-response":
        post.side_effect = jobs_module.requests.exceptions.ConnectionError("lost")
    elif failure == "http-error":
        post.return_value = _streaming_response(status_code=503, body=b"{}")
    elif failure == "decode-error":
        post.return_value = _streaming_response(status_code=200, body=b"{")
    else:
        response = _streaming_response(status_code=200, body=b"{}")
        response.headers["Content-Length"] = "16385"
        post.return_value = response

    result = jobs_module._call_backend(_backend_target(jobs_module), execution)

    assert result["ok"] is False
    assert result["error_code"] == "RPC_BACKEND_OUTCOME_UNKNOWN"
    assert result["result"]["status"] == "indeterminate"
    assert result["result"]["phase"] == (
        "restart" if procedure_name == NETBOX_PRODUCTION_RESTART_RQ_WORKER else "status"
    )
    assert result["result"]["retry_requires_status_check"] is True
    if post.call_args is not None:
        assert post.call_args.kwargs["allow_redirects"] is False
        assert post.call_args.kwargs["stream"] is True


def test_result_contract_marks_indeterminate_phase_and_retry_guard() -> None:
    migration = _load_migration()
    contract, _constants = _load_contract()

    for procedure_name in NETBOX_PRODUCTION_RQ_WORKER_PROCEDURE_NAMES:
        schema = contract.RESULT_SCHEMAS[procedure_name]
        assert schema == migration._result_schema(procedure_name)
        assert "indeterminate" in schema["properties"]["status"]["enum"]
        assert schema["properties"]["phase"]["enum"] == [
            "status",
            "restart",
            "readiness",
        ]
        assert schema["properties"]["retry_requires_status_check"] == {
            "type": "boolean"
        }

    assert contract.RUNTIME_CONTRACT["transport"] == {
        "driver": "asyncssh",
        "strict_auth": True,
        "allow_fallback": False,
        "stream_capture_max_bytes": 8192,
        "capture_overflow": "indeterminate",
    }
    assert contract.RUNTIME_CONTRACT["indeterminate_outcome"] == {
        "phases": ["status", "restart", "readiness"],
        "status_check_required_before_retry": True,
    }
    assert contract.RUNTIME_CONTRACT["control_queue"] == {
        "name": "netbox_rpc.control",
        "procedure_names": [
            NETBOX_PRODUCTION_RESTART_RQ_WORKER,
            NETBOX_PRODUCTION_STATUS_RQ_WORKER,
        ],
        "worker_heartbeat_max_age_seconds": 120,
        "restart_queue_max_age_seconds": 600,
        "expiry_sweep_interval_minutes": 1,
        "expiry_sweep_queue": "default",
    }
    assert contract.RUNTIME_CONTRACT["http_transport"] == {
        "route_budget_seconds": {
            NETBOX_PRODUCTION_STATUS_RQ_WORKER: 55,
            NETBOX_PRODUCTION_RESTART_RQ_WORKER: 160,
        },
        "stream_response": True,
        "response_max_bytes": 16384,
        "allow_redirects": False,
        "ambiguous_failure": "reconciliation_required",
    }
    assert contract.RUNTIME_CONTRACT["reconciliation"] == {
        "restart_launch_ambiguity_requires_status_check": True,
        "post_restart_readiness_failure_requires_status_check": True,
    }
