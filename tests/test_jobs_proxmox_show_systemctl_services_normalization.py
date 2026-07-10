"""Tests for the os.linux.proxmox.show_systemctl_services normalizer.

These verify that _normalize_show_systemctl_services_execution() in
netbox_rpc.domain.normalization:
- forwards proxmox_endpoint_id and a validated units list
- emits NO rpc_ssh_* keys and never resolves the netbox-nms
  ProxmoxEndpointSSHBinding (unlike the sibling Mellanox/QEMU normalizers) —
  the execution backend resolves SSH downstream from the endpoint's own
  stored credential (fetched from netbox-proxbox), not netbox-nms
- defaults units to an empty list when omitted
- rejects invalid unit names, non-list units, an oversized units array, and an
  invalid/out-of-range proxmox_endpoint_id
- stays aligned with the seed migration's name/handler_id/target_models/
  effect/approval_required
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PROCEDURE_NAME = "os.linux.proxmox.show_systemctl_services"
_HANDLER_ID = "os.linux_proxmox.show_systemctl_services"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_show_systemctl_services_normalizes_with_units(jobs_module) -> None:
    execution = _execution(
        proxmox_endpoint_id=42,
        units=["nginx.service", "qemu-guest-agent"],
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "pve01"
    assert normalized["proxmox_endpoint_id"] == 42
    assert normalized["units"] == ["nginx.service", "qemu-guest-agent"]
    fp = normalized["command_fingerprint"]
    assert fp["handler_id"] == _HANDLER_ID
    assert fp["proxmox_endpoint_id"] == 42
    assert fp["units"] == ["nginx.service", "qemu-guest-agent"]
    # The execution backend resolves SSH downstream from the endpoint's own
    # credential: no rpc_ssh_* override keys are emitted anywhere.
    assert not any(key.startswith("rpc_ssh_") for key in normalized)
    assert not any(key.startswith("rpc_ssh_") for key in fp)


def test_show_systemctl_services_never_imports_ssh_resolver(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=7)

    jobs_module.normalize_execution_params(execution)

    # netbox_nms is deliberately NOT stubbed anywhere in this test module. If
    # the normalizer ever called _resolve_proxmox_ssh_binding (the
    # Mellanox/QEMU SSH-binding resolver), it would attempt to import
    # netbox_nms.proxmox_ssh. Since that never happens, this proves the
    # procedure does not touch netbox-nms — the endpoint's own credential is
    # resolved downstream by the execution backend.
    assert "netbox_nms" not in sys.modules
    assert "netbox_nms.proxmox_ssh" not in sys.modules


def test_show_systemctl_services_defaults_units_to_empty_list(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=5)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["units"] == []
    assert normalized["command_fingerprint"]["units"] == []


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_show_systemctl_services_rejects_invalid_unit_name(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=5, units=["bad unit!"])

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_rejects_non_list_units(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=5, units="nginx.service")

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_rejects_too_many_units(jobs_module) -> None:
    execution = _execution(
        proxmox_endpoint_id=5,
        units=[f"svc{i}.service" for i in range(33)],
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_rejects_missing_endpoint_id(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=None)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_rejects_out_of_range_endpoint_id(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=0)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_OUT_OF_RANGE"


def test_show_systemctl_services_rejects_endpoint_id_target_mismatch(jobs_module) -> None:
    # Audit integrity: params endpoint id must match the execution target object.
    execution = _execution(proxmox_endpoint_id=2, assigned_object_id=1)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_allows_missing_assigned_object(jobs_module) -> None:
    # Internal callers without an assigned object are not rejected by the match.
    execution = _execution(proxmox_endpoint_id=9, assigned_object_id=None)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["proxmox_endpoint_id"] == 9


def test_show_systemctl_services_rejects_leading_dash_unit(jobs_module) -> None:
    # A unit like "--user" must never pass — it could be read as a systemctl option.
    execution = _execution(proxmox_endpoint_id=5, units=["--user"])

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_rejects_non_string_unit(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=5, units=["nginx.service", 123])

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_rejects_empty_string_unit(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=5, units=[""])

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_rejects_overlong_unit(jobs_module) -> None:
    execution = _execution(proxmox_endpoint_id=5, units=["a" * 101])

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_show_systemctl_services_accepts_boundary_units(jobs_module) -> None:
    # Exactly 32 units, one exactly 100 chars long, all valid.
    boundary = "a" * 100
    units = [f"svc{i}.service" for i in range(31)] + [boundary]
    execution = _execution(proxmox_endpoint_id=5, units=units)

    normalized = jobs_module.normalize_execution_params(execution)

    assert len(normalized["units"]) == 32
    assert boundary in normalized["units"]


# ---------------------------------------------------------------------------
# Migration / constants alignment
# ---------------------------------------------------------------------------


def test_constants_match_migration_seed_dict(jobs_module) -> None:
    # normalization.py only imports the bare name constant (it dispatches on
    # procedure name; handler_id comes from execution.procedure.handler_id at
    # runtime), so read the _HANDLER constant straight from constants.py.
    normalization_module = sys.modules["netbox_rpc.domain.normalization"]
    constants_module = importlib.import_module("netbox_rpc.constants")
    assert (
        normalization_module.LINUX_PROXMOX_SHOW_SYSTEMCTL_SERVICES
        == _PROCEDURE_NAME
    )
    assert (
        constants_module.LINUX_PROXMOX_SHOW_SYSTEMCTL_SERVICES_HANDLER
        == _HANDLER_ID
    )

    migration_src = (
        ROOT / "netbox_rpc/migrations/0044_seed_proxmox_show_systemctl_services.py"
    ).read_text()
    assert f'"{_PROCEDURE_NAME}"' in migration_src
    assert f'"handler_id": "{_HANDLER_ID}"' in migration_src
    assert '"target_models": ["netbox_proxbox.proxmoxendpoint"]' in migration_src
    assert '"effect": "read"' in migration_src
    assert '"approval_required": False' in migration_src
    assert '"0043_rpcbackend_ip_domain"' in migration_src


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_MATCH = object()


def _execution(proxmox_endpoint_id, units=None, assigned_object_id=_MATCH, **extra_params):
    params: dict = dict(extra_params)
    if proxmox_endpoint_id is not None:
        params["proxmox_endpoint_id"] = proxmox_endpoint_id
    if units is not None:
        params["units"] = units
    if assigned_object_id is _MATCH:
        assigned_object_id = proxmox_endpoint_id
    return SimpleNamespace(
        procedure=SimpleNamespace(name=_PROCEDURE_NAME, handler_id=_HANDLER_ID),
        params=params,
        assigned_object_id=assigned_object_id,
        target_display="pve01",
        target_model_label="netbox_proxbox.proxmoxendpoint",
    )


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
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    # Stub requests so jobs.py can be imported without the package installed.
    # Include a requests.exceptions namespace so _call_backend's
    # `except requests.exceptions.RequestException` path stays importable even
    # when the real requests package is installed (CI installs requests, which
    # would otherwise be shadowed by this bare stub and lack .exceptions).
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

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
    # Deliberately do NOT stub netbox_nms / netbox_nms.proxmox_ssh: this
    # procedure must never import or call the SSH-binding resolver.
