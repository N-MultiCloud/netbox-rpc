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

ANALYZE = "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade"
SAVE = "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state"
UPGRADE = "os.linux.ubuntu.24.upgrade_26.run_upgrade"
VERIFY = "os.linux.ubuntu.24.upgrade_26.verify_postupgrade"
PROCEDURES = (ANALYZE, SAVE, UPGRADE, VERIFY)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_run_upgrade_uses_safe_semantic_defaults(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(_execution(UPGRADE, {}))

    assert normalized["dry_run"] is True
    assert normalized["reboot_after_upgrade"] is False
    assert normalized["command_fingerprint"]["dry_run"] is True
    assert normalized["command_fingerprint"]["reboot_after_upgrade"] is False


def test_run_upgrade_preserves_explicit_false_dry_run(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(UPGRADE, {"dry_run": False})
    )

    assert normalized["dry_run"] is False
    assert normalized["reboot_after_upgrade"] is False


@pytest.mark.parametrize("backup_dir", ["relative/path", "/tmp/bad path", "/tmp/x;id"])
def test_save_preupgrade_state_rejects_invalid_backup_dir(
    jobs_module,
    backup_dir: str,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(
            _execution(SAVE, {"backup_dir": backup_dir})
        )

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_save_preupgrade_state_passes_valid_backup_dir(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(SAVE, {"backup_dir": "/var/backups/ubuntu-upgrade-26"})
    )

    assert normalized["backup_dir"] == "/var/backups/ubuntu-upgrade-26"
    assert (
        normalized["command_fingerprint"]["backup_dir"]
        == "/var/backups/ubuntu-upgrade-26"
    )


def test_verify_postupgrade_passes_expected_version_id(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(VERIFY, {"expected_version_id": "26.04"})
    )

    assert normalized["expected_version_id"] == "26.04"
    assert normalized["command_fingerprint"]["expected_version_id"] == "26.04"


@pytest.mark.parametrize("expected_version_id", ["", 26, "x" * 33])
def test_verify_postupgrade_rejects_malformed_expected_version_id(
    jobs_module,
    expected_version_id: object,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(
            _execution(VERIFY, {"expected_version_id": expected_version_id})
        )

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize("procedure_name", PROCEDURES)
def test_all_upgrade_procedures_pass_through_optional_ssh_overrides(
    jobs_module,
    procedure_name: str,
) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            procedure_name,
            {
                "rpc_ssh_host": "ubuntu-upgrade.example.net",
                "rpc_ssh_port": 2222,
                "rpc_ssh_credential_pk": 73,
            },
        )
    )

    assert normalized["rpc_ssh_host"] == "ubuntu-upgrade.example.net"
    assert normalized["rpc_ssh_port"] == 2222
    assert normalized["rpc_ssh_credential_pk"] == 73
    assert normalized["command_fingerprint"]["rpc_ssh_host"] == (
        "ubuntu-upgrade.example.net"
    )
    assert normalized["command_fingerprint"]["rpc_ssh_port"] == 2222
    assert normalized["command_fingerprint"]["rpc_ssh_credential_pk"] == 73


def _execution(procedure_name: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=procedure_name),
        params=params,
        target_display="ubuntu-upgrade-01",
        target_model_label="dcim.device",
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

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)

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
