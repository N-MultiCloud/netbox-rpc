"""Source-only contract and migration checks for runner 44 inspection."""

from __future__ import annotations

import importlib
import runpy
import sys
import types
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
HANDLER_ID = "service.gitea.actions_runner.inspect_user_cache"
MIGRATION_MODULE = "netbox_rpc.migrations.0113_seed_user_runner_cache_inspection"
CONTRACT = runpy.run_path(str(ROOT / "netbox_rpc/gitea_user_runner_cache_contract.py"))


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    django.db = django_db
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


class _Query:
    def __init__(self, rows: dict[str, dict[str, object]], name: str) -> None:
        self.rows = rows
        self.name = name

    def exists(self) -> bool:
        return self.name in self.rows

    def update(self, **fields: object) -> int:
        if self.name not in self.rows:
            return 0
        self.rows[self.name].update(fields)
        return 1


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def filter(self, *, name: str) -> _Query:
        return _Query(self.rows, name)

    def create(self, *, name: str, **fields: object) -> SimpleNamespace:
        self.rows[name] = dict(fields)
        return SimpleNamespace(name=name)


class _CommandManager:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def create(self, *, procedure: SimpleNamespace, **fields: object) -> None:
        self.rows.append({"procedure": procedure.name, **fields})


def _apps(procedures: _ProcedureManager, commands: _CommandManager) -> SimpleNamespace:
    def get_model(app_label: str, model_name: str) -> SimpleNamespace:
        assert app_label == "netbox_rpc"
        if model_name == "RPCProcedure":
            return SimpleNamespace(objects=procedures)
        assert model_name == "RPCProcedureCommand"
        return SimpleNamespace(objects=commands)

    return SimpleNamespace(get_model=get_model)


def test_migration_seeds_one_disabled_exact_read_only_procedure(migration) -> None:
    procedures = _ProcedureManager()
    commands = _CommandManager()
    apps = _apps(procedures, commands)

    migration.seed_user_runner_cache_inspection(apps, None)

    assert set(procedures.rows) == {HANDLER_ID}
    row = procedures.rows[HANDLER_ID]
    assert row["handler_id"] == HANDLER_ID
    assert row["version"] == 2
    assert row["enabled"] is False
    assert row["effect"] == "read"
    assert row["approval_required"] is False
    assert row["timeout_seconds"] == 120
    assert row["target_models"] == ["virtualization.virtualmachine"]
    assert row["transport_driver"] == "asyncssh"
    assert row["transport_pinned"] is True
    assert row["params_schema"] == CONTRACT["PARAMS_SCHEMA"]
    assert row["result_schema"] == CONTRACT["RESULT_SCHEMA"]
    assert commands.rows == [
        {"procedure": HANDLER_ID, **CONTRACT["COMMAND_CONTRACT"][0]}
    ]
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0112_seed_iam_ui_control")
    ]

    with pytest.raises(RuntimeError, match="cannot adopt"):
        migration.seed_user_runner_cache_inspection(apps, None)

    procedures.rows["unrelated"] = {"enabled": True}
    migration.disable_user_runner_cache_inspection(apps, None)
    assert procedures.rows[HANDLER_ID]["enabled"] is False
    assert procedures.rows["unrelated"]["enabled"] is True


def test_result_schema_excludes_raw_source_and_adjacent_runner_identity() -> None:
    validate({}, CONTRACT["PARAMS_SCHEMA"])
    with pytest.raises(ValidationError):
        validate({"path": "/etc/act_runner/config.yaml"}, CONTRACT["PARAMS_SCHEMA"])

    fallback = CONTRACT["fallback_result"]()
    validate(fallback, CONTRACT["RESULT_SCHEMA"])
    with pytest.raises(ValidationError):
        validate({**fallback, "stderr": "secret"}, CONTRACT["RESULT_SCHEMA"])
    altered = deepcopy(fallback)
    altered["procedure"] = "service.gitea.actions_runner.diagnose_user_ci_runner"
    with pytest.raises(ValidationError):
        validate(altered, CONTRACT["RESULT_SCHEMA"])


def _complete_envelope() -> dict[str, object]:
    evidence = {
        "target": "Gitea-Runner",
        "target_object_id": 604,
        "runner_name": "ci-untrusted-emersonfelipesp-241",
        "config_path": "/opt/nmc-ci-untrusted-user-241/config.yaml",
        "config_sha256": "a" * 64,
        "compose_sha256": "b" * 64,
        "trusted_fixed_paths": True,
        "capacity": 1,
        "host_label_matches": True,
        "config_paths_match": True,
        "compose_identity_matches": True,
        "configured_image": "nmc/ci-untrusted-runner:python312-241",
        "running_image": "nmc/ci-untrusted-runner:python312-241",
        "running_image_id": "sha256:" + "c" * 64,
        "container_id": "d" * 64,
        "observed_container_name": "nmc-ci-untrusted-user-241-runner-1",
        "matches_source": True,
        "installed_binary_version": "v0.6.1",
        "exec_process_uid": 1000,
        "container_config_user": "cirunner",
        "runtime_identity_matches": True,
        "state": "running",
        "health": None,
        "cap_drop_all": True,
        "cap_add_count": 0,
        "no_new_privileges": True,
        "privileged": False,
        "read_only_rootfs": False,
        "mount_count": 3,
        "bind_mount_count": 1,
        "docker_socket_mounted": True,
        "config_mount_read_only": True,
        "registration_id": None,
        "user_scope_verified": False,
        "active_job": None,
        "scheduling_drained": False,
    }
    return {
        "ok": True,
        "result": {
            "ok": True,
            "procedure": HANDLER_ID,
            "stage": "complete",
            "evidence": evidence,
        },
        "events": [],
        "error_code": "",
        "error_message": "",
    }


def test_closed_backend_response_accepts_complete_and_explicit_mismatch() -> None:
    normalize = CONTRACT["normalize_backend_response"]
    complete = _complete_envelope()
    assert normalize(complete) == {"ok": True, "result": complete["result"]}

    mismatch = deepcopy(complete)
    evidence = mismatch["result"]["evidence"]
    evidence["config_mount_read_only"] = False
    evidence["matches_source"] = False
    evidence["container_config_user"] = "0:0"
    evidence["exec_process_uid"] = 0
    evidence["runtime_identity_matches"] = False
    assert normalize(mismatch) == {"ok": True, "result": mismatch["result"]}


def test_closed_backend_response_accepts_failure_without_returning_error_text() -> None:
    normalize = CONTRACT["normalize_backend_response"]
    failure = {
        "ok": False,
        "result": CONTRACT["fallback_result"](),
        "events": [],
        "error_code": "RPC_HANDLER_FAILED",
        "error_message": "Backend detail that must not be persisted.",
    }
    assert normalize(failure) == {"ok": False, "result": failure["result"]}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"debug": "secret"}),
        lambda value: value.update({"ok": "true"}),
        lambda value: value.update({"events": [{"message": "secret"}]}),
        lambda value: value.update({"error_message": "secret"}),
        lambda value: value["result"].update({"target": "adjacent runner"}),
        lambda value: value["result"].update({"stage": "indeterminate"}),
        lambda value: value["result"]["evidence"].update({"token": "secret"}),
    ],
)
def test_closed_backend_response_rejects_untrusted_success_shapes(mutate) -> None:
    envelope = _complete_envelope()
    mutate(envelope)
    assert CONTRACT["normalize_backend_response"](envelope) is None


def test_closed_backend_response_rejects_failed_result_with_evidence() -> None:
    failure = _complete_envelope()
    failure["ok"] = False
    failure["result"]["ok"] = False
    failure["result"]["stage"] = "indeterminate"
    assert CONTRACT["normalize_backend_response"](failure) is None

    failure["result"]["evidence"] = None
    failure["result"]["stage"] = "complete"
    assert CONTRACT["normalize_backend_response"](failure) is None

    success = _complete_envelope()
    success["result"]["evidence"] = None
    assert CONTRACT["normalize_backend_response"](success) is None


def test_fixed_contract_and_admission_gate_are_registered() -> None:
    assert CONTRACT["VERSION"] == 2
    assert CONTRACT["EFFECT"] == "read"
    assert CONTRACT["TARGET_OBJECT_ID"] == 604
    assert CONTRACT["HOST_MANAGEMENT_IP"] == "10.0.30.241"
    assert CONTRACT["TARGET_SSH_POLICY_REF"] == CONTRACT["SSH_POLICY_REF"]
    assert CONTRACT["canonical_sha256"](CONTRACT["PARAMS_SCHEMA"]) == (
        "c5f382b5cddec61fdc7500429aee2778032957461d5e415489e9aba802a3fcaf"
    )
    assert CONTRACT["canonical_sha256"](CONTRACT["RESULT_SCHEMA"]) == (
        "276b549e7efa4128a77ff39190ea484d28e5e1c3d5e4fea65ae7129609aa7c04"
    )
    assert CONTRACT["canonical_sha256"](CONTRACT["SEMANTIC_CONTRACT"]) == (
        "d1e0d743a929785259e12c1c2660bc75b31b7236b2b50b61301be6c82165aadd"
    )
    command = {
        key: value
        for key, value in CONTRACT["COMMAND_CONTRACT"][0].items()
        if key != "description"
    }
    capability_payload = {
        "handler_id": HANDLER_ID,
        "version": 2,
        "effect": "read",
        "commands": [command],
        "semantic_contract": CONTRACT["SEMANTIC_CONTRACT"],
    }
    assert CONTRACT["canonical_sha256"](capability_payload) == (
        "7d1a1b5b804c7c60e181e287ac2bf67e6a3e76a258efa0346818fd32b61271f0"
    )
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))
    assert HANDLER_ID in constants["EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES"]
    assert HANDLER_ID not in constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    normalizer = (ROOT / "netbox_rpc/domain/normalization.py").read_text()
    assert "_GITEA_USER_RUNNER_CACHE_AVAILABLE = False" in normalizer
    assert "validate_gitea_user_runner_cache_target" in normalizer
    commands = runpy.run_path(str(ROOT / "netbox_rpc/command_contract.py"))
    assert HANDLER_ID in commands["EXEMPT_HANDLER_IDS"]
