"""Tests for the issue-#605 release-marker check/reconcile procedures."""

from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
import types
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "netbox_rpc/migrations/0098_seed_release_marker_procedures.py"
CHECK_ID = "service.nmulticloud.deploy.release_marker_check"
RECONCILE_ID = "service.nmulticloud.deploy.release_marker_reconcile"
DEPLOY_HOST_SLUG = "nmulticloud-deploy-host"


def _literal_assignment(name: str) -> dict[str, object]:
    module = ast.parse(MIGRATION.read_text())
    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in statement.targets
        ):
            return ast.literal_eval(statement.value)
    raise AssertionError(f"Missing migration assignment: {name}")


def test_migration_is_single_leaf_and_expand_only() -> None:
    source = MIGRATION.read_text()

    assert '("netbox_rpc", "0097_rpctargetbinding")' in source
    assert "DeleteModel" not in source
    assert "RemoveField" not in source
    assert "AlterField" not in source
    assert "RemoveModel" not in source


def test_params_schema_accepts_only_the_closed_app_enum() -> None:
    schema = _literal_assignment("_APP_PARAMS_SCHEMA")

    assert schema["additionalProperties"] is False
    assert schema["required"] == ["app"]
    assert schema["properties"]["app"]["enum"] == [
        "nms-backend-staging",
        "nms-backend",
    ]


def test_check_is_read_and_no_approval() -> None:
    source = MIGRATION.read_text()
    check_block = source[
        source.index("_CHECK_DEFAULTS = {") : source.index("_RECONCILE_DEFAULTS = {")
    ]

    assert '"handler_id": _CHECK_NAME' in check_block
    assert '"effect": "read"' in check_block
    assert '"approval_required": False' in check_block
    assert '"target_models": _TARGET_MODELS' in check_block


def test_reconcile_is_destructive_and_approval_required() -> None:
    source = MIGRATION.read_text()
    reconcile_block = source[source.index("_RECONCILE_DEFAULTS = {") :]

    assert '"handler_id": _RECONCILE_NAME' in reconcile_block
    assert '"effect": "destructive"' in reconcile_block
    assert '"approval_required": True' in reconcile_block
    assert '"target_models": _TARGET_MODELS' in reconcile_block


def test_representative_commands_use_the_fixed_helper_argv() -> None:
    source = MIGRATION.read_text()

    assert '"/opt/nmulticloud/deploy/bin/reconcile-release-marker"' in source
    assert '"{app}"' in source
    assert '(_CHECK_NAME, _CHECK_DEFAULTS, "--check")' in source
    assert '(_RECONCILE_NAME, _RECONCILE_DEFAULTS, "--apply")' in source


def _load_constants_module():
    spec = importlib.util.spec_from_file_location(
        "release_marker_constants",
        ROOT / "netbox_rpc/constants.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reconcile_is_registered_as_a_protected_two_person_procedure() -> None:
    constants = _load_constants_module()

    assert RECONCILE_ID in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert CHECK_ID not in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert constants.NMULTICLOUD_DEPLOY_RELEASE_MARKER_PROCEDURE_NAMES == {
        CHECK_ID,
        RECONCILE_ID,
    }
    assert (
        constants.RPC_TARGET_BINDING_SLUG_NMULTICLOUD_DEPLOY_HOST
        == DEPLOY_HOST_SLUG
    )


def _load_release_marker_contract_module():
    spec = importlib.util.spec_from_file_location(
        "release_marker_contract_under_test",
        ROOT / "netbox_rpc/release_marker_contract.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reconcile_contract_matches_migration_apply_defaults() -> None:
    contract = _load_release_marker_contract_module()
    defaults_source = MIGRATION.read_text()
    reconcile_block = defaults_source[defaults_source.index("_RECONCILE_DEFAULTS = {") :]

    assert contract.PROCEDURE_NAME == RECONCILE_ID
    assert contract.HANDLER_ID == RECONCILE_ID
    assert contract.EFFECT == "destructive"
    assert contract.APPROVAL_REQUIRED is True
    assert f'"timeout_seconds": {contract.TIMEOUT_SECONDS}' in reconcile_block
    assert contract.COMMAND_CONTRACT[0]["argv"] == [
        "/opt/nmulticloud/deploy/bin/reconcile-release-marker",
        "{app}",
        "--apply",
    ]


def _execution(
    params: object,
    *,
    app: str = "nms-backend-staging",
    target_model_label: str = "dcim.device",
    assigned_object_id: object = 44,
    handler_id: str = CHECK_ID,
):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=handler_id, handler_id=handler_id),
        params=params,
        target_display="nmc-prod-207",
        target_model_label=target_model_label,
        assigned_object_id=assigned_object_id,
        assigned_object=(
            SimpleNamespace(pk=assigned_object_id, name="nmc-prod-207")
            if assigned_object_id
            else None
        ),
    )


class _FakeBinding:
    def __init__(self, pk: int, device_id: int, last_updated) -> None:
        self.pk = pk
        self.device_id = device_id
        self.last_updated = last_updated


class _FakeBindingQuerySet:
    def __init__(self, binding: _FakeBinding | None) -> None:
        self._binding = binding

    def first(self) -> _FakeBinding | None:
        return self._binding


class _FakeBindingManager:
    def __init__(
        self, bindings_by_slug: dict[str, _FakeBinding | None], *, raise_on_query: bool
    ) -> None:
        self._bindings_by_slug = bindings_by_slug
        self._raise_on_query = raise_on_query

    def select_related(self, *_args: object, **_kwargs: object) -> _FakeBindingManager:
        return self

    def filter(self, **kwargs: object) -> _FakeBindingQuerySet:
        if self._raise_on_query:
            raise RuntimeError("simulated NetBox target-binding query failure")
        slug = kwargs.get("slug")
        return _FakeBindingQuerySet(self._bindings_by_slug.get(slug))


_DEFAULT_LAST_UPDATED = datetime(2026, 1, 1, tzinfo=UTC)
_DEFAULT_BINDINGS = {DEPLOY_HOST_SLUG: _FakeBinding(3, 44, _DEFAULT_LAST_UPDATED)}


def _install_release_marker_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    bindings_by_slug: dict[str, _FakeBinding | None] = _DEFAULT_BINDINGS,
    raise_on_device_query: bool = False,
) -> None:
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
    django_conf = types.ModuleType("django.conf")
    django_conf.settings = SimpleNamespace(PLUGINS_CONFIG={})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    netbox_rpc_models.RPCNetBoxPluginAllowlist = type(
        "RPCNetBoxPluginAllowlist", (), {}
    )
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})
    netbox_rpc_models.RPCTargetBinding = type(
        "RPCTargetBinding",
        (),
        {
            "objects": _FakeBindingManager(
                bindings_by_slug, raise_on_query=raise_on_device_query
            )
        },
    )

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
    monkeypatch.setitem(sys.modules, "django.conf", django_conf)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)


def _import_jobs_module(monkeypatch: pytest.MonkeyPatch, **stub_kwargs: object):
    _install_release_marker_stubs(monkeypatch, **stub_kwargs)
    sys.modules.pop("netbox_rpc.jobs", None)
    return importlib.import_module("netbox_rpc.jobs")


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    module = _import_jobs_module(monkeypatch)
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_normalizer_accepts_a_valid_app(jobs_module) -> None:
    execution = _execution({"app": "nms-backend"})

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["app"] == "nms-backend"
    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 44,
    }
    assert normalized["command_fingerprint"]["handler_id"] == CHECK_ID
    assert normalized["command_fingerprint"]["app"] == "nms-backend"


def test_normalizer_rejects_an_unknown_app(jobs_module) -> None:
    execution = _execution({"app": "nms"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_PARAM_INVALID"


def test_normalizer_rejects_unexpected_params(jobs_module) -> None:
    execution = _execution({"app": "nms-backend-staging", "force": True})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_PARAM_INVALID"


def test_normalizer_requires_a_dcim_device_target(jobs_module) -> None:
    execution = _execution(
        {"app": "nms-backend-staging"},
        target_model_label="virtualization.virtualmachine",
    )

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_normalizer_requires_an_existing_assigned_object(jobs_module) -> None:
    execution = _execution({"app": "nms-backend-staging"}, assigned_object_id=None)

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_reconcile_normalizer_binds_the_reconcile_handler_id(jobs_module) -> None:
    execution = _execution({"app": "nms-backend"}, handler_id=RECONCILE_ID)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["command_fingerprint"]["handler_id"] == RECONCILE_ID


def test_normalizer_binds_the_target_binding_id_and_revision_into_the_fingerprint(
    jobs_module,
) -> None:
    execution = _execution({"app": "nms-backend-staging"})

    normalized = jobs_module.normalize_execution_params(execution)

    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["target_binding_id"] == 3
    assert fingerprint["target_binding_revision"] == "2026-01-01T00:00:00Z"
    assert fingerprint["assigned_object_id"] == 44


def test_normalizer_refuses_when_no_binding_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs_module = _import_jobs_module(monkeypatch, bindings_by_slug={})
    execution = _execution({"app": "nms-backend-staging"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_normalizer_refuses_when_the_binding_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs_module = _import_jobs_module(monkeypatch, raise_on_device_query=True)
    execution = _execution({"app": "nms-backend-staging"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_normalizer_refuses_when_target_device_does_not_match_the_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The binding's device is 900; the execution's assigned device is 44
    # (the _execution() default) -- must refuse before any further
    # normalization.
    jobs_module = _import_jobs_module(
        monkeypatch,
        bindings_by_slug={DEPLOY_HOST_SLUG: _FakeBinding(3, 900, _DEFAULT_LAST_UPDATED)},
    )
    execution = _execution({"app": "nms-backend-staging"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"
