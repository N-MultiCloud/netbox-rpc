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
MIGRATION = ROOT / "netbox_rpc/migrations/0096_seed_netbox_openbao_import_procedures.py"
DRY_RUN_ID = "service.netbox.openbao_import.dry_run"
APPLY_ID = "service.netbox.openbao_import.apply"


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

    assert '("netbox_rpc", "0095_packer_openbao_assignment_id_param")' in source
    assert "DeleteModel" not in source
    assert "RemoveField" not in source
    assert "AlterField" not in source
    assert "RemoveModel" not in source


def test_params_schema_accepts_only_the_closed_environment_enum() -> None:
    schema = _literal_assignment("_ENVIRONMENT_PARAMS_SCHEMA")

    assert schema["additionalProperties"] is False
    assert schema["required"] == ["environment"]
    assert schema["properties"]["environment"]["enum"] == ["staging", "production"]


def test_dry_run_is_read_and_no_approval() -> None:
    # ``_DRY_RUN_DEFAULTS``/``_APPLY_DEFAULTS`` embed a function call
    # (``_result_schema(...)``), so they are not ``ast.literal_eval``-safe;
    # assert the source text directly instead.
    source = MIGRATION.read_text()
    dry_run_block = source[
        source.index("_DRY_RUN_DEFAULTS = {") : source.index("_APPLY_DEFAULTS = {")
    ]

    assert '"handler_id": _DRY_RUN_NAME' in dry_run_block
    assert '"effect": "read"' in dry_run_block
    assert '"approval_required": False' in dry_run_block
    assert '"target_models": _TARGET_MODELS' in dry_run_block


def test_apply_is_destructive_and_approval_required() -> None:
    source = MIGRATION.read_text()
    apply_block = source[source.index("_APPLY_DEFAULTS = {") :]

    assert '"handler_id": _APPLY_NAME' in apply_block
    assert '"effect": "destructive"' in apply_block
    assert '"approval_required": True' in apply_block
    assert '"target_models": _TARGET_MODELS' in apply_block


def test_both_handlers_have_documented_command_contract_exemptions() -> None:
    spec = importlib.util.spec_from_file_location(
        "openbao_import_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec is not None and spec.loader is not None
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    for handler_id in (DRY_RUN_ID, APPLY_ID):
        assert handler_id in command_contract.EXEMPT_HANDLER_IDS
        assert command_contract.EXEMPT_HANDLER_RATIONALE[handler_id].strip()


def _load_constants_module():
    spec = importlib.util.spec_from_file_location(
        "openbao_import_constants",
        ROOT / "netbox_rpc/constants.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_apply_is_registered_as_a_protected_two_person_procedure() -> None:
    constants = _load_constants_module()

    assert APPLY_ID in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert constants.NETBOX_OPENBAO_IMPORT_PROCEDURE_NAMES == {DRY_RUN_ID, APPLY_ID}


def _execution(
    params: object,
    *,
    environment: str = "staging",
    target_model_label: str = "dcim.device",
    assigned_object_id: object = 32,
    handler_id: str = DRY_RUN_ID,
):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=handler_id, handler_id=handler_id),
        params=params,
        target_display="netbox-staging-host",
        target_model_label=target_model_label,
        assigned_object_id=assigned_object_id,
        assigned_object=(
            SimpleNamespace(pk=assigned_object_id, name="netbox-staging-host")
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
    def __init__(self, bindings_by_slug: dict[str, _FakeBinding | None], *, raise_on_query: bool) -> None:
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

# Default fixture: device 32 is bound for both staging and production (the
# same device may be bound for both environments when staging and production
# NetBox share one host).
_DEFAULT_BINDINGS = {
    "netbox-openbao-import-staging": _FakeBinding(1, 32, _DEFAULT_LAST_UPDATED),
    "netbox-openbao-import-production": _FakeBinding(2, 32, _DEFAULT_LAST_UPDATED),
}


def _install_import_stubs(
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
        {"objects": _FakeBindingManager(bindings_by_slug, raise_on_query=raise_on_device_query)},
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
    _install_import_stubs(monkeypatch, **stub_kwargs)
    sys.modules.pop("netbox_rpc.jobs", None)
    return importlib.import_module("netbox_rpc.jobs")


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    module = _import_jobs_module(monkeypatch)
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_normalizer_accepts_a_valid_environment(jobs_module) -> None:
    execution = _execution({"environment": "production"})

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["environment"] == "production"
    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 32,
    }
    assert normalized["command_fingerprint"]["handler_id"] == DRY_RUN_ID
    assert normalized["command_fingerprint"]["environment"] == "production"


def test_normalizer_rejects_an_unknown_environment(jobs_module) -> None:
    execution = _execution({"environment": "prod"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_PARAM_INVALID"


def test_normalizer_rejects_unexpected_params(jobs_module) -> None:
    execution = _execution({"environment": "staging", "id_map_path": "/tmp/x"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_PARAM_INVALID"


def test_normalizer_accepts_platform_internal_keys(jobs_module) -> None:
    execution = _execution(
        {"environment": "staging", "_timeout_seconds_snapshot": 900, "_intent": None}
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["environment"] == "staging"


def test_normalizer_requires_a_dcim_device_target(jobs_module) -> None:
    execution = _execution(
        {"environment": "staging"},
        target_model_label="virtualization.virtualmachine",
    )

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_normalizer_requires_an_existing_assigned_object(jobs_module) -> None:
    execution = _execution({"environment": "staging"}, assigned_object_id=None)

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_apply_normalizer_binds_the_apply_handler_id(jobs_module) -> None:
    execution = _execution({"environment": "production"}, handler_id=APPLY_ID)

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["command_fingerprint"]["handler_id"] == APPLY_ID


# --- environment -> RPCTargetBinding device binding (round-4, #326) ---


def test_normalizer_binds_the_target_binding_id_and_revision_into_the_fingerprint(
    jobs_module,
) -> None:
    execution = _execution({"environment": "staging"})

    normalized = jobs_module.normalize_execution_params(execution)

    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["target_binding_id"] == 1
    assert fingerprint["target_binding_revision"] == "2026-01-01T00:00:00Z"
    assert fingerprint["assigned_object_id"] == 32
    assert "configured_target_device_id" not in fingerprint


def test_normalizer_refuses_when_no_binding_exists_for_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs_module = _import_jobs_module(
        monkeypatch,
        bindings_by_slug={
            "netbox-openbao-import-production": _FakeBinding(2, 32, _DEFAULT_LAST_UPDATED),
        },
    )
    execution = _execution({"environment": "staging"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_normalizer_refuses_when_the_binding_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs_module = _import_jobs_module(monkeypatch, raise_on_device_query=True)
    execution = _execution({"environment": "staging"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_normalizer_refuses_when_target_device_does_not_match_the_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The staging binding's device is 900; the execution's assigned device is
    # 32 (the _execution() default) -- must refuse before any further
    # normalization.
    jobs_module = _import_jobs_module(
        monkeypatch,
        bindings_by_slug={
            "netbox-openbao-import-staging": _FakeBinding(1, 900, _DEFAULT_LAST_UPDATED),
            "netbox-openbao-import-production": _FakeBinding(2, 32, _DEFAULT_LAST_UPDATED),
        },
    )
    execution = _execution({"environment": "staging"})

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_normalizer_allows_the_same_device_id_for_both_environments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Staging and production NetBox may share one host: the same device may
    # be bound for both environments, and either must accept it.
    jobs_module = _import_jobs_module(
        monkeypatch,
        bindings_by_slug={
            "netbox-openbao-import-staging": _FakeBinding(1, 32, _DEFAULT_LAST_UPDATED),
            "netbox-openbao-import-production": _FakeBinding(2, 32, _DEFAULT_LAST_UPDATED),
        },
    )

    staging = jobs_module.normalize_execution_params(_execution({"environment": "staging"}))
    production = jobs_module.normalize_execution_params(
        _execution({"environment": "production"})
    )

    assert staging["command_fingerprint"]["target_binding_id"] == 1
    assert production["command_fingerprint"]["target_binding_id"] == 2
