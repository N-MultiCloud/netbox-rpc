"""Creation-time Akvorado authorization and content-validation guards."""

from __future__ import annotations

import importlib
import sys
import types
from itertools import product
from contextlib import nullcontext
from types import SimpleNamespace

import pytest


OPENBAO_DECLARED_STRING_FIELDS = (
    ("policy_write", "policy_name"),
    ("policy_write", "policy_content"),
    ("auth_enable", "auth_type"),
    ("auth_enable", "mount_path"),
    ("secrets_enable", "engine_type"),
    ("secrets_enable", "mount_path"),
    ("audit_enable", "audit_type"),
    ("audit_enable", "mount_path"),
    ("snapshot_create", "snapshot_name"),
    ("service_action", "action"),
    ("raft_remove_peer", "peer_id"),
    ("policy_delete", "policy_name"),
    ("auth_disable", "mount_path"),
    ("secrets_disable", "mount_path"),
    ("audit_disable", "mount_path"),
)
OPENBAO_SECRET_SHAPES = (
    ("provider-token", "hvs.ABCDEFGH1234"),
    ("base64", "QWxhZGRpbjpvcGVuIHNlc2FtZSBhbmQtbW9yZS1tYXRlcmlhbA=="),
    ("hex", "a" * 64),
)


@pytest.fixture()
def command_handlers_module(monkeypatch: pytest.MonkeyPatch):
    class ValidationError(Exception):
        def __init__(self, detail, *, code=None):
            super().__init__(detail)
            self.detail = detail
            self.code = code

    class PermissionDenied(Exception):
        pass

    class RPCExecutionError(RuntimeError):
        def __init__(self, message: str, *, code: str) -> None:
            super().__init__(message)
            self.code = code

    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.transaction = SimpleNamespace(atomic=lambda: nullcontext())
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_migration_exceptions = types.ModuleType("django.db.migrations.exceptions")
    django_migration_exceptions.IrreversibleError = type(
        "IrreversibleError", (RuntimeError,), {}
    )
    django_db.migrations = django_migrations
    rest_framework = types.ModuleType("rest_framework")
    drf_serializers = types.ModuleType("rest_framework.serializers")
    drf_serializers.ValidationError = ValidationError
    drf_exceptions = types.ModuleType("rest_framework.exceptions")
    drf_exceptions.PermissionDenied = PermissionDenied
    rest_framework.serializers = drf_serializers

    backends = types.ModuleType("netbox_rpc.backends")
    backends.resolve_backend = lambda value: value
    constants = types.ModuleType("netbox_rpc.constants")
    constants.AKVORADO_1_PROCEDURE_NAMES = {
        "service.akvorado.1.config_read",
        "service.akvorado.1.config_deploy",
    }
    constants.INFLUXDB3_DEBIAN13_PROCEDURE_NAMES = {
        "os.linux.debian.13.preflight_influxdb3_core",
        "os.linux.debian.13.install_influxdb3_core",
    }
    constants.NETBOX_STAGING_ROTATE_BACKEND_TOKEN = (
        "service.netbox.staging.rotate_backend_token"
    )
    constants.GITEA_PRODUCTION_UPGRADE_1_27_1 = (
        "service.gitea.production.upgrade_1_27_1"
    )
    constants.PROTECTED_APPROVAL_PROCEDURE_NAMES = {
        constants.NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
        constants.GITEA_PRODUCTION_UPGRADE_1_27_1,
    }
    aggregate = types.ModuleType("netbox_rpc.domain.aggregate")
    aggregate.RPCExecutionAggregate = type("RPCExecutionAggregate", (), {})
    aggregate.RPCExecutionAggregateError = type(
        "RPCExecutionAggregateError",
        (Exception,),
        {},
    )
    normalization = types.ModuleType("netbox_rpc.domain.normalization")
    normalization.RPCExecutionError = RPCExecutionError
    normalization.normalize_execution_params = lambda execution: {}
    normalization.validate_gitea_upgrade_target = lambda *args, **kwargs: {}
    normalization.validate_akvorado_content_params = lambda name, params: None
    normalization.code_gate_unavailable_reason = lambda procedure_name: None
    event_store = types.ModuleType("netbox_rpc.event_store")
    event_store.mark_execution_failed = lambda *args, **kwargs: None

    for name, module in {
        "netbox": netbox,
        "netbox.plugins": netbox_plugins,
        "django": django,
        "django.db": django_db,
        "django.db.migrations": django_migrations,
        "django.db.migrations.exceptions": django_migration_exceptions,
        "rest_framework": rest_framework,
        "rest_framework.serializers": drf_serializers,
        "rest_framework.exceptions": drf_exceptions,
        "netbox_rpc.backends": backends,
        "netbox_rpc.constants": constants,
        "netbox_rpc.domain.aggregate": aggregate,
        "netbox_rpc.domain.normalization": normalization,
        "netbox_rpc.event_store": event_store,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delitem(
        sys.modules,
        "netbox_rpc.application.command_handlers",
        raising=False,
    )
    module = importlib.import_module("netbox_rpc.application.command_handlers")
    yield module, ValidationError, RPCExecutionError
    sys.modules.pop("netbox_rpc.application.command_handlers", None)
    sys.modules.pop("netbox_rpc.migrations.0078_seed_openbao_procedures", None)


class _RestrictedQuerySet:
    def __init__(self, result: object | None) -> None:
        self.result = result
        self.filtered_pk = None

    def filter(self, *, pk: int):
        self.filtered_pk = pk
        return self

    def first(self):
        return self.result


class _RestrictedManager:
    def __init__(self, result: object | None) -> None:
        self.queryset = _RestrictedQuerySet(result)
        self.restricted_user = None
        self.restricted_action = None

    def restrict(self, user: object, action: str):
        self.restricted_user = user
        self.restricted_action = action
        return self.queryset


def _openbao_procedure(operation: str, *, permissive_schema: bool = False):
    migration_name = "netbox_rpc.migrations.0078_seed_openbao_procedures"
    sys.modules.pop(migration_name, None)
    migration = importlib.import_module(migration_name)
    row = next(
        item
        for item in migration._PROCEDURES
        if item["name"] == f"service.openbao.1.{operation}"
    )
    values = {**row, "version": 1, "enabled": True}
    if permissive_schema:
        values["params_schema"] = {"type": "object"}
    return SimpleNamespace(**values)


class _CreationSerializer:
    def __init__(
        self,
        procedure: object,
        params: dict[str, object],
    ) -> None:
        self.validated_data = {"procedure": procedure, "params": params}
        self.saved = False
        self.persisted_params: dict[str, object] | None = None

    def is_valid(self, *, raise_exception: bool) -> None:
        assert raise_exception is True

    def save(self, **kwargs):
        self.saved = True
        self.persisted_params = dict(self.validated_data["params"])
        return SimpleNamespace(
            pk=901,
            procedure=self.validated_data["procedure"],
            params=self.validated_data["params"],
            **kwargs,
        )


def _allow_creation_to_persist(
    command_handlers: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def queue(self) -> None:
            return None

    models = types.ModuleType("netbox_rpc.models")
    models.RPCExecution = type(
        "RPCExecution",
        (),
        {"TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY": "_timeout_seconds_snapshot"},
    )
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda requester: 1,
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_viewable_assigned_object",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "_verify_backend_capability",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    monkeypatch.setattr(
        command_handlers,
        "_enqueue_execution_job",
        lambda *args, **kwargs: None,
    )


def test_akvorado_target_lookup_uses_user_restricted_queryset(
    command_handlers_module,
) -> None:
    command_handlers, _, _ = command_handlers_module
    user = object()
    target = object()
    manager = _RestrictedManager(target)
    model = SimpleNamespace(objects=manager)
    content_type = SimpleNamespace(model_class=lambda: model)
    procedure = SimpleNamespace(name="service.akvorado.1.config_read")

    command_handlers._require_viewable_assigned_object(
        {
            "assigned_object_type": content_type,
            "assigned_object_id": 42,
        },
        procedure,
        user,
    )

    assert manager.restricted_user is user
    assert manager.restricted_action == "view"
    assert manager.queryset.filtered_pk == 42


def test_akvorado_target_lookup_hides_unauthorized_object_existence(
    command_handlers_module,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    manager = _RestrictedManager(None)
    content_type = SimpleNamespace(model_class=lambda: SimpleNamespace(objects=manager))

    with pytest.raises(ValidationError) as exc_info:
        command_handlers._require_viewable_assigned_object(
            {
                "assigned_object_type": content_type,
                "assigned_object_id": 42,
            },
            SimpleNamespace(name="service.akvorado.1.config_read"),
            object(),
        )

    assert exc_info.value.code == "does_not_exist"
    assert "does not exist" in str(exc_info.value)


def test_staging_rotation_target_is_exact_and_user_viewable(
    command_handlers_module,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    user = object()
    target = SimpleNamespace(name="nms-front-door")
    manager = _RestrictedManager(target)
    model = SimpleNamespace(objects=manager)
    content_type = SimpleNamespace(
        app_label="dcim",
        model="device",
        model_class=lambda: model,
    )
    procedure = SimpleNamespace(name="service.netbox.staging.rotate_backend_token")

    command_handlers._require_staging_rotation_assigned_object(
        {
            "assigned_object_type": content_type,
            "assigned_object_id": 32,
        },
        procedure,
        user,
    )

    assert manager.restricted_user is user
    assert manager.restricted_action == "view"
    assert manager.queryset.filtered_pk == 32

    manager.queryset.result = SimpleNamespace(name="different-device")
    with pytest.raises(ValidationError) as exc_info:
        command_handlers._require_staging_rotation_assigned_object(
            {
                "assigned_object_type": content_type,
                "assigned_object_id": 33,
            },
            procedure,
            user,
        )
    assert exc_info.value.code == "does_not_exist"


def test_staging_rotation_rejects_wrong_or_dangling_target_type(
    command_handlers_module,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = SimpleNamespace(name="service.netbox.staging.rotate_backend_token")

    for content_type in (
        None,
        SimpleNamespace(app_label="virtualization", model="virtualmachine"),
    ):
        with pytest.raises(ValidationError) as exc_info:
            command_handlers._require_staging_rotation_assigned_object(
                {
                    "assigned_object_type": content_type,
                    "assigned_object_id": 32,
                },
                procedure,
                object(),
            )
        assert exc_info.value.code == "required"


def test_staging_rotation_runtime_policy_rejects_every_mutable_drift(
    command_handlers_module,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    contract = command_handlers.staging_contract
    canonical = {
        **contract.PROCEDURE_POLICY,
        "params_schema": contract.PARAMS_SCHEMA,
        "result_schema": contract.RESULT_SCHEMA,
    }

    class Commands:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self

        def order_by(self, _field):
            return self.rows

    def procedure(policy, command_contract=None):
        rows = command_contract or contract.COMMAND_CONTRACT
        return SimpleNamespace(
            **policy,
            commands=Commands([SimpleNamespace(**row) for row in rows]),
        )

    command_handlers._require_staging_rotation_procedure_policy(
        procedure(canonical)
    )

    drifted_values = {
        "name": "service.netbox.staging.different",
        "handler_id": "service.netbox.staging.different",
        "version": 2,
        "enabled": False,
        "target_models": ["virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 1799,
        "approval_required": False,
        "transport_driver": "paramiko",
        "transport_driver_chain": ["paramiko"],
        "output_parser": "json",
        "output_schema": {"type": "object"},
        "params_schema": {"type": "object"},
        "result_schema": {"type": "object"},
    }
    for field, value in drifted_values.items():
        policy = dict(canonical)
        policy[field] = value
        with pytest.raises(ValidationError):
            command_handlers._require_staging_rotation_procedure_policy(
                procedure(policy)
            )

    changed_command = [dict(contract.COMMAND_CONTRACT[0])]
    changed_command[0]["argv"] = ["backend-orchestrated", "different-operation"]
    with pytest.raises(ValidationError):
        command_handlers._require_staging_rotation_procedure_policy(
            procedure(canonical, changed_command)
        )


def test_gitea_upgrade_target_lookup_is_exact_and_user_restricted(
    command_handlers_module,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    user = object()
    target = SimpleNamespace(pk=170, name="Gitea")
    manager = _RestrictedManager(target)
    content_type = SimpleNamespace(
        app_label="virtualization",
        model="virtualmachine",
        model_class=lambda: SimpleNamespace(objects=manager),
    )
    procedure = SimpleNamespace(name="service.gitea.production.upgrade_1_27_1")

    command_handlers._require_gitea_upgrade_assigned_object(
        {
            "assigned_object_type": content_type,
            "assigned_object_id": 170,
        },
        procedure,
        user,
    )
    assert manager.restricted_user is user
    assert manager.restricted_action == "view"
    assert manager.queryset.filtered_pk == 170

    for object_id in (None, 169, 171):
        with pytest.raises(ValidationError):
            command_handlers._require_gitea_upgrade_assigned_object(
                {
                    "assigned_object_type": content_type,
                    "assigned_object_id": object_id,
                },
                procedure,
                user,
            )


def test_gitea_upgrade_active_policy_and_credential_reference_are_exact(
    command_handlers_module,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    contract = command_handlers.gitea_contract

    class Commands:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self

        def order_by(self, _field):
            return self.rows

    def procedure(policy):
        return SimpleNamespace(
            **policy,
            commands=Commands(
                [SimpleNamespace(**row) for row in contract.COMMAND_CONTRACT]
            ),
        )

    canonical = {
        **contract.PROCEDURE_POLICY,
        "params_schema": contract.PARAMS_SCHEMA,
        "result_schema": contract.RESULT_SCHEMA,
    }
    command_handlers._require_protected_procedure_policy(procedure(canonical))
    for field, value in {
        "enabled": False,
        "handler_id": "different-handler",
        "target_models": ["dcim.device"],
        "timeout_seconds": 1799,
        "approval_required": False,
        "params_schema": {"type": "object"},
        "result_schema": {"type": "object"},
    }.items():
        drifted = dict(canonical)
        drifted[field] = value
        with pytest.raises(ValidationError):
            command_handlers._require_protected_procedure_policy(procedure(drifted))

    execution = SimpleNamespace(procedure=SimpleNamespace(effect="destructive"))
    assert command_handlers._credential_policy_reference(
        {"ssh_policy_ref": contract.SSH_POLICY_REF},
        execution,
    ) == contract.SSH_POLICY_REF


def test_gitea_requires_explicit_compatible_backend_capability(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    statuses = SimpleNamespace(
        COMPATIBLE=object(),
        MISMATCH=object(),
        UNKNOWN=object(),
    )
    observed = {}
    capabilities = types.ModuleType("netbox_rpc.capabilities")
    capabilities.CapabilityStatus = statuses
    capabilities.fetch_backend_capabilities = lambda target, use_cache=True: observed.update(
        {"target": target, "use_cache": use_cache}
    ) or object()
    procedure = SimpleNamespace(
        name="service.gitea.production.upgrade_1_27_1",
    )
    capabilities.verify_procedure_capability = lambda proc, manifest: statuses.UNKNOWN
    models = types.ModuleType("netbox_rpc.models")
    models.RpcPluginSettings = type("RpcPluginSettings", (), {})
    monkeypatch.setitem(sys.modules, "netbox_rpc.capabilities", capabilities)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.setattr(
        sys.modules["netbox_rpc"], "capabilities", capabilities, raising=False
    )

    with pytest.raises(ValidationError):
        command_handlers._verify_backend_capability(
            procedure,
            backend_target="locked-backend",
            use_cache=False,
        )
    assert observed == {"target": "locked-backend", "use_cache": False}

    capabilities.verify_procedure_capability = (
        lambda proc, manifest: statuses.COMPATIBLE
    )
    command_handlers._verify_backend_capability(
        procedure,
        backend_target="locked-backend",
        use_cache=False,
    )


def test_run_execution_persists_jobs_closed_gitea_indeterminate_response(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    closed = {
        "ok": False,
        "result": {
            "ok": False,
            "procedure": "service.gitea.production.upgrade_1_27_1",
            "target": "Gitea",
            "changed": None,
            "healthy": None,
            "stage": "indeterminate",
        },
    }
    recorded = []

    class Aggregate:
        def __init__(self, execution):
            self.execution = execution

        def normalize(self, normalized, resolved_hash):
            return None

        def record_backend_response(self, response):
            recorded.append(response)

        def fail(self, message, code):
            pytest.fail(f"unexpected worker failure {code}: {message}")

    procedure = SimpleNamespace(
        name="service.gitea.production.upgrade_1_27_1",
        handler_id="service.gitea.production.upgrade_1_27_1",
    )
    execution = SimpleNamespace(
        pk=1700,
        procedure=procedure,
        backend_id=1,
        status="running",
        STATUS_RUNNING="running",
    )
    models = types.ModuleType("netbox_rpc.models")
    models.RpcPluginSettings = type(
        "RpcPluginSettings",
        (),
        {"get_solo": classmethod(lambda cls: SimpleNamespace(enabled=True))},
    )
    jobs = types.ModuleType("netbox_rpc.jobs")
    jobs._hash_json = lambda value: "fingerprint"
    jobs._call_backend = lambda target, execution, lease=None: closed
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.setitem(sys.modules, "netbox_rpc.jobs", jobs)
    monkeypatch.setattr(sys.modules["netbox_rpc"], "jobs", jobs, raising=False)
    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    monkeypatch.setattr(command_handlers, "_transition_locked", lambda ex, fn: ex)
    backend_target = SimpleNamespace(
        url="http://127.0.0.1:16005",
        verify_ssl=False,
    )
    monkeypatch.setattr(
        command_handlers,
        "resolve_backend",
        lambda backend: backend_target,
    )
    monkeypatch.setattr(
        command_handlers,
        "_verify_backend_capability",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "normalize_execution_params",
        lambda ex: {"command_fingerprint": {"handler_id": procedure.handler_id}},
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_current_protected_approval",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "_issue_dispatch_lease",
        lambda *args, **kwargs: object(),
    )

    command_handlers.run_execution(execution)

    assert recorded == [closed]


def test_protected_admission_rejects_backend_drift_before_capability_probe(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = SimpleNamespace(
        name="service.gitea.production.upgrade_1_27_1",
        enabled=True,
        approval_required=True,
    )

    class Serializer:
        validated_data = {"procedure": procedure, "params": {}}
        initial_data = {
            "procedure_id": procedure.name,
            "assigned_object_type": "virtualization.virtualmachine",
            "assigned_object_id": 170,
            "params": {},
        }
        saved = False

        def is_valid(self, *, raise_exception: bool) -> None:
            assert raise_exception is True

        def save(self, **kwargs):
            self.saved = True
            return SimpleNamespace()

    serializer = Serializer()
    capability_probe = SimpleNamespace(called=False)
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda user: 1,
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_protected_procedure_policy",
        lambda protected_procedure: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_protected_procedure_scope",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_protected_creation_shape",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "resolve_backend",
        lambda backend: SimpleNamespace(
            url="https://public-proxy.invalid",
            verify_ssl=True,
        ),
    )
    monkeypatch.setattr(
        command_handlers,
        "_verify_backend_capability",
        lambda *args, **kwargs: setattr(capability_probe, "called", True),
    )

    with pytest.raises(ValidationError):
        command_handlers.create_execution(
            serializer=serializer,
            user=SimpleNamespace(has_perm=lambda permission: True),
        )

    assert capability_probe.called is False
    assert serializer.saved is False


def test_worker_rejects_backend_drift_before_capability_or_dispatch(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    observed = []

    class Aggregate:
        def __init__(self, execution):
            self.execution = execution

        def fail(self, message, code):
            observed.append(("fail", code))

    procedure = SimpleNamespace(
        name="service.gitea.production.upgrade_1_27_1",
        handler_id="service.gitea.production.upgrade_1_27_1",
    )
    execution = SimpleNamespace(
        pk=1701,
        procedure=procedure,
        backend_id=1,
        status="running",
        STATUS_RUNNING="running",
    )
    models = types.ModuleType("netbox_rpc.models")
    models.RpcPluginSettings = type(
        "RpcPluginSettings",
        (),
        {"get_solo": classmethod(lambda cls: SimpleNamespace(enabled=True))},
    )
    jobs = types.ModuleType("netbox_rpc.jobs")
    jobs._call_backend = lambda *args, **kwargs: observed.append(("dispatch", None))
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.setitem(sys.modules, "netbox_rpc.jobs", jobs)
    monkeypatch.setattr(sys.modules["netbox_rpc"], "jobs", jobs, raising=False)
    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    monkeypatch.setattr(command_handlers, "_transition_locked", lambda ex, fn: ex)
    monkeypatch.setattr(
        command_handlers,
        "resolve_backend",
        lambda backend: SimpleNamespace(
            url="https://public-proxy.invalid",
            verify_ssl=True,
        ),
    )
    monkeypatch.setattr(
        command_handlers,
        "_verify_backend_capability",
        lambda *args, **kwargs: observed.append(("capability", None)),
    )

    with pytest.raises(RPCExecutionError) as raised:
        command_handlers.run_execution(execution)

    assert raised.value.code == "RPC_BACKEND_BINDING_INVALID"
    assert observed == [("fail", "RPC_BACKEND_BINDING_INVALID")]


def test_protected_worker_terminalizes_resolver_exception_without_contact(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    observed = []

    class Aggregate:
        def __init__(self, execution):
            self.execution = execution

        def fail(self, message, code):
            observed.append(("fail", message, code))

    procedure = SimpleNamespace(
        name="service.gitea.production.upgrade_1_27_1",
        handler_id="service.gitea.production.upgrade_1_27_1",
    )
    execution = SimpleNamespace(
        pk=1702,
        procedure=procedure,
        backend_id=1,
        status="running",
        STATUS_RUNNING="running",
    )
    models = types.ModuleType("netbox_rpc.models")
    models.RpcPluginSettings = type(
        "RpcPluginSettings",
        (),
        {"get_solo": classmethod(lambda cls: SimpleNamespace(enabled=True))},
    )
    jobs = types.ModuleType("netbox_rpc.jobs")
    jobs._call_backend = lambda *args, **kwargs: observed.append(("dispatch",))
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.setitem(sys.modules, "netbox_rpc.jobs", jobs)
    monkeypatch.setattr(sys.modules["netbox_rpc"], "jobs", jobs, raising=False)
    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    monkeypatch.setattr(command_handlers, "_transition_locked", lambda ex, fn: ex)
    def raise_resolver_error(backend):
        raise RuntimeError("opaque resolver diagnostic")

    monkeypatch.setattr(command_handlers, "resolve_backend", raise_resolver_error)
    monkeypatch.setattr(
        command_handlers,
        "_verify_backend_capability",
        lambda *args, **kwargs: observed.append(("capability",)),
    )

    with pytest.raises(RPCExecutionError) as raised:
        command_handlers.run_execution(execution)

    assert raised.value.code == "RPC_BACKEND_RESOLUTION_FAILED"
    assert observed == [
        (
            "fail",
            "RPC backend resolution failed; execution not dispatched.",
            "RPC_BACKEND_RESOLUTION_FAILED",
        )
    ]


def test_unsafe_config_content_is_rejected_before_serializer_save(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, ValidationError, RPCExecutionError = command_handlers_module
    procedure = SimpleNamespace(
        name="service.akvorado.1.config_deploy",
        enabled=True,
        approval_required=False,
        params_schema={},
    )

    class Serializer:
        validated_data = {"procedure": procedure, "params": {"config_content": "x"}}
        saved = False

        def is_valid(self, *, raise_exception: bool) -> None:
            assert raise_exception is True

        def save(self, **kwargs):
            self.saved = True
            return SimpleNamespace()

    serializer = Serializer()
    user = SimpleNamespace(has_perm=lambda permission: True)
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda user: 1,
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_viewable_assigned_object",
        lambda validated_data, procedure, user: None,
    )
    monkeypatch.setattr(command_handlers, "_verify_backend_capability", lambda p: None)

    def reject_unsafe_content(name, params):
        raise RPCExecutionError("unsafe config content", code="RPC_PARAM_INVALID")

    monkeypatch.setattr(
        command_handlers,
        "validate_akvorado_content_params",
        reject_unsafe_content,
    )

    with pytest.raises(ValidationError) as caught:
        command_handlers.create_execution(serializer=serializer, user=user)

    assert set(caught.value.detail) == {"params"}
    assert serializer.saved is False


def test_openbao_string_field_oracle_covers_the_complete_seeded_catalogue(
    command_handlers_module,
) -> None:
    command_handlers, _, _ = command_handlers_module
    migration_name = "netbox_rpc.migrations.0078_seed_openbao_procedures"
    sys.modules.pop(migration_name, None)
    migration = importlib.import_module(migration_name)
    actual = set()
    for row in migration._PROCEDURES:
        operation = row["name"].removeprefix("service.openbao.1.")
        for field, schema in row["params_schema"]["properties"].items():
            declared_type = schema.get("type")
            if declared_type == "string" or (
                isinstance(declared_type, list) and "string" in declared_type
            ):
                actual.add((operation, field))

    assert actual == set(OPENBAO_DECLARED_STRING_FIELDS)
    # Prove this oracle observes the production scanner imported by the
    # creation command rather than a test-local imitation.
    assert command_handlers.validate_openbao_params_for_persistence.__module__ == (
        "netbox_rpc.openbao_validation"
    )


@pytest.mark.parametrize(
    ("operation", "field", "shape_label", "material"),
    [
        (operation, field, shape_label, material)
        for (operation, field), (shape_label, material) in product(
            OPENBAO_DECLARED_STRING_FIELDS,
            OPENBAO_SECRET_SHAPES,
        )
    ],
)
def test_openbao_secret_shape_is_rejected_in_every_declared_string_field_before_save(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    field: str,
    shape_label: str,
    material: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = _openbao_procedure(operation, permissive_schema=True)
    serializer = _CreationSerializer(procedure, {field: material})
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda requester: 1,
    )

    with pytest.raises(ValidationError) as caught:
        command_handlers.create_execution(
            serializer=serializer,
            user=SimpleNamespace(has_perm=lambda permission: True),
        )

    assert set(caught.value.detail) == {"params"}, shape_label
    assert "secret-shaped material" in caught.value.detail["params"]
    assert serializer.saved is False


@pytest.mark.parametrize(
    ("case_name", "policy_content"),
    [
        ("json-unicode-key", r'{"pass\u0077ord":"hunter2"}'),
        (
            "json-unicode-value",
            r'{"description":"hvs.\u0041BCDEFGH1234"}',
        ),
        ("escaped-hcl-key", r'"pass\u0077ord" = "hunter2"'),
        ("comment", r'# {"pass\u0077ord":"hunter2"}'),
        (
            "heredoc",
            "description = <<EOF\n"
            + r'{"note":"hvs.\u0041BCDEFGH1234"}'
            + "\nEOF",
        ),
        (
            "unicode-separators",
            '"pass\\u0077ord"\u2028=\u2029"hunter2"',
        ),
    ],
)
def test_openbao_decodes_adversarial_policy_content_before_persistence(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    case_name: str,
    policy_content: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = _openbao_procedure("policy_write")
    params = {"policy_name": "decode-oracle", "policy_content": policy_content}
    # The legacy raw-text schema patterns intentionally remain as defense in
    # depth, but these inputs demonstrate their escaped-text blind spot.
    command_handlers.jsonschema.validate(params, procedure.params_schema)
    serializer = _CreationSerializer(procedure, params)
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda requester: 1,
    )

    with pytest.raises(ValidationError) as caught:
        command_handlers.create_execution(
            serializer=serializer,
            user=SimpleNamespace(has_perm=lambda permission: True),
        )

    assert set(caught.value.detail) == {"params"}, case_name
    assert serializer.saved is False


@pytest.mark.parametrize(
    ("case_name", "params"),
    [
        ("decoded-dictionary-key", {"outer": [{"password": "hunter2"}]}),
        ("secret-shaped-key", {"outer": {"a" * 64: "ordinary"}}),
        ("nested-provider-value", {"outer": [{"label": "hvs.ABCDEFGH1234"}]}),
        (
            "nested-base64-value",
            {
                "outer": [
                    "QWxhZGRpbjpvcGVuIHNlc2FtZSBhbmQtbW9yZS1tYXRlcmlhbA=="
                ]
            },
        ),
    ],
)
def test_openbao_scanner_walks_nested_dictionary_keys_and_values_before_save(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    case_name: str,
    params: dict[str, object],
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = _openbao_procedure("inspect", permissive_schema=True)
    serializer = _CreationSerializer(procedure, params)
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda requester: 1,
    )

    with pytest.raises(ValidationError) as caught:
        command_handlers.create_execution(
            serializer=serializer,
            user=SimpleNamespace(has_perm=lambda permission: True),
        )

    assert set(caught.value.detail) == {"params"}, case_name
    assert serializer.saved is False


@pytest.mark.parametrize(
    ("accepted", "policy_content"),
    [
        (True, "🙂" * 262_144),
        (False, "🙂" * 262_144 + "x"),
    ],
    ids=("exactly-1-mib", "one-byte-over"),
)
def test_openbao_policy_content_creation_limit_is_utf8_bytes_not_characters(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    accepted: bool,
    policy_content: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = _openbao_procedure("policy_write")
    serializer = _CreationSerializer(
        procedure,
        {"policy_name": "byte-boundary", "policy_content": policy_content},
    )
    _allow_creation_to_persist(command_handlers, monkeypatch)
    user = SimpleNamespace(has_perm=lambda permission: True)

    if accepted:
        execution = command_handlers.create_execution(serializer=serializer, user=user)
        assert execution is not None
        assert serializer.saved is True
        assert len(policy_content.encode("utf-8")) == 1_048_576
    else:
        with pytest.raises(ValidationError) as caught:
            command_handlers.create_execution(serializer=serializer, user=user)
        assert set(caught.value.detail) == {"params"}
        assert serializer.saved is False
        assert len(policy_content) < 1_048_576
        assert len(policy_content.encode("utf-8")) == 1_048_577


def test_legitimate_openbao_names_paths_and_real_policy_body_still_persist(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    _allow_creation_to_persist(command_handlers, monkeypatch)
    user = SimpleNamespace(has_perm=lambda permission: True)
    cases = (
        (
            _openbao_procedure("policy_write"),
            {
                "policy_name": "ops-read",
                "policy_content": (
                    'path "kv/data/operations/*" {\n'
                    '  capabilities = ["read", "list"]\n'
                    "}"
                ),
            },
        ),
        (
            _openbao_procedure("auth_enable"),
            {"auth_type": "approle", "mount_path": "machine/auth"},
        ),
    )

    for procedure, params in cases:
        serializer = _CreationSerializer(procedure, params)
        command_handlers.create_execution(serializer=serializer, user=user)
        assert serializer.saved is True
        assert all(serializer.persisted_params[key] == value for key, value in params.items())


def test_openbao_scanner_does_not_change_non_openbao_creation(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    _allow_creation_to_persist(command_handlers, monkeypatch)
    procedure = SimpleNamespace(
        name="service.example.1.write",
        handler_id="service.example_1.write",
        enabled=True,
        approval_required=False,
        params_schema={"type": "object"},
        timeout_seconds=60,
    )
    params = {"public_reference": "hvs.ABCDEFGH1234"}
    serializer = _CreationSerializer(procedure, params)

    command_handlers.create_execution(
        serializer=serializer,
        user=SimpleNamespace(has_perm=lambda permission: True),
    )

    assert serializer.saved is True
    assert serializer.persisted_params["public_reference"] == params["public_reference"]


@pytest.mark.parametrize(
    "policy_content",
    [
        '  client_secret = "hunter2!"\npath "kv/*" {}',
        '  connection_url =\n    "opaque-credential"\ntelemetry {}',
    ],
)
def test_openbao_sensitive_assignment_is_rejected_before_serializer_save(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    policy_content: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    migration_name = "netbox_rpc.migrations.0078_seed_openbao_procedures"
    sys.modules.pop(migration_name, None)
    migration = importlib.import_module(migration_name)
    row = next(
        item
        for item in migration._PROCEDURES
        if item["name"] == "service.openbao.1.policy_write"
    )
    procedure = SimpleNamespace(**row, version=1, enabled=True)

    class Serializer:
        validated_data = {
            "procedure": procedure,
            "params": {
                "policy_name": "must-not-persist",
                "policy_content": policy_content,
            },
        }
        saved = False

        def is_valid(self, *, raise_exception: bool) -> None:
            assert raise_exception is True

        def save(self, **kwargs):
            self.saved = True
            return SimpleNamespace()

    serializer = Serializer()
    user = SimpleNamespace(
        has_perm=lambda permission: permission == "netbox_rpc.execute_rpcprocedure"
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda requester: 1,
    )

    with pytest.raises(ValidationError) as caught:
        command_handlers.create_execution(serializer=serializer, user=user)

    assert set(caught.value.detail) == {"params"}
    assert serializer.saved is False


@pytest.mark.parametrize("action", ["stop", "disable"])
def test_execute_only_caller_cannot_stop_or_disable_openbao(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    command_handlers, _, _ = command_handlers_module
    migration_name = "netbox_rpc.migrations.0078_seed_openbao_procedures"
    sys.modules.pop(migration_name, None)
    migration = importlib.import_module(migration_name)
    row = next(
        item
        for item in migration._PROCEDURES
        if item["name"] == "service.openbao.1.service_action"
    )
    procedure = SimpleNamespace(**row, version=1, enabled=True)

    class Serializer:
        validated_data = {"procedure": procedure, "params": {"action": action}}
        saved = False

        def is_valid(self, *, raise_exception: bool) -> None:
            assert raise_exception is True

        def save(self, **kwargs):
            self.saved = True
            return SimpleNamespace()

    serializer = Serializer()
    user = SimpleNamespace(
        has_perm=lambda permission: permission == "netbox_rpc.execute_rpcprocedure"
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda requester: 1,
    )

    with pytest.raises(command_handlers.PermissionDenied, match="requires approval"):
        command_handlers.create_execution(serializer=serializer, user=user)

    assert serializer.saved is False
