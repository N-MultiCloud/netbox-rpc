"""Creation-time Akvorado authorization and content-validation guards."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import types
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from itertools import product
from types import SimpleNamespace

import pytest

OPENBAO_DECLARED_STRING_FIELDS = (
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
OPENBAO_HIGH_ENTROPY_BASE64 = "X7J3qP9mZv1KcR8sTy4NbW6LdA2HgU0eFo5IiE_aBcD"
OPENBAO_OPERATIONAL_IDENTIFIER_CASES = (
    (
        "policy_delete",
        "policy_name",
        "production-kubernetes-authentication-read-only-policy",
        {},
    ),
    (
        "auth_enable",
        "mount_path",
        "production-kubernetes-authentication-backend",
        {"auth_type": "kubernetes"},
    ),
    (
        "raft_remove_peer",
        "peer_id",
        "openbao-production-eu-west-peer-identifier-000001",
        {},
    ),
    (
        "snapshot_create",
        "snapshot_name",
        "openbao-production-snapshot-20260825T120000Z",
        {},
    ),
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
    constants.AKVORADO_BOOTSTRAP_DEBIAN13_PROCEDURE_NAMES = {
        "os.linux.debian.13.preflight_akvorado",
        "os.linux.debian.13.install_akvorado",
    }
    constants.AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL = (
        "os.linux.debian.13.install_akvorado"
    )
    constants.INFLUXDB3_DEBIAN13_PROCEDURE_NAMES = {
        "os.linux.debian.13.preflight_influxdb3_core",
        "os.linux.debian.13.install_influxdb3_core",
    }
    constants.NETBOX_STAGING_ROTATE_BACKEND_TOKEN = (
        "service.netbox.staging.rotate_backend_token"
    )
    constants.NETBOX_STAGING_DEPLOY_DNS_PAIR = "service.netbox.staging.deploy_dns_pair"
    constants.GITEA_PRODUCTION_UPGRADE_1_27_1 = (
        "service.gitea.production.upgrade_1_27_1"
    )
    constants.GITEA_RUNNER_REGISTER = "service.gitea.runner.register"
    constants.GITEA_ORG_CI_RUNNER_PROVISION = (
        "service.gitea.actions_runner.provision_org_ci_runner"
    )
    constants.EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES = (
        constants.AKVORADO_BOOTSTRAP_DEBIAN13_PROCEDURE_NAMES
        | {
            constants.NETBOX_STAGING_DEPLOY_DNS_PAIR,
            constants.GITEA_PRODUCTION_UPGRADE_1_27_1,
            constants.GITEA_RUNNER_REGISTER,
            constants.GITEA_ORG_CI_RUNNER_PROVISION,
        }
    )
    constants.PROTECTED_APPROVAL_PROCEDURE_NAMES = {
        constants.NETBOX_STAGING_ROTATE_BACKEND_TOKEN,
        constants.NETBOX_STAGING_DEPLOY_DNS_PAIR,
        constants.GITEA_PRODUCTION_UPGRADE_1_27_1,
        constants.GITEA_RUNNER_REGISTER,
        constants.GITEA_ORG_CI_RUNNER_PROVISION,
        constants.AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL,
    }
    akvorado_contract = types.ModuleType("netbox_rpc.akvorado_bootstrap_contract")
    akvorado_contract.AKVORADO_BOOTSTRAP_CURRENT_CAPABILITY_HASHES = {
        constants.AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL: "a" * 64,
    }
    akvorado_contract.canonical_sha256 = lambda value: hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
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
    normalization.validate_gitea_org_ci_runner_target = lambda *args, **kwargs: {}
    normalization.validate_gitea_runner_target = lambda *args, **kwargs: {}
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
        "netbox_rpc.akvorado_bootstrap_contract": akvorado_contract,
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
        self.persisted_kwargs: dict[str, object] | None = None

    def is_valid(self, *, raise_exception: bool) -> None:
        assert raise_exception is True

    def save(self, **kwargs):
        self.saved = True
        self.persisted_params = dict(self.validated_data["params"])
        self.persisted_kwargs = dict(kwargs)
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

    command_handlers._require_staging_rotation_procedure_policy(procedure(canonical))

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


def test_gitea_org_ci_runner_uses_protected_exact_viewable_target_paths(
    command_handlers_module,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure_name = "service.gitea.actions_runner.provision_org_ci_runner"
    procedure = SimpleNamespace(name=procedure_name)
    user = object()
    target = SimpleNamespace(pk=416, name="Gitea-Runner")
    manager = _RestrictedManager(target)
    content_type = SimpleNamespace(
        app_label="virtualization",
        model="virtualmachine",
        model_class=lambda: SimpleNamespace(objects=manager),
    )
    validated_data = {
        "assigned_object_type": content_type,
        "assigned_object_id": 416,
    }

    assert procedure_name in command_handlers.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert procedure_name in command_handlers._ASSIGNED_OBJECT_SCOPED_PROCEDURE_NAMES
    assert (
        command_handlers._protected_contract(procedure_name)
        is command_handlers.gitea_org_ci_runner_contract
    )
    assert command_handlers._PROTECTED_APPROVAL_REASON[procedure_name] != (
        command_handlers._GITEA_RUNNER_APPROVAL_REASON
    )
    assert command_handlers._PROTECTED_REJECTION_REASON[procedure_name] != (
        command_handlers._GITEA_RUNNER_REJECTION_REASON
    )

    command_handlers._require_viewable_assigned_object(
        validated_data,
        procedure,
        user,
    )
    command_handlers._require_gitea_runner_assigned_object(
        validated_data,
        procedure,
        user,
    )
    assert manager.restricted_user is user
    assert manager.restricted_action == "view"
    assert manager.queryset.filtered_pk == 416

    for object_id in (None, True, 241, 417):
        with pytest.raises(ValidationError):
            command_handlers._require_gitea_runner_assigned_object(
                {
                    "assigned_object_type": content_type,
                    "assigned_object_id": object_id,
                },
                procedure,
                user,
            )

    manager.queryset.result = None
    with pytest.raises(ValidationError) as exc_info:
        command_handlers._require_viewable_assigned_object(
            validated_data,
            procedure,
            user,
        )
    assert exc_info.value.code == "does_not_exist"


def test_gitea_org_root_creation_fails_before_backend_or_target_access(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    contract = command_handlers.gitea_org_ci_runner_contract
    procedure = SimpleNamespace(
        name=contract.PROCEDURE_NAME,
        enabled=True,
        params_schema=contract.PARAMS_SCHEMA,
    )
    params = {
        "operation": "provision",
        "lane": "root-python312",
        "registration_token_secret_ref": (
            "nms-secret:11111111-1111-4111-8111-111111111111"
        ),
    }

    class Serializer:
        validated_data = {"procedure": procedure, "params": params}

        def is_valid(self, *, raise_exception: bool) -> None:
            assert raise_exception is True

    def explode(*args, **kwargs):
        raise AssertionError("backend, inventory, fence, or capability was accessed")

    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        explode,
    )
    monkeypatch.setattr(command_handlers, "_verify_backend_capability", explode)
    monkeypatch.setattr(command_handlers, "_require_viewable_assigned_object", explode)
    monkeypatch.setattr(command_handlers, "normalize_execution_params", explode)

    with pytest.raises(ValidationError) as caught:
        command_handlers.create_execution(
            serializer=Serializer(),
            user=SimpleNamespace(has_perm=lambda permission: True),
        )

    assert caught.value.code == "RPC_HOST_GENERATION_UNAVAILABLE"


def test_gitea_org_root_worker_claim_fails_before_protected_access(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    contract = command_handlers.gitea_org_ci_runner_contract
    procedure = SimpleNamespace(pk=71, name=contract.PROCEDURE_NAME, enabled=True)
    execution = SimpleNamespace(
        procedure_id=71,
        procedure=procedure,
        params={
            "operation": "provision",
            "lane": "root-python312",
            "registration_token_secret_ref": (
                "nms-secret:11111111-1111-4111-8111-111111111111"
            ),
            "_timeout_seconds_snapshot": 1800,
        },
    )
    failures: list[tuple[str, str]] = []

    class Aggregate:
        status = "queued"

        def __init__(self) -> None:
            self.execution = execution

        def fail(self, message: str, code: str) -> None:
            failures.append((message, code))

        def start(self) -> None:
            raise AssertionError("activation-ineligible work was started")

    manager = SimpleNamespace(
        select_for_update=lambda: SimpleNamespace(get=lambda pk: procedure)
    )
    models = types.ModuleType("netbox_rpc.models")
    models.RPCExecution = type("RPCExecution", (), {"STATUS_QUEUED": "queued"})
    models.RPCProcedure = type("RPCProcedure", (), {"objects": manager})
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)

    command_handlers._claim_if_procedure_enabled(Aggregate())

    assert failures == [
        (
            "root-python312 host generation is unavailable until "
            "N-MultiCloud/nmulticloud-context#411 publishes a reviewed "
            "content-addressed provision-and-prove boundary.",
            "RPC_HOST_GENERATION_UNAVAILABLE",
        )
    ]


def test_akvorado_install_creation_requests_protected_two_person_approval(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    procedure = SimpleNamespace(
        pk=264,
        name="os.linux.debian.13.install_akvorado",
        handler_id="os.linux_debian_13.install_akvorado",
        enabled=True,
        approval_required=True,
        params_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {"allow_resource_shortfall": {"type": "boolean"}},
        },
        timeout_seconds=1200,
    )
    params = {"allow_resource_shortfall": False}
    execution = SimpleNamespace(pk=2640, procedure=procedure, params=params)

    class Serializer:
        validated_data = {"procedure": procedure, "params": params}
        initial_data = {
            "procedure_id": procedure.name,
            "assigned_object_type": "dcim.device",
            "assigned_object_id": 45,
            "params": params,
        }

        def is_valid(self, *, raise_exception: bool) -> None:
            assert raise_exception is True

        def save(self, **kwargs):
            execution.requested_by = kwargs["requested_by"]
            execution.requested_by_id = kwargs["requested_by"].pk
            execution.backend_id = kwargs["backend"]
            return execution

    transitions: list[tuple[object, ...]] = []

    class Aggregate:
        def __init__(self, aggregate_execution):
            assert aggregate_execution is execution

        def request(self, *, requested_by_id):
            transitions.append(("request", requested_by_id))

        def request_approval(self, *, snapshot_hash, requested_by_id):
            transitions.append(("request_approval", snapshot_hash, requested_by_id))

        def queue(self):
            pytest.fail("Akvorado install must not queue before distinct approval")

    models = types.ModuleType("netbox_rpc.models")
    models.RPCExecution = type(
        "RPCExecution",
        (),
        {"TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY": "_timeout_seconds_snapshot"},
    )
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    monkeypatch.setattr(
        command_handlers,
        "_require_enabled_and_authoritative_backend",
        lambda user: 1,
    )
    scoped_actions: list[str] = []
    monkeypatch.setattr(
        command_handlers,
        "_require_protected_procedure_scope",
        lambda candidate, user, action: scoped_actions.append(action),
    )
    monkeypatch.setattr(
        command_handlers,
        "_require_protected_procedure_policy",
        lambda candidate: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "_resolve_validated_protected_backend_target",
        lambda *args, **kwargs: object(),
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
    monkeypatch.setattr(
        command_handlers,
        "normalize_execution_params",
        lambda candidate: {"command_fingerprint": {"handler_id": procedure.handler_id}},
    )
    monkeypatch.setattr(
        command_handlers,
        "_create_approval_request",
        lambda *args, **kwargs: SimpleNamespace(payload_hash="b" * 64),
    )
    monkeypatch.setattr(
        command_handlers,
        "_enqueue_execution_job",
        lambda *args, **kwargs: pytest.fail(
            "Akvorado install must not enqueue before distinct approval"
        ),
    )
    user = SimpleNamespace(pk=2641, has_perm=lambda permission: True)

    created = command_handlers.create_execution(serializer=Serializer(), user=user)

    assert created is execution
    assert scoped_actions == ["execute"]
    assert transitions == [
        ("request", user.pk),
        ("request_approval", "b" * 64, user.pk),
    ]


def test_akvorado_install_protected_policy_is_enabled_and_digest_pinned(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = SimpleNamespace(
        name="os.linux.debian.13.install_akvorado",
        enabled=True,
    )
    capabilities = types.ModuleType("netbox_rpc.capabilities")
    capabilities.derive_command_contract_hash = lambda candidate: "a" * 64
    monkeypatch.setitem(sys.modules, "netbox_rpc.capabilities", capabilities)
    monkeypatch.setattr(
        command_handlers.akvorado_contract,
        "AKVORADO_BOOTSTRAP_CURRENT_CAPABILITY_HASHES",
        {procedure.name: "a" * 64},
    )

    command_handlers._require_protected_procedure_policy(procedure)

    procedure.enabled = False
    with pytest.raises(ValidationError):
        command_handlers._require_protected_procedure_policy(procedure)
    procedure.enabled = True
    capabilities.derive_command_contract_hash = lambda candidate: "b" * 64
    with pytest.raises(ValidationError):
        command_handlers._require_protected_procedure_policy(procedure)


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
    assert (
        command_handlers._credential_policy_reference(
            {"ssh_policy_ref": contract.SSH_POLICY_REF},
            execution,
        )
        == contract.SSH_POLICY_REF
    )


@pytest.mark.parametrize(
    "procedure_name",
    [
        "service.gitea.production.upgrade_1_27_1",
        "service.gitea.runner.register",
        "service.gitea.actions_runner.provision_org_ci_runner",
        "service.netbox.staging.deploy_dns_pair",
        "os.linux.debian.13.preflight_akvorado",
        "os.linux.debian.13.install_akvorado",
    ],
)
def test_protected_procedures_require_explicit_compatible_backend_capability(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    procedure_name: str,
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
    capabilities.fetch_backend_capabilities = lambda target, use_cache=True: (
        observed.update({"target": target, "use_cache": use_cache}) or object()
    )
    procedure = SimpleNamespace(name=procedure_name)
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

    capabilities.verify_procedure_capability = lambda proc, manifest: (
        statuses.COMPATIBLE
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
    execution.approval_request = SimpleNamespace(
        backend_target_sha256=command_handlers._protected_backend_target_sha256(
            execution.backend_id,
            procedure_name=procedure.name,
            backend_target=backend_target,
        )
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


def test_dns_approval_rejects_snapshot_backend_drift_before_capability_probe(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = SimpleNamespace(
        name="service.netbox.staging.deploy_dns_pair",
    )
    approved_target = SimpleNamespace(
        url="https://backend-a.invalid",
        verify_ssl=True,
    )
    drifted_target = SimpleNamespace(
        url="https://backend-b.invalid",
        verify_ssl=True,
    )
    execution = SimpleNamespace(
        pk=2701,
        procedure=procedure,
        backend_id=1,
        approval_request=SimpleNamespace(
            backend_target_sha256=(
                command_handlers._protected_backend_target_sha256(
                    1,
                    procedure_name=procedure.name,
                    backend_target=approved_target,
                )
            )
        ),
    )

    class Manager:
        def select_for_update(self, **kwargs):
            assert kwargs == {"of": ("self", "procedure")}
            return self

        def select_related(self, *fields):
            assert "procedure" in fields
            return self

        def get(self, *, pk):
            assert pk == execution.pk
            return execution

    models = types.ModuleType("netbox_rpc.models")
    models.RPCExecution = type("RPCExecution", (), {"objects": Manager()})
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
    monkeypatch.setattr(
        command_handlers,
        "_require_protected_procedure_policy",
        lambda candidate: None,
    )
    monkeypatch.setattr(
        command_handlers,
        "resolve_backend",
        lambda backend_id: drifted_target,
    )
    capability_calls = []
    monkeypatch.setattr(
        command_handlers,
        "_verify_backend_capability",
        lambda *args, **kwargs: capability_calls.append((args, kwargs)),
    )

    with pytest.raises(ValidationError):
        command_handlers._approve_protected_execution(
            execution,
            SimpleNamespace(pk=2702),
        )

    assert capability_calls == []


def test_dns_worker_rejects_snapshot_backend_drift_before_authenticated_io(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    procedure = SimpleNamespace(
        name="service.netbox.staging.deploy_dns_pair",
    )
    approved_target = SimpleNamespace(
        url="https://backend-a.invalid",
        verify_ssl=True,
    )
    drifted_target = SimpleNamespace(
        url="https://backend-b.invalid",
        verify_ssl=True,
    )
    execution = SimpleNamespace(
        pk=2703,
        procedure=procedure,
        backend_id=1,
        status="running",
        STATUS_RUNNING="running",
        approval_request=SimpleNamespace(
            backend_target_sha256=(
                command_handlers._protected_backend_target_sha256(
                    1,
                    procedure_name=procedure.name,
                    backend_target=approved_target,
                )
            )
        ),
    )
    observed = []

    class Aggregate:
        def __init__(self, candidate):
            assert candidate is execution

        def fail(self, message, code):
            observed.append(("fail", code))

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
        lambda backend_id: drifted_target,
    )
    monkeypatch.setattr(
        command_handlers,
        "_verify_backend_capability",
        lambda *args, **kwargs: observed.append(("capability", None)),
    )

    with pytest.raises(RPCExecutionError) as raised:
        command_handlers.run_execution(execution)

    assert raised.value.code == "RPC_APPROVAL_INVALIDATED"
    assert observed == [("fail", "RPC_APPROVAL_INVALIDATED")]


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
    ("case_name", "identifier"),
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
            "description = <<EOF\n" + r'{"note":"hvs.\u0041BCDEFGH1234"}' + "\nEOF",
        ),
        (
            "unicode-separators",
            '"pass\\u0077ord"\u2028=\u2029"hunter2"',
        ),
    ],
)
def test_openbao_decodes_adversarial_identifier_before_persistence(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    case_name: str,
    identifier: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = _openbao_procedure("policy_delete", permissive_schema=True)
    params = {"policy_name": identifier}
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
            {"outer": ["QWxhZGRpbjpvcGVuIHNlc2FtZSBhbmQtbW9yZS1tYXRlcmlhbA=="]},
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
    ("accepted", "snapshot_name"),
    [
        (True, "🙂" * 262_144),
        (False, "🙂" * 262_144 + "x"),
    ],
    ids=("exactly-1-mib", "one-byte-over"),
)
def test_openbao_scanner_string_limit_is_utf8_bytes_not_characters(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    accepted: bool,
    snapshot_name: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = _openbao_procedure("snapshot_create", permissive_schema=True)
    serializer = _CreationSerializer(
        procedure,
        {"snapshot_name": snapshot_name},
    )
    _allow_creation_to_persist(command_handlers, monkeypatch)
    user = SimpleNamespace(has_perm=lambda permission: True)

    if accepted:
        execution = command_handlers.create_execution(serializer=serializer, user=user)
        assert execution is not None
        assert serializer.saved is True
        assert len(snapshot_name.encode("utf-8")) == 1_048_576
    else:
        with pytest.raises(ValidationError) as caught:
            command_handlers.create_execution(serializer=serializer, user=user)
        assert set(caught.value.detail) == {"params"}
        assert serializer.saved is False
        assert len(snapshot_name) < 1_048_576
        assert len(snapshot_name.encode("utf-8")) == 1_048_577


def test_legitimate_openbao_names_and_paths_still_persist(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    _allow_creation_to_persist(command_handlers, monkeypatch)
    user = SimpleNamespace(has_perm=lambda permission: True)
    cases = (
        (
            _openbao_procedure("policy_delete"),
            {"policy_name": "retired-ops-read"},
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
        assert all(
            serializer.persisted_params[key] == value for key, value in params.items()
        )


@pytest.mark.parametrize(
    ("operation", "field", "identifier", "companion_params"),
    OPENBAO_OPERATIONAL_IDENTIFIER_CASES,
)
def test_long_operational_openbao_identifiers_are_accepted_at_creation(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    field: str,
    identifier: str,
    companion_params: dict[str, object],
) -> None:
    command_handlers, _, _ = command_handlers_module
    _allow_creation_to_persist(command_handlers, monkeypatch)
    if field == "mount_path":
        boundary_identifier = identifier + "/" + ("r" * 64)
        boundary_identifier += "/" + ("r" * (128 - len(boundary_identifier) - 1))
    else:
        boundary_identifier = (identifier + "-" + ("regional-archive-" * 16))[:128]

    for accepted_identifier in (identifier, boundary_identifier):
        params = {**companion_params, field: accepted_identifier}
        serializer = _CreationSerializer(_openbao_procedure(operation), params)
        command_handlers.create_execution(
            serializer=serializer,
            user=SimpleNamespace(has_perm=lambda permission: True),
        )

        assert 40 <= len(accepted_identifier) <= 128
        assert serializer.saved is True
        assert serializer.persisted_params[field] == accepted_identifier
    assert len(boundary_identifier) == 128


@pytest.mark.parametrize(
    ("operation", "field", "_identifier", "companion_params"),
    OPENBAO_OPERATIONAL_IDENTIFIER_CASES,
)
@pytest.mark.parametrize(
    "secret_material",
    (
        "hvs.ABCDEFGH1234",
        OPENBAO_HIGH_ENTROPY_BASE64,
        "a" * 64,
    ),
    ids=("provider-token", "high-entropy-base64url", "hex"),
)
def test_secret_material_in_openbao_identifier_fields_is_refused_at_creation(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    field: str,
    _identifier: str,
    companion_params: dict[str, object],
    secret_material: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    _allow_creation_to_persist(command_handlers, monkeypatch)
    serializer = _CreationSerializer(
        _openbao_procedure(operation),
        {**companion_params, field: secret_material},
    )

    with pytest.raises(ValidationError) as caught:
        command_handlers.create_execution(
            serializer=serializer,
            user=SimpleNamespace(has_perm=lambda permission: True),
        )

    assert set(caught.value.detail) == {"params"}
    assert serializer.saved is False


def test_identifier_entropy_exception_is_limited_to_top_level_identifier_fields(
    command_handlers_module,
) -> None:
    command_handlers, _, _ = command_handlers_module
    long_identifier_shape = "production-kubernetes-authentication-backend"

    command_handlers.validate_openbao_params_for_persistence(
        "service.openbao.1.auth_enable",
        {"mount_path": long_identifier_shape},
    )
    with pytest.raises(command_handlers.OpenBaoSecretIngressError):
        command_handlers.validate_openbao_params_for_persistence(
            "service.openbao.1.auth_enable",
            {"nested": {"mount_path": long_identifier_shape}},
        )


def test_openbao_source_intent_is_persisted_separately_from_final_params(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    _allow_creation_to_persist(command_handlers, monkeypatch)
    token_shaped_name = "hvs.ABCDEFGH1234"
    source_intent = SimpleNamespace(pk=77, name=token_shaped_name)
    serializer = _CreationSerializer(_openbao_procedure("inspect"), {})

    execution = command_handlers.create_execution(
        serializer=serializer,
        user=SimpleNamespace(has_perm=lambda permission: True),
        source_intent=source_intent,
    )

    assert serializer.saved is True
    assert serializer.persisted_kwargs["source_intent"] is source_intent
    assert execution.source_intent is source_intent
    assert token_shaped_name not in json.dumps(serializer.persisted_params)
    assert "_intent" not in serializer.persisted_params
    assert "_intent_name" not in serializer.persisted_params


def test_intent_fan_out_never_mutates_openbao_params_after_creation(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    procedure = _openbao_procedure("inspect")
    procedure.pk = 901
    token_shaped_name = "hvs.ABCDEFGH1234"
    intent = SimpleNamespace(
        pk=78,
        name=token_shaped_name,
        enabled=True,
        ordered_intent_procedures=[SimpleNamespace(procedure=procedure)],
    )
    serializer_module = types.ModuleType("netbox_rpc.api.serializers")

    class Serializer:
        def __init__(self, *, data: dict[str, object]) -> None:
            self.initial_data = data

    serializer_module.RPCExecutionSerializer = Serializer
    monkeypatch.setitem(sys.modules, "netbox_rpc.api.serializers", serializer_module)
    persisted: list[SimpleNamespace] = []

    def persist(*, serializer, user, source_intent=None):
        row = SimpleNamespace(
            params=dict(serializer.initial_data["params"]),
            source_intent=source_intent,
        )
        persisted.append(row)
        return row

    monkeypatch.setattr(command_handlers, "create_execution", persist)
    [execution] = command_handlers.execute_intent(
        intent,
        SimpleNamespace(has_perm=lambda permission: True),
        assigned_object_type=SimpleNamespace(app_label="dcim", model="device"),
        assigned_object_id=32,
    )

    assert persisted == [execution]
    assert execution.source_intent is intent
    assert token_shaped_name not in json.dumps(execution.params)
    assert execution.params == {}


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


class _GiteaFence:
    def __init__(
        self,
        *,
        state: str = "clear",
        blocking_execution_id: int | None = None,
        reconciliation_execution_id: int | None = None,
        expected_token_sha256: str = "",
        blocking_execution_status: str = "failed",
        last_updated: datetime | None = None,
        takeover_generation: int = 1,
    ) -> None:
        self.state = state
        self.blocking_execution_id = blocking_execution_id
        self.blocking_execution = (
            SimpleNamespace(pk=blocking_execution_id, status=blocking_execution_status)
            if blocking_execution_id is not None
            else None
        )
        self.reconciliation_execution_id = reconciliation_execution_id
        self.takeover_generation = takeover_generation
        self.expected_token_sha256 = expected_token_sha256
        self.last_updated = last_updated or (
            datetime.now(timezone.utc) - timedelta(seconds=1801)
        )
        self.last_reset_state = ""
        self.last_prior_token_id = None
        self.last_replacement_token_id = None
        self.last_prior_active_sha256 = ""
        self.saved_fields: list[str] = []

    def save(self, *, update_fields: list[str]) -> None:
        self.saved_fields = list(update_fields)


class _GiteaFenceManager:
    def __init__(self, fence: _GiteaFence) -> None:
        self.fence = fence
        self.canonical_scopes: list[str] = []

    def select_for_update(self) -> _GiteaFenceManager:
        return self

    def get(self, *, canonical_scope: str) -> _GiteaFence:
        self.canonical_scopes.append(canonical_scope)
        return self.fence


class _GiteaExecutionManager:
    def __init__(self, execution: object | None) -> None:
        self.execution = execution

    def select_for_update(self) -> _GiteaExecutionManager:
        return self

    def get(self, *, pk: int) -> object:
        if self.execution is None or getattr(self.execution, "pk", None) != pk:
            raise LookupError(pk)
        return self.execution


def _install_gitea_fence_model(
    monkeypatch: pytest.MonkeyPatch,
    fence: _GiteaFence,
) -> None:
    models = types.ModuleType("netbox_rpc.models")
    models.RPCGiteaRunnerScopeFence = type(
        "RPCGiteaRunnerScopeFence",
        (),
        {
            "STATE_CLEAR": "clear",
            "STATE_PENDING": "pending",
            "STATE_BLOCKED": "blocked",
            "DoesNotExist": type("DoesNotExist", (Exception,), {}),
            "objects": _GiteaFenceManager(fence),
        },
    )
    models.RPCExecution = type(
        "RPCExecution",
        (),
        {
            "DoesNotExist": LookupError,
            "objects": _GiteaExecutionManager(fence.blocking_execution),
        },
    )
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)


def _gitea_fence_normalized(
    *,
    operation: str,
    state: str,
    execution_id: int | None,
    digest: str = "0" * 64,
    generation: int | None = None,
) -> dict[str, object]:
    if generation is None:
        generation = 2 if operation == "reconcile" else 1
    return {
        "operation": operation,
        "scope": "nmulticloud-org",
        "gitea_scope": "N-MultiCloud",
        "fence_state": state,
        "fence_execution_id": execution_id,
        "fence_generation": generation,
        "fence_expected_sha256": digest,
    }


def _gitea_register_result(
    *,
    stage: str,
    token_invalidated: bool,
    token_reset_required: bool,
    token_sha256: str | None,
    reset_state: str,
) -> dict[str, object]:
    reset_proven = token_invalidated and not token_reset_required
    result = {
        "ok": False,
        "procedure": "service.gitea.runner.register",
        "target": "nmultifibra-ci-untrusted-01",
        "operation": "register",
        "scope": "nmulticloud-org",
        "fence_execution_id": None,
        "fence_generation": 1,
        "registered": False,
        "reconciled": None,
        "token_invalidated": token_invalidated,
        "token_reset_required": token_reset_required,
        "token_sha256": token_sha256,
        "reset_state": reset_state,
        "prior_token_id": 11 if reset_proven else None,
        "prior_active_sha256": None,
        "replacement_token_id": 12 if reset_proven else None,
        "stage": stage,
    }
    return {"ok": False, "result": result}


def test_gitea_runner_registration_reservation_is_canonical_and_exclusive(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    fence = _GiteaFence(takeover_generation=0)
    _install_gitea_fence_model(monkeypatch, fence)
    normalized = _gitea_fence_normalized(
        operation="register",
        state="clear",
        execution_id=None,
    )

    command_handlers._reserve_gitea_runner_scope(
        SimpleNamespace(pk=2351),
        normalized,
    )

    assert fence.state == "pending"
    assert fence.blocking_execution_id == 2351
    assert fence.reconciliation_execution_id is None
    model = sys.modules["netbox_rpc.models"].RPCGiteaRunnerScopeFence
    assert model.objects.canonical_scopes == ["N-MultiCloud"]
    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._reserve_gitea_runner_scope(
            SimpleNamespace(pk=2352),
            normalized,
        )
    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"


def test_gitea_runner_only_one_reconciliation_can_own_a_blocked_scope(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence(
        state="blocked",
        blocking_execution_id=2351,
        expected_token_sha256=digest,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    normalized = _gitea_fence_normalized(
        operation="reconcile",
        state="blocked",
        execution_id=2351,
        digest=digest,
    )

    command_handlers._reserve_gitea_runner_scope(
        SimpleNamespace(pk=2352),
        normalized,
    )
    assert fence.reconciliation_execution_id == 2352
    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._reserve_gitea_runner_scope(
            SimpleNamespace(pk=2353),
            normalized,
        )
    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert fence.reconciliation_execution_id == 2352


@pytest.mark.parametrize(
    ("state", "blocking_status", "age_seconds", "expected_code"),
    (
        ("pending", "running", 30, "RPC_SCOPE_FENCE_BUSY"),
        ("blocked", "running", 361, "RPC_SCOPE_FENCE_BUSY"),
        ("blocked", "failed", 30, "RPC_SCOPE_FENCE_BUSY"),
    ),
)
def test_gitea_runner_reconciliation_waits_for_terminal_remote_quiescence(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    blocking_status: str,
    age_seconds: int,
    expected_code: str,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence(
        state=state,
        blocking_execution_id=2351,
        expected_token_sha256=digest,
        blocking_execution_status=blocking_status,
        last_updated=datetime.now(timezone.utc) - timedelta(seconds=age_seconds),
    )
    _install_gitea_fence_model(monkeypatch, fence)

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._reserve_gitea_runner_scope(
            SimpleNamespace(pk=2352),
            _gitea_fence_normalized(
                operation="reconcile",
                state=state,
                execution_id=2351,
                digest=digest,
            ),
        )

    assert caught.value.code == expected_code
    assert fence.reconciliation_execution_id is None


def test_gitea_runner_reconciliation_atomically_recovers_stale_pending_worker(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2351,
        expected_token_sha256=digest,
        blocking_execution_status="running",
        last_updated=datetime.now(timezone.utc) - timedelta(seconds=1801),
    )
    _install_gitea_fence_model(monkeypatch, fence)
    failed: list[tuple[object, str, str]] = []

    def mark_failed(execution: object, message: str, code: str) -> None:
        failed.append((execution, message, code))
        execution.status = "failed"

    monkeypatch.setattr(command_handlers, "mark_execution_failed", mark_failed)

    command_handlers._reserve_gitea_runner_scope(
        SimpleNamespace(pk=2352),
        _gitea_fence_normalized(
            operation="reconcile",
            state="pending",
            execution_id=2351,
            digest=digest,
        ),
    )

    assert failed == [
        (
            fence.blocking_execution,
            "Gitea runner worker was lost after scope reservation; reconciliation is required.",
            "RPC_RUNNER_WORKER_LOST",
        )
    ]
    assert fence.blocking_execution.status == "failed"
    assert fence.state == "blocked"
    assert fence.reconciliation_execution_id == 2352


def test_gitea_runner_late_original_response_cannot_erase_reconciliation_owner(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence(
        state="blocked",
        blocking_execution_id=2351,
        reconciliation_execution_id=2352,
        expected_token_sha256=digest,
    )
    _install_gitea_fence_model(monkeypatch, fence)

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            SimpleNamespace(pk=2351),
            _gitea_fence_normalized(
                operation="register",
                state="clear",
                execution_id=None,
            ),
            _gitea_register_result(
                stage="register",
                token_invalidated=True,
                token_reset_required=False,
                token_sha256=digest,
                reset_state="rotated",
            ),
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert fence.state == "blocked"
    assert fence.blocking_execution_id == 2351
    assert fence.reconciliation_execution_id == 2352


def test_gitea_runner_late_original_response_cannot_reopen_reconciled_scope(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence()
    _install_gitea_fence_model(monkeypatch, fence)

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            SimpleNamespace(pk=2351),
            _gitea_fence_normalized(
                operation="register",
                state="clear",
                execution_id=None,
            ),
            _gitea_register_result(
                stage="register",
                token_invalidated=True,
                token_reset_required=False,
                token_sha256=digest,
                reset_state="rotated",
            ),
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert fence.state == "clear"
    assert fence.blocking_execution_id is None
    assert fence.reconciliation_execution_id is None


@pytest.mark.parametrize(
    ("response", "expected_state", "expected_digest"),
    (
        (
            _gitea_register_result(
                stage="generate_token",
                token_invalidated=False,
                token_reset_required=False,
                token_sha256=None,
                reset_state="not_started",
            ),
            "clear",
            "",
        ),
        (
            _gitea_register_result(
                stage="register",
                token_invalidated=True,
                token_reset_required=False,
                token_sha256="a" * 64,
                reset_state="rotated",
            ),
            "clear",
            "",
        ),
        (
            _gitea_register_result(
                stage="reset",
                token_invalidated=False,
                token_reset_required=True,
                token_sha256="a" * 64,
                reset_state="failed",
            ),
            "blocked",
            "a" * 64,
        ),
    ),
)
def test_gitea_runner_response_atomically_clears_or_blocks_scope(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, object],
    expected_state: str,
    expected_digest: str,
) -> None:
    command_handlers, _, _ = command_handlers_module
    fence = _GiteaFence(state="pending", blocking_execution_id=2351)
    _install_gitea_fence_model(monkeypatch, fence)
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, backend_response: dict[str, object]) -> None:
            recorded.append(backend_response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    command_handlers._record_gitea_runner_response(
        SimpleNamespace(pk=2351),
        _gitea_fence_normalized(
            operation="register",
            state="clear",
            execution_id=None,
        ),
        response,
    )

    assert recorded == [response]
    assert fence.state == expected_state
    assert fence.expected_token_sha256 == expected_digest
    if expected_state == "clear":
        assert fence.blocking_execution_id is None
        assert fence.reconciliation_execution_id is None
    else:
        assert fence.blocking_execution_id == 2351


def test_gitea_runner_response_rejects_unsafe_fence_generation(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2351,
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    response = _gitea_register_result(
        stage="register",
        token_invalidated=True,
        token_reset_required=False,
        token_sha256="a" * 64,
        reset_state="rotated",
    )
    response["result"]["fence_generation"] = 9_007_199_254_740_992

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            _gitea_legacy_execution(2351),
            _gitea_fence_normalized(
                operation="register",
                state="clear",
                execution_id=None,
                generation=1,
            ),
            response,
        )

    assert caught.value.code == "RPC_BACKEND_BAD_RESPONSE"
    assert fence.state == "pending"
    assert fence.takeover_generation == 1


def test_gitea_runner_reconciliation_must_match_the_persisted_digest(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    expected_digest = "a" * 64
    fence = _GiteaFence(
        state="blocked",
        blocking_execution_id=2351,
        reconciliation_execution_id=2352,
        expected_token_sha256=expected_digest,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, backend_response: dict[str, object]) -> None:
            recorded.append(backend_response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    result = {
        "ok": True,
        "procedure": "service.gitea.runner.register",
        "target": "nmultifibra-ci-untrusted-01",
        "operation": "reconcile",
        "scope": "nmulticloud-org",
        "fence_execution_id": 2351,
        "fence_generation": 2,
        "registered": None,
        "reconciled": True,
        "token_invalidated": True,
        "token_reset_required": False,
        "token_sha256": "b" * 64,
        "reset_state": "reconciled_expected_inactive",
        "prior_token_id": 11,
        "prior_active_sha256": "b" * 64,
        "replacement_token_id": 12,
        "stage": "complete",
    }
    response = {"ok": True, "result": result}

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            SimpleNamespace(pk=2352),
            _gitea_fence_normalized(
                operation="reconcile",
                state="blocked",
                execution_id=2351,
                digest=expected_digest,
            ),
            response,
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert recorded == []
    assert fence.state == "blocked"
    assert fence.blocking_execution_id == 2351
    assert fence.reconciliation_execution_id == 2352
    assert fence.expected_token_sha256 == expected_digest


@pytest.mark.parametrize("expected_digest", ("0" * 64, "a" * 64))
def test_gitea_runner_matching_reconciliation_proof_clears_the_scope(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    expected_digest: str,
) -> None:
    command_handlers, _, _ = command_handlers_module
    fence = _GiteaFence(
        state="blocked",
        blocking_execution_id=2351,
        reconciliation_execution_id=2352,
        expected_token_sha256=("" if expected_digest == "0" * 64 else expected_digest),
        takeover_generation=2,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, backend_response: dict[str, object]) -> None:
            recorded.append(backend_response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    result = {
        "ok": True,
        "procedure": "service.gitea.runner.register",
        "target": "nmultifibra-ci-untrusted-01",
        "operation": "reconcile",
        "scope": "nmulticloud-org",
        "fence_execution_id": 2351,
        "fence_generation": 2,
        "registered": None,
        "reconciled": True,
        "token_invalidated": True,
        "token_reset_required": False,
        "token_sha256": expected_digest,
        "reset_state": "reconciled_expected_inactive",
        "prior_token_id": 11,
        "prior_active_sha256": "b" * 64,
        "replacement_token_id": 12,
        "stage": "complete",
    }
    response = {"ok": True, "result": result}

    command_handlers._record_gitea_runner_response(
        SimpleNamespace(pk=2352),
        _gitea_fence_normalized(
            operation="reconcile",
            state="blocked",
            execution_id=2351,
            digest=expected_digest,
        ),
        response,
    )

    assert recorded == [response]
    assert fence.state == "clear"
    assert fence.blocking_execution_id is None
    assert fence.reconciliation_execution_id is None
    assert fence.expected_token_sha256 == ""


def test_gitea_runner_failed_reconciliation_releases_only_its_retry_owner(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    expected_digest = "a" * 64
    fence = _GiteaFence(
        state="blocked",
        blocking_execution_id=2351,
        reconciliation_execution_id=2352,
        expected_token_sha256=expected_digest,
        takeover_generation=2,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, backend_response: dict[str, object]) -> None:
            recorded.append(backend_response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    result = {
        "ok": False,
        "procedure": "service.gitea.runner.register",
        "target": "nmultifibra-ci-untrusted-01",
        "operation": "reconcile",
        "scope": "nmulticloud-org",
        "fence_execution_id": 2351,
        "fence_generation": 2,
        "registered": None,
        "reconciled": False,
        "token_invalidated": False,
        "token_reset_required": True,
        "token_sha256": expected_digest,
        "reset_state": "failed",
        "prior_token_id": None,
        "prior_active_sha256": None,
        "replacement_token_id": None,
        "stage": "reconcile",
    }
    response = {"ok": False, "result": result}

    command_handlers._record_gitea_runner_response(
        SimpleNamespace(pk=2352),
        _gitea_fence_normalized(
            operation="reconcile",
            state="blocked",
            execution_id=2351,
            digest=expected_digest,
        ),
        response,
    )

    assert recorded == [response]
    assert fence.state == "blocked"
    assert fence.blocking_execution_id == 2351
    assert fence.reconciliation_execution_id is None
    assert fence.expected_token_sha256 == expected_digest


def _gitea_org_execution(pk: int) -> SimpleNamespace:
    return SimpleNamespace(
        pk=pk,
        procedure=SimpleNamespace(
            name="service.gitea.actions_runner.provision_org_ci_runner"
        ),
    )


def _gitea_legacy_execution(pk: int) -> SimpleNamespace:
    return SimpleNamespace(
        pk=pk,
        procedure=SimpleNamespace(name="service.gitea.runner.register"),
    )


def _gitea_org_normalized(
    *,
    operation: str,
    state: str,
    execution_id: int | None,
    digest: str = "0" * 64,
    generation: int = 1,
) -> dict[str, object]:
    return {
        "operation": operation,
        "scope": "nmulticloud-org-root",
        "gitea_scope": "N-MultiCloud",
        "fence_state": state,
        "fence_execution_id": execution_id,
        "fence_generation": generation,
        "fence_expected_sha256": digest,
        "lane": "root-python312",
    }


def _gitea_org_response(
    *,
    operation: str = "provision",
    ok: bool = True,
    fence_execution_id: int | None = None,
    fence_generation: int = 1,
    token_sha256: str = "a" * 64,
) -> dict[str, object]:
    from netbox_rpc import gitea_org_ci_runner_contract as contract

    result: dict[str, object] = {
        "ok": ok,
        "procedure": contract.PROCEDURE_NAME,
        "target": contract.TARGET_NAME,
        "operation": operation,
        "scope": "nmulticloud-org-root",
        "lane": "root-python312",
        "fence_execution_id": fence_execution_id,
        "fence_generation": fence_generation,
        "organization": contract.DEFAULT_ORGANIZATION,
        "gitea_instance_url": contract.DEFAULT_GITEA_INSTANCE_URL,
        "token_sha256": token_sha256,
        "prior_token_id": 11,
        "prior_active_sha256": None,
        "replacement_token_id": 12,
        **contract.LANES["root-python312"],
    }
    if operation == "reconcile":
        result.update(
            {
                "provisioned": None,
                "registered": None,
                "reconciled": ok,
                "token_invalidated": ok,
                "token_reset_required": not ok,
                "reset_state": (
                    "reconciled_expected_active" if ok else "indeterminate"
                ),
                "stage": "complete" if ok else "reconcile",
            }
        )
    else:
        result.update(
            {
                "provisioned": ok,
                "registered": ok,
                "reconciled": None,
                "token_invalidated": ok,
                "token_reset_required": not ok,
                "reset_state": "rotated" if ok else "indeterminate",
                "stage": "complete" if ok else "indeterminate",
            }
        )
    return {"ok": ok, "result": result}


def test_gitea_org_provision_uses_the_same_canonical_exclusive_fence(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    fence = _GiteaFence(takeover_generation=0)
    _install_gitea_fence_model(monkeypatch, fence)
    normalized = _gitea_org_normalized(
        operation="provision",
        state="clear",
        execution_id=None,
    )

    command_handlers._reserve_gitea_runner_scope(
        _gitea_org_execution(2890),
        normalized,
    )

    assert fence.state == "pending"
    assert fence.blocking_execution_id == 2890
    assert fence.takeover_generation == 1
    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._reserve_gitea_runner_scope(
            _gitea_org_execution(2891),
            normalized,
        )
    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"


def test_gitea_org_provision_proof_atomically_clears_its_fence(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, _ = command_handlers_module
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2890,
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, response: dict[str, object]) -> None:
            recorded.append(response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    response = _gitea_org_response()
    command_handlers._record_gitea_runner_response(
        _gitea_org_execution(2890),
        _gitea_org_normalized(
            operation="provision",
            state="clear",
            execution_id=None,
        ),
        response,
    )

    assert recorded == [response]
    assert fence.state == "clear"
    assert fence.blocking_execution_id is None
    assert fence.reconciliation_execution_id is None
    assert fence.expected_token_sha256 == ""
    assert fence.last_reset_state == "rotated"
    assert fence.last_prior_token_id == 11
    assert fence.last_replacement_token_id == 12


def test_gitea_org_response_cannot_switch_lane_or_fence_owner(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2890,
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    response = _gitea_org_response()
    response["result"]["lane"] = "general-ubuntu"

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            _gitea_org_execution(2890),
            _gitea_org_normalized(
                operation="provision",
                state="clear",
                execution_id=None,
            ),
            response,
        )

    assert caught.value.code == "RPC_BACKEND_BAD_RESPONSE"
    assert fence.state == "pending"
    assert fence.blocking_execution_id == 2890


def test_gitea_org_reconciliation_proof_must_match_the_durable_digest(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    fence = _GiteaFence(
        state="blocked",
        blocking_execution_id=2890,
        reconciliation_execution_id=2891,
        expected_token_sha256="a" * 64,
        takeover_generation=2,
    )
    _install_gitea_fence_model(monkeypatch, fence)

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            _gitea_org_execution(2891),
            _gitea_org_normalized(
                operation="reconcile",
                state="blocked",
                execution_id=2890,
                digest="a" * 64,
                generation=2,
            ),
            _gitea_org_response(
                operation="reconcile",
                fence_execution_id=2890,
                fence_generation=2,
                token_sha256="b" * 64,
            ),
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert fence.state == "blocked"
    assert fence.reconciliation_execution_id == 2891


def test_gitea_org_running_owner_is_not_quiescent_before_full_max_budget(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2890,
        blocking_execution_status="running",
        last_updated=datetime.now(timezone.utc) - timedelta(seconds=1799),
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._reserve_gitea_runner_scope(
            _gitea_org_execution(2891),
            _gitea_org_normalized(
                operation="reconcile",
                state="pending",
                execution_id=2890,
                generation=2,
            ),
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_BUSY"
    assert fence.takeover_generation == 1
    assert fence.reconciliation_execution_id is None


@pytest.mark.parametrize("age_seconds", [361, 1799])
@pytest.mark.parametrize(
    ("reconcile_execution", "normalized"),
    [
        (
            _gitea_org_execution(2891),
            _gitea_org_normalized(
                operation="reconcile",
                state="pending",
                execution_id=2351,
                generation=2,
            ),
        ),
        (
            _gitea_legacy_execution(2352),
            _gitea_fence_normalized(
                operation="reconcile",
                state="pending",
                execution_id=2890,
                generation=2,
            ),
        ),
    ],
)
def test_shared_gitea_fence_rejects_both_mixed_direction_takeovers_before_1800(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    age_seconds: int,
    reconcile_execution: SimpleNamespace,
    normalized: dict[str, object],
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=int(normalized["fence_execution_id"]),
        blocking_execution_status="running",
        last_updated=datetime.now(timezone.utc) - timedelta(seconds=age_seconds),
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._reserve_gitea_runner_scope(
            reconcile_execution,
            normalized,
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_BUSY"
    assert fence.takeover_generation == 1
    assert fence.reconciliation_execution_id is None


def test_gitea_org_takeover_generation_rejects_late_success_after_failed_reconcile(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2890,
        expected_token_sha256=digest,
        blocking_execution_status="running",
        last_updated=datetime.now(timezone.utc) - timedelta(seconds=1801),
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    monkeypatch.setattr(
        command_handlers,
        "mark_execution_failed",
        lambda execution, message, code: setattr(execution, "status", "failed"),
    )
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, response: dict[str, object]) -> None:
            recorded.append(response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    reconcile_normalized = _gitea_org_normalized(
        operation="reconcile",
        state="pending",
        execution_id=2890,
        digest=digest,
        generation=2,
    )
    command_handlers._reserve_gitea_runner_scope(
        _gitea_org_execution(2891),
        reconcile_normalized,
    )
    assert fence.takeover_generation == 2
    assert fence.reconciliation_execution_id == 2891

    failed_reconcile = _gitea_org_response(
        operation="reconcile",
        ok=False,
        fence_execution_id=2890,
        fence_generation=2,
        token_sha256=digest,
    )
    command_handlers._record_gitea_runner_response(
        _gitea_org_execution(2891),
        reconcile_normalized,
        failed_reconcile,
    )
    assert fence.state == "blocked"
    assert fence.reconciliation_execution_id is None
    assert fence.takeover_generation == 2

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            _gitea_org_execution(2890),
            _gitea_org_normalized(
                operation="provision",
                state="clear",
                execution_id=None,
                generation=1,
            ),
            _gitea_org_response(fence_generation=1),
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert fence.state == "blocked"
    assert fence.takeover_generation == 2
    assert recorded == [failed_reconcile]


def test_org_takeover_then_failed_reconcile_rejects_late_legacy_success(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2351,
        expected_token_sha256=digest,
        blocking_execution_status="running",
        last_updated=datetime.now(timezone.utc) - timedelta(seconds=1801),
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    monkeypatch.setattr(
        command_handlers,
        "mark_execution_failed",
        lambda execution, message, code: setattr(execution, "status", "failed"),
    )
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, response: dict[str, object]) -> None:
            recorded.append(response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    reconcile_normalized = _gitea_org_normalized(
        operation="reconcile",
        state="pending",
        execution_id=2351,
        digest=digest,
        generation=2,
    )
    command_handlers._reserve_gitea_runner_scope(
        _gitea_org_execution(2891),
        reconcile_normalized,
    )
    failed_reconcile = _gitea_org_response(
        operation="reconcile",
        ok=False,
        fence_execution_id=2351,
        fence_generation=2,
        token_sha256=digest,
    )
    command_handlers._record_gitea_runner_response(
        _gitea_org_execution(2891),
        reconcile_normalized,
        failed_reconcile,
    )

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            _gitea_legacy_execution(2351),
            _gitea_fence_normalized(
                operation="register",
                state="clear",
                execution_id=None,
                generation=1,
            ),
            _gitea_register_result(
                stage="register",
                token_invalidated=True,
                token_reset_required=False,
                token_sha256=digest,
                reset_state="rotated",
            ),
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert fence.state == "blocked"
    assert fence.takeover_generation == 2
    assert recorded == [failed_reconcile]


def test_legacy_takeover_then_failed_reconcile_rejects_late_org_success(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, _, RPCExecutionError = command_handlers_module
    digest = "a" * 64
    fence = _GiteaFence(
        state="pending",
        blocking_execution_id=2890,
        expected_token_sha256=digest,
        blocking_execution_status="running",
        last_updated=datetime.now(timezone.utc) - timedelta(seconds=1801),
        takeover_generation=1,
    )
    _install_gitea_fence_model(monkeypatch, fence)
    monkeypatch.setattr(
        command_handlers,
        "mark_execution_failed",
        lambda execution, message, code: setattr(execution, "status", "failed"),
    )
    recorded: list[dict[str, object]] = []

    class Aggregate:
        def __init__(self, execution: object) -> None:
            self.execution = execution

        def record_backend_response(self, response: dict[str, object]) -> None:
            recorded.append(response)

    monkeypatch.setattr(command_handlers, "RPCExecutionAggregate", Aggregate)
    reconcile_normalized = _gitea_fence_normalized(
        operation="reconcile",
        state="pending",
        execution_id=2890,
        digest=digest,
        generation=2,
    )
    command_handlers._reserve_gitea_runner_scope(
        _gitea_legacy_execution(2352),
        reconcile_normalized,
    )
    failed_result = {
        "ok": False,
        "procedure": "service.gitea.runner.register",
        "target": "nmultifibra-ci-untrusted-01",
        "operation": "reconcile",
        "scope": "nmulticloud-org",
        "fence_execution_id": 2890,
        "fence_generation": 2,
        "registered": None,
        "reconciled": False,
        "token_invalidated": False,
        "token_reset_required": True,
        "token_sha256": digest,
        "reset_state": "failed",
        "prior_token_id": None,
        "prior_active_sha256": None,
        "replacement_token_id": None,
        "stage": "reconcile",
    }
    failed_reconcile = {"ok": False, "result": failed_result}
    command_handlers._record_gitea_runner_response(
        _gitea_legacy_execution(2352),
        reconcile_normalized,
        failed_reconcile,
    )

    with pytest.raises(RPCExecutionError) as caught:
        command_handlers._record_gitea_runner_response(
            _gitea_org_execution(2890),
            _gitea_org_normalized(
                operation="provision",
                state="clear",
                execution_id=None,
                generation=1,
            ),
            _gitea_org_response(fence_generation=1),
        )

    assert caught.value.code == "RPC_SCOPE_FENCE_CHANGED"
    assert fence.state == "blocked"
    assert fence.takeover_generation == 2
    assert recorded == [failed_reconcile]


@pytest.mark.parametrize(
    "identifier",
    [
        '  client_secret = "hunter2!"\npath "kv/*" {}',
        '  connection_url =\n    "opaque-credential"\ntelemetry {}',
    ],
)
def test_openbao_sensitive_assignment_is_rejected_before_serializer_save(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
    identifier: str,
) -> None:
    command_handlers, ValidationError, _ = command_handlers_module
    procedure = _openbao_procedure("policy_delete", permissive_schema=True)

    class Serializer:
        validated_data = {
            "procedure": procedure,
            "params": {"policy_name": identifier},
        }
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
