"""Creation-time Akvorado authorization and content-validation guards."""

from __future__ import annotations

import importlib
import sys
import types
from contextlib import nullcontext
from types import SimpleNamespace

import pytest


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
    constants.NETBOX_STAGING_ROTATE_BACKEND_TOKEN = (
        "service.netbox.staging.rotate_backend_token"
    )
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
    normalization.validate_akvorado_content_params = lambda name, params: None
    normalization.code_gate_unavailable_reason = lambda procedure_name: None
    event_store = types.ModuleType("netbox_rpc.event_store")
    event_store.mark_execution_failed = lambda *args, **kwargs: None

    for name, module in {
        "netbox": netbox,
        "netbox.plugins": netbox_plugins,
        "django": django,
        "django.db": django_db,
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

    command_handlers._require_akvorado_assigned_object(
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
        command_handlers._require_akvorado_assigned_object(
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
        "_require_akvorado_assigned_object",
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

    with pytest.raises(ValidationError):
        command_handlers.create_execution(serializer=serializer, user=user)

    assert serializer.saved is False
