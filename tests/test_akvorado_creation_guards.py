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
        pass

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
        "service.akvorado.1.deploy_stack",
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
    normalization.validate_akvorado_content_params = lambda name, params: None
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
    content_type = SimpleNamespace(
        model_class=lambda: SimpleNamespace(objects=manager)
    )

    with pytest.raises(ValidationError) as exc_info:
        command_handlers._require_akvorado_assigned_object(
            {
                "assigned_object_type": content_type,
                "assigned_object_id": 42,
            },
            SimpleNamespace(name="service.akvorado.1.config_read"),
            object(),
        )

    assert "does not exist" in str(exc_info.value)


def test_unsafe_content_is_rejected_before_serializer_save(
    command_handlers_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_handlers, ValidationError, RPCExecutionError = command_handlers_module
    procedure = SimpleNamespace(
        name="service.akvorado.1.deploy_stack",
        enabled=True,
        approval_required=False,
        params_schema={},
    )

    class Serializer:
        validated_data = {"procedure": procedure, "params": {"compose_content": "x"}}
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
        raise RPCExecutionError("unsafe Compose environment", code="RPC_PARAM_INVALID")

    monkeypatch.setattr(
        command_handlers,
        "validate_akvorado_content_params",
        reject_unsafe_content,
    )

    with pytest.raises(ValidationError):
        command_handlers.create_execution(serializer=serializer, user=user)

    assert serializer.saved is False
