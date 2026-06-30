from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def backends_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.backends", None)
    module = importlib.import_module("netbox_rpc.backends")
    yield module
    sys.modules.pop("netbox_rpc.backends", None)


def test_adapts_backend_target_from_object(backends_module) -> None:
    backend = SimpleNamespace(
        backend_url="https://backend.example",
        get_auth_headers=MagicMock(return_value={"Authorization": "Token abc"}),
        verify_ssl=False,
    )

    target = backends_module._adapt_backend(backend)

    assert target == backends_module.BackendTarget(
        url="https://backend.example",
        headers={"Authorization": "Token abc"},
        verify_ssl=False,
    )


def test_resolver_uses_custom_dotted_path(backends_module, monkeypatch) -> None:
    target = backends_module.BackendTarget(
        url="https://custom.example",
        headers={"X-Test": "1"},
        verify_ssl=True,
    )
    resolver_module = types.ModuleType("resolver_stub")
    resolver_module.resolve = MagicMock(return_value=target)
    monkeypatch.setitem(sys.modules, "resolver_stub", resolver_module)
    _set_plugin_config(
        monkeypatch,
        {"netbox_rpc": {"backend_resolver": "resolver_stub.resolve"}},
    )

    resolved = backends_module.resolve_backend(123)

    assert resolved == target
    resolver_module.resolve.assert_called_once_with(123)


def test_resolver_adapts_netbox_nms_backend_when_present(
    backends_module,
    monkeypatch,
) -> None:
    _set_plugin_config(monkeypatch, {"netbox_rpc": {}})
    nms_backend = SimpleNamespace(
        backend_url="https://nms.example",
        get_auth_headers=MagicMock(return_value={"Authorization": "Token nms"}),
        verify_ssl=True,
    )
    netbox_nms = types.ModuleType("netbox_nms")
    netbox_nms_backend = types.ModuleType("netbox_nms.backend")
    netbox_nms_backend.get_backend = MagicMock(return_value=nms_backend)
    monkeypatch.setitem(sys.modules, "netbox_nms", netbox_nms)
    monkeypatch.setitem(sys.modules, "netbox_nms.backend", netbox_nms_backend)

    resolved = backends_module.resolve_backend(7)

    assert resolved == backends_module.BackendTarget(
        url="https://nms.example",
        headers={"Authorization": "Token nms"},
        verify_ssl=True,
    )
    netbox_nms_backend.get_backend.assert_called_once_with(7)


def test_resolver_falls_back_to_rpcbackend_when_nms_absent(
    backends_module,
    monkeypatch,
) -> None:
    _set_plugin_config(monkeypatch, {"netbox_rpc": {}})
    monkeypatch.setattr(
        backends_module,
        "_resolve_nms_backend",
        MagicMock(return_value=backends_module._NMS_MISSING),
    )
    backend = SimpleNamespace(
        backend_url="https://local.example",
        get_auth_headers=MagicMock(return_value={}),
        verify_ssl=True,
    )

    class Query:
        def first(self):
            return backend

    class Manager:
        def filter(self, **kwargs):
            assert kwargs == {"pk": 42}
            return Query()

    models_module = types.ModuleType("netbox_rpc.models")
    models_module.RPCBackend = SimpleNamespace(objects=Manager())
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models_module)

    resolved = backends_module.resolve_backend("42")

    assert resolved == backends_module.BackendTarget(
        url="https://local.example",
        headers={},
        verify_ssl=True,
    )


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        pass

    netbox_plugins.PluginConfig = PluginConfig
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    _set_plugin_config(monkeypatch, {"netbox_rpc": {}})


def _set_plugin_config(
    monkeypatch: pytest.MonkeyPatch,
    plugins_config: dict[str, dict[str, object]],
) -> None:
    django = types.ModuleType("django")
    django_conf = types.ModuleType("django.conf")
    django_conf.settings = SimpleNamespace(PLUGINS_CONFIG=plugins_config)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.conf", django_conf)
