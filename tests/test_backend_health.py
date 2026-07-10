"""Pure-domain tests for netbox_rpc.health.probe_backend (no NetBox/DB)."""

from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace

import pytest


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        pass

    netbox_plugins.PluginConfig = PluginConfig
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)


@pytest.fixture()
def health_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.health", None)
    module = importlib.import_module("netbox_rpc.health")
    yield module
    sys.modules.pop("netbox_rpc.health", None)


class _Resp:
    def __init__(self, status_code: int, payload: object = None, raise_json: bool = False):
        self.status_code = status_code
        self._payload = payload
        self._raise_json = raise_json

    def json(self) -> object:
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


def _target(url: str = "https://backend.rpc.nmulti.cloud/", verify_ssl: bool = True):
    return SimpleNamespace(url=url, headers={"Authorization": "Token x"}, verify_ssl=verify_ssl)


def test_probe_none_target_is_not_configured(health_module) -> None:
    assert health_module.probe_backend(None) == {
        "ok": False,
        "latency_ms": None,
        "error": "No backend configured",
        "url": "",
    }


def test_probe_empty_url_is_not_configured(health_module) -> None:
    result = health_module.probe_backend(_target(url=""))
    assert result["ok"] is False
    assert result["error"] == "No backend configured"


def test_probe_ok(health_module, monkeypatch) -> None:
    calls: dict[str, object] = {}

    def fake_get(url, headers=None, verify=None, timeout=None):
        calls["url"] = url
        calls["verify"] = verify
        calls["timeout"] = timeout
        return _Resp(200, {"status": "ok"})

    monkeypatch.setattr(health_module.requests, "get", fake_get)
    result = health_module.probe_backend(_target(), timeout=2)

    assert result["ok"] is True
    assert result["error"] is None
    assert result["latency_ms"] is not None
    # Trailing slash trimmed; fixed /status/ping path appended.
    assert result["url"] == "https://backend.rpc.nmulti.cloud"
    assert calls["url"] == "https://backend.rpc.nmulti.cloud/status/ping"
    assert calls["verify"] is True
    assert calls["timeout"] == 2


def test_probe_http_error(health_module, monkeypatch) -> None:
    monkeypatch.setattr(health_module.requests, "get", lambda *a, **k: _Resp(503, {}))
    result = health_module.probe_backend(_target())
    assert result["ok"] is False
    assert result["error"] == "HTTP 503"
    assert result["url"] == "https://backend.rpc.nmulti.cloud"


def test_probe_200_but_not_ok_status(health_module, monkeypatch) -> None:
    monkeypatch.setattr(
        health_module.requests, "get", lambda *a, **k: _Resp(200, {"status": "starting"})
    )
    result = health_module.probe_backend(_target())
    assert result["ok"] is False
    assert "non-ok" in (result["error"] or "")


def test_probe_200_non_json_is_serving(health_module, monkeypatch) -> None:
    monkeypatch.setattr(
        health_module.requests, "get", lambda *a, **k: _Resp(200, raise_json=True)
    )
    result = health_module.probe_backend(_target())
    assert result["ok"] is True


def test_probe_connection_error_never_raises(health_module, monkeypatch) -> None:
    def boom(*a, **k):
        raise health_module.requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(health_module.requests, "get", boom)
    result = health_module.probe_backend(_target())
    assert result["ok"] is False
    assert result["latency_ms"] is None
    assert "refused" in (result["error"] or "")
