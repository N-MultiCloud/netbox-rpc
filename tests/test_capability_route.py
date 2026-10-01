from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_capabilities(monkeypatch):
    package = types.ModuleType("netbox_rpc")
    package.__path__ = [str(ROOT / "netbox_rpc")]
    monkeypatch.setitem(sys.modules, "netbox_rpc", package)
    spec = importlib.util.spec_from_file_location(
        "netbox_rpc.capabilities", ROOT / "netbox_rpc/capabilities.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def test_capability_fetch_uses_authenticated_rpc_route(monkeypatch) -> None:
    capabilities = _load_capabilities(monkeypatch)
    response = mock.Mock(status_code=404)
    response.close.return_value = None
    get = mock.Mock(return_value=response)
    monkeypatch.setattr(capabilities.requests, "get", get)
    target = SimpleNamespace(
        url="https://backend.rpc.example",
        headers={"Authorization": "Bearer redacted"},
        verify_ssl=True,
    )

    assert capabilities.fetch_backend_capabilities(target, use_cache=False) is None
    assert get.call_args.args[0] == "https://backend.rpc.example/rpc/capabilities"
    assert get.call_args.kwargs["allow_redirects"] is False
