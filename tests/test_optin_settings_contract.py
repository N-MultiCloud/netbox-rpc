"""Static-contract tests for the opt-in RpcPluginSettings surface.

Assert the opt-in integration is wired (model singleton, landing page, settings
redirect, test-connection endpoint, navigation) WITHOUT breaking netbox-rpc's
standalone invariants: no ``required_plugins`` and no top-level import of
``netbox_proxbox`` / ``netbox_nms``.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_plugin_stays_standalone_no_required_plugins() -> None:
    init = _read("netbox_rpc/__init__.py")
    assert "required_plugins" not in init


def test_no_top_level_companion_imports_in_new_modules() -> None:
    for rel in ("netbox_rpc/health.py",):
        top = _read(rel).split("def ", 1)[0]
        assert "import netbox_proxbox" not in top
        assert "from netbox_proxbox" not in top
        assert "import netbox_nms" not in top
        assert "from netbox_nms" not in top


def test_model_defines_optin_singleton() -> None:
    src = _read("netbox_rpc/models.py")
    assert "class RpcPluginSettings(NetBoxModel):" in src
    assert "def get_solo(cls)" in src
    assert "singleton_key" in src
    # Opt-in gate defaults OFF.
    assert "enabled = models.BooleanField(" in src
    assert "default=False" in src.split("class RpcPluginSettings", 1)[1]
    assert "def resolved_backend_target(self)" in src


def test_backends_resolution_is_reused_not_reinvented() -> None:
    src = _read("netbox_rpc/models.py")
    body = src.split("def resolved_backend_target", 1)[1]
    assert "from . import backends" in body  # function-local, soft
    assert "resolve_backend(None)" in body


def test_migration_is_additive_and_independent() -> None:
    mig = _read("netbox_rpc/migrations/0044_rpcpluginsettings.py")
    assert "CreateModel" in mig
    assert "RpcPluginSettings" in mig
    assert "netbox_nms" not in mig
    assert "netbox_proxbox" not in mig


def test_urls_register_landing_settings_and_test() -> None:
    urls = _read("netbox_rpc/urls.py")
    assert 'name="home"' in urls
    assert 'name="rpcpluginsettings_singleton_edit"' in urls
    assert 'name="rpcpluginsettings_test_connection"' in urls
    assert '("rpcpluginsettings", "settings")' in urls


def test_navigation_exposes_settings_and_dashboard() -> None:
    nav = _read("netbox_rpc/navigation.py")
    assert "plugins:netbox_rpc:rpcpluginsettings_singleton_edit" in nav
    assert "plugins:netbox_rpc:home" in nav


def test_health_probe_is_fixed_ping_get() -> None:
    src = _read("netbox_rpc/health.py")
    assert 'PING_PATH = "/status/ping"' in src
    assert "requests.get(" in src
    # No caller-controlled shell/eval surface.
    for bad in ("eval(", "exec(", "os.system(", "subprocess"):
        assert bad not in src


def test_views_expose_optin_surface() -> None:
    src = _read("netbox_rpc/views.py")
    assert "class RpcPluginSettingsView(" in src
    assert "class RpcPluginSettingsEditView(" in src
    assert "class RPCHomeView(" in src
    assert "class RpcBackendTestConnectionView(" in src
    assert "rpc_settings_singleton_redirect" in src
