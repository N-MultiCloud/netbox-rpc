"""Static contracts for the RpcPluginSettings REST API + management command.

No NetBox harness: pure source assertions that pin the API wiring, the
management command surface, and the standalone invariants (no Proxbox/NMS
dependency).
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_serializer_exposes_settings_fields() -> None:
    src = _read("netbox_rpc/api/serializers.py")
    assert "class RpcPluginSettingsSerializer(NetBoxModelSerializer):" in src
    block = src.split("class RpcPluginSettingsSerializer", 1)[1].split(
        "\nclass RPCBackendSerializer", 1
    )[0]
    for field in ('"enabled"', '"backend"', '"comments"'):
        assert field in block
    assert "rpcpluginsettings-detail" in block


def test_viewset_is_singleton_get_patch_only() -> None:
    src = _read("netbox_rpc/api/views.py")
    block = src.split("class RpcPluginSettingsViewSet", 1)[1].split(
        "class RPCBackendViewSet", 1
    )[0]
    assert 'http_method_names = ["get", "patch", "head", "options"]' in block
    # Materializes the singleton so GET/PATCH always resolve a row.
    assert "get_solo()" in block


def test_route_registered() -> None:
    src = _read("netbox_rpc/api/urls.py")
    assert 'router.register("settings", views.RpcPluginSettingsViewSet)' in src


def test_management_command_surface() -> None:
    src = _read("netbox_rpc/management/commands/rpc_settings.py")
    for flag in (
        "--enable",
        "--disable",
        "--backend",
        "--clear-backend",
        "--show",
        "--dry-run",
    ):
        assert flag in src
    assert "RpcPluginSettings.get_solo()" in src
    assert "full_clean()" in src  # validate before save
    # No shell/eval surface; caller input never reaches a shell.
    for bad in ("eval(", "exec(", "os.system(", "subprocess", "shell=True"):
        assert bad not in src


def test_new_files_do_not_depend_on_proxbox_or_nms() -> None:
    for rel in (
        "netbox_rpc/api/views.py",
        "netbox_rpc/api/serializers.py",
        "netbox_rpc/management/commands/rpc_settings.py",
    ):
        src = _read(rel)
        assert "netbox_proxbox" not in src
        assert "netbox_nms" not in src


def test_plugin_still_has_no_required_plugins() -> None:
    assert "required_plugins" not in _read("netbox_rpc/__init__.py")
