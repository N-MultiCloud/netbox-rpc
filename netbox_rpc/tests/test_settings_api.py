"""DB-backed tests for the RpcPluginSettings REST API + management command."""

from __future__ import annotations

from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.models import RPCBackend, RpcPluginSettings

from ._common import make_user


class RpcPluginSettingsApiTests(TestCase):
    def setUp(self):
        self.user = make_user("rpc-settings-api", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def _list_url(self):
        return reverse("plugins-api:netbox_rpc-api:rpcpluginsettings-list")

    def _detail_url(self, pk):
        return reverse("plugins-api:netbox_rpc-api:rpcpluginsettings-detail", args=[pk])

    def test_get_returns_singleton_default_disabled(self):
        resp = self.client.get(self._list_url())
        assert resp.status_code == 200, resp.content
        assert resp.data["count"] == 1
        row = resp.data["results"][0]
        assert row["enabled"] is False
        assert row["backend"] is None

    def test_patch_enables_and_sets_backend(self):
        backend = RPCBackend.objects.create(
            name="rpc-prod", base_url="http://127.0.0.1:16005"
        )
        pk = RpcPluginSettings.get_solo().pk
        resp = self.client.patch(
            self._detail_url(pk),
            {"enabled": True, "backend": backend.pk},
            format="json",
        )
        assert resp.status_code == 200, resp.content
        settings_obj = RpcPluginSettings.get_solo()
        assert settings_obj.enabled is True
        assert settings_obj.backend_id == backend.pk

    def test_create_and_delete_are_method_not_allowed(self):
        assert self.client.post(self._list_url(), {}, format="json").status_code == 405
        pk = RpcPluginSettings.get_solo().pk
        assert self.client.delete(self._detail_url(pk)).status_code == 405


class RpcSettingsCommandTests(TestCase):
    def _run(self, *args) -> str:
        out = StringIO()
        call_command("rpc_settings", *args, stdout=out)
        return out.getvalue()

    def test_enable_and_disable(self):
        assert RpcPluginSettings.get_solo().enabled is False
        self._run("--enable")
        assert RpcPluginSettings.get_solo().enabled is True
        self._run("--disable")
        assert RpcPluginSettings.get_solo().enabled is False

    def test_show_reports_state_without_writing(self):
        out = self._run("--show")
        assert "enabled: False" in out
        assert RpcPluginSettings.get_solo().enabled is False

    def test_backend_selection_by_name(self):
        backend = RPCBackend.objects.create(
            name="rpc-b", base_url="http://127.0.0.1:16005"
        )
        self._run("--enable", "--backend", "rpc-b")
        settings_obj = RpcPluginSettings.get_solo()
        assert settings_obj.enabled is True
        assert settings_obj.backend_id == backend.pk

    def test_dry_run_does_not_write(self):
        out = self._run("--enable", "--dry-run")
        assert "Dry run" in out
        assert RpcPluginSettings.get_solo().enabled is False
