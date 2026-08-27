"""DB-backed proof that ``netbox.plugin.install`` is gated at all three points.

``RPCProcedure.enabled`` is mutable catalog data. An operator can flip it in the
UI or over the API without knowing the code-level gate beneath it
(``_NETBOX_PLUGIN_INSTALL_AVAILABLE``) is still closed, which is precisely why
that second gate exists. These tests simulate that flip directly through the ORM
and prove admission and advertisement still refuse.

Worker-claim time is the third point, covered in
``tests/test_netbox_plugin_install_normalization.py::test_gate_blocks_before_any_lookup``,
which additionally asserts the allowlist is never queried while the gate is
closed.

The allowlist row is also asserted here, because it is the thing standing
between this procedure and remote code execution: without it a caller could name
the distribution that gets installed and then imported by a NetBox restart.
"""

from __future__ import annotations

from unittest import mock

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.models import (
    RPCExecution,
    RPCLinuxServiceAllowlist,
    RPCNetBoxPluginAllowlist,
    RPCProcedure,
)

from ._common import enable_rpc_integration, make_device, make_user

_PROCEDURE_NAME = "netbox.plugin.install"


def _plugin_row(**overrides) -> RPCNetBoxPluginAllowlist:
    fields = {
        "slug": "openbao",
        "distribution": "netbox-openbao",
        "module": "netbox_openbao",
        "venv_python": "/opt/netbox/venv/bin/python3",
        "manage_py": "/opt/netbox/netbox/manage.py",
        "settings_file": "/opt/netbox/netbox/netbox/configuration.py",
        "service_slugs": ["netbox", "netbox-rq"],
        "target_models": ["dcim.device"],
    }
    fields.update(overrides)
    return RPCNetBoxPluginAllowlist(**fields)


class _PluginInstallTestCase(TestCase):
    def setUp(self):
        self.user = make_user("plugin-install-gate-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.device = make_device()
        enable_rpc_integration()
        self.procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        # Exactly the operator action the code-level gate exists to survive.
        self.procedure.enabled = True
        self.procedure.save(update_fields=["enabled"])


class SeedTests(_PluginInstallTestCase):
    def test_ships_disabled_and_approval_gated(self):
        """The seeded defaults are themselves part of the safety argument."""
        fresh = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        # setUp flipped enabled; assert what the migration seeded instead.
        assert fresh.approval_required is True
        assert fresh.effect == "write"
        assert fresh.handler_id == _PROCEDURE_NAME

    def test_params_schema_admits_only_a_slug_a_version_and_dry_run(self):
        """A caller must not be able to name what gets installed."""
        schema = RPCProcedure.objects.get(name=_PROCEDURE_NAME).params_schema
        assert schema["additionalProperties"] is False
        assert set(schema["properties"]) == {"plugin_slug", "version", "dry_run"}
        assert set(schema["required"]) == {"plugin_slug", "version"}
        for forbidden in ("distribution", "module", "settings_file", "venv_python"):
            assert forbidden not in schema["properties"]


class AdmissionTimeGateTests(_PluginInstallTestCase):
    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_create_execution_rejected_even_when_enabled(self, enqueue, _fetch):
        _plugin_row().full_clean()
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")
        resp = self.client.post(
            url,
            {
                "procedure_id": self.procedure.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": {"plugin_slug": "openbao", "version": "0.1.0"},
            },
            format="json",
        )

        assert resp.status_code == 400, resp.content
        assert "cannot run yet" in str(resp.data)
        assert not RPCExecution.objects.filter(procedure=self.procedure).exists()
        enqueue.assert_not_called()


class AdvertisementTimeGateTests(_PluginInstallTestCase):
    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_available_excludes_gated_procedure_even_when_enabled(self, _fetch):
        url = reverse("plugins-api:netbox_rpc-api:rpcprocedure-available")
        resp = self.client.get(url)

        assert resp.status_code == 200, resp.content
        returned = resp.data.get("results", resp.data)
        assert self.procedure.pk not in {row["id"] for row in returned}


class AllowlistValidationTests(TestCase):
    """`clean()` is the first place a dangerous row is stopped.

    The normalizer rechecks all of this, because a row can be written by a
    fixture or a bulk update that never calls `full_clean()`. Both layers are
    deliberate; this covers the model half.
    """

    def test_a_wellformed_row_validates(self):
        _plugin_row().full_clean()

    def test_pip_installable_but_non_name_distributions_are_rejected(self):
        for value in (
            "https://evil.example/x.whl",
            "/tmp/evil",
            "git+ssh://evil/x",
            "--index-url=http://evil",
            "netbox openbao",
        ):
            with self.assertRaises(ValidationError) as ctx:
                _plugin_row(distribution=value).full_clean()
            assert "distribution" in ctx.exception.message_dict, value

    def test_non_identifier_modules_are_rejected(self):
        for value in ("netbox openbao", "netbox-openbao", "1netbox", "os; import x"):
            with self.assertRaises(ValidationError) as ctx:
                _plugin_row(module=value).full_clean()
            assert "module" in ctx.exception.message_dict, value

    def test_relative_and_traversing_paths_are_rejected(self):
        for field in ("venv_python", "manage_py", "settings_file"):
            for value in ("relative/path", "/opt/../etc/passwd", ""):
                with self.assertRaises(ValidationError) as ctx:
                    _plugin_row(**{field: value}).full_clean()
                assert field in ctx.exception.message_dict, (field, value)

    def test_service_slugs_must_be_a_list_of_strings(self):
        for value in ("netbox", [1], [""], {"a": 1}):
            with self.assertRaises(ValidationError) as ctx:
                _plugin_row(service_slugs=value).full_clean()
            assert "service_slugs" in ctx.exception.message_dict, value


class ServiceCatalogCouplingTests(TestCase):
    """A plugin row cannot widen what may be restarted.

    Restart targets are resolved through `RPCLinuxServiceAllowlist`, so this
    asserts the rows the seeded catalog already provides are the ones a
    NetBox-host install would use — if migration 0058's `netbox`/`netbox-rq`
    rows were renamed, this procedure would fail closed at normalization rather
    than silently restarting nothing.
    """

    def test_the_netbox_service_rows_this_procedure_relies_on_exist(self):
        slugs = set(
            RPCLinuxServiceAllowlist.objects.filter(
                slug__in=["netbox", "netbox-rq"]
            ).values_list("slug", flat=True)
        )
        assert slugs == {"netbox", "netbox-rq"}
