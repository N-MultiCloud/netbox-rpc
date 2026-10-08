"""Protected backend diagnostic route authorization and target selection."""

from unittest import mock

from django.test import TestCase
from rest_framework.test import APIClient

from netbox_rpc.models import RPCBackend

from ._common import make_user
from .test_api import _grant
from ._common import make_procedure


class BackendCapabilityDiagnosticsTests(TestCase):
    def setUp(self):
        self.backend = RPCBackend.objects.create(
            name="diagnostic-test", base_url="https://trusted.example", auth_token="private-token"
        )
        self.url = f"/api/plugins/rpc/backends/{self.backend.pk}/capabilities/"
        self.client = APIClient()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_anonymous_and_nonstaff_never_fetch(self, fetch):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))
        self.client.force_authenticate(make_user("diagnostic-nonstaff", superuser=False))
        self.assertEqual(self.client.get(self.url).status_code, 403)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_staff_without_backend_view_permission_never_fetch(self, fetch):
        user = make_user("diagnostic-staff", superuser=False)
        user.is_staff = True
        user.save()
        self.client.force_authenticate(user)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_missing_backend_and_query_controls_never_fetch(self, fetch):
        self.client.force_authenticate(make_user("diagnostic-admin"))
        self.assertEqual(self.client.get("/api/plugins/rpc/backends/999999999/capabilities/").status_code, 404)
        self.assertEqual(self.client.get(self.url, {"url": "https://attacker.example"}).status_code, 400)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_trusted_target_and_fresh_fetch(self, fetch):
        self.client.force_authenticate(make_user("diagnostic-admin"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        target = fetch.call_args.args[0]
        self.assertEqual(target.url, self.backend.backend_url)
        self.assertEqual(target.headers, self.backend.get_auth_headers())
        self.assertEqual(fetch.call_args.kwargs, {"use_cache": False})
        self.assertNotIn("private-token", str(response.data))
        self.assertNotIn("trusted.example", str(response.data))

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", side_effect=RuntimeError("private-token"))
    def test_raw_errors_are_sanitized(self, fetch):
        self.client.force_authenticate(make_user("diagnostic-admin"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, {"detail": "Capability diagnostics are unavailable."})

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_backend_object_restriction_precedes_fetch(self, fetch):
        user = make_user("diagnostic-scoped", superuser=False)
        user.is_staff = True
        user.save()
        _grant(user, model=RPCBackend, actions=["view"], constraints={"id": -1})
        self.client.force_authenticate(user)
        self.assertEqual(self.client.get(self.url).status_code, 404)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_catalog_respects_independent_procedure_object_permissions(self, fetch):
        from netbox_rpc.models import RPCProcedure

        visible = make_procedure("diagnostic.visible", effect="read")
        hidden = make_procedure("diagnostic.hidden", effect="read")
        user = make_user("diagnostic-catalog", superuser=False)
        user.is_staff = True
        user.save()
        _grant(user, model=RPCBackend, actions=["view"], constraints={"id": self.backend.pk})
        _grant(user, model=RPCProcedure, actions=["view"], constraints={"id": visible.pk})
        self.client.force_authenticate(user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([entry["procedure_id"] for entry in response.data["procedures"]], [visible.pk])
        self.assertNotIn(hidden.handler_id, str(response.data))
