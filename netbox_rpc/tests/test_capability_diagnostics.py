"""Protected backend diagnostic route authorization and target selection."""

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from netbox_rpc.models import RPCBackend

from .test_api import _grant
from ._common import make_procedure


class BackendCapabilityDiagnosticsTests(TestCase):
    def _user(self, username, *, superuser=True):
        """Load the actual model without synthetic Django staff attributes."""
        model = get_user_model()
        user = model.objects.create(username=username, is_superuser=superuser)
        user = model.objects.get(pk=user.pk)
        return user

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
        self.client.force_authenticate(self._user("diagnostic-nonstaff", superuser=False))
        self.assertEqual(self.client.get(self.url).status_code, 403)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_administrator_without_backend_view_permission_never_fetch(self, fetch):
        user = self._user("diagnostic-admin")
        self.client.force_authenticate(user)
        with mock.patch.object(type(user), "has_perm", return_value=False):
            self.assertEqual(self.client.get(self.url).status_code, 403)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_ordinary_user_with_backend_view_permission_never_fetch(self, fetch):
        user = self._user("diagnostic-viewer", superuser=False)
        _grant(user, model=RPCBackend, actions=["view"])
        user = get_user_model().objects.get(pk=user.pk)
        self.assertTrue(user.has_perm("netbox_rpc.view_rpcbackend"))
        self.assertFalse(getattr(user, "is_staff", False))
        self.client.force_authenticate(user)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_superuser_without_staff_attribute_is_authorized(self, fetch):
        user = self._user("diagnostic-native-admin")
        if hasattr(user, "is_staff"):
            self.skipTest("This NetBox user model retains the native staff field.")
        self.assertTrue(user.is_superuser)
        self.assertFalse(hasattr(user, "is_staff"))
        self.client.force_authenticate(user)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        fetch.assert_called_once()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities")
    def test_missing_backend_and_query_controls_never_fetch(self, fetch):
        self.client.force_authenticate(self._user("diagnostic-admin"))
        self.assertEqual(self.client.get("/api/plugins/rpc/backends/999999999/capabilities/").status_code, 404)
        self.assertEqual(self.client.get(self.url, {"url": "https://attacker.example"}).status_code, 400)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_trusted_target_and_fresh_fetch(self, fetch):
        self.client.force_authenticate(self._user("diagnostic-admin"))
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
        self.client.force_authenticate(self._user("diagnostic-admin"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, {"detail": "Capability diagnostics are unavailable."})

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_backend_object_restriction_precedes_fetch(self, fetch):
        user = self._user("diagnostic-scoped")
        self.client.force_authenticate(user)
        with mock.patch(
            "netbox_rpc.api.views.RPCBackendViewSet.get_queryset",
            return_value=RPCBackend.objects.none(),
        ):
            self.assertEqual(self.client.get(self.url).status_code, 404)
        fetch.assert_not_called()

    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    def test_catalog_respects_independent_procedure_object_permissions(self, fetch):
        from netbox_rpc.models import RPCProcedure

        visible = make_procedure("diagnostic.visible", effect="read")
        hidden = make_procedure("diagnostic.hidden", effect="read")
        user = self._user("diagnostic-catalog")
        self.client.force_authenticate(user)
        with mock.patch.object(
            RPCProcedure.objects, "restrict", return_value=RPCProcedure.objects.filter(pk=visible.pk)
        ) as restrict:
            response = self.client.get(self.url)
        restrict.assert_called_once_with(user, "view")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([entry["procedure_id"] for entry in response.data["procedures"]], [visible.pk])
        self.assertNotIn(hidden.handler_id, str(response.data))
