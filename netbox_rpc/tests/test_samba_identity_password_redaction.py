"""DB-backed proof that Samba identity passwords are never persisted (#160).

Any ``RPCExecution`` created for ``service.samba.1.user_create`` /
``service.samba.1.user_set_password`` must never contain the raw password
anywhere: not in the persisted ``params`` row (scrubbed synchronously in
``command_handlers._scrub_password_param()`` before ``serializer.save()``),
not in ``normalized_params`` after a (mocked-backend) run through the real
normalizer, and not in any ``RPCExecutionEvent.data`` recorded along the way.
Only a sha256 fingerprint + byte count may ever be stored.
"""

from __future__ import annotations

import hashlib
import json
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_rpc.application import command_handlers
from netbox_rpc.backends import BackendTarget
from netbox_rpc.models import RPCExecution, RPCExecutionEvent, RPCProcedure

from ._common import enable_rpc_integration, make_device, make_user

_TARGET = BackendTarget(url="http://backend.example", headers={}, verify_ssl=True)
_RAW_PASSWORD = "Sup3r-Secret-Password!42"


class _SambaIdentityExecutionTestCase(TestCase):
    """Shared setup: an authenticated superuser, a real target device, the
    opt-in enabled, and the real migration-seeded user_create procedure."""

    procedure_name = "service.samba.1.user_create"

    def setUp(self):
        self.user = make_user("samba-identity-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.device = make_device()
        enable_rpc_integration()
        self.procedure = RPCProcedure.objects.get(name=self.procedure_name)

    def _create_execution(self, params):
        url = reverse("plugins-api:netbox_rpc-api:rpcexecution-list")
        body = {
            "procedure_id": self.procedure.pk,
            "assigned_object_type": "dcim.device",
            "assigned_object_id": self.device.pk,
            "params": params,
        }
        with (
            mock.patch(
                "netbox_rpc.capabilities.fetch_backend_capabilities",
                return_value=None,
            ),
            mock.patch(
                "netbox_rpc.jobs.RPCExecutionJob.enqueue",
                return_value=mock.Mock(pk=4242),
            ),
        ):
            return self.client.post(url, body, format="json")


class UserCreatePasswordRedactionTests(_SambaIdentityExecutionTestCase):
    procedure_name = "service.samba.1.user_create"

    def test_created_execution_row_never_contains_plaintext_password(self):
        resp = self._create_execution(
            {"username": "alice", "password": _RAW_PASSWORD}
        )
        assert resp.status_code == 201, resp.content

        execution = RPCExecution.objects.get(pk=resp.data["id"])
        expected_sha256 = hashlib.sha256(_RAW_PASSWORD.encode("utf-8")).hexdigest()
        expected_bytes = len(_RAW_PASSWORD.encode("utf-8"))

        assert "password" not in execution.params
        assert execution.params["password_sha256"] == expected_sha256
        assert execution.params["password_bytes"] == expected_bytes
        assert execution.params["username"] == "alice"

        serialized_params = json.dumps(execution.params)
        assert _RAW_PASSWORD not in serialized_params

    @mock.patch.object(command_handlers, "resolve_backend", return_value=_TARGET)
    @mock.patch(
        "netbox_rpc.jobs._call_backend",
        return_value={
            "ok": True,
            "result": {"stdout": "ok", "username": "alice", "created": True},
        },
    )
    def test_normalized_params_and_events_never_contain_plaintext_password(
        self, _call_backend, _resolve
    ):
        resp = self._create_execution(
            {"username": "alice", "password": _RAW_PASSWORD}
        )
        assert resp.status_code == 201, resp.content
        execution = RPCExecution.objects.get(pk=resp.data["id"])

        # Run the real (unmocked) normalizer end to end -- only resolve_backend
        # and the outbound HTTP call to the backend are mocked.
        command_handlers.run_execution(execution)
        execution.refresh_from_db()

        assert execution.status == RPCExecution.STATUS_SUCCEEDED
        assert "password" not in execution.normalized_params
        assert "password" not in execution.normalized_params.get(
            "command_fingerprint", {}
        )
        assert execution.normalized_params.get("password_sha256") == hashlib.sha256(
            _RAW_PASSWORD.encode("utf-8")
        ).hexdigest()

        serialized_normalized = json.dumps(execution.normalized_params)
        assert _RAW_PASSWORD not in serialized_normalized

        events = RPCExecutionEvent.objects.filter(execution=execution)
        assert events.exists()
        for event in events:
            serialized_event = json.dumps(event.data)
            assert _RAW_PASSWORD not in serialized_event
            # Catch both a literal "password" value key and any nested
            # occurrence -- password_sha256/password_bytes are fine, a bare
            # "password" key is not.
            assert '"password":' not in serialized_event
            assert event.message.find(_RAW_PASSWORD) == -1


class UserSetPasswordRedactionTests(_SambaIdentityExecutionTestCase):
    procedure_name = "service.samba.1.user_set_password"

    def test_created_execution_row_never_contains_plaintext_password(self):
        resp = self._create_execution(
            {"username": "alice", "password": _RAW_PASSWORD}
        )
        assert resp.status_code == 201, resp.content

        execution = RPCExecution.objects.get(pk=resp.data["id"])
        expected_sha256 = hashlib.sha256(_RAW_PASSWORD.encode("utf-8")).hexdigest()

        assert "password" not in execution.params
        assert execution.params["password_sha256"] == expected_sha256
        assert execution.params["password_bytes"] == len(
            _RAW_PASSWORD.encode("utf-8")
        )

        serialized_params = json.dumps(execution.params)
        assert _RAW_PASSWORD not in serialized_params
