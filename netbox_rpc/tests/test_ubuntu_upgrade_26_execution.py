"""Integration coverage for Ubuntu 24.04 to 26.04 execution gating."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from rest_framework.exceptions import PermissionDenied

from netbox_rpc.application import command_handlers
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.models import RPCExecution, RPCIntent, RPCProcedure

from ._common import device_ct, enable_rpc_integration, make_device, make_user

ANALYZE = "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade"
SAVE = "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state"
UPGRADE = "os.linux.ubuntu.24.upgrade_26.run_upgrade"
VERIFY = "os.linux.ubuntu.24.upgrade_26.verify_postupgrade"
INTENT_NAME = "Update Ubuntu OS from 24 LTS to 26 LTS"


class _FakeJob:
    pk = 2604


def _grant(user, *, model, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    permission = ObjectPermission.objects.create(
        name=f"grant-{user.username}-{model.__name__}-{'-'.join(actions)}",
        actions=list(actions),
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(model)])
    permission.users.set([user])


def _execution_serializer(procedure: RPCProcedure, device) -> RPCExecutionSerializer:
    return RPCExecutionSerializer(
        data={
            "procedure_id": procedure.pk,
            "assigned_object_type": "dcim.device",
            "assigned_object_id": device.pk,
            "params": {},
        }
    )


class UbuntuUpgrade26ExecutionGateTests(TestCase):
    def setUp(self):
        enable_rpc_integration()
        self.device = make_device("ubuntu-upgrade-26-target")

    def _procedure(self, name: str) -> RPCProcedure:
        return RPCProcedure.objects.get(name=name)

    def _execution_user(self, username: str, *, approve: bool = False):
        user = make_user(username, superuser=False)
        actions = ("execute", "approve") if approve else ("execute",)
        _grant(user, model=RPCProcedure, actions=actions)
        return make_user(username, superuser=False)

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_run_upgrade_without_approval_permission_is_denied(
        self,
        enqueue,
        _fetch,
    ):
        procedure = self._procedure(UPGRADE)
        user = self._execution_user("ubuntu-upgrade-denied")

        with self.assertRaises(PermissionDenied):
            command_handlers.create_execution(
                serializer=_execution_serializer(procedure, self.device),
                user=user,
            )

        assert not RPCExecution.objects.filter(procedure=procedure).exists()
        enqueue.assert_not_called()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_run_upgrade_with_approval_permission_creates_execution(
        self,
        enqueue,
        _fetch,
    ):
        procedure = self._procedure(UPGRADE)
        user = self._execution_user("ubuntu-upgrade-approved", approve=True)

        execution = command_handlers.create_execution(
            serializer=_execution_serializer(procedure, self.device),
            user=user,
        )

        assert execution.procedure_id == procedure.pk
        assert RPCExecution.objects.filter(pk=execution.pk).exists()
        enqueue.assert_called_once()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_non_approval_procedures_create_without_approval_permission(
        self,
        enqueue,
        _fetch,
    ):
        user = self._execution_user("ubuntu-upgrade-read-write")

        executions = [
            command_handlers.create_execution(
                serializer=_execution_serializer(self._procedure(name), self.device),
                user=user,
            )
            for name in (ANALYZE, SAVE, VERIFY)
        ]

        assert [execution.procedure.name for execution in executions] == [
            ANALYZE,
            SAVE,
            VERIFY,
        ]
        assert enqueue.call_count == 3

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_seeded_intent_fails_fast_at_upgrade_without_approval(
        self,
        enqueue,
        _fetch,
    ):
        user = self._execution_user("ubuntu-upgrade-intent-denied")
        _grant(user, model=RPCIntent, actions=("execute",))
        user = make_user("ubuntu-upgrade-intent-denied", superuser=False)
        intent = RPCIntent.objects.get(name=INTENT_NAME)

        with self.assertRaises(PermissionDenied):
            command_handlers.execute_intent(
                intent,
                user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )

        assert RPCExecution.objects.filter(procedure__name=ANALYZE).count() == 1
        assert RPCExecution.objects.filter(procedure__name=SAVE).count() == 1
        assert not RPCExecution.objects.filter(procedure__name=UPGRADE).exists()
        assert not RPCExecution.objects.filter(procedure__name=VERIFY).exists()
        assert enqueue.call_count == 2
