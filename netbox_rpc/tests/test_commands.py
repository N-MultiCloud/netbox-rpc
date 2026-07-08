from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient, APIRequestFactory

from netbox_rpc.api.serializers import RPCExecutionSerializer, RPCProcedureSerializer
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCExecution, RPCProcedureCommand

from ._common import make_execution, make_procedure, make_user


class RPCProcedureCommandModelTests(TestCase):
    def setUp(self):
        self.proc = make_procedure(
            "os.linux.test.commands",
            params_schema={
                "type": "object",
                "properties": {"service_slug": {"type": "string"}},
            },
        )

    def test_clean_accepts_safe_argv_placeholder(self):
        command = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["sudo", "/bin/systemctl", "restart", "{service_slug}"],
        )

        command.full_clean()

    def test_clean_rejects_bad_placeholder(self):
        command = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["sudo", "/bin/systemctl", "restart", "{missing}"],
        )

        with self.assertRaises(ValidationError):
            command.full_clean()

    def test_clean_rejects_shell_metachar_token(self):
        command = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["echo", "bad;token"],
        )

        with self.assertRaises(ValidationError):
            command.full_clean()

    def test_clean_rejects_empty_argv(self):
        command = RPCProcedureCommand(procedure=self.proc, sequence=1, argv=[])

        with self.assertRaises(ValidationError):
            command.full_clean()

    def test_clean_rejects_device_cli_mode_on_shell_argv(self):
        command = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            step_type=RPCProcedureCommand.STEP_TYPE_SHELL_ARGV,
            device_cli_mode=RPCProcedureCommand.DEVICE_CLI_EXEC,
            argv=["echo", "ok"],
        )

        with self.assertRaises(ValidationError):
            command.full_clean()


class RPCProcedureCommandApiTests(TestCase):
    def setUp(self):
        self.user = make_user("command-api-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.request = APIRequestFactory().get("/")
        self.proc = make_procedure("os.linux.test.command-api")
        self.command = RPCProcedureCommand.objects.create(
            procedure=self.proc,
            sequence=1,
            argv=["sudo", "/usr/sbin/nginx", "-t"],
            description="Validate nginx configuration",
        )

    def test_procedure_serializer_embeds_commands(self):
        data = RPCProcedureSerializer(self.proc, context={"request": self.request}).data

        assert data["commands"][0]["sequence"] == 1
        assert data["commands"][0]["argv"] == ["sudo", "/usr/sbin/nginx", "-t"]

    def test_execution_serializer_nested_procedure_includes_commands(self):
        execution = make_execution(procedure=self.proc, user=self.user)
        RPCExecutionAggregate(execution).queue()

        data = RPCExecutionSerializer(execution, context={"request": self.request}).data

        assert (
            data["procedure"]["commands"][0]["description"]
            == "Validate nginx configuration"
        )

    def test_procedure_detail_api_embeds_commands(self):
        url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-detail", args=[self.proc.pk]
        )

        resp = self.client.get(url)

        assert resp.status_code == 200, resp.content
        assert resp.data["commands"][0]["argv"] == ["sudo", "/usr/sbin/nginx", "-t"]

    def test_child_commands_endpoint_lists_and_creates_commands(self):
        url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-commands", args=[self.proc.pk]
        )

        list_resp = self.client.get(url)
        assert list_resp.status_code == 200, list_resp.content
        list_payload = list_resp.data.get("results", list_resp.data)
        assert list_payload[0]["sequence"] == 1

        create_resp = self.client.post(
            url,
            {
                "sequence": 2,
                "step_type": "shell_argv",
                "argv": ["sudo", "/bin/systemctl", "reload", "nginx"],
                "description": "Reload nginx",
            },
            format="json",
        )

        assert create_resp.status_code == 201, create_resp.content
        assert RPCProcedureCommand.objects.filter(
            procedure=self.proc, sequence=2
        ).exists()
        assert create_resp.data["procedure"] == self.proc.pk

    def test_execution_detail_api_nested_procedure_includes_commands(self):
        execution = make_execution(procedure=self.proc, user=self.user)
        RPCExecutionAggregate(execution).queue()
        url = reverse(
            "plugins-api:netbox_rpc-api:rpcexecution-detail", args=[execution.pk]
        )

        resp = self.client.get(url)

        assert resp.status_code == 200, resp.content
        assert resp.data["procedure"]["commands"][0]["sequence"] == 1
        assert RPCExecution.objects.filter(pk=execution.pk).exists()
