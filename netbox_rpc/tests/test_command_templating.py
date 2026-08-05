"""DB-backed tests for Jinja templating + output-capture on RPCProcedureCommand.

Covers the model ``clean()`` validation (jinja tokens, output-capture spec, and
the output→input chain ordering), the served API contract (the four new fields),
and the concrete "command 2 consumes a value captured from command 1's output,
which command 1 derived from a NetBox object" chain.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient, APIRequestFactory

from netbox_rpc.api.serializers import RPCProcedureSerializer
from netbox_rpc.models import RPCProcedureCommand

from ._common import make_procedure, make_user

_SCHEMA = {
    "type": "object",
    "properties": {"vlan_id": {"type": "string"}},
}


class JinjaCommandCleanTests(TestCase):
    def setUp(self):
        self.proc = make_procedure(
            "network.device.test.templating",
            params_schema=_SCHEMA,
            target_models=["dcim.device"],
        )

    def _command(self, **kwargs) -> RPCProcedureCommand:
        defaults = {
            "procedure": self.proc,
            "sequence": 1,
            "render_mode": RPCProcedureCommand.RENDER_MODE_JINJA,
            "argv": ["/bin/echo", "{{ params.vlan_id }}"],
        }
        defaults.update(kwargs)
        return RPCProcedureCommand(**defaults)

    def test_jinja_command_with_declared_param_and_target_is_valid(self):
        self._command(
            argv=["/bin/set", "{{ params.vlan_id }}", "{{ target.name }}"]
        ).full_clean()

    def test_jinja_command_rejects_unknown_param(self):
        with self.assertRaises(ValidationError):
            self._command(argv=["{{ params.bogus }}"]).full_clean()

    def test_jinja_command_rejects_statement_block(self):
        with self.assertRaises(ValidationError):
            self._command(argv=["{% for x in y %}{{ x }}{% endfor %}"]).full_clean()

    def test_jinja_command_rejects_function_call(self):
        with self.assertRaises(ValidationError):
            self._command(argv=["{{ target.name.upper() }}"]).full_clean()

    def test_jinja_command_rejects_dunder_access(self):
        with self.assertRaises(ValidationError):
            self._command(argv=["{{ target.__class__ }}"]).full_clean()

    def test_jinja_command_rejects_unsafe_literal_span(self):
        with self.assertRaises(ValidationError):
            self._command(argv=["rm;-rf/{{ params.vlan_id }}"]).full_clean()

    def test_reference_to_unproduced_output_var_is_rejected(self):
        with self.assertRaises(ValidationError):
            self._command(sequence=1, argv=["{{ vars.ghost }}"]).full_clean()

    def test_literal_mode_is_unchanged_and_can_capture(self):
        # Backward compatibility: literal {param} still validates, and a literal
        # command may still declare an output capture.
        command = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["sudo", "/bin/systemctl", "restart", "{vlan_id}"],
            produces_var="active_state",
            capture_kind="stdout_stripped",
        )
        command.full_clean()


class OutputCaptureCleanTests(TestCase):
    def setUp(self):
        self.proc = make_procedure("network.device.test.capture", params_schema=_SCHEMA)

    def test_regex_capture_requires_single_group(self):
        bad = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["/bin/echo", "hi"],
            produces_var="vmid",
            capture_kind="regex",
            capture_expression=r"VMID=\d+",  # zero groups
        )
        with self.assertRaises(ValidationError):
            bad.full_clean()

        good = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["/bin/echo", "hi"],
            produces_var="vmid",
            capture_kind="regex",
            capture_expression=r"VMID=(\d+)",
        )
        good.full_clean()

    def test_capture_expression_without_var_is_rejected(self):
        bad = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["/bin/echo", "hi"],
            capture_kind="regex",
            capture_expression=r"(\d+)",
        )
        with self.assertRaises(ValidationError):
            bad.full_clean()

    def test_duplicate_output_var_across_commands_is_rejected(self):
        RPCProcedureCommand.objects.create(
            procedure=self.proc,
            sequence=1,
            argv=["/bin/echo", "one"],
            produces_var="vmid",
            capture_kind="stdout_stripped",
        )
        dup = RPCProcedureCommand(
            procedure=self.proc,
            sequence=2,
            argv=["/bin/echo", "two"],
            produces_var="vmid",
            capture_kind="stdout_stripped",
        )
        with self.assertRaises(ValidationError):
            dup.full_clean()

    def test_reserved_output_var_name_is_rejected(self):
        bad = RPCProcedureCommand(
            procedure=self.proc,
            sequence=1,
            argv=["/bin/echo", "hi"],
            produces_var="target",
            capture_kind="stdout_stripped",
        )
        with self.assertRaises(ValidationError):
            bad.full_clean()


class NestedChainTests(TestCase):
    """The concrete scenario from the feature request: command 2 needs a value
    that only exists in command 1's output, which command 1 derived from a
    NetBox object."""

    def setUp(self):
        self.proc = make_procedure(
            "os.linux.proxmox.test.chain",
            params_schema=_SCHEMA,
            target_models=["dcim.device"],
        )
        # Command 1: derives its command from the NetBox target object and
        # captures a VMID out of its output into `vmid`.
        self.step1 = RPCProcedureCommand.objects.create(
            procedure=self.proc,
            sequence=1,
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
            argv=["/usr/bin/lookup-vmid", "--host", "{{ target.name }}"],
            produces_var="vmid",
            capture_kind="regex",
            capture_expression=r"VMID=(\d+)",
            description="Resolve the VMID for the target host from lookup output",
        )

    def test_downstream_command_can_consume_captured_output_var(self):
        step2 = RPCProcedureCommand(
            procedure=self.proc,
            sequence=2,
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
            argv=["/usr/sbin/qm", "start", "{{ vars.vmid }}"],
            description="Start the VM whose id was captured in step 1",
        )
        # No ValidationError: vmid is produced by the earlier command.
        step2.full_clean()

    def test_editing_producer_to_orphan_a_consumer_is_rejected(self):
        # A consumer at seq 2 depends on `vmid` produced by step 1 (seq 1).
        RPCProcedureCommand.objects.create(
            procedure=self.proc,
            sequence=2,
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
            argv=["/usr/sbin/qm", "start", "{{ vars.vmid }}"],
        )
        # Moving the producer AFTER the consumer must be rejected...
        self.step1.sequence = 3
        with self.assertRaises(ValidationError):
            self.step1.full_clean()
        # ...as must renaming the produced variable, which orphans the consumer.
        self.step1.sequence = 1
        self.step1.produces_var = "vmid_renamed"
        with self.assertRaises(ValidationError):
            self.step1.full_clean()

    def test_benign_producer_edit_still_validates(self):
        RPCProcedureCommand.objects.create(
            procedure=self.proc,
            sequence=2,
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
            argv=["/usr/sbin/qm", "start", "{{ vars.vmid }}"],
        )
        # Editing the producer's description leaves the chain intact.
        self.step1.description = "Resolve VMID (updated)"
        self.step1.full_clean()

    def test_out_of_order_reference_is_rejected(self):
        # A command at sequence 1 cannot consume a var produced at sequence 2.
        self.step1.delete()
        RPCProcedureCommand.objects.create(
            procedure=self.proc,
            sequence=5,
            argv=["/bin/echo", "late"],
            produces_var="vmid",
            capture_kind="stdout_stripped",
        )
        early = RPCProcedureCommand(
            procedure=self.proc,
            sequence=2,
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
            argv=["/usr/sbin/qm", "start", "{{ vars.vmid }}"],
        )
        with self.assertRaises(ValidationError):
            early.full_clean()


class TemplatingContractTests(TestCase):
    def setUp(self):
        self.user = make_user("templating-api-tester", superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.request = APIRequestFactory().get("/")
        self.proc = make_procedure(
            "network.device.test.contract",
            params_schema=_SCHEMA,
            target_models=["dcim.device"],
        )
        self.command = RPCProcedureCommand.objects.create(
            procedure=self.proc,
            sequence=1,
            render_mode=RPCProcedureCommand.RENDER_MODE_JINJA,
            argv=["/usr/sbin/qm", "start", "{{ params.vlan_id }}"],
            produces_var="job_id",
            capture_kind="regex",
            capture_expression=r"job=(\d+)",
        )

    def test_serializer_embeds_templating_fields(self):
        data = RPCProcedureSerializer(self.proc, context={"request": self.request}).data
        command = data["commands"][0]
        assert command["render_mode"] == "jinja"
        assert command["produces_var"] == "job_id"
        assert command["capture_kind"] == "regex"
        assert command["capture_expression"] == r"job=(\d+)"

    def test_child_endpoint_creates_jinja_command(self):
        url = reverse(
            "plugins-api:netbox_rpc-api:rpcprocedure-commands", args=[self.proc.pk]
        )
        resp = self.client.post(
            url,
            {
                "sequence": 2,
                "step_type": "shell_argv",
                "render_mode": "jinja",
                "argv": ["/bin/echo", "{{ params.vlan_id }}"],
            },
            format="json",
        )
        assert resp.status_code == 201, resp.content
        assert resp.data["render_mode"] == "jinja"
