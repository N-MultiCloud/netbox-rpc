"""DB-backed proof of the Ubuntu 26.04 Samba AD DC bootstrap seed and gates.

The pure-domain tier (``tests/test_ubuntu_26_samba_ad_dc_procedures.py``) drives
the migration through fake managers, which enforce no column width, NOT NULL,
uniqueness or JSON round trip. These tests check what only a real database can:
that migration ``0103`` applied, that the rows carry the intended gating, that the
stored ``provision`` row still equals its immutable protected contract after the
JSON round trip, and that creation is capability-gated and enters the two-person
``pending_approval`` state.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from jsonschema import Draft202012Validator
from rest_framework.exceptions import ValidationError

from netbox_rpc import command_contract
from netbox_rpc import samba_ad_dc_protected_contract as protected_contract
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.application import command_handlers
from netbox_rpc.models import RPCExecution, RPCProcedure

from ._common import enable_rpc_integration, event_names, make_device, make_user

PREFLIGHT = "os.linux.ubuntu.26.samba_ad_dc.preflight"
PROVISION = "os.linux.ubuntu.26.samba_ad_dc.provision"
VERIFY = "os.linux.ubuntu.26.samba_ad_dc.verify"
ALL_PROCEDURES = (PREFLIGHT, PROVISION, VERIFY)

# Transcribed from the shared contract, not read back from the migration.
EXPECTED_GATING = {
    PREFLIGHT: ("read", False, 120),
    PROVISION: ("destructive", True, 3600),
    VERIFY: ("read", False, 180),
}
SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "token", "hash")


def _property_names(schema):
    names = set()
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            names.update(str(key) for key in properties)
        for child in schema.values():
            names |= _property_names(child)
    elif isinstance(schema, list):
        for child in schema:
            names |= _property_names(child)
    return names


class Ubuntu26SambaAdDcSeedTests(TestCase):
    def test_the_three_procedures_are_seeded_with_the_intended_gating(self):
        rows = {
            procedure.name: procedure
            for procedure in RPCProcedure.objects.filter(name__in=ALL_PROCEDURES)
        }
        assert set(rows) == set(ALL_PROCEDURES)

        for name, (effect, approval_required, timeout) in EXPECTED_GATING.items():
            procedure = rows[name]
            assert procedure.handler_id == name
            assert procedure.effect == effect
            assert procedure.approval_required is approval_required
            assert procedure.timeout_seconds == timeout
            assert procedure.version == 1
            assert procedure.target_models == [
                "dcim.device",
                "virtualization.virtualmachine",
            ]
            assert procedure.params_schema["additionalProperties"] is False

    def test_the_rows_ship_enabled_and_transport_pinned(self):
        for procedure in RPCProcedure.objects.filter(name__in=ALL_PROCEDURES):
            # Enabled: the explicit backend-capability requirement, not a second
            # flag, keeps them undispatchable until the backend advertises them.
            assert procedure.enabled is True, procedure.name
            assert procedure.transport_driver == "asyncssh", procedure.name
            assert procedure.transport_pinned is True, procedure.name
            assert procedure.transport_driver_chain == [], procedure.name

    def test_each_procedure_has_exactly_one_backend_orchestrated_command(self):
        for name in ALL_PROCEDURES:
            procedure = RPCProcedure.objects.get(name=name)
            commands = list(procedure.commands.order_by("sequence"))
            assert len(commands) == 1, name
            command = commands[0]
            assert command.sequence == 1
            assert command.argv[0] == "backend-orchestrated"
            assert command.step_type == "shell_argv"
            for token in command.argv:
                assert command_contract.token_is_safe(token), (name, token)
            assert name in command_contract.EXEMPT_HANDLER_IDS

    def test_schemas_are_valid_and_declare_nothing_password_shaped(self):
        for name in ALL_PROCEDURES:
            procedure = RPCProcedure.objects.get(name=name)
            Draft202012Validator.check_schema(procedure.params_schema)
            Draft202012Validator.check_schema(procedure.result_schema)
            for schema in (procedure.params_schema, procedure.result_schema):
                names = {n.lower() for n in _property_names(schema)}
                for word in SECRET_WORDS:
                    assert not any(word in n for n in names), (name, word)
        provision = RPCProcedure.objects.get(name=PROVISION)
        assert provision.params_schema["properties"]["dry_run"]["default"] is True
        assert "admin_credential_pk" in provision.params_schema["properties"]

    def test_seeded_descriptions_fit_the_real_column(self):
        for procedure in RPCProcedure.objects.filter(name__in=ALL_PROCEDURES):
            max_length = RPCProcedure._meta.get_field("description").max_length
            assert len(procedure.description) <= max_length, procedure.name
            for command in procedure.commands.all():
                assert len(command.description) <= 255, procedure.name

    def test_only_the_declared_transport_pins_exist_for_this_family(self):
        pinned = set(
            RPCProcedure.objects.filter(
                name__in=ALL_PROCEDURES, transport_pinned=True
            ).values_list("name", flat=True)
        )
        assert pinned == set(ALL_PROCEDURES)


class _ProtectedProvisionTestCase(TestCase):
    PARAMS = {
        "domain": "ad.example.com",
        "netbios": "EXAMPLE",
        "hostname": "ad01",
        "ip": "10.0.30.10",
        "forwarder": "10.0.30.1",
        "client_networks": ["10.0.30.0/24"],
    }

    def setUp(self):
        enable_rpc_integration()
        self.device = make_device("samba-ad-dc-target")
        self.requester = make_user("samba-ad-dc-requester", superuser=True)
        self.provision = RPCProcedure.objects.get(name=PROVISION)
        # The real DeviceService/DeviceCredential resolution needs netbox-nms
        # fixtures; the frozen-binding rules are covered by the pure-domain tier.
        for target, value in (
            (
                "netbox_rpc.domain.normalization._samba_ad_dc_primary_ipv4",
                "10.0.30.10",
            ),
            (
                "netbox_rpc.domain.normalization._resolve_locked_ssh_identity",
                lambda **kwargs: {
                    "ssh_service_id": 1,
                    "ssh_identity_id": 2,
                    "ssh_host": kwargs["expected_host"],
                    "ssh_port": 22,
                    "ssh_known_hosts_sha256": "a" * 64,
                    "ssh_policy_ref": kwargs["policy_ref"],
                },
            ),
        ):
            patcher = mock.patch(
                target,
                new=(lambda *a, _v=value, **k: _v) if isinstance(value, str) else value,
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def _serializer(self, procedure=None, params=None):
        procedure = procedure or self.provision
        return RPCExecutionSerializer(
            data={
                "procedure_id": procedure.pk,
                "assigned_object_type": "dcim.device",
                "assigned_object_id": self.device.pk,
                "params": self.PARAMS if params is None else params,
            }
        )


class ProtectedContractTests(_ProtectedProvisionTestCase):
    def test_the_stored_row_equals_the_immutable_contract_after_the_json_round_trip(
        self,
    ):
        procedure = RPCProcedure.objects.get(name=PROVISION)

        assert procedure.params_schema == protected_contract.PARAMS_SCHEMA
        assert procedure.result_schema == protected_contract.RESULT_SCHEMA
        assert (
            command_handlers._protected_procedure_policy(procedure)
            == protected_contract.PROCEDURE_POLICY
        )
        # Admission would raise a ValidationError on any drift.
        command_handlers._require_protected_procedure_policy(procedure)

    def test_only_provision_is_protected(self):
        from netbox_rpc.constants import PROTECTED_APPROVAL_PROCEDURE_NAMES

        assert PROVISION in PROTECTED_APPROVAL_PROCEDURE_NAMES
        assert not {PREFLIGHT, VERIFY} & PROTECTED_APPROVAL_PROCEDURE_NAMES


class CapabilityRequiredTests(_ProtectedProvisionTestCase):
    @mock.patch("netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None)
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_every_procedure_needs_a_compatible_backend_capability(self, enqueue, _f):
        for name in ALL_PROCEDURES:
            procedure = RPCProcedure.objects.get(name=name)
            params = self.PARAMS if name == PROVISION else {}
            with self.assertRaises(ValidationError):
                command_handlers.create_execution(
                    serializer=self._serializer(procedure, params),
                    user=self.requester,
                )
        assert not RPCExecution.objects.filter(
            procedure__name__in=ALL_PROCEDURES
        ).exists()
        enqueue.assert_not_called()


class PendingApprovalTests(_ProtectedProvisionTestCase):
    @mock.patch("netbox_rpc.application.command_handlers._verify_backend_capability")
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_provision_enters_pending_approval_and_never_enqueues(self, enqueue, _v):
        execution = command_handlers.create_execution(
            serializer=self._serializer(),
            user=self.requester,
        )
        execution.refresh_from_db()

        assert execution.status == RPCExecution.STATUS_PENDING_APPROVAL
        assert execution.requested_by_id == self.requester.pk
        assert execution.approved_by_id is None
        assert execution.job_id is None
        assert event_names(execution) == ["ExecutionRequested", "ApprovalRequested"]
        enqueue.assert_not_called()

        snapshot = execution.approval_request
        normalized = snapshot.normalized_params
        assert normalized["dry_run"] is True
        assert normalized["domain"] == "ad.example.com"
        assert normalized["target_object"]["object_id"] == self.device.pk
        assert normalized["ssh_snapshot"]["ssh_host"] == "10.0.30.10"
        assert normalized["ssh_policy_ref"].startswith("target-owned-ssh:dcim.device:")
        rendered = str(normalized).lower() + str(snapshot.command_fingerprint).lower()
        assert "password" not in rendered
        assert snapshot.payload_hash


class ConcurrencyFenceTests(_ProtectedProvisionTestCase):
    @mock.patch("netbox_rpc.application.command_handlers._verify_backend_capability")
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_a_second_open_provision_for_the_same_target_is_refused(self, _e, _v):
        first = command_handlers.create_execution(
            serializer=self._serializer(), user=self.requester
        )
        assert first.status == RPCExecution.STATUS_PENDING_APPROVAL

        with self.assertRaises(ValidationError):
            command_handlers.create_execution(
                serializer=self._serializer(), user=self.requester
            )
        assert RPCExecution.objects.filter(procedure=self.provision).count() == 1

    @mock.patch("netbox_rpc.application.command_handlers._verify_backend_capability")
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue")
    def test_a_terminal_provision_does_not_block_a_new_request(self, _e, _v):
        first = command_handlers.create_execution(
            serializer=self._serializer(), user=self.requester
        )
        RPCExecution.objects.filter(pk=first.pk).update(
            status=RPCExecution.STATUS_REJECTED
        )

        second = command_handlers.create_execution(
            serializer=self._serializer(), user=self.requester
        )
        assert second.status == RPCExecution.STATUS_PENDING_APPROVAL


class CapabilityFixtureTests(TestCase):
    def test_the_seeded_rows_hash_to_the_cross_repository_fixture(self):
        import json
        from pathlib import Path

        from netbox_rpc.capabilities import derive_command_contract_hash

        fixture = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "tests/fixtures/samba_ad_dc_capability_contract.json"
            ).read_text()
        )
        for name in ALL_PROCEDURES:
            procedure = RPCProcedure.objects.get(name=name)
            assert (
                derive_command_contract_hash(procedure)
                == fixture["handlers"][name]["contract_hash"]
            ), name
