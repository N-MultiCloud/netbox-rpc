"""DB-backed tests for the #321 round-1-review redesign: an
assignment-based OpenBao credential reference (``openbao_assignment_id``)
replacing the raw ``openbao_credential_id`` integer.

Covers:
- ``RPCLinuxServiceAllowlist``/``RPCNetBoxPluginAllowlist`` row-save
  validation (existence, enabled, purpose) via
  ``models._validate_openbao_assignment_id_for_save``.
- ``domain.normalization.resolve_openbao_assignment_reference`` dispatch-time
  validation: existence, enabled, purpose, target binding, requester
  visibility.
- ``rpc_remap_credentials_to_openbao``'s lookup/create-when-unambiguous
  behavior against real ``CredentialAssignment`` rows.

Skipped entirely when netbox-openbao is not installed in the test
environment, consistent with it being an optional dependency everywhere else
in this plugin.
"""

from __future__ import annotations

import unittest

from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase

from netbox_rpc import models
from netbox_rpc.domain.normalization import (
    RPCExecutionError,
    resolve_openbao_assignment_reference,
)
from netbox_rpc.management.commands.rpc_remap_credentials_to_openbao import (
    _resolve_or_create_assignment,
)

from . import _common

_OPENBAO_INSTALLED = apps.is_installed("netbox_openbao")


@unittest.skipUnless(_OPENBAO_INSTALLED, "netbox-openbao is not installed")
class OpenBaoAssignmentFixtureMixin:
    """Builds the minimal real netbox-openbao estate: engine, policy,
    credential, and (optionally) an assignment."""

    def setUp(self):
        super().setUp()
        from netbox_openbao.choices import CredentialTypeChoices
        from netbox_openbao.models import Credential, CredentialPolicy, SecretEngine

        self.engine = SecretEngine.objects.create(
            name="RPC Test Engine",
            slug="rpc-test-engine",
            api_url="https://bao.example.net:8200",
            kv_mount="secret",
        )
        self.policy = CredentialPolicy.objects.create(
            name="RPC Test Policy",
            slug="rpc-test-policy",
            engine=self.engine,
            openbao_policy="netbox-rpc-test",
        )
        self.credential = Credential.objects.create(
            name="rpc-test-credential",
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=self.policy,
            engine=self.engine,
        )
        self.device = _common.make_device("openbao-ref-device")

    def make_assignment(
        self,
        *,
        target=None,
        target_type=None,
        target_id=None,
        purpose="login",
        enabled=True,
    ):
        from netbox_openbao.models import CredentialAssignment

        if target_type is not None or target_id is not None:
            assert target is None, "pass either target= or target_type=/target_id=, not both"
            assigned_object_type, assigned_object_id = target_type, target_id
        else:
            target = target or self.device
            assigned_object_type = ContentType.objects.get_for_model(target)
            assigned_object_id = target.pk
        return CredentialAssignment.objects.create(
            credential=self.credential,
            assigned_object_type=assigned_object_type,
            assigned_object_id=assigned_object_id,
            purpose=purpose,
            enabled=enabled,
        )


class AllowlistRowValidationTest(OpenBaoAssignmentFixtureMixin, TestCase):
    def test_row_accepts_a_valid_enabled_login_assignment(self):
        assignment = self.make_assignment()
        row = models.RPCLinuxServiceAllowlist(
            slug="openbao-valid",
            systemd_unit="openbao-valid.service",
            openbao_assignment_id=assignment.pk,
        )
        row.full_clean()  # must not raise

    def test_row_rejects_a_nonexistent_assignment(self):
        row = models.RPCLinuxServiceAllowlist(
            slug="openbao-missing",
            systemd_unit="openbao-missing.service",
            openbao_assignment_id=999999,
        )
        with self.assertRaises(ValidationError):
            row.full_clean()

    def test_row_rejects_a_disabled_assignment(self):
        assignment = self.make_assignment(enabled=False)
        row = models.RPCLinuxServiceAllowlist(
            slug="openbao-disabled",
            systemd_unit="openbao-disabled.service",
            openbao_assignment_id=assignment.pk,
        )
        with self.assertRaises(ValidationError):
            row.full_clean()

    def test_row_rejects_the_wrong_purpose(self):
        assignment = self.make_assignment(purpose="backup")
        row = models.RPCLinuxServiceAllowlist(
            slug="openbao-wrong-purpose",
            systemd_unit="openbao-wrong-purpose.service",
            openbao_assignment_id=assignment.pk,
        )
        with self.assertRaises(ValidationError):
            row.full_clean()

    def test_plugin_allowlist_row_applies_the_same_validation(self):
        assignment = self.make_assignment(purpose="backup")
        row = models.RPCNetBoxPluginAllowlist(
            slug="openbao-plugin-wrong-purpose",
            distribution="example-plugin",
            module="example_plugin",
            venv_python="/opt/netbox/venv/bin/python",
            manage_py="/opt/netbox/netbox/manage.py",
            settings_file="/opt/netbox/netbox/netbox/configuration.py",
            openbao_assignment_id=assignment.pk,
        )
        with self.assertRaises(ValidationError):
            row.full_clean()


class ResolveOpenbaoAssignmentReferenceTest(OpenBaoAssignmentFixtureMixin, TestCase):
    def _execution_for(self, target):
        user = _common.make_user()
        return models.RPCExecution.objects.create(
            procedure=_common.make_procedure(),
            assigned_object_type=ContentType.objects.get_for_model(target),
            assigned_object_id=target.pk,
            requested_by=user,
        )

    def test_none_assignment_id_returns_none(self):
        execution = self._execution_for(self.device)
        self.assertIsNone(resolve_openbao_assignment_reference(None, execution))

    def test_valid_assignment_bound_to_the_execution_target_resolves(self):
        assignment = self.make_assignment(target=self.device)
        execution = self._execution_for(self.device)
        result = resolve_openbao_assignment_reference(assignment.pk, execution)
        self.assertEqual(result, {"rpc_openbao_assignment_id": assignment.pk})

    def test_assignment_bound_to_a_different_target_is_rejected(self):
        other_device = _common.make_device("openbao-ref-other-device")
        assignment = self.make_assignment(target=other_device)
        execution = self._execution_for(self.device)
        with self.assertRaises(RPCExecutionError) as ctx:
            resolve_openbao_assignment_reference(assignment.pk, execution)
        self.assertEqual(ctx.exception.code, "RPC_OPENBAO_ASSIGNMENT_TARGET_MISMATCH")

    def test_disabled_assignment_is_rejected(self):
        assignment = self.make_assignment(target=self.device, enabled=False)
        execution = self._execution_for(self.device)
        with self.assertRaises(RPCExecutionError) as ctx:
            resolve_openbao_assignment_reference(assignment.pk, execution)
        self.assertEqual(ctx.exception.code, "RPC_OPENBAO_ASSIGNMENT_INVALID")

    def test_wrong_purpose_is_rejected(self):
        assignment = self.make_assignment(target=self.device, purpose="console")
        execution = self._execution_for(self.device)
        with self.assertRaises(RPCExecutionError) as ctx:
            resolve_openbao_assignment_reference(assignment.pk, execution)
        self.assertEqual(
            ctx.exception.code, "RPC_OPENBAO_ASSIGNMENT_PURPOSE_MISMATCH"
        )

    def test_target_binding_can_be_disabled(self):
        # Generic capability test for the enforce_target_binding=False
        # parameter itself. packer_normalizer.py no longer uses this (round-2
        # #321 review: packer.vm.* now enforces target binding against the
        # PackerTemplate execution target -- see
        # PackerVmOpenbaoCredentialTest below); this parameter remains
        # available to a future caller with a genuinely different binding
        # target than its execution's assigned_object.
        assignment = self.make_assignment(target=self.device)
        other_device = _common.make_device("openbao-ref-unbound-target")
        execution = self._execution_for(other_device)
        result = resolve_openbao_assignment_reference(
            assignment.pk, execution, enforce_target_binding=False
        )
        self.assertEqual(result, {"rpc_openbao_assignment_id": assignment.pk})

    def test_requester_without_view_permission_is_denied(self):
        from django.contrib.auth import get_user_model

        assignment = self.make_assignment(target=self.device)
        unprivileged = get_user_model().objects.create_user(
            username="openbao-ref-unprivileged"
        )
        execution = models.RPCExecution.objects.create(
            procedure=_common.make_procedure(),
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            requested_by=unprivileged,
        )
        with self.assertRaises(RPCExecutionError) as ctx:
            resolve_openbao_assignment_reference(assignment.pk, execution)
        self.assertEqual(
            ctx.exception.code, "RPC_OPENBAO_CREDENTIAL_PERMISSION_DENIED"
        )


class LinuxServiceExecutionOpenbaoPrecedenceTest(OpenBaoAssignmentFixtureMixin, TestCase):
    """The allowlist normalizer must prefer a valid openbao_assignment_id
    over the legacy ssh_credential_override, and include it in the
    command_fingerprint."""

    def test_openbao_reference_takes_precedence_over_legacy_override(self):
        from netbox_rpc.domain.normalization import _normalize_linux_service_execution

        assignment = self.make_assignment(target=self.device)
        allow = models.RPCLinuxServiceAllowlist.objects.create(
            slug="openbao-precedence",
            systemd_unit="openbao-precedence.service",
            ssh_credential_override=4242,
            openbao_assignment_id=assignment.pk,
        )
        execution = models.RPCExecution.objects.create(
            procedure=_common.make_procedure(name="os.linux.test.restart_openbao"),
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            requested_by=_common.make_user(),
            params={"service_slug": allow.slug},
        )
        result = _normalize_linux_service_execution(execution, "target-display")
        self.assertEqual(result["rpc_openbao_assignment_id"], assignment.pk)
        self.assertNotIn("rpc_ssh_credential_pk", result)
        self.assertEqual(
            result["command_fingerprint"]["rpc_openbao_assignment_id"], assignment.pk
        )

    def test_legacy_override_still_used_when_no_openbao_assignment(self):
        from netbox_rpc.domain.normalization import _normalize_linux_service_execution

        allow = models.RPCLinuxServiceAllowlist.objects.create(
            slug="openbao-legacy-fallback",
            systemd_unit="openbao-legacy-fallback.service",
            ssh_credential_override=4242,
        )
        execution = models.RPCExecution.objects.create(
            procedure=_common.make_procedure(name="os.linux.test.restart_legacy"),
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            requested_by=_common.make_user(),
            params={"service_slug": allow.slug},
        )
        result = _normalize_linux_service_execution(execution, "target-display")
        self.assertEqual(result["rpc_ssh_credential_pk"], 4242)
        self.assertNotIn("rpc_openbao_assignment_id", result)


class RemapCommandAssignmentTest(OpenBaoAssignmentFixtureMixin, TestCase):
    def test_resolve_or_create_finds_existing_login_assignment(self):
        from netbox_openbao.models import CredentialAssignment

        assignment = self.make_assignment(target=self.device)
        resolved = _resolve_or_create_assignment(
            CredentialAssignment, self.credential.pk, dry_run=False
        )
        self.assertEqual(resolved, assignment.pk)

    def test_resolve_or_create_creates_when_exactly_one_existing_assignment(self):
        from netbox_openbao.models import CredentialAssignment

        console_assignment = self.make_assignment(purpose="console")
        resolved = _resolve_or_create_assignment(
            CredentialAssignment, self.credential.pk, dry_run=False
        )
        self.assertIsNotNone(resolved)
        self.assertNotEqual(resolved, console_assignment.pk)
        created = CredentialAssignment.objects.get(pk=resolved)
        self.assertEqual(created.purpose, "login")
        self.assertEqual(created.assigned_object_id, console_assignment.assigned_object_id)
        self.assertEqual(
            created.assigned_object_type_id, console_assignment.assigned_object_type_id
        )

    def test_resolve_or_create_refuses_to_guess_with_zero_assignments(self):
        from netbox_openbao.models import CredentialAssignment

        resolved = _resolve_or_create_assignment(
            CredentialAssignment, self.credential.pk, dry_run=False
        )
        self.assertIsNone(resolved)

    def test_resolve_or_create_refuses_to_guess_with_multiple_assignments(self):
        from netbox_openbao.models import CredentialAssignment

        other_device = _common.make_device("openbao-remap-other-device")
        self.make_assignment(target=self.device, purpose="console")
        self.make_assignment(target=other_device, purpose="backup")
        resolved = _resolve_or_create_assignment(
            CredentialAssignment, self.credential.pk, dry_run=False
        )
        self.assertIsNone(resolved)

    def test_dry_run_never_writes(self):
        from netbox_openbao.models import CredentialAssignment

        self.make_assignment(purpose="console")
        before = CredentialAssignment.objects.count()
        resolved = _resolve_or_create_assignment(
            CredentialAssignment, self.credential.pk, dry_run=True
        )
        self.assertEqual(resolved, -1)
        self.assertEqual(CredentialAssignment.objects.count(), before)

    def test_command_end_to_end_sets_openbao_assignment_id(self):
        from netbox_openbao.models import CredentialAssignment

        # The remap command only ever reads the legacy DeviceCredential pk as
        # an opaque integer to build the import_source marker string -- it
        # never queries netbox_nms.DeviceCredential itself (see
        # rpc_remap_credentials_to_openbao._resolve_credential_pk). A
        # standalone-installable environment with netbox-openbao but not
        # netbox-nms must still be able to run this command, so a real
        # DeviceCredential row is deliberately not required here.
        legacy_credential_pk = 4321
        migrated = type(self.credential).objects.create(
            name="rpc-legacy-openbao-remap-migrated",
            credential_type="password",
            policy=self.policy,
            engine=self.engine,
            import_source=f"netbox_nms.DeviceCredential:{legacy_credential_pk}",
        )
        assignment = CredentialAssignment.objects.create(
            credential=migrated,
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            purpose="login",
            enabled=True,
        )
        allow = models.RPCLinuxServiceAllowlist.objects.create(
            slug="openbao-remap-e2e",
            systemd_unit="openbao-remap-e2e.service",
            ssh_credential_override=legacy_credential_pk,
        )

        call_command("rpc_remap_credentials_to_openbao")

        allow.refresh_from_db()
        self.assertEqual(allow.openbao_assignment_id, assignment.pk)
        # Legacy value is never cleared.
        self.assertEqual(allow.ssh_credential_override, legacy_credential_pk)


@unittest.skipUnless(_OPENBAO_INSTALLED, "netbox-openbao is not installed")
class PackerVmOpenbaoCredentialTest(OpenBaoAssignmentFixtureMixin, TestCase):
    """#321 round-2 review: packer.vm.* target binding + ssh_host authority,
    and the never-both-credential-keys invariant.

    ``netbox_packer`` is not installed in this test environment, and
    ``normalize_packer_vm_execution()`` only needs ``isinstance(assigned_
    object, PackerTemplate)`` to succeed and a few plain attributes off it --
    it never issues a Django ORM query against ``PackerTemplate`` itself. So
    this stubs ``netbox_packer.models.PackerTemplate`` as a bare Python class
    via ``sys.modules`` (the same style this repo's pure-domain tests already
    use for stubbing NetBox/Django modules) and builds a plain
    ``SimpleNamespace`` standing in for the ``RPCExecution`` the normalizer
    reads. The ``CredentialAssignment``/``Credential`` rows underneath are
    real DB rows via the shared fixture mixin -- only the "PackerTemplate"
    object and its owning "execution" are stubs.
    """

    def setUp(self):
        super().setUp()
        import sys
        import types

        self._fake_packer_module = types.ModuleType("netbox_packer")
        fake_models_module = types.ModuleType("netbox_packer.models")

        class _FakePackerTemplate:
            def __init__(self, proxmox_node, proxmox_template_id=None):
                self.proxmox_node = proxmox_node
                self.proxmox_template_id = proxmox_template_id

        fake_models_module.PackerTemplate = _FakePackerTemplate
        self._FakePackerTemplate = _FakePackerTemplate
        sys.modules["netbox_packer"] = self._fake_packer_module
        sys.modules["netbox_packer.models"] = fake_models_module
        self.addCleanup(sys.modules.pop, "netbox_packer", None)
        self.addCleanup(sys.modules.pop, "netbox_packer.models", None)

        # A fresh ContentType, standing in for netbox_packer.packertemplate;
        # the code under test only compares assigned_object_type_id values,
        # it never checks that the type names any particular app.
        self.template_ct = ContentType.objects.get_for_model(models.RPCBackend)
        self.template_pk = 9001

    def _fake_execution(self, *, params, requester=None):
        from types import SimpleNamespace

        template = self._FakePackerTemplate(
            proxmox_node="pve-node-a.example.net", proxmox_template_id=9100
        )
        return SimpleNamespace(
            assigned_object=template,
            assigned_object_type_id=self.template_ct.pk,
            assigned_object_id=self.template_pk,
            procedure=SimpleNamespace(
                name="packer.vm.test_ssh_connectivity",
                handler_id="packer.vm.test_ssh_connectivity",
            ),
            requested_by=requester or self._common_user(),
            params=params,
        )

    def _common_user(self):
        return _common.make_user("openbao-packer-tester")

    def test_legacy_credential_pk_path_omits_openbao_key(self):
        from netbox_rpc.packer_normalizer import normalize_packer_vm_execution

        execution = self._fake_execution(params={"rpc_ssh_credential_pk": 4242})
        result = normalize_packer_vm_execution(execution, "packer-target")
        self.assertEqual(result["rpc_ssh_credential_pk"], 4242)
        self.assertNotIn("rpc_openbao_assignment_id", result)
        self.assertNotIn("rpc_openbao_assignment_id", result["command_fingerprint"])

    def test_openbao_path_omits_rpc_ssh_credential_pk(self):
        from netbox_rpc.packer_normalizer import normalize_packer_vm_execution

        assignment = self.make_assignment(
            target_type=self.template_ct, target_id=self.template_pk
        )
        execution = self._fake_execution(
            params={"openbao_assignment_id": assignment.pk}
        )
        result = normalize_packer_vm_execution(execution, "packer-target")
        self.assertEqual(result["rpc_openbao_assignment_id"], assignment.pk)
        self.assertNotIn("rpc_ssh_credential_pk", result)
        self.assertNotIn("rpc_ssh_credential_pk", result["command_fingerprint"])
        self.assertEqual(
            result["command_fingerprint"]["rpc_openbao_assignment_id"], assignment.pk
        )

    def test_neither_credential_param_is_rejected(self):
        from netbox_rpc.packer_normalizer import normalize_packer_vm_execution

        execution = self._fake_execution(params={})
        with self.assertRaises(RPCExecutionError) as ctx:
            normalize_packer_vm_execution(execution, "packer-target")
        self.assertEqual(ctx.exception.code, "RPC_PARAM_INVALID")

    def test_both_credential_params_is_rejected(self):
        from netbox_rpc.packer_normalizer import normalize_packer_vm_execution

        assignment = self.make_assignment(
            target_type=self.template_ct, target_id=self.template_pk
        )
        execution = self._fake_execution(
            params={
                "rpc_ssh_credential_pk": 4242,
                "openbao_assignment_id": assignment.pk,
            }
        )
        with self.assertRaises(RPCExecutionError) as ctx:
            normalize_packer_vm_execution(execution, "packer-target")
        self.assertEqual(ctx.exception.code, "RPC_PARAM_INVALID")

    def test_an_assignment_bound_to_a_different_template_is_rejected(self):
        """Critical #321 round-2 finding: a credential assigned to template A
        must never be usable dispatching against template B's execution."""
        from netbox_rpc.packer_normalizer import normalize_packer_vm_execution

        other_template_pk = self.template_pk + 1
        assignment = self.make_assignment(
            target_type=self.template_ct, target_id=other_template_pk
        )
        execution = self._fake_execution(
            params={"openbao_assignment_id": assignment.pk}
        )
        with self.assertRaises(RPCExecutionError) as ctx:
            normalize_packer_vm_execution(execution, "packer-target")
        self.assertEqual(ctx.exception.code, "RPC_OPENBAO_ASSIGNMENT_TARGET_MISMATCH")

    def test_ssh_host_override_matching_proxmox_node_is_accepted(self):
        from netbox_rpc.packer_normalizer import normalize_packer_vm_execution

        execution = self._fake_execution(
            params={
                "rpc_ssh_credential_pk": 4242,
                "ssh_host": "pve-node-a.example.net",
            }
        )
        result = normalize_packer_vm_execution(execution, "packer-target")
        self.assertEqual(result["rpc_ssh_host"], "pve-node-a.example.net")

    def test_ssh_host_override_redirecting_off_the_template_node_is_rejected(self):
        """Critical #321 round-2 finding: a caller-controlled ssh_host must
        not be able to redirect dispatch to a host other than the template's
        own proxmox_node, even with a validly target-bound credential."""
        from netbox_rpc.packer_normalizer import normalize_packer_vm_execution

        assignment = self.make_assignment(
            target_type=self.template_ct, target_id=self.template_pk
        )
        execution = self._fake_execution(
            params={
                "openbao_assignment_id": assignment.pk,
                "ssh_host": "attacker-controlled-host.example.net",
            }
        )
        with self.assertRaises(RPCExecutionError) as ctx:
            normalize_packer_vm_execution(execution, "packer-target")
        self.assertEqual(ctx.exception.code, "RPC_PACKER_HOST_MISMATCH")
