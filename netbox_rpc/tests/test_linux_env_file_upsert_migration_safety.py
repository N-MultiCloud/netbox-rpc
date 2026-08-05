"""DB-backed proof for the round-3 adversarial-review fixes on migration 0060/0061.

Calls the ``RunPython`` functions directly against the live app registry
rather than driving a full ``MigrationExecutor`` replay. This repo has no
existing pattern for historical-state migration tests (see the pure-domain
stub-based suite under ``tests/`` instead), and these two functions only call
``apps.get_model(app_label, model_name)`` with no field/schema access that
differs between migration-time and current state, so the live registry is a
faithful stand-in.

1. ``force_disable_linux_env_file_upsert_var`` (0061) must flip an
   already-``enabled=True`` row to ``False`` -- the version-skew case where a
   database applied the original 0060 before it was edited in place.
2. ``unseed_linux_env_file_upsert_var`` (0060 reverse) must leave BOTH the
   procedure and its command row intact when an ``RPCExecution`` protects the
   procedure from deletion -- never delete the command and strand the
   procedure without one.
"""

from __future__ import annotations

import importlib

from django.apps import apps as django_apps
from django.test import TestCase

from netbox_rpc.models import RPCExecution, RPCProcedure, RPCProcedureCommand

from ._common import device_ct, make_user

_0060 = importlib.import_module(
    "netbox_rpc.migrations.0060_seed_linux_env_file_upsert_var"
)
_0061 = importlib.import_module(
    "netbox_rpc.migrations.0061_linux_env_file_upsert_var_force_disabled"
)

_PROCEDURE_NAME = "os.linux_env_file.upsert_var"


class ForceDisableMigrationTests(TestCase):
    """0061 must correct a stale enabled=True row left by the original 0060."""

    def test_force_disable_flips_stale_enabled_true_row(self):
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        procedure.enabled = True
        procedure.save(update_fields=["enabled"])

        _0061.force_disable_linux_env_file_upsert_var(django_apps, None)

        procedure.refresh_from_db()
        self.assertFalse(procedure.enabled)

    def test_force_disable_is_idempotent_when_already_disabled(self):
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        self.assertFalse(procedure.enabled)

        _0061.force_disable_linux_env_file_upsert_var(django_apps, None)

        procedure.refresh_from_db()
        self.assertFalse(procedure.enabled)


class ReverseMigrationRollbackSafetyTests(TestCase):
    """0060's reverse function must not partially delete a protected procedure."""

    def test_unseed_deletes_procedure_and_cascades_commands_when_unprotected(self):
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        self.assertTrue(
            RPCProcedureCommand.objects.filter(procedure=procedure).exists()
        )

        _0060.unseed_linux_env_file_upsert_var(django_apps, None)

        self.assertFalse(RPCProcedure.objects.filter(name=_PROCEDURE_NAME).exists())
        self.assertFalse(
            RPCProcedureCommand.objects.filter(procedure_id=procedure.pk).exists()
        )

    def test_unseed_leaves_procedure_and_commands_intact_when_protected(self):
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
        command_ids = list(
            RPCProcedureCommand.objects.filter(procedure=procedure).values_list(
                "pk", flat=True
            )
        )
        self.assertTrue(command_ids)

        RPCExecution.objects.create(
            procedure=procedure,
            assigned_object_type=device_ct(),
            assigned_object_id=1,
            requested_by=make_user(),
        )

        _0060.unseed_linux_env_file_upsert_var(django_apps, None)

        self.assertTrue(RPCProcedure.objects.filter(pk=procedure.pk).exists())
        self.assertEqual(
            set(
                RPCProcedureCommand.objects.filter(procedure=procedure).values_list(
                    "pk", flat=True
                )
            ),
            set(command_ids),
        )
