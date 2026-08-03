"""Migration 0057 rollback retains and disables every seeded procedure."""

from __future__ import annotations

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class AkvoradoMigrationRollbackTests(TransactionTestCase):
    migrate_from = ("netbox_rpc", "0057_seed_akvorado_procedures")
    migrate_to = ("netbox_rpc", "0056_seed_influxdb_onboarding_procedures")

    def test_all_procedures_are_disabled_with_execution_and_intent_references(self):
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        apps = executor.loader.project_state([self.migrate_from]).apps
        ContentType = apps.get_model("contenttypes", "ContentType")
        RPCExecution = apps.get_model("netbox_rpc", "RPCExecution")
        RPCIntent = apps.get_model("netbox_rpc", "RPCIntent")
        RPCIntentProcedure = apps.get_model("netbox_rpc", "RPCIntentProcedure")
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        procedure_names = {
            "service.akvorado.1.config_read",
            "service.akvorado.1.config_deploy",
            "service.akvorado.1.status_stack",
            "service.akvorado.1.restart_stack",
        }
        procedures = {
            procedure.name: procedure
            for procedure in RPCProcedure.objects.filter(name__in=procedure_names)
        }
        RPCProcedure.objects.filter(name__in=procedure_names).update(enabled=True)
        content_type, _ = ContentType.objects.get_or_create(
            app_label="dcim",
            model="device",
        )
        RPCExecution.objects.create(
            procedure=procedures["service.akvorado.1.config_read"],
            assigned_object_type=content_type,
            assigned_object_id=1,
        )
        intent = RPCIntent.objects.create(name="intent.akvorado.rollback")
        RPCIntentProcedure.objects.create(
            intent=intent,
            procedure=procedures["service.akvorado.1.config_deploy"],
            sequence=1,
        )

        try:
            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            old_apps = executor.loader.project_state([self.migrate_to]).apps
            OldRPCProcedure = old_apps.get_model("netbox_rpc", "RPCProcedure")
            retained = OldRPCProcedure.objects.filter(name__in=procedure_names)

            assert set(retained.values_list("name", flat=True)) == procedure_names
            assert not retained.exclude(enabled=False).exists()
        finally:
            MigrationExecutor(connection).migrate([self.migrate_from])
