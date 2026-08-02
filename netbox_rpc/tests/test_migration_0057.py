"""Migration 0057 rollback behavior with retained execution history."""

from __future__ import annotations

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class AkvoradoMigrationRollbackTests(TransactionTestCase):
    migrate_from = ("netbox_rpc", "0057_seed_akvorado_procedures")
    migrate_to = ("netbox_rpc", "0056_seed_influxdb_onboarding_procedures")

    def test_referenced_procedure_is_disabled_instead_of_deleted(self):
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        apps = executor.loader.project_state([self.migrate_from]).apps
        ContentType = apps.get_model("contenttypes", "ContentType")
        RPCExecution = apps.get_model("netbox_rpc", "RPCExecution")
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        procedure = RPCProcedure.objects.get(
            name="service.akvorado.1.config_read"
        )
        content_type, _ = ContentType.objects.get_or_create(
            app_label="dcim",
            model="device",
        )
        RPCExecution.objects.create(
            procedure=procedure,
            assigned_object_type=content_type,
            assigned_object_id=1,
        )

        try:
            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            old_apps = executor.loader.project_state([self.migrate_to]).apps
            OldRPCProcedure = old_apps.get_model("netbox_rpc", "RPCProcedure")
            retained = OldRPCProcedure.objects.get(pk=procedure.pk)

            assert retained.name == "service.akvorado.1.config_read"
            assert retained.enabled is False
        finally:
            MigrationExecutor(connection).migrate([self.migrate_from])
