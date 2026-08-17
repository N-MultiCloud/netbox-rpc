"""Historical-app irreversibility coverage for migration 0071."""

from __future__ import annotations

import importlib

from django.db import connection
from django.db.migrations.exceptions import IrreversibleError
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.recorder import MigrationRecorder
from django.test import TransactionTestCase


class GiteaUpgradeMigrationIrreversibilityTests(TransactionTestCase):
    migration = ("netbox_rpc", "0071_seed_gitea_production_upgrade_1271")
    previous_migration = ("netbox_rpc", "0070_rpcapprovalrequest_policy_hashes")
    procedure_name = "service.gitea.production.upgrade_1_27_1"

    @classmethod
    def tearDownClass(cls) -> None:
        """Restore the migration's data seed after TransactionTestCase flushes."""

        try:
            executor = MigrationExecutor(connection)
            apps = executor.loader.project_state([cls.migration]).apps
            RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
            if not RPCProcedure.objects.filter(name=cls.procedure_name).exists():
                cls._migration_module().seed_gitea_production_upgrade(apps, None)
        finally:
            super().tearDownClass()

    @staticmethod
    def _migration_module():
        return importlib.import_module(
            "netbox_rpc.migrations.0071_seed_gitea_production_upgrade_1271"
        )

    def _historical_apps(self):
        executor = MigrationExecutor(connection)
        return executor.loader.project_state([self.migration]).apps

    def _seed(self):
        apps = self._historical_apps()
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        if not RPCProcedure.objects.filter(name=self.procedure_name).exists():
            self._migration_module().seed_gitea_production_upgrade(apps, None)
        return apps

    @staticmethod
    def _delete_procedure_without_current_model_collection(
        RPCProcedure,
        RPCProcedureCommand,
        procedure_id: int,
    ) -> None:
        quote_name = connection.ops.quote_name
        with connection.cursor() as cursor:
            cursor.execute(
                f"DELETE FROM {quote_name(RPCProcedureCommand._meta.db_table)} "
                f"WHERE {quote_name(RPCProcedureCommand._meta.get_field('procedure').column)} = %s",
                [procedure_id],
            )
            cursor.execute(
                f"DELETE FROM {quote_name(RPCProcedure._meta.db_table)} "
                f"WHERE {quote_name(RPCProcedure._meta.pk.column)} = %s",
                [procedure_id],
            )

    def _assert_migration_still_applied(self) -> None:
        assert MigrationRecorder(connection).migration_qs.filter(
            app="netbox_rpc",
            name=self.migration[1],
        ).exists()

    def _assert_reverse_aborts(self) -> None:
        with self.assertRaisesRegex(IrreversibleError, "intentionally irreversible"):
            MigrationExecutor(connection).migrate([self.previous_migration])
        self._assert_migration_still_applied()

    def test_unreferenced_seed_reverse_aborts_before_any_mutation(self) -> None:
        apps = self._seed()
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
        procedure = RPCProcedure.objects.get(name=self.procedure_name)
        before_procedure = RPCProcedure.objects.filter(pk=procedure.pk).values().get()
        before_commands = list(
            RPCProcedureCommand.objects.filter(procedure_id=procedure.pk)
            .order_by("sequence")
            .values()
        )

        self._assert_reverse_aborts()

        assert RPCProcedure.objects.filter(pk=procedure.pk).values().get() == (
            before_procedure
        )
        assert list(
            RPCProcedureCommand.objects.filter(procedure_id=procedure.pk)
            .order_by("sequence")
            .values()
        ) == before_commands

    def test_forward_rejects_and_preserves_preexisting_operator_procedure(self) -> None:
        apps = self._historical_apps()
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
        existing = RPCProcedure.objects.filter(name=self.procedure_name).first()
        if existing is not None:
            self._delete_procedure_without_current_model_collection(
                RPCProcedure,
                RPCProcedureCommand,
                existing.pk,
            )
        procedure = RPCProcedure.objects.create(
            name=self.procedure_name,
            handler_id="operator-owned.gitea.upgrade",
            enabled=True,
            description="Preserve this pre-existing operator procedure.",
        )
        RPCProcedureCommand.objects.create(
            procedure_id=procedure.pk,
            sequence=1,
            argv=["operator-owned", "first-command"],
        )
        RPCProcedureCommand.objects.create(
            procedure_id=procedure.pk,
            sequence=2,
            argv=["operator-owned", "additional-command"],
        )

        with self.assertRaisesRegex(RuntimeError, "canonical name already exists"):
            self._migration_module().seed_gitea_production_upgrade(apps, None)

        preserved = RPCProcedure.objects.get(pk=procedure.pk)
        assert preserved.handler_id == "operator-owned.gitea.upgrade"
        assert preserved.enabled is True
        assert preserved.description == "Preserve this pre-existing operator procedure."
        assert list(
            RPCProcedureCommand.objects.filter(procedure_id=procedure.pk)
            .order_by("sequence")
            .values_list("sequence", "argv")
        ) == [
            (1, ["operator-owned", "first-command"]),
            (2, ["operator-owned", "additional-command"]),
        ]

    def test_replacement_under_canonical_name_is_never_deleted(self) -> None:
        apps = self._seed()
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
        seed = RPCProcedure.objects.get(name=self.procedure_name)
        self._delete_procedure_without_current_model_collection(
            RPCProcedure,
            RPCProcedureCommand,
            seed.pk,
        )
        replacement = RPCProcedure.objects.create(
            name=self.procedure_name,
            handler_id="operator-owned.replacement",
            enabled=True,
        )
        command = RPCProcedureCommand.objects.create(
            procedure_id=replacement.pk,
            sequence=9,
            argv=["operator-owned", "replacement"],
        )

        self._assert_reverse_aborts()

        replacement.refresh_from_db()
        assert replacement.handler_id == "operator-owned.replacement"
        assert replacement.enabled is True
        assert RPCProcedureCommand.objects.filter(pk=command.pk).exists()

    def test_renamed_seed_and_command_are_never_orphaned(self) -> None:
        apps = self._seed()
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
        procedure = RPCProcedure.objects.get(name=self.procedure_name)
        command_ids = list(
            RPCProcedureCommand.objects.filter(procedure_id=procedure.pk).values_list(
                "pk",
                flat=True,
            )
        )
        procedure.name = "operator-renamed.gitea.upgrade"
        procedure.save(update_fields=["name"])

        self._assert_reverse_aborts()

        procedure.refresh_from_db()
        assert procedure.name == "operator-renamed.gitea.upgrade"
        assert list(
            RPCProcedureCommand.objects.filter(procedure_id=procedure.pk).values_list(
                "pk",
                flat=True,
            )
        ) == command_ids

    def test_history_and_generic_metadata_remain_untouched(self) -> None:
        apps = self._seed()
        ContentType = apps.get_model("contenttypes", "ContentType")
        JournalEntry = apps.get_model("extras", "JournalEntry")
        RPCExecution = apps.get_model("netbox_rpc", "RPCExecution")
        RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
        RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
        Tag = apps.get_model("extras", "Tag")
        TaggedItem = apps.get_model("extras", "TaggedItem")

        procedure = RPCProcedure.objects.get(name=self.procedure_name)
        command = RPCProcedureCommand.objects.get(procedure_id=procedure.pk)
        target_type, _ = ContentType.objects.get_or_create(
            app_label="virtualization",
            model="virtualmachine",
        )
        execution = RPCExecution.objects.create(
            procedure_id=procedure.pk,
            assigned_object_type_id=target_type.pk,
            assigned_object_id=170,
        )
        procedure_type = ContentType.objects.get(
            app_label="netbox_rpc",
            model="rpcprocedure",
        )
        command_type = ContentType.objects.get(
            app_label="netbox_rpc",
            model="rpcprocedurecommand",
        )
        tag = Tag.objects.create(
            name="Gitea 0071 irreversible",
            slug="gitea-0071-irreversible",
        )
        tagged = TaggedItem.objects.create(
            tag_id=tag.pk,
            content_type_id=procedure_type.pk,
            object_id=procedure.pk,
        )
        journal = JournalEntry.objects.create(
            assigned_object_type_id=command_type.pk,
            assigned_object_id=command.pk,
            comments="Preserve operator rollback context.",
        )

        self._assert_reverse_aborts()

        assert RPCExecution.objects.filter(pk=execution.pk).exists()
        assert RPCProcedure.objects.filter(pk=procedure.pk).exists()
        assert RPCProcedureCommand.objects.filter(pk=command.pk).exists()
        assert TaggedItem.objects.filter(pk=tagged.pk).exists()
        assert JournalEntry.objects.filter(pk=journal.pk).exists()
