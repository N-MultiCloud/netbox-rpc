"""Event-sourcing integration tests: append+project, the rebuild oracle, and
the append-only ledger, against a real NetBox test database."""

from __future__ import annotations

import yaml
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.test import TestCase

from netbox_rpc import event_store
from netbox_rpc.domain.aggregate import (
    RPCExecutionAggregate,
)
from netbox_rpc.domain.projection import ProjectionState
from netbox_rpc.models import RPCExecution, RPCExecutionEvent

from ._common import event_names, make_execution, make_procedure


class EventStoreProjectionTests(TestCase):
    def test_queued_event_is_appended_and_projected(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        ex.refresh_from_db()
        assert event_names(ex) == ["ExecutionQueued"]
        assert ex.status == RPCExecution.STATUS_QUEUED

    def test_running_transition_appends_event_and_sets_started_at(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        event_store.mark_execution_running(ex)
        ex.refresh_from_db()
        assert event_names(ex) == ["ExecutionQueued", "ExecutionStarted"]
        assert ex.status == RPCExecution.STATUS_RUNNING
        assert ex.started_at is not None

    def test_job_enqueued_event_projects_job_id(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        event_store.record_execution_enqueued(ex, 4242)
        ex.refresh_from_db()
        assert "JobEnqueued" in event_names(ex)
        assert ex.job_id == 4242

    def test_sequences_are_monotonic_per_execution(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        event_store.mark_execution_running(ex)
        event_store.record_execution_succeeded(ex, {"ok": True})
        seqs = list(ex.events.order_by("sequence").values_list("sequence", flat=True))
        assert seqs == [1, 2, 3]

    def test_sensitive_keys_redacted_but_credential_refs_preserved(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        event_store.mark_execution_running(ex)
        event_store.record_execution_normalized(
            ex,
            {"password": "topsecret", "rpc_ssh_credential_pk": 7, "target": "vm01"},
            "hash123",
        )
        ev = ex.events.get(event="ParametersNormalized")
        np = ev.data["normalized_params"]
        assert np["password"] == "[REDACTED]"
        assert np["rpc_ssh_credential_pk"] == 7
        # The projection keeps the raw operational value for dispatch.
        ex.refresh_from_db()
        assert ex.normalized_params["password"] == "topsecret"


class RebuildOracleTests(TestCase):
    """rebuild_projection(stored events) must reproduce the live projection."""

    def _assert_rebuild_matches(self, ex):
        ex.refresh_from_db()
        live = ProjectionState.from_execution(ex)
        rebuilt = event_store.rebuild_projection(ex)
        assert rebuilt == live, f"rebuild != projection: {rebuilt} != {live}"

    def test_success_path(self):
        ex = make_execution()
        a = RPCExecutionAggregate(ex)
        a.queue()
        a.enqueue(11)
        a.start()
        a.normalize({"target": "vm01", "command_fingerprint": {}}, "h")
        a.record_backend_response(
            {"ok": True, "result": {"stdout": "done"},
             "events": [{"level": "info", "event": "SSHConnected", "message": "ok", "data": {}}]}
        )
        self._assert_rebuild_matches(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_SUCCEEDED

    def test_failure_path(self):
        ex = make_execution()
        a = RPCExecutionAggregate(ex)
        a.queue()
        a.start()
        a.fail("boom", "RPC_TEST_FAIL")
        self._assert_rebuild_matches(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_FAILED
        assert ex.error_code == "RPC_TEST_FAIL"

    def test_cancelled_path(self):
        ex = make_execution()
        a = RPCExecutionAggregate(ex)
        a.queue()
        a.cancel()
        self._assert_rebuild_matches(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_CANCELLED

    def test_enqueue_failed_path(self):
        ex = make_execution()
        RPCExecutionAggregate(ex).queue()
        event_store.mark_execution_failed(
            ex, "no redis", "RPC_ENQUEUE_FAILED", event_name="ExecutionEnqueueFailed"
        )
        self._assert_rebuild_matches(ex)
        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_FAILED

    def test_reproject_is_idempotent(self):
        ex = make_execution()
        a = RPCExecutionAggregate(ex)
        a.queue()
        a.enqueue(9)
        a.start()
        a.normalize({"k": "v", "command_fingerprint": {}}, "h")
        a.record_backend_response({"ok": True, "result": {"x": 1}})
        before = ProjectionState.from_execution(RPCExecution.objects.get(pk=ex.pk))
        event_store.reproject(ex)
        after = ProjectionState.from_execution(RPCExecution.objects.get(pk=ex.pk))
        assert before == after

    def test_large_normalized_compose_content_replays_without_truncation(self):
        content = "services:\n  akvorado:\n    image: akvorado:latest\n" + (
            "x" * (event_store.MAX_EVENT_STRING_LENGTH + 1024)
        )
        ex = make_execution()
        aggregate = RPCExecutionAggregate(ex)
        aggregate.queue()
        aggregate.start()
        aggregate.normalize(
            {"compose_content": content, "command_fingerprint": {}},
            "hash123",
        )

        normalized = ex.events.get(event="ParametersNormalized")
        stored_content = normalized.data["normalized_params"]["compose_content"]
        assert stored_content == content
        assert len(stored_content) == len(content)
        assert not stored_content.endswith("...[truncated]")

        rebuilt = event_store.rebuild_projection(ex)
        assert rebuilt.normalized_params["compose_content"] == content
        self._assert_rebuild_matches(ex)

    def test_large_normalized_content_limit_still_truncates_oversized_values(self):
        limit = event_store._LARGE_NORMALIZED_CONTENT_LIMIT
        oversized = "x" * (limit + 1)

        redacted = event_store.redact_event_value(
            {"normalized_params": {"compose_content": oversized}},
            string_limits={
                ("normalized_params", "compose_content"): limit,
            },
        )

        stored_content = redacted["normalized_params"]["compose_content"]
        assert stored_content == f"{oversized[:limit]}...[truncated]"

    def test_large_normalized_compose_content_redacts_block_scalar_secrets(self):
        content = (
            "services:\n"
            "  akvorado:\n"
            "    environment:\n"
            "      password: |\n"
            "        hunter2\n"
            "        more-secret-line\n"
        )
        ex = make_execution()
        aggregate = RPCExecutionAggregate(ex)
        aggregate.queue()
        aggregate.start()
        aggregate.normalize(
            {"compose_content": content, "command_fingerprint": {}},
            "hash123",
        )

        normalized = ex.events.get(event="ParametersNormalized")
        rebuilt = event_store.rebuild_projection(ex)
        for secret in ("hunter2", "more-secret-line"):
            assert secret not in str(normalized.data)
            assert secret not in str(rebuilt.normalized_params)

    def test_large_normalized_compose_content_redacts_plain_secrets(self):
        content = "environment:\n  secret: hunter2\n"
        redacted = event_store.redact_event_data(
            {"normalized_params": {"compose_content": content}},
            string_limits={
                (
                    "normalized_params",
                    "compose_content",
                ): event_store._LARGE_NORMALIZED_CONTENT_LIMIT,
            },
        )

        assert "hunter2" not in redacted["normalized_params"]["compose_content"]

    def test_large_normalized_non_yaml_content_keeps_regex_only_behavior(self):
        content = "root preexec = /bin/sh -c 'echo hunter2'\n"
        redacted = event_store.redact_event_data(
            {"normalized_params": {"content": content}},
            string_limits={
                (
                    "normalized_params",
                    "content",
                ): event_store._LARGE_NORMALIZED_CONTENT_LIMIT,
            },
        )

        assert redacted["normalized_params"]["content"] == content

    def test_schema_bounded_large_config_read_result_replays_without_truncation(self):
        procedure_name = "service.akvorado.1.config_read"
        procedure = make_procedure(
            procedure_name,
            result_schema={
                "type": "object",
                "required": ["ok", "procedure", "target", "content"],
                "additionalProperties": False,
                "properties": {
                    "ok": {"type": "boolean"},
                    "procedure": {"type": "string"},
                    "target": {"type": "string"},
                    "content": {"type": "string", "maxLength": 1024 * 1024},
                },
            },
        )
        content = (
            "inlet:\n"
            "  interface: eth0\n"
            "  retention: 90\n"
            f"  notes: {'x' * 8192}\n"
        )
        ex = make_execution(procedure=procedure)
        aggregate = RPCExecutionAggregate(ex)
        aggregate.queue()
        aggregate.start()
        aggregate.record_backend_response(
            {
                "ok": True,
                "result": {
                    "ok": True,
                    "procedure": procedure_name,
                    "target": "akvorado-01",
                    "content": content,
                },
            }
        )

        ex.refresh_from_db()
        success = ex.events.get(event="ExecutionSucceeded")
        assert yaml.safe_load(ex.result["content"]) == yaml.safe_load(content)
        assert yaml.safe_load(success.data["result"]["content"]) == yaml.safe_load(
            content
        )
        assert "...[truncated]" not in ex.result["content"]
        assert "...[truncated]" not in success.data["result"]["content"]
        self._assert_rebuild_matches(ex)

    def test_schema_bounded_large_config_read_redacts_secret_content(self):
        procedure_name = "service.akvorado.1.config_read"
        procedure = make_procedure(
            procedure_name,
            result_schema={
                "type": "object",
                "required": ["ok", "procedure", "target", "content"],
                "additionalProperties": False,
                "properties": {
                    "ok": {"type": "boolean"},
                    "procedure": {"type": "string"},
                    "target": {"type": "string"},
                    "content": {"type": "string", "maxLength": 1024 * 1024},
                },
            },
        )
        prefix = (
            "inlet:\n"
            "  interface: eth0\n"
            "  retention: 90\n"
            f"  notes: {'x' * 8192}\n"
        )
        suffix = "outlet:\n  kafka:\n    topic: flows\n"
        content = f"{prefix}password: hunter2\n{suffix}"
        ex = make_execution(procedure=procedure)
        aggregate = RPCExecutionAggregate(ex)
        aggregate.queue()
        aggregate.start()
        aggregate.record_backend_response(
            {
                "ok": True,
                "result": {
                    "ok": True,
                    "procedure": procedure_name,
                    "target": "akvorado-01",
                    "content": content,
                },
            }
        )

        ex.refresh_from_db()
        success = ex.events.get(event="ExecutionSucceeded")
        expected = yaml.safe_load(content)
        expected["password"] = "[REDACTED]"
        assert yaml.safe_load(ex.result["content"]) == expected
        assert yaml.safe_load(success.data["result"]["content"]) == expected
        assert "hunter2" not in str(ex.result)
        assert "hunter2" not in str(success.data)
        self._assert_rebuild_matches(ex)


class AppendOnlyLedgerTests(TestCase):
    def test_event_save_on_existing_is_rejected(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        ev = ex.events.first()
        ev.message = "tampered"
        with self.assertRaises(ValidationError):
            ev.save()

    def test_event_delete_is_rejected(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        ev = ex.events.first()
        with self.assertRaises(ValidationError):
            ev.delete()

    def test_deleting_execution_with_events_is_rejected_by_the_ledger(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        # The cascade delete of the append-only events is blocked by the
        # database trigger, so the execution cannot be deleted.
        with self.assertRaises(DatabaseError):
            with transaction.atomic():
                ex.delete()
        assert RPCExecution.objects.filter(pk=ex.pk).exists()

    def test_db_trigger_blocks_queryset_update(self):
        ex = make_execution()
        event_store.record_execution_queued(ex)
        # Bypass the ORM save() guard with a bulk update; the DB trigger still
        # rejects it.
        with self.assertRaises(DatabaseError):
            with transaction.atomic():
                RPCExecutionEvent.objects.filter(execution=ex).update(message="x")
