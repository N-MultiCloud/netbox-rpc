"""Keyed placeholders for secret-bearing mapping names, and backend progress metadata.

The placeholders are fixed literals under TEST_SECRET_KEY. Each one is HMAC-SHA256
over the complete mapping name, keyed with SHA-256(salt + secret), which is how
Django's salted_hmac computes it, with the purpose salt of the event ledger.
"""

from __future__ import annotations

import copy
import time

import jsonschema
from django.test import TestCase, override_settings

from netbox_rpc import event_store
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.domain.projection import ProjectionState
from netbox_rpc.models import RPCExecution, RPCExecutionEvent

from ._common import device_ct, make_procedure, make_user

TEST_SECRET_KEY = "netbox-rpc-418-test-secret-key-0123456789"

RESULT_NAME = "password=fake-result-key-secret"
RESULT_PLACEHOLDER = (
    "[REDACTED-NAME:8b25e2d72fe14410cdd2e65236d21f3cca2f15aced67bf1c71507e76227b1adf]"
)
RESULT_PLACEHOLDER_SECOND = RESULT_PLACEHOLDER + "#2"
ALPHA_NAME = "password=fake-collide-alpha"
ALPHA_PLACEHOLDER = (
    "[REDACTED-NAME:748c61a98ce45c42a3a601d24484104fe03c8e4ba13a047c0c4032206c039dea]"
)
BETA_NAME = "password=fake-collide-beta"
BETA_PLACEHOLDER = (
    "[REDACTED-NAME:c3a62b6b76da1392f74b4489933ae9fef69f8648238c70cb95765e6b7eeb238d]"
)
NESTED_NAME = "token=fake-nested-name"
NESTED_PLACEHOLDER = (
    "[REDACTED-NAME:3400124d1850d6e386b1bdc4d933acacee8cdbbec3d2d36989ede269a7cb533a]"
)
SUCCESS_DATA = {"result": {RESULT_PLACEHOLDER: "[REDACTED]"}, "status": "succeeded"}


def _started_execution(procedure=None) -> RPCExecution:
    procedure = procedure or make_procedure("os.linux.test.echo")
    execution = RPCExecution.objects.create(
        procedure=procedure,
        assigned_object_type=device_ct(),
        assigned_object_id=1,
        requested_by=make_user(),
        params={},
    )
    aggregate = RPCExecutionAggregate(execution)
    aggregate.queue()
    aggregate.start()
    return execution


def _backend_events(execution: RPCExecution):
    return list(
        execution.events.filter(event__startswith="Backend::").order_by("sequence")
    )


@override_settings(SECRET_KEY=TEST_SECRET_KEY)
class MappingNameRedactionTests(TestCase):
    def test_result_mapping_name_is_replaced_by_its_keyed_placeholder(self):
        redacted = event_store.redact_event_data({"result": {RESULT_NAME: "routine"}})
        self.assertEqual(redacted, {"result": {RESULT_PLACEHOLDER: "[REDACTED]"}})

    def test_original_name_drives_sensitivity_and_is_absent_from_the_output(self):
        redacted = event_store.redact_event_data({"settings": {NESTED_NAME: "routine"}})
        self.assertEqual(redacted, {"settings": {NESTED_PLACEHOLDER: "[REDACTED]"}})
        self.assertNotIn("fake-nested-name", repr(redacted))

    def test_two_matching_names_in_one_mapping_keep_both_values(self):
        redacted = event_store.redact_event_data(
            {"result": {ALPHA_NAME: "routine alpha", BETA_NAME: "routine beta"}}
        )
        self.assertEqual(
            redacted,
            {
                "result": {
                    ALPHA_PLACEHOLDER: "[REDACTED]",
                    BETA_PLACEHOLDER: "[REDACTED]",
                }
            },
        )

    def test_placeholder_does_not_overwrite_an_existing_non_secret_key(self):
        redacted = event_store.redact_event_data(
            {"result": {RESULT_NAME: "routine", RESULT_PLACEHOLDER: "keep-me"}}
        )
        self.assertEqual(
            redacted,
            {
                "result": {
                    RESULT_PLACEHOLDER: "keep-me",
                    RESULT_PLACEHOLDER_SECOND: "[REDACTED]",
                }
            },
        )

    def test_redaction_is_idempotent(self):
        data = {
            "result": {
                RESULT_NAME: "routine",
                RESULT_PLACEHOLDER: "keep-me",
                ALPHA_NAME: "routine alpha",
            },
            "status": "succeeded",
        }
        once = event_store.redact_event_data(data)
        self.assertEqual(event_store.redact_event_data(copy.deepcopy(once)), once)

    def test_ledger_normalized_params_is_idempotent_for_secret_bearing_names(self):
        params = {"command_fingerprint": {"probe": {RESULT_NAME: "routine"}}}
        once = event_store.ledger_normalized_params(params)
        self.assertEqual(
            event_store.ledger_normalized_params(copy.deepcopy(once)), once
        )
        self.assertEqual(
            once,
            {"command_fingerprint": {"probe": {RESULT_PLACEHOLDER: "[REDACTED]"}}},
        )

    def test_one_megabyte_name_and_value_redact_in_linear_time(self):
        name = "password=" + "a" * (1024 * 1024)
        started = time.perf_counter()
        redacted = event_store.redact_event_data(
            {"result": {name: "x" * (1024 * 1024)}}
        )
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 10.0)
        keys = list(redacted["result"])
        self.assertEqual(len(keys), 1)
        self.assertTrue(keys[0].startswith("[REDACTED-NAME:"))
        self.assertEqual(redacted["result"][keys[0]], "[REDACTED]")

    def test_one_megabyte_backend_event_name_is_redacted_before_the_bound(self):
        name = "password=" + "a" * (1024 * 1024)
        event = event_store._backend_progress_event(
            {"event": name, "message": "routine"}
        )
        self.assertEqual(event.event_name, "Backend::[REDACTED]")
        self.assertLessEqual(len(event.event_name), 100)


@override_settings(SECRET_KEY=TEST_SECRET_KEY)
class BackendProgressMetadataTests(TestCase):
    def test_backend_event_name_is_redacted_on_the_event_row(self):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {
                "ok": True,
                "result": {},
                "events": [
                    {"event": "password=fake-progress-name", "message": "routine"}
                ],
            }
        )
        rows = _backend_events(execution)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].event, "Backend::[REDACTED]")
        self.assertEqual(rows[0].message, "routine")
        self.assertEqual(rows[0].level, "info")
        self.assertNotIn(
            "fake-progress-name",
            repr(list(execution.events.values_list("event", flat=True))),
        )

    def test_backend_level_is_recorded_as_info_when_unsupported(self):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {
                "ok": True,
                "result": {},
                "events": [{"event": "Progress", "level": "password=fake-level-value"}],
            }
        )
        rows = _backend_events(execution)
        self.assertEqual(
            [(row.event, row.level) for row in rows], [("Backend::Progress", "info")]
        )
        self.assertNotIn(
            "fake-level-value",
            repr(list(execution.events.values_list("level", flat=True))),
        )

    def test_supported_level_set_matches_the_model_choices(self):
        self.assertEqual(
            event_store._EVENT_LEVELS,
            frozenset(level for level, _label in RPCExecutionEvent.LEVEL_CHOICES),
        )

    def test_supported_levels_are_stored_exactly(self):
        for level in ("debug", "info", "warning", "error"):
            with self.subTest(level=level):
                self.assertEqual(event_store._event_level(level), level)
        for value in ("critical", "", None, 5, ["warning"], " warning "):
            with self.subTest(value=value):
                self.assertEqual(event_store._event_level(value), "info")

    def test_backend_progress_event_keeps_a_supported_level_and_a_plain_name(self):
        event = event_store._backend_progress_event(
            {"event": "Progress", "level": "warning", "message": "step"}
        )
        self.assertEqual(
            (event.event_name, event.level), ("Backend::Progress", "warning")
        )


@override_settings(SECRET_KEY=TEST_SECRET_KEY)
class LedgerRowAndProjectionTests(TestCase):
    def test_event_row_and_rebuilt_projection_hold_the_placeholder(self):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {"ok": True, "result": {RESULT_NAME: "routine"}, "events": []}
        )
        row = execution.events.get(event="ExecutionSucceeded")
        self.assertIn("finished_at", row.data)
        self.assertEqual(
            {key: value for key, value in row.data.items() if key != "finished_at"},
            SUCCESS_DATA,
        )
        self.assertEqual(
            row.payload_hash,
            event_store._stable_hash(
                {
                    "level": row.level,
                    "event": row.event,
                    "message": row.message,
                    "data": row.data,
                }
            ),
        )
        state = event_store.rebuild_projection(execution)
        self.assertEqual(state.status, "succeeded")
        self.assertEqual(state.result, {RESULT_PLACEHOLDER: "[REDACTED]"})
        self.assertNotIn("fake-result-key-secret", repr(state))

    def test_projection_rebuild_matches_the_stored_projection_after_a_redacted_result(
        self,
    ):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {"ok": True, "result": {RESULT_NAME: "routine"}, "events": []}
        )
        execution.refresh_from_db()
        self.assertEqual(
            event_store.rebuild_projection(execution),
            ProjectionState.from_execution(execution),
        )


WIDE_NAME = "https://u:abc@host"
WIDE_SCHEMA = {
    "type": "object",
    "properties": {WIDE_NAME: {"type": "string", "maxLength": 10000}},
    "additionalProperties": {"type": "string", "minLength": 5000},
}


def _terminal_row(execution: RPCExecution):
    return execution.events.filter(
        event__in=["ExecutionSucceeded", "ExecutionFailed"]
    ).get()


@override_settings(SECRET_KEY=TEST_SECRET_KEY)
class WideLimitValidationTests(TestCase):
    """The stored result is the validated result, and a wide limit follows its name."""

    def _record(self, name, schema, result):
        procedure = make_procedure(name, result_schema=schema)
        execution = _started_execution(procedure)
        RPCExecutionAggregate(execution).record_backend_response(
            {"ok": True, "result": result, "events": []}
        )
        return execution, _terminal_row(execution)

    def test_wide_limit_on_a_secret_bearing_name_stores_a_valid_result(self):
        execution, row = self._record(
            "os.linux.test.redaction.wide-result", WIDE_SCHEMA, {WIDE_NAME: "x" * 5000}
        )
        self.assertEqual(row.event, "ExecutionSucceeded")
        result = row.data["result"]
        (key,) = result
        self.assertTrue(key.startswith("[REDACTED-NAME:"))
        self.assertEqual(len(result[key]), 5000)
        jsonschema.validate(instance=result, schema=WIDE_SCHEMA)
        self.assertEqual(event_store.rebuild_projection(execution).result, result)

    def test_plain_key_holding_the_placeholder_fails_closed(self):
        # The renamed secret key is suffixed because a plain key already holds the
        # placeholder, so the plain key's value takes the default bound and no longer
        # fits the schema. The row must fail closed, never record a bad success.
        placeholder = event_store._keyed_mapping_name(WIDE_NAME)
        execution, row = self._record(
            "os.linux.test.redaction.collide-result",
            WIDE_SCHEMA,
            {WIDE_NAME: "x" * 5000, placeholder: "y" * 5000},
        )
        self.assertEqual(row.event, "ExecutionFailed")
        execution.refresh_from_db()
        self.assertEqual(execution.error_code, "RPC_RESULT_SCHEMA_MISMATCH")

    def test_schema_declared_placeholder_name_keeps_its_own_bounds(self):
        placeholder = event_store._keyed_mapping_name(WIDE_NAME)
        schema = {
            "type": "object",
            "properties": {
                WIDE_NAME: {"type": "string", "maxLength": 10000},
                placeholder: {
                    "type": "string",
                    "minLength": 5000,
                    "maxLength": 5000,
                    "pattern": "^x+$",
                },
            },
            "additionalProperties": False,
        }
        _execution, row = self._record(
            "os.linux.test.redaction.declared-result", schema, {WIDE_NAME: "x" * 5000}
        )
        self.assertEqual(row.event, "ExecutionSucceeded")
        result = row.data["result"]
        jsonschema.validate(instance=result, schema=schema)
        self.assertEqual(len(result[placeholder]), 5000)

    def test_collision_resolved_parent_with_a_nested_list_stores_a_valid_result(self):
        placeholder = event_store._keyed_mapping_name(WIDE_NAME)
        schema = {
            "type": "object",
            "properties": {
                WIDE_NAME: {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 10000},
                        },
                    },
                },
            },
        }
        _execution, row = self._record(
            "os.linux.test.redaction.nested-result",
            schema,
            {WIDE_NAME: {"items": ["x" * 5000]}, placeholder: "routine"},
        )
        self.assertEqual(row.event, "ExecutionSucceeded")
        result = row.data["result"]
        jsonschema.validate(instance=result, schema=schema)
        self.assertEqual(len(result[placeholder + "#2"]["items"][0]), 5000)


PEM_TAIL_TEXT = (
    "-----BEGIN PRIVATE KEY-----\nkey-body\n-----END PRIVATE KEY-----token=fake-tail-secret"
)


@override_settings(SECRET_KEY=TEST_SECRET_KEY)
class FixedPointRedactionTests(TestCase):
    """A secret assignment exposed by a PEM replacement is redacted on every path."""

    EXPECTED = "[REDACTED][REDACTED]"

    def _assert_no_tail_secret(self, value):
        self.assertEqual(value, self.EXPECTED)
        self.assertNotIn("fake-tail-secret", repr(value))

    def test_success_path_stores_the_fixed_point(self):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {"ok": True, "result": {"note": PEM_TAIL_TEXT}, "events": []}
        )
        row = execution.events.get(event="ExecutionSucceeded")
        self._assert_no_tail_secret(row.data["result"]["note"])

    def test_direct_success_path_stores_the_fixed_point(self):
        execution = _started_execution()
        event_store.record_execution_succeeded(execution, {"note": PEM_TAIL_TEXT})
        row = execution.events.get(event="ExecutionSucceeded")
        self._assert_no_tail_secret(row.data["result"]["note"])

    def test_failure_path_with_a_kept_result_stores_the_fixed_point(self):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {
                "ok": False,
                "result": {"note": PEM_TAIL_TEXT},
                "error_code": "RPC_FIXED_POINT",
                "error_message": "Failed.",
            }
        )
        row = execution.events.get(event="ExecutionFailed")
        self._assert_no_tail_secret(row.data["result"]["note"])

    def test_repeated_normalized_parameter_redaction_is_a_no_op(self):
        once = event_store.ledger_normalized_params(
            {"command_fingerprint": {"note": PEM_TAIL_TEXT}}
        )
        self._assert_no_tail_secret(once["command_fingerprint"]["note"])
        self.assertEqual(event_store.ledger_normalized_params(copy.deepcopy(once)), once)


LONG_TAIL_TEXT = (
    "-----BEGIN PRIVATE KEY-----\nkey-body\n-----END PRIVATE KEY-----token="
    + "a" * 5000
    + " password: |\n  fake-tail-secret\n"
)


@override_settings(SECRET_KEY=TEST_SECRET_KEY)
class LongTailRedactionTests(TestCase):
    """The length bound applies between redaction passes, on every persistence path."""

    EXPECTED = "[REDACTED][REDACTED]"

    def _assert_stored(self, value):
        self.assertEqual(value, self.EXPECTED)
        self.assertNotIn("fake-tail-secret", repr(value))

    def test_success_path_stores_the_bounded_fixed_point(self):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {"ok": True, "result": {"note": LONG_TAIL_TEXT}, "events": []}
        )
        row = execution.events.get(event="ExecutionSucceeded")
        self._assert_stored(row.data["result"]["note"])

    def test_direct_success_path_stores_the_bounded_fixed_point(self):
        execution = _started_execution()
        event_store.record_execution_succeeded(execution, {"note": LONG_TAIL_TEXT})
        row = execution.events.get(event="ExecutionSucceeded")
        self._assert_stored(row.data["result"]["note"])

    def test_failure_path_with_a_kept_result_stores_the_bounded_fixed_point(self):
        execution = _started_execution()
        RPCExecutionAggregate(execution).record_backend_response(
            {
                "ok": False,
                "result": {"note": LONG_TAIL_TEXT},
                "error_code": "RPC_LONG_TAIL",
                "error_message": "Failed.",
            }
        )
        row = execution.events.get(event="ExecutionFailed")
        self._assert_stored(row.data["result"]["note"])

    def test_normalized_parameters_store_the_bounded_fixed_point(self):
        once = event_store.ledger_normalized_params(
            {"command_fingerprint": {"note": LONG_TAIL_TEXT}}
        )
        self._assert_stored(once["command_fingerprint"]["note"])
        self.assertEqual(event_store.ledger_normalized_params(copy.deepcopy(once)), once)


@override_settings(SECRET_KEY=TEST_SECRET_KEY)
class RowsWrittenBeforeTheChangeTests(TestCase):
    """A row written by the base code keeps its stored form and still verifies."""

    def test_base_written_row_rebuilds_as_stored_and_keeps_its_payload_hash(self):
        execution = _started_execution()
        base_data = {"result": {RESULT_NAME: "[REDACTED]"}, "status": "succeeded"}
        base_message = "RPC execution completed."
        base_hash = event_store._stable_hash(
            {
                "level": "info",
                "event": "ExecutionSucceeded",
                "message": base_message,
                "data": base_data,
            }
        )
        RPCExecutionEvent.objects.create(
            execution=execution,
            sequence=execution.events.count() + 1,
            level="info",
            event="ExecutionSucceeded",
            message=base_message,
            data=base_data,
            payload_hash=base_hash,
        )
        row = execution.events.get(event="ExecutionSucceeded")
        self.assertEqual(row.data, base_data)
        self.assertEqual(row.payload_hash, base_hash)
        state = event_store.rebuild_projection(execution)
        self.assertEqual(state.result, {RESULT_NAME: "[REDACTED]"})
        event_store.reproject(execution)
        execution.refresh_from_db()
        self.assertEqual(
            event_store.rebuild_projection(execution),
            ProjectionState.from_execution(execution),
        )
        row.refresh_from_db()
        self.assertEqual(row.data, base_data)
