"""Integration coverage for Ubuntu 24.04 to 26.04 execution gating."""

from __future__ import annotations

from typing import Any
from unittest import mock

from django.test import TestCase
from rest_framework.exceptions import PermissionDenied

from netbox_rpc import event_store, jobs
from netbox_rpc.application import command_handlers
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.backends import BackendTarget
from netbox_rpc.domain.aggregate import RPCExecutionAggregate
from netbox_rpc.models import RPCExecution, RPCIntent, RPCProcedure

from ._common import device_ct, enable_rpc_integration, make_device, make_execution, make_user

ANALYZE = "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade"
SAVE = "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state"
UPGRADE = "os.linux.ubuntu.24.upgrade_26.run_upgrade"
VERIFY = "os.linux.ubuntu.24.upgrade_26.verify_postupgrade"
INTENT_NAME = "Update Ubuntu OS from 24 LTS to 26 LTS"


class _FakeJob:
    pk = 2604


def _grant(user, *, model, actions, constraints=None):
    from core.models import ObjectType
    from users.models import ObjectPermission

    permission = ObjectPermission.objects.create(
        name=f"grant-{user.username}-{model.__name__}-{'-'.join(actions)}",
        actions=list(actions),
        constraints=constraints,
    )
    permission.object_types.set([ObjectType.objects.get_for_model(model)])
    permission.users.set([user])


def _execution_serializer(procedure: RPCProcedure, device) -> RPCExecutionSerializer:
    return RPCExecutionSerializer(
        data={
            "procedure_id": procedure.pk,
            "assigned_object_type": "dcim.device",
            "assigned_object_id": device.pk,
            "params": {},
        }
    )


class UbuntuUpgrade26ExecutionGateTests(TestCase):
    def setUp(self):
        enable_rpc_integration()
        self.device = make_device("ubuntu-upgrade-26-target")

    def _procedure(self, name: str) -> RPCProcedure:
        return RPCProcedure.objects.get(name=name)

    def _execution_user(self, username: str, *, approve: bool = False):
        user = make_user(username, superuser=False)
        actions = ("execute", "approve") if approve else ("execute",)
        _grant(user, model=RPCProcedure, actions=actions)
        return make_user(username, superuser=False)

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_run_upgrade_without_approval_permission_is_denied(
        self,
        enqueue,
        _fetch,
    ):
        procedure = self._procedure(UPGRADE)
        user = self._execution_user("ubuntu-upgrade-denied")

        with self.assertRaises(PermissionDenied):
            command_handlers.create_execution(
                serializer=_execution_serializer(procedure, self.device),
                user=user,
            )

        assert not RPCExecution.objects.filter(procedure=procedure).exists()
        enqueue.assert_not_called()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_run_upgrade_with_approval_permission_creates_execution(
        self,
        enqueue,
        _fetch,
    ):
        procedure = self._procedure(UPGRADE)
        user = self._execution_user("ubuntu-upgrade-approved", approve=True)

        execution = command_handlers.create_execution(
            serializer=_execution_serializer(procedure, self.device),
            user=user,
        )

        assert execution.procedure_id == procedure.pk
        assert RPCExecution.objects.filter(pk=execution.pk).exists()
        enqueue.assert_called_once()

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_non_approval_procedures_create_without_approval_permission(
        self,
        enqueue,
        _fetch,
    ):
        user = self._execution_user("ubuntu-upgrade-read-write")

        executions = [
            command_handlers.create_execution(
                serializer=_execution_serializer(self._procedure(name), self.device),
                user=user,
            )
            for name in (ANALYZE, SAVE, VERIFY)
        ]

        assert [execution.procedure.name for execution in executions] == [
            ANALYZE,
            SAVE,
            VERIFY,
        ]
        assert enqueue.call_count == 3

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_seeded_intent_fails_fast_at_upgrade_without_approval(
        self,
        enqueue,
        _fetch,
    ):
        user = self._execution_user("ubuntu-upgrade-intent-denied")
        _grant(user, model=RPCIntent, actions=("execute",))
        user = make_user("ubuntu-upgrade-intent-denied", superuser=False)
        intent = RPCIntent.objects.get(name=INTENT_NAME)

        with self.assertRaises(PermissionDenied):
            command_handlers.execute_intent(
                intent,
                user,
                assigned_object_type=device_ct(),
                assigned_object_id=self.device.pk,
            )

        assert RPCExecution.objects.filter(procedure__name=ANALYZE).count() == 1
        assert RPCExecution.objects.filter(procedure__name=SAVE).count() == 1
        assert not RPCExecution.objects.filter(procedure__name=UPGRADE).exists()
        assert not RPCExecution.objects.filter(procedure__name=VERIFY).exists()
        assert enqueue.call_count == 2


class UbuntuUpgrade26IntentSeedTests(TestCase):
    """DB proof that migration 0065 seeds the Ubuntu upgrade RPCIntent with the
    documented membership, ordering, and execution mode.

    Executing the intent is covered separately by
    test_seeded_intent_fails_fast_at_upgrade_without_approval above; this only
    proves the migration's declarative reference data landed correctly.
    """

    def test_intent_is_sequential_with_the_four_procedures_in_order(self):
        intent = RPCIntent.objects.get(name=INTENT_NAME)
        assert intent.execution_mode == RPCIntent.MODE_SEQUENTIAL
        assert intent.enabled is True

        ordered_names = [
            ip.procedure.name for ip in intent.ordered_intent_procedures
        ]
        assert ordered_names == [ANALYZE, SAVE, UPGRADE, VERIFY]

        ordered_sequences = [
            ip.sequence for ip in intent.ordered_intent_procedures
        ]
        assert ordered_sequences == [1, 2, 3, 4]


class UbuntuUpgrade26JobTimeoutTests(TestCase):
    """#215: RPCExecutionJob.enqueue() must derive job_timeout from the
    dispatched procedure's own timeout_seconds instead of the flat 600s
    RPC_JOB_TIMEOUT constant -- run_upgrade's 7200s timeout_seconds is the
    motivating case: at the old flat 600s ceiling, a real (non-dry-run)
    upgrade running past 10 minutes would have its RQ worker killed mid
    do-release-upgrade, stranding the execution in RUNNING forever.
    """

    def setUp(self):
        enable_rpc_integration()
        self.device = make_device("ubuntu-upgrade-26-timeout-target")

    def _procedure(self, name: str) -> RPCProcedure:
        return RPCProcedure.objects.get(name=name)

    def _execution_user(self, username: str, *, approve: bool = False):
        user = make_user(username, superuser=False)
        actions = ("execute", "approve") if approve else ("execute",)
        _grant(user, model=RPCProcedure, actions=actions)
        return make_user(username, superuser=False)

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_run_upgrade_job_timeout_covers_its_7200s_procedure_timeout(
        self,
        enqueue,
        _fetch,
    ):
        procedure = self._procedure(UPGRADE)
        assert procedure.timeout_seconds == 7200
        user = self._execution_user("ubuntu-upgrade-timeout-run", approve=True)

        command_handlers.create_execution(
            serializer=_execution_serializer(procedure, self.device),
            user=user,
        )

        enqueue.assert_called_once()
        job_timeout = enqueue.call_args.kwargs["job_timeout"]
        assert job_timeout == command_handlers._execution_job_timeout(
            procedure.timeout_seconds
        )
        # The RQ job_timeout must exceed the _call_backend() HTTP read
        # timeout (max(timeout_seconds + 10, 30), jobs.py:_call_backend) --
        # otherwise the worker is killed before its own blocking HTTP call
        # to nms-backend could ever return cleanly.
        assert job_timeout > procedure.timeout_seconds + 10
        # And it must exceed the historical flat 600s ceiling this bug fixes.
        assert job_timeout > 600

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_short_procedure_keeps_the_historical_600s_floor(
        self,
        enqueue,
        _fetch,
    ):
        procedure = self._procedure(ANALYZE)
        assert procedure.timeout_seconds == 120
        user = self._execution_user("ubuntu-upgrade-timeout-analyze")

        command_handlers.create_execution(
            serializer=_execution_serializer(procedure, self.device),
            user=user,
        )

        enqueue.assert_called_once()
        job_timeout = enqueue.call_args.kwargs["job_timeout"]
        # 120 + headroom is well under the historical 600s constant, so the
        # floor keeps behavior unchanged for procedures that were already
        # comfortably inside it.
        assert job_timeout == 600

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_timeout_snapshot_keeps_rq_and_http_timeouts_consistent_after_edit(
        self,
        enqueue,
        _fetch,
    ):
        """#215 round 2 (adversarial-review medium finding): the RQ
        job_timeout committed at enqueue and the jobs._call_backend() HTTP
        read timeout used later at dispatch must always be derived from the
        SAME frozen value, even when an operator edits
        procedure.timeout_seconds while the execution still sits queued.
        Before this fix, _call_backend() re-read the procedure's *current*
        timeout_seconds, so an edit made after enqueue (but before the
        worker dispatches) could desync the two -- e.g. RQ still allows the
        original 7200s-derived deadline while the HTTP call now uses a much
        shorter, edited timeout and aborts a live upgrade early.
        """
        procedure = self._procedure(UPGRADE)
        assert procedure.timeout_seconds == 7200
        user = self._execution_user("ubuntu-upgrade-timeout-snapshot", approve=True)

        execution = command_handlers.create_execution(
            serializer=_execution_serializer(procedure, self.device),
            user=user,
        )

        enqueue.assert_called_once()
        job_timeout = enqueue.call_args.kwargs["job_timeout"]
        assert job_timeout == command_handlers._execution_job_timeout(7200)
        assert execution.params[
            RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY
        ] == 7200

        # An operator raises the procedure's timeout_seconds while this
        # execution still sits queued -- RQ already committed job_timeout
        # above, derived from the original 7200s value.
        procedure.timeout_seconds = 60
        procedure.save(update_fields=["timeout_seconds"])
        execution.refresh_from_db()

        target = BackendTarget(
            url="http://backend.example", headers={}, verify_ssl=True
        )
        with mock.patch.object(jobs.requests, "post") as post:
            post.return_value = mock.Mock(
                status_code=200,
                json=lambda: {"ok": True, "result": {}},
            )
            jobs._call_backend(target, execution)

        actual_timeout = post.call_args.kwargs["timeout"]
        # Derived from the frozen 7200s snapshot stamped at creation, not
        # the edited 60s value read live off the procedure.
        assert actual_timeout == (10, max(7200 + 10, 30))
        assert actual_timeout != (10, max(60 + 10, 30))

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_timeout_snapshot_is_visible_in_validated_data_before_serializer_save(
        self,
        enqueue,
        _fetch,
    ):
        """#215 round 3 (adversarial-review finding 2): the timeout snapshot
        must be stamped into ``serializer.validated_data["params"]`` BEFORE
        ``serializer.save()`` is invoked -- not written onto the model
        instance afterward. This is the specific behaviour the round-2
        broken implementation lacked: it stamped ``execution.params``
        directly on the *already-saved* instance via a second, separate
        ``execution.save(update_fields=["params"])`` call, so
        ``serializer.validated_data`` at ``save()``-call time never carried
        the snapshot. Spying on ``RPCExecutionSerializer.save`` and
        inspecting ``self.validated_data`` at the moment it is called
        (before delegating to the real implementation) fails against that
        broken shape and passes only when the stamp is folded into the same
        dict ``save()`` persists -- unlike asserting the final
        ``execution.params`` value, which both implementations produce
        identically.

        This also exercises the falsy-params-aliasing fix: the serializer is
        given ``params: {}`` (falsy), which is exactly the case
        ``serializer.validated_data.get("params") or {}`` used to silently
        detach from ``validated_data``.
        """
        procedure = self._procedure(UPGRADE)
        assert procedure.timeout_seconds == 7200
        user = self._execution_user(
            "ubuntu-upgrade-timeout-snapshot-presave", approve=True
        )

        captured_params_at_save: dict[str, Any] = {}
        original_save = RPCExecutionSerializer.save

        def _spy_save(self, **kwargs):
            captured_params_at_save.update(
                dict(self.validated_data.get("params") or {})
            )
            return original_save(self, **kwargs)

        with mock.patch.object(RPCExecutionSerializer, "save", _spy_save):
            command_handlers.create_execution(
                serializer=_execution_serializer(procedure, self.device),
                user=user,
            )

        enqueue.assert_called_once()
        assert (
            captured_params_at_save.get(
                RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY
            )
            == 7200
        )

    @mock.patch(
        "netbox_rpc.capabilities.fetch_backend_capabilities", return_value=None
    )
    @mock.patch("netbox_rpc.jobs.RPCExecutionJob.enqueue", return_value=_FakeJob())
    def test_no_standalone_params_only_save_follows_execution_creation(
        self,
        enqueue,
        _fetch,
    ):
        """#215 round 3 (adversarial-review finding 2): the round-2 broken
        implementation stamped the timeout snapshot with a SECOND, unguarded
        ``execution.save(update_fields=["params"])`` call sitting outside
        both the creation ``transaction.atomic()`` block and the RQ-enqueue
        ``try``/``except`` -- a failure in that second write could orphan an
        already-committed ``queued`` execution with no job and no failure
        event. Every legitimate ``RPCExecution.save()`` call during
        ``create_execution()`` either has no ``update_fields`` (the initial
        creation save) or an ``update_fields`` list derived from projection
        state (status/result/error fields via
        ``event_store._write_projection``) -- never a save isolated to just
        ``["params"]``. Spying on every ``RPCExecution.save()`` call and
        asserting none of them target only ``params`` fails against the
        round-2 shape and passes only when the snapshot commits atomically
        with the rest of the execution row.
        """
        procedure = self._procedure(UPGRADE)
        user = self._execution_user(
            "ubuntu-upgrade-timeout-snapshot-no-followup", approve=True
        )

        recorded_update_fields: list[object] = []
        original_save = RPCExecution.save

        def _spy_save(self, *args, **kwargs):
            recorded_update_fields.append(kwargs.get("update_fields"))
            return original_save(self, *args, **kwargs)

        with mock.patch.object(RPCExecution, "save", _spy_save):
            execution = command_handlers.create_execution(
                serializer=_execution_serializer(procedure, self.device),
                user=user,
            )

        enqueue.assert_called_once()
        assert ["params"] not in recorded_update_fields
        assert execution.params[
            RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY
        ] == procedure.timeout_seconds


class UbuntuUpgrade26ResultSchemaLimitsTests(TestCase):
    """#215: migration 0066 must add an explicit maxLength to
    run_upgrade's upgrade_log_tail -- the one result string that was actually
    hitting the 4096-char event_store default and being silently clamped --
    without editing migration 0063's seed data in place. The procedure's
    other free-form result strings (new_version_id, backup_dir,
    manifest_sha256, disk_free_root, kernel) were never near that default, so
    they are deliberately left untouched: widening their bounds would only
    grow the fail-closed surface of schema validation with no bug fixed.
    """

    def _procedure(self, name: str) -> RPCProcedure:
        return RPCProcedure.objects.get(name=name)

    def test_run_upgrade_log_tail_has_an_explicit_maxlength_above_the_event_default(
        self,
    ):
        procedure = self._procedure(UPGRADE)
        max_length = procedure.result_schema["properties"]["upgrade_log_tail"][
            "maxLength"
        ]
        assert max_length > event_store.MAX_EVENT_STRING_LENGTH

    def test_run_upgrade_long_log_tail_replays_without_silent_truncation(self):
        procedure = self._procedure(UPGRADE)
        max_length = procedure.result_schema["properties"]["upgrade_log_tail"][
            "maxLength"
        ]
        # Comfortably larger than the old 4096-char default clamp, but still
        # within the schema's declared maxLength.
        log_tail = "Reading package lists...\n" + ("x" * (max_length - 1024))
        ex = make_execution(procedure=procedure)
        aggregate = RPCExecutionAggregate(ex)
        aggregate.queue()
        aggregate.start()
        aggregate.record_backend_response(
            {
                "ok": True,
                "result": {
                    "ok": True,
                    "procedure": UPGRADE,
                    "target": "ubuntu-upgrade-target",
                    "dry_run": False,
                    "upgrade_log_tail": log_tail,
                },
            }
        )

        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_SUCCEEDED
        assert ex.result["upgrade_log_tail"] == log_tail
        assert not ex.result["upgrade_log_tail"].endswith("...[truncated]")

    def test_run_upgrade_oversized_log_tail_is_clamped_not_failed(self):
        """#215 round 3 (adversarial-review high finding): a backend that
        returns more upgrade_log_tail content than the schema's maxLength no
        longer fails schema validation. Before round 2's fix, a
        still-unpatched or version-skewed nms-backend (issue #623) returning
        even a few bytes over the bound would convert an otherwise
        successful -- possibly destructive, already-completed -- upgrade
        into a reported RPC_RESULT_SCHEMA_MISMATCH failure, which could
        prompt an operator to re-run a real do-release-upgrade
        unnecessarily. Round 2's fix validated a length-clamped copy of the
        result instead of the raw value, which round 3 replaced: the
        complete, untouched result is now validated against a schema copy
        with maxLength removed only at this wide-override path
        (event_store._backend_result_schema_mismatch /
        _relax_schema_string_lengths) -- round 2's approach could silently
        hide a genuine pattern/enum/type violation that only appeared past
        the clamp point (see the companion test below) and could persist a
        truncated value longer than the schema's own maxLength. The
        persisted result is still truncated with the standard
        "...[truncated]" marker, but event_store._result_schema_string_limits
        now reserves room for that marker so the truncated value (content +
        marker) never exceeds the schema's declared maxLength -- the
        execution still succeeds.
        """
        procedure = self._procedure(UPGRADE)
        max_length = procedure.result_schema["properties"]["upgrade_log_tail"][
            "maxLength"
        ]
        oversized_tail = "x" * (max_length + 1024)
        ex = make_execution(procedure=procedure)
        aggregate = RPCExecutionAggregate(ex)
        aggregate.queue()
        aggregate.start()
        aggregate.record_backend_response(
            {
                "ok": True,
                "result": {
                    "ok": True,
                    "procedure": UPGRADE,
                    "target": "ubuntu-upgrade-target",
                    "dry_run": False,
                    "upgrade_log_tail": oversized_tail,
                },
            }
        )

        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_SUCCEEDED
        assert ex.error_code != event_store.RESULT_SCHEMA_MISMATCH_CODE
        truncated_length = max_length - len("...[truncated]")
        assert ex.result["upgrade_log_tail"] == (
            f"{oversized_tail[:truncated_length]}...[truncated]"
        )
        assert len(ex.result["upgrade_log_tail"]) <= max_length

    def test_run_upgrade_oversized_log_tail_does_not_mask_other_violations(self):
        """#215 round 3: an oversized wide field must not hide a genuine
        schema violation elsewhere in the same result. Round 2's
        clamp-before-validate approach validated a *copy* of the result, so
        this scenario would have passed validation identically regardless of
        this test -- the point is that round 3's relax-then-validate-raw
        approach still fails closed on a violation unrelated to the wide
        field's own length, proving the schema relaxation is scoped only to
        the specific wide-override path and does not weaken any other
        validator.
        """
        procedure = self._procedure(UPGRADE)
        max_length = procedure.result_schema["properties"]["upgrade_log_tail"][
            "maxLength"
        ]
        oversized_tail = "x" * (max_length + 1024)
        ex = make_execution(procedure=procedure)
        aggregate = RPCExecutionAggregate(ex)
        aggregate.queue()
        aggregate.start()
        aggregate.record_backend_response(
            {
                "ok": True,
                "result": {
                    "ok": True,
                    "procedure": UPGRADE,
                    "target": "ubuntu-upgrade-target",
                    # dry_run must be a boolean per result_schema; a string
                    # here is a genuine, unrelated schema violation that must
                    # still be caught even though upgrade_log_tail (in the
                    # same result) is oversized and schema-relaxed.
                    "dry_run": "not-a-boolean",
                    "upgrade_log_tail": oversized_tail,
                },
            }
        )

        ex.refresh_from_db()
        assert ex.status == RPCExecution.STATUS_FAILED
        assert ex.error_code == event_store.RESULT_SCHEMA_MISMATCH_CODE
