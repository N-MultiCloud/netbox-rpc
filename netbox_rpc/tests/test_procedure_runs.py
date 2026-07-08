"""DB integration tests for the RPC Procedure "Runs" history tab.

Covers the `RPCExecution` presentation helpers used by the tab
(`intent_reference`, `source_label`, `result_steps`), the `source` column on
`RPCExecutionTable`, and the `runs` tab view which lists a procedure's
executions (owner, source, status, target, timing) and links each to its
detail where the issued commands and output are rendered.
"""

from __future__ import annotations

from django.test import Client, TestCase
from django.urls import reverse

from netbox_rpc import tables
from netbox_rpc.models import RPCExecution

from ._common import device_ct, make_execution, make_procedure, make_user


def _make_execution(procedure, *, params=None, result=None, user=None):
    return RPCExecution.objects.create(
        procedure=procedure,
        assigned_object_type=device_ct(),
        assigned_object_id=1,
        requested_by=user,
        params=params or {},
        result=result or {},
    )


class ExecutionPresentationHelperTests(TestCase):
    def test_direct_execution_has_no_intent_reference(self):
        proc = make_procedure("os.linux.test.direct")
        ex = _make_execution(proc)
        assert ex.intent_reference is None
        assert ex.source_label == "Direct"

    def test_intent_marker_in_params_is_surfaced(self):
        proc = make_procedure("os.linux.test.intent")
        ex = _make_execution(proc, params={"_intent_name": "deploy.dns.stack"})
        assert ex.intent_reference == "deploy.dns.stack"
        assert ex.source_label == "Intent: deploy.dns.stack"

    def test_intent_marker_alternate_key(self):
        proc = make_procedure("os.linux.test.intent2")
        ex = _make_execution(proc, params={"_intent": "grouped.run"})
        assert ex.intent_reference == "grouped.run"

    def test_plain_intent_param_is_not_treated_as_marker(self):
        # A procedure's own declared ``intent`` param must not be misread as an
        # intent-origin marker; only underscore-prefixed internal keys count.
        proc = make_procedure("os.linux.test.intent3")
        ex = _make_execution(proc, params={"intent": "user-supplied-value"})
        assert ex.intent_reference is None
        assert ex.source_label == "Direct"

    def test_result_steps_returns_ordered_steps(self):
        proc = make_procedure("os.linux.test.steps")
        steps = [
            {"command": "systemctl is-active nginx", "exit_code": 0, "ok": True,
             "stdout": "active", "stderr": ""},
            {"command": "systemctl status nginx", "exit_code": 0, "ok": True,
             "stdout": "running", "stderr": ""},
        ]
        ex = _make_execution(proc, result={"ok": True, "steps": steps})
        assert ex.result_steps == steps

    def test_result_steps_empty_when_absent_or_malformed(self):
        proc = make_procedure("os.linux.test.nosteps")
        assert _make_execution(proc).result_steps == []
        assert _make_execution(proc, result={"steps": "oops"}).result_steps == []


class ExecutionTableSourceColumnTests(TestCase):
    def test_source_column_renders_direct_and_intent(self):
        proc = make_procedure("os.linux.test.table")
        direct = _make_execution(proc)
        intent = _make_execution(proc, params={"_intent_name": "batch.job"})
        table = tables.RPCExecutionTable(RPCExecution.objects.all())
        rendered = {row.record.pk: row.get_cell("source") for row in table.rows}
        assert rendered[direct.pk] == "Direct"
        assert rendered[intent.pk] == "Intent: batch.job"


class ProcedureRunsTabViewTests(TestCase):
    def setUp(self):
        self.user = make_user("runs-tab-tester", superuser=True)
        self.client = Client()
        self.client.force_login(self.user)

    def test_runs_tab_lists_only_this_procedures_executions(self):
        proc = make_procedure("os.linux.test.runs.a")
        other = make_procedure("os.linux.test.runs.b")
        mine = make_execution(procedure=proc, user=self.user)
        theirs = make_execution(procedure=other, user=self.user)

        url = reverse("plugins:netbox_rpc:rpcprocedure_runs", args=[proc.pk])
        resp = self.client.get(url)
        assert resp.status_code == 200, resp.content

        table = resp.context["table"]
        pks = {row.record.pk for row in table.rows}
        assert mine.pk in pks
        assert theirs.pk not in pks
