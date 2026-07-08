"""DB integration tests for the RPC Procedure "Runs" history tab.

Covers the `RPCExecution` presentation helpers used by the tab
(`intent_reference`, `source_label`, `result_steps`), the `source` column on
`RPCExecutionTable`, the `runs` tab view (scoping, rendered owner/source, badge
count), and the execution-detail page which renders the issued commands and
their output (the "Command Output" card) plus the run's Source.
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

    def test_runs_tab_renders_owner_and_source(self):
        proc = make_procedure("os.linux.test.runs.render")
        _make_execution(proc, user=self.user)
        _make_execution(proc, user=self.user, params={"_intent_name": "batch.job"})

        url = reverse("plugins:netbox_rpc:rpcprocedure_runs", args=[proc.pk])
        html = self.client.get(url).content.decode()
        # Owner column value and both Source variants appear in the rendered tab.
        assert self.user.username in html
        assert "Direct" in html
        assert "Intent: batch.job" in html

    def test_runs_tab_is_registered_with_a_badge_count(self):
        from netbox_rpc.views import RPCProcedureRunsView

        proc = make_procedure("os.linux.test.runs.badge")
        assert RPCProcedureRunsView.tab.badge(proc) == 0
        make_execution(procedure=proc, user=self.user)
        make_execution(procedure=proc, user=self.user)
        assert RPCProcedureRunsView.tab.badge(proc) == 2


class ExecutionDetailCommandOutputTests(TestCase):
    """The execution detail page renders the issued commands and their output."""

    def setUp(self):
        self.user = make_user("runs-detail-tester", superuser=True)
        self.client = Client()
        self.client.force_login(self.user)

    def _detail_html(self, execution) -> str:
        url = reverse("plugins:netbox_rpc:rpcexecution", args=[execution.pk])
        resp = self.client.get(url)
        assert resp.status_code == 200, resp.content
        return resp.content.decode()

    def test_detail_renders_command_output_card(self):
        proc = make_procedure("os.linux.test.detail.output")
        steps = [
            {"command": "systemctl is-active nginx", "operation": "status",
             "exit_code": 0, "ok": True, "stdout": "active-marker", "stderr": ""},
            {"command": "false", "operation": "probe", "exit_code": 1,
             "ok": False, "stdout": "", "stderr": "stderr-marker"},
        ]
        ex = _make_execution(proc, user=self.user, result={"ok": False, "steps": steps})
        html = self._detail_html(ex)
        assert "Command Output" in html
        assert "systemctl is-active nginx" in html
        assert "active-marker" in html      # stdout of a successful step
        assert "stderr-marker" in html      # stderr of a failed step

    def test_detail_shows_direct_source_without_steps(self):
        proc = make_procedure("os.linux.test.detail.direct")
        ex = _make_execution(proc, user=self.user)
        html = self._detail_html(ex)
        assert "Direct" in html
        # No steps -> no Command Output card.
        assert "Command Output" not in html

    def test_detail_shows_intent_source(self):
        proc = make_procedure("os.linux.test.detail.intent")
        ex = _make_execution(proc, user=self.user, params={"_intent_name": "grouped.run"})
        html = self._detail_html(ex)
        assert "grouped.run" in html
