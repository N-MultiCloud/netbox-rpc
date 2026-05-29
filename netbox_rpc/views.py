from netbox.object_actions import AddObject, BulkDelete, BulkExport
from netbox.views import generic
from utilities.views import register_model_view

from . import filtersets, forms, models, tables

LIST_ACTIONS = (AddObject, BulkExport, BulkDelete)
READ_ONLY_ACTIONS = (BulkExport,)


# ── RPCProcedure ─────────────────────────────────────────────────────────────


@register_model_view(models.RPCProcedure, "list", path="", detail=False)
class RPCProcedureListView(generic.ObjectListView):
    queryset = models.RPCProcedure.objects.all()
    table = tables.RPCProcedureTable
    filterset = filtersets.RPCProcedureFilterSet
    filterset_form = forms.RPCProcedureFilterForm
    actions = LIST_ACTIONS


@register_model_view(models.RPCProcedure)
class RPCProcedureView(generic.ObjectView):
    queryset = models.RPCProcedure.objects.all()


@register_model_view(models.RPCProcedure, "add", detail=False)
@register_model_view(models.RPCProcedure, "edit")
class RPCProcedureEditView(generic.ObjectEditView):
    queryset = models.RPCProcedure.objects.all()
    form = forms.RPCProcedureForm


@register_model_view(models.RPCProcedure, "delete")
class RPCProcedureDeleteView(generic.ObjectDeleteView):
    queryset = models.RPCProcedure.objects.all()


@register_model_view(models.RPCProcedure, "bulk_delete", path="delete", detail=False)
class RPCProcedureBulkDeleteView(generic.BulkDeleteView):
    queryset = models.RPCProcedure.objects.all()
    table = tables.RPCProcedureTable


# ── RPCLinuxServiceAllowlist ──────────────────────────────────────────────────


@register_model_view(models.RPCLinuxServiceAllowlist, "list", path="", detail=False)
class RPCLinuxServiceAllowlistListView(generic.ObjectListView):
    queryset = models.RPCLinuxServiceAllowlist.objects.all()
    table = tables.RPCLinuxServiceAllowlistTable
    filterset = filtersets.RPCLinuxServiceAllowlistFilterSet
    filterset_form = forms.RPCLinuxServiceAllowlistFilterForm
    actions = LIST_ACTIONS


@register_model_view(models.RPCLinuxServiceAllowlist)
class RPCLinuxServiceAllowlistView(generic.ObjectView):
    queryset = models.RPCLinuxServiceAllowlist.objects.all()


@register_model_view(models.RPCLinuxServiceAllowlist, "add", detail=False)
@register_model_view(models.RPCLinuxServiceAllowlist, "edit")
class RPCLinuxServiceAllowlistEditView(generic.ObjectEditView):
    queryset = models.RPCLinuxServiceAllowlist.objects.all()
    form = forms.RPCLinuxServiceAllowlistForm


@register_model_view(models.RPCLinuxServiceAllowlist, "delete")
class RPCLinuxServiceAllowlistDeleteView(generic.ObjectDeleteView):
    queryset = models.RPCLinuxServiceAllowlist.objects.all()


@register_model_view(
    models.RPCLinuxServiceAllowlist,
    "bulk_delete",
    path="delete",
    detail=False,
)
class RPCLinuxServiceAllowlistBulkDeleteView(generic.BulkDeleteView):
    queryset = models.RPCLinuxServiceAllowlist.objects.all()
    table = tables.RPCLinuxServiceAllowlistTable


# ── RPCExecution (read-only) ──────────────────────────────────────────────────


@register_model_view(models.RPCExecution, "list", path="", detail=False)
class RPCExecutionListView(generic.ObjectListView):
    queryset = models.RPCExecution.objects.select_related(
        "procedure", "assigned_object_type", "requested_by", "backend"
    )
    table = tables.RPCExecutionTable
    filterset = filtersets.RPCExecutionFilterSet
    filterset_form = forms.RPCExecutionFilterForm
    actions = READ_ONLY_ACTIONS


@register_model_view(models.RPCExecution)
class RPCExecutionView(generic.ObjectView):
    queryset = models.RPCExecution.objects.select_related(
        "procedure", "assigned_object_type", "requested_by", "backend"
    )

    def get_extra_context(self, request, instance):
        events_table = tables.RPCExecutionEventTable(
            instance.events.all().order_by("sequence"),
            orderable=False,
        )
        return {"events_table": events_table}


# ── RPCExecutionEvent (read-only) ─────────────────────────────────────────────


@register_model_view(models.RPCExecutionEvent, "list", path="", detail=False)
class RPCExecutionEventListView(generic.ObjectListView):
    queryset = models.RPCExecutionEvent.objects.select_related("execution__procedure")
    table = tables.RPCExecutionEventTable
    filterset = filtersets.RPCExecutionEventFilterSet
    filterset_form = forms.RPCExecutionEventFilterForm
    actions = READ_ONLY_ACTIONS
