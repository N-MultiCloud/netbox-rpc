from django.http import HttpRequest
from netbox.object_actions import AddObject, BulkDelete, BulkExport
from netbox.views import generic
from utilities.views import register_model_view

from . import filtersets, forms, models, tables

LIST_ACTIONS = (AddObject, BulkExport, BulkDelete)
READ_ONLY_ACTIONS = (BulkExport,)


class RequestAwareObjectEditView(generic.ObjectEditView):
    """Attach the current request to the edited object for form-level policy checks."""

    def alter_object(
        self,
        obj: object,
        request: HttpRequest,
        url_args: tuple[object, ...],
        url_kwargs: dict[str, object],
    ) -> object:
        setattr(obj, forms.REQUEST_ATTR, request)
        return super().alter_object(obj, request, url_args, url_kwargs)


# ── RPCBackend ───────────────────────────────────────────────────────────────


@register_model_view(models.RPCBackend, "list", path="", detail=False)
class RPCBackendListView(generic.ObjectListView):
    queryset = models.RPCBackend.objects.all()
    table = tables.RPCBackendTable
    filterset = filtersets.RPCBackendFilterSet
    filterset_form = forms.RPCBackendFilterForm
    actions = LIST_ACTIONS


@register_model_view(models.RPCBackend)
class RPCBackendView(generic.ObjectView):
    queryset = models.RPCBackend.objects.all()


@register_model_view(models.RPCBackend, "add", detail=False)
@register_model_view(models.RPCBackend, "edit")
class RPCBackendEditView(generic.ObjectEditView):
    queryset = models.RPCBackend.objects.all()
    form = forms.RPCBackendForm


@register_model_view(models.RPCBackend, "delete")
class RPCBackendDeleteView(generic.ObjectDeleteView):
    queryset = models.RPCBackend.objects.all()


@register_model_view(models.RPCBackend, "bulk_delete", path="delete", detail=False)
class RPCBackendBulkDeleteView(generic.BulkDeleteView):
    queryset = models.RPCBackend.objects.all()
    table = tables.RPCBackendTable


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
class RPCProcedureEditView(RequestAwareObjectEditView):
    queryset = models.RPCProcedure.objects.all()
    form = forms.RPCProcedureForm


@register_model_view(models.RPCProcedure, "delete")
class RPCProcedureDeleteView(generic.ObjectDeleteView):
    queryset = models.RPCProcedure.objects.all()


@register_model_view(models.RPCProcedure, "bulk_delete", path="delete", detail=False)
class RPCProcedureBulkDeleteView(generic.BulkDeleteView):
    queryset = models.RPCProcedure.objects.all()
    table = tables.RPCProcedureTable


# ── RPCProcedureCommand ─────────────────────────────────────────────────────


@register_model_view(models.RPCProcedureCommand, "list", path="", detail=False)
class RPCProcedureCommandListView(generic.ObjectListView):
    queryset = models.RPCProcedureCommand.objects.select_related("procedure")
    table = tables.RPCProcedureCommandTable
    filterset = filtersets.RPCProcedureCommandFilterSet
    filterset_form = forms.RPCProcedureCommandFilterForm
    actions = LIST_ACTIONS


@register_model_view(models.RPCProcedureCommand)
class RPCProcedureCommandView(generic.ObjectView):
    queryset = models.RPCProcedureCommand.objects.select_related("procedure")


@register_model_view(models.RPCProcedureCommand, "add", detail=False)
@register_model_view(models.RPCProcedureCommand, "edit")
class RPCProcedureCommandEditView(generic.ObjectEditView):
    queryset = models.RPCProcedureCommand.objects.select_related("procedure")
    form = forms.RPCProcedureCommandForm


@register_model_view(models.RPCProcedureCommand, "delete")
class RPCProcedureCommandDeleteView(generic.ObjectDeleteView):
    queryset = models.RPCProcedureCommand.objects.select_related("procedure")


@register_model_view(
    models.RPCProcedureCommand, "bulk_delete", path="delete", detail=False
)
class RPCProcedureCommandBulkDeleteView(generic.BulkDeleteView):
    queryset = models.RPCProcedureCommand.objects.select_related("procedure")
    table = tables.RPCProcedureCommandTable


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
class RPCLinuxServiceAllowlistEditView(RequestAwareObjectEditView):
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


# ── RPCIntent ────────────────────────────────────────────────────────────────


@register_model_view(models.RPCIntent, "list", path="", detail=False)
class RPCIntentListView(generic.ObjectListView):
    queryset = models.RPCIntent.objects.prefetch_related("procedures")
    table = tables.RPCIntentTable
    filterset = filtersets.RPCIntentFilterSet
    filterset_form = forms.RPCIntentFilterForm
    actions = LIST_ACTIONS


@register_model_view(models.RPCIntent)
class RPCIntentView(generic.ObjectView):
    # The detail template renders the ordered through rows directly via
    # `object.ordered_intent_procedures`.
    queryset = models.RPCIntent.objects.prefetch_related(
        "intent_procedures__procedure"
    )


@register_model_view(models.RPCIntent, "add", detail=False)
@register_model_view(models.RPCIntent, "edit")
class RPCIntentEditView(generic.ObjectEditView):
    queryset = models.RPCIntent.objects.all()
    form = forms.RPCIntentForm


@register_model_view(models.RPCIntent, "delete")
class RPCIntentDeleteView(generic.ObjectDeleteView):
    queryset = models.RPCIntent.objects.all()


@register_model_view(models.RPCIntent, "bulk_delete", path="delete", detail=False)
class RPCIntentBulkDeleteView(generic.BulkDeleteView):
    queryset = models.RPCIntent.objects.all()
    table = tables.RPCIntentTable


# ── RPCExecution (read-only) ──────────────────────────────────────────────────


@register_model_view(models.RPCExecution, "list", path="", detail=False)
class RPCExecutionListView(generic.ObjectListView):
    queryset = models.RPCExecution.objects.select_related(
        "procedure", "assigned_object_type", "requested_by"
    )
    table = tables.RPCExecutionTable
    filterset = filtersets.RPCExecutionFilterSet
    filterset_form = forms.RPCExecutionFilterForm
    actions = READ_ONLY_ACTIONS


@register_model_view(models.RPCExecution)
class RPCExecutionView(generic.ObjectView):
    queryset = models.RPCExecution.objects.select_related(
        "procedure", "assigned_object_type", "requested_by"
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
