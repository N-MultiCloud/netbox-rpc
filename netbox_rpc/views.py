from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views import View
from netbox.object_actions import AddObject, BulkDelete, BulkExport
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from . import filtersets, forms, health, models, tables

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


@register_model_view(models.RPCProcedure, "runs", path="runs")
class RPCProcedureRunsView(generic.ObjectChildrenView):
    """Run-history tab: the ``RPCExecution`` records for a procedure.

    Each row surfaces the run's user owner (``requested_by``), how it was issued
    (``source`` — directly, or as part of an intent), status, target, backend,
    and timing, and links to the execution detail where the issued commands and
    their output are rendered.
    """

    queryset = models.RPCProcedure.objects.all()
    child_model = models.RPCExecution
    table = tables.RPCExecutionTable
    filterset = filtersets.RPCExecutionFilterSet
    actions = READ_ONLY_ACTIONS
    tab = ViewTab(
        label="Runs",
        badge=lambda obj: obj.executions.count(),
        permission="netbox_rpc.view_rpcexecution",
        weight=500,
    )

    def get_children(self, request, parent):
        return (
            parent.executions.restrict(request.user, "view")
            .select_related("assigned_object_type", "requested_by")
            .order_by("-created", "-id")
        )

    def get_table(self, data, request, bulk_actions=True):
        table = super().get_table(data, request, bulk_actions)
        # The procedure is implied by the parent object; hide the redundant column.
        if "procedure" in table.columns:
            table.columns.hide("procedure")
        return table


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


# ── RpcPluginSettings (opt-in) + landing/dashboard ───────────────────────────


@register_model_view(models.RpcPluginSettings)
class RpcPluginSettingsView(generic.ObjectView):
    queryset = models.RpcPluginSettings.objects.all()


@register_model_view(models.RpcPluginSettings, "edit")
class RpcPluginSettingsEditView(generic.ObjectEditView):
    queryset = models.RpcPluginSettings.objects.all()
    form = forms.RpcPluginSettingsForm


class RpcSettingsSingletonRedirectView(LoginRequiredMixin, View):
    """UI helper: always edit the single settings row (create-on-first-visit)."""

    def get(
        self,
        request: HttpRequest,
        *args: object,
        **kwargs: object,
    ) -> HttpResponse:
        obj = models.RpcPluginSettings.get_solo()
        return redirect("plugins:netbox_rpc:rpcpluginsettings_edit", pk=obj.pk)


rpc_settings_singleton_redirect = RpcSettingsSingletonRedirectView.as_view()


class RPCHomeView(LoginRequiredMixin, View):
    """Landing/status page for /plugins/rpc/.

    Shows whether the operator has opted in (``enabled``), the resolved backend,
    counts, and a *Test connection* button (which calls the probe endpoint via
    JS so the page render is never blocked on a network call).
    """

    template_name = "netbox_rpc/home.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        settings_obj = models.RpcPluginSettings.get_solo()
        target = settings_obj.resolved_backend_target()
        backend_url = str(getattr(target, "url", "") or "") if target is not None else ""
        context = {
            "settings": settings_obj,
            "enabled": settings_obj.enabled,
            "backend": settings_obj.backend,
            "backend_url": backend_url,
            "backend_configured": bool(backend_url),
            "procedure_count": models.RPCProcedure.objects.restrict(
                request.user, "view"
            ).count(),
            "intent_count": models.RPCIntent.objects.restrict(
                request.user, "view"
            ).count(),
            "execution_count": models.RPCExecution.objects.restrict(
                request.user, "view"
            ).count(),
        }
        return render(request, self.template_name, context)


class RpcBackendTestConnectionView(LoginRequiredMixin, View):
    """POST-only: probe the configured backend's ``/status/ping`` and return JSON.

    Issues a single fixed GET to the resolved backend base URL — no caller-
    controlled host or shell input. Used by the landing/settings *Test
    connection* button.
    """

    def post(
        self,
        request: HttpRequest,
        *args: object,
        **kwargs: object,
    ) -> JsonResponse:
        settings_obj = models.RpcPluginSettings.get_solo()
        target = settings_obj.resolved_backend_target()
        return JsonResponse(health.probe_backend(target))
