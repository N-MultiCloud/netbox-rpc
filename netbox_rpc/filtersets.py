import re

import django_filters
from netbox.filtersets import NetBoxModelFilterSet

from .models import (
    RPCBackend,
    RPCExecution,
    RPCExecutionEvent,
    RPCIntent,
    RPCLinuxServiceAllowlist,
    RPCNetBoxPluginAllowlist,
    RPCProcedure,
    RPCProcedureCommand,
    RPCTargetBinding,
)


class RPCBackendFilterSet(NetBoxModelFilterSet):
    name = django_filters.CharFilter()

    class Meta:
        model = RPCBackend
        fields = ("name",)


class RPCTargetBindingFilterSet(NetBoxModelFilterSet):
    slug = django_filters.CharFilter()
    device_id = django_filters.NumberFilter(field_name="device_id")

    class Meta:
        model = RPCTargetBinding
        fields = ("slug", "device_id")


class RPCProcedureFilterSet(NetBoxModelFilterSet):
    enabled = django_filters.BooleanFilter()
    approval_required = django_filters.BooleanFilter()
    effect = django_filters.CharFilter()
    transport_driver = django_filters.CharFilter()
    output_parser = django_filters.CharFilter()

    class Meta:
        model = RPCProcedure
        fields = (
            "name",
            "handler_id",
            "enabled",
            "effect",
            "approval_required",
            "transport_driver",
            "transport_pinned",
            "output_parser",
        )


class RPCProcedureCommandFilterSet(NetBoxModelFilterSet):
    procedure_id = django_filters.ModelChoiceFilter(
        field_name="procedure",
        queryset=RPCProcedure.objects.all(),
        label="Procedure",
    )
    step_type = django_filters.CharFilter()
    render_mode = django_filters.CharFilter()

    class Meta:
        model = RPCProcedureCommand
        fields = (
            "procedure_id",
            "sequence",
            "step_type",
            "device_cli_mode",
            "render_mode",
            "produces_var",
            "condition_param",
            "for_each_param",
        )


class RPCLinuxServiceAllowlistFilterSet(NetBoxModelFilterSet):
    enabled = django_filters.BooleanFilter()

    class Meta:
        model = RPCLinuxServiceAllowlist
        fields = ("slug", "systemd_unit", "environment_file", "enabled")


class RPCNetBoxPluginAllowlistFilterSet(NetBoxModelFilterSet):
    enabled = django_filters.BooleanFilter()

    class Meta:
        model = RPCNetBoxPluginAllowlist
        fields = ("slug", "distribution", "module", "enabled")


class RPCIntentFilterSet(NetBoxModelFilterSet):
    enabled = django_filters.BooleanFilter()
    execution_mode = django_filters.CharFilter()
    procedure_id = django_filters.ModelMultipleChoiceFilter(
        field_name="procedures",
        queryset=RPCProcedure.objects.all(),
        label="Procedures",
    )

    class Meta:
        model = RPCIntent
        fields = ("name", "enabled", "execution_mode", "procedure_id")


class RPCExecutionFilterSet(NetBoxModelFilterSet):
    _TARGET_TYPE_RE = re.compile(r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*")
    _TARGET_ID_RE = re.compile(r"[1-9][0-9]{0,18}")

    procedure = django_filters.ModelChoiceFilter(
        field_name="procedure",
        queryset=RPCProcedure.objects.all(),
        label="Procedure",
    )
    procedure_id = django_filters.ModelChoiceFilter(
        field_name="procedure",
        queryset=RPCProcedure.objects.all(),
        label="Procedure",
    )
    assigned_object_type = django_filters.CharFilter(
        method="filter_assigned_object_type",
        label="Target type (app_label.model)",
        strip=False,
    )
    assigned_object_id = django_filters.NumberFilter(
        method="filter_assigned_object_id", label="Target ID"
    )
    status = django_filters.CharFilter()
    backend_id = django_filters.NumberFilter(field_name="backend", label="Backend ID")

    def filter_assigned_object_type(self, queryset, name, value):
        if not self._TARGET_TYPE_RE.fullmatch(value):
            return queryset.none()
        app_label, model = value.split(".", 1)
        return queryset.filter(
            assigned_object_type__app_label=app_label,
            assigned_object_type__model=model,
        )

    def filter_assigned_object_id(self, queryset, name, value):
        raw_id = self.data.get(name, "")
        if not self._TARGET_ID_RE.fullmatch(raw_id):
            return queryset.none()
        target_id = int(raw_id)
        if target_id > 9_223_372_036_854_775_807:
            return queryset.none()
        return queryset.filter(assigned_object_id=target_id)

    def filter_queryset(self, queryset):
        # django-filter skips blank optional values. A supplied blank selector
        # must not silently broaden an execution-history query.
        for key in ("procedure", "procedure_id", "assigned_object_type", "assigned_object_id"):
            if key in self.data and not str(self.data.get(key) or "").strip():
                return queryset.none()
        return super().filter_queryset(queryset)

    class Meta:
        model = RPCExecution
        fields = (
            "procedure",
            "procedure_id",
            "assigned_object_type",
            "assigned_object_id",
            "status",
            "backend_id",
        )


class RPCExecutionEventFilterSet(NetBoxModelFilterSet):
    execution_id = django_filters.ModelChoiceFilter(
        field_name="execution",
        queryset=RPCExecution.objects.all(),
        label="Execution",
    )
    level = django_filters.CharFilter()

    class Meta:
        model = RPCExecutionEvent
        fields = ("execution_id", "level")
