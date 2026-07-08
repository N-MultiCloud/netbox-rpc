import django_filters
from netbox.filtersets import NetBoxModelFilterSet

from .models import (
    RPCBackend,
    RPCExecution,
    RPCExecutionEvent,
    RPCIntent,
    RPCLinuxServiceAllowlist,
    RPCProcedure,
    RPCProcedureCommand,
)


class RPCBackendFilterSet(NetBoxModelFilterSet):
    name = django_filters.CharFilter()

    class Meta:
        model = RPCBackend
        fields = ("name",)


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
            "output_parser",
        )


class RPCProcedureCommandFilterSet(NetBoxModelFilterSet):
    procedure_id = django_filters.ModelChoiceFilter(
        field_name="procedure",
        queryset=RPCProcedure.objects.all(),
        label="Procedure",
    )
    step_type = django_filters.CharFilter()

    class Meta:
        model = RPCProcedureCommand
        fields = (
            "procedure_id",
            "sequence",
            "step_type",
            "device_cli_mode",
            "condition_param",
            "for_each_param",
        )


class RPCLinuxServiceAllowlistFilterSet(NetBoxModelFilterSet):
    enabled = django_filters.BooleanFilter()

    class Meta:
        model = RPCLinuxServiceAllowlist
        fields = ("slug", "systemd_unit", "enabled")


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
    procedure_id = django_filters.ModelChoiceFilter(
        field_name="procedure",
        queryset=RPCProcedure.objects.all(),
        label="Procedure",
    )
    status = django_filters.CharFilter()
    backend_id = django_filters.NumberFilter(field_name="backend", label="Backend ID")

    class Meta:
        model = RPCExecution
        fields = ("procedure_id", "status", "backend_id")


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
