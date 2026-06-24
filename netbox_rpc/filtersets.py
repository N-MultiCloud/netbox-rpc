import django_filters
from netbox.filtersets import NetBoxModelFilterSet

from .models import RPCExecution, RPCExecutionEvent, RPCLinuxServiceAllowlist, RPCProcedure


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


class RPCLinuxServiceAllowlistFilterSet(NetBoxModelFilterSet):
    enabled = django_filters.BooleanFilter()

    class Meta:
        model = RPCLinuxServiceAllowlist
        fields = ("slug", "systemd_unit", "enabled")


class RPCExecutionFilterSet(NetBoxModelFilterSet):
    procedure_id = django_filters.ModelChoiceFilter(
        field_name="procedure",
        queryset=RPCProcedure.objects.all(),
        label="Procedure",
    )
    status = django_filters.CharFilter()
    backend_id = django_filters.NumberFilter(field_name="backend_id", label="Backend ID")

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
