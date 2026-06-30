import django_tables2 as tables
from netbox.tables import NetBoxTable, columns

from .models import (
    RPCBackend,
    RPCExecution,
    RPCExecutionEvent,
    RPCLinuxServiceAllowlist,
    RPCProcedure,
)


class RPCBackendTable(NetBoxTable):
    name = tables.Column(linkify=True)
    verify_ssl = columns.BooleanColumn()

    class Meta(NetBoxTable.Meta):
        model = RPCBackend
        fields = (
            "pk",
            "id",
            "name",
            "base_url",
            "verify_ssl",
            "auth_header_name",
            "tags",
            "actions",
        )
        default_columns = ("name", "base_url", "verify_ssl", "auth_header_name")


class RPCProcedureTable(NetBoxTable):
    name = tables.Column(linkify=True)
    enabled = columns.BooleanColumn()
    effect = columns.ChoiceFieldColumn()
    approval_required = columns.BooleanColumn()
    transport_driver = columns.ChoiceFieldColumn()
    output_parser = columns.ChoiceFieldColumn()

    class Meta(NetBoxTable.Meta):
        model = RPCProcedure
        fields = (
            "pk",
            "id",
            "name",
            "handler_id",
            "version",
            "enabled",
            "effect",
            "timeout_seconds",
            "approval_required",
            "transport_driver",
            "output_parser",
            "description",
            "tags",
            "actions",
        )
        default_columns = (
            "name",
            "handler_id",
            "enabled",
            "effect",
            "timeout_seconds",
            "approval_required",
        )


class RPCLinuxServiceAllowlistTable(NetBoxTable):
    slug = tables.Column(linkify=True)
    enabled = columns.BooleanColumn()
    ssh_credential_override = tables.Column(verbose_name="SSH Credential Override")

    class Meta(NetBoxTable.Meta):
        model = RPCLinuxServiceAllowlist
        fields = (
            "pk",
            "id",
            "slug",
            "systemd_unit",
            "enabled",
            "ssh_credential_override",
            "description",
            "tags",
            "actions",
        )
        default_columns = ("slug", "systemd_unit", "enabled", "ssh_credential_override")


class RPCExecutionTable(NetBoxTable):
    id = tables.Column(linkify=True, verbose_name="ID")
    procedure = tables.Column(linkify=True)
    status = columns.ChoiceFieldColumn()
    backend = tables.Column(verbose_name="Backend ID")

    class Meta(NetBoxTable.Meta):
        model = RPCExecution
        fields = (
            "pk",
            "id",
            "procedure",
            "target_display",
            "status",
            "requested_by",
            "backend",
            "started_at",
            "finished_at",
            "created",
            "tags",
            "actions",
        )
        default_columns = (
            "id",
            "procedure",
            "target_display",
            "status",
            "requested_by",
            "started_at",
        )


class RPCExecutionEventTable(NetBoxTable):
    execution = tables.Column(linkify=True)
    level = columns.ChoiceFieldColumn()

    class Meta(NetBoxTable.Meta):
        model = RPCExecutionEvent
        fields = (
            "pk",
            "id",
            "execution",
            "sequence",
            "level",
            "event",
            "message",
            "created",
            "actions",
        )
        default_columns = ("execution", "sequence", "level", "event", "message")
