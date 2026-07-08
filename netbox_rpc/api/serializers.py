from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from drf_spectacular.utils import extend_schema_field
from netbox.api.fields import ContentTypeField
from netbox.api.gfk_fields import GFKSerializerField
from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers

from ..models import (
    RPCBackend,
    RPCExecution,
    RPCExecutionEvent,
    RPCIntent,
    RPCIntentProcedure,
    RPCLinuxServiceAllowlist,
    RPCProcedure,
    RPCProcedureCommand,
)


class RPCBackendSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_rpc-api:rpcbackend-detail",
    )
    auth_token = serializers.CharField(
        required=False,
        allow_blank=True,
        write_only=True,
    )

    class Meta:
        model = RPCBackend
        fields = (
            "id",
            "url",
            "display",
            "name",
            "base_url",
            "verify_ssl",
            "auth_header_name",
            "auth_token",
            "comments",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "base_url")


class RPCProcedureCommandSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_rpc-api:rpcprocedurecommand-detail",
    )
    device_cli_mode = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
    )

    class Meta:
        model = RPCProcedureCommand
        fields = (
            "id",
            "url",
            "display",
            "procedure",
            "sequence",
            "step_type",
            "device_cli_mode",
            "argv",
            "description",
            "condition_param",
            "condition_negate",
            "for_each_param",
            "continue_on_error",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "procedure", "sequence", "step_type")

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not data.get("device_cli_mode"):
            data["device_cli_mode"] = None
        return data

    def validate_device_cli_mode(self, value):
        return value or ""


class RPCProcedureSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_rpc-api:rpcprocedure-detail",
    )
    commands = RPCProcedureCommandSerializer(many=True, read_only=True)

    class Meta:
        model = RPCProcedure
        fields = (
            "id",
            "url",
            "display",
            "name",
            "handler_id",
            "version",
            "enabled",
            "target_models",
            "effect",
            "timeout_seconds",
            "approval_required",
            "params_schema",
            "result_schema",
            "transport_driver",
            "output_parser",
            "output_schema",
            "commands",
            "description",
            "comments",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "handler_id", "enabled")


class RPCLinuxServiceAllowlistSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_rpc-api:rpclinuxserviceallowlist-detail",
    )

    class Meta:
        model = RPCLinuxServiceAllowlist
        fields = (
            "id",
            "url",
            "display",
            "slug",
            "systemd_unit",
            "enabled",
            "target_models",
            "description",
            "comments",
            "ssh_credential_override",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "slug", "enabled")


class RPCIntentProcedureSerializer(serializers.Serializer):
    """Read representation of one grouped procedure with its execution order."""

    id = serializers.IntegerField(source="procedure_id", read_only=True)
    name = serializers.CharField(source="procedure.name", read_only=True)
    handler_id = serializers.CharField(source="procedure.handler_id", read_only=True)
    effect = serializers.CharField(source="procedure.effect", read_only=True)
    approval_required = serializers.BooleanField(
        source="procedure.approval_required", read_only=True
    )
    sequence = serializers.IntegerField(read_only=True)


class RPCIntentSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_rpc-api:rpcintent-detail",
    )
    procedures = serializers.SerializerMethodField()
    procedure_ids = serializers.PrimaryKeyRelatedField(
        queryset=RPCProcedure.objects.all(),
        many=True,
        write_only=True,
        required=False,
        help_text=(
            "Ordered list of RPCProcedure IDs to group under this intent. The "
            "list order becomes the through 'sequence' (used in sequential mode)."
        ),
    )

    class Meta:
        model = RPCIntent
        fields = (
            "id",
            "url",
            "display",
            "name",
            "execution_mode",
            "enabled",
            "procedures",
            "procedure_ids",
            "description",
            "comments",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "execution_mode", "enabled")

    @extend_schema_field(RPCIntentProcedureSerializer(many=True))
    def get_procedures(self, obj: RPCIntent) -> list[dict]:
        rows = obj.intent_procedures.select_related("procedure").all()
        return RPCIntentProcedureSerializer(rows, many=True).data

    def _set_procedures(self, intent: RPCIntent, procedures: list) -> None:
        # Reconcile the ordered through rows to exactly the provided list,
        # renumbering `sequence` from 1 in list order.
        RPCIntentProcedure.objects.filter(intent=intent).delete()
        RPCIntentProcedure.objects.bulk_create(
            [
                RPCIntentProcedure(intent=intent, procedure=proc, sequence=index)
                for index, proc in enumerate(procedures, start=1)
            ]
        )

    def create(self, validated_data: dict) -> RPCIntent:
        procedures = validated_data.pop("procedure_ids", None)
        intent = super().create(validated_data)
        if procedures is not None:
            self._set_procedures(intent, procedures)
        return intent

    def update(self, instance: RPCIntent, validated_data: dict) -> RPCIntent:
        procedures = validated_data.pop("procedure_ids", None)
        intent = super().update(instance, validated_data)
        if procedures is not None:
            self._set_procedures(intent, procedures)
        return intent


class RPCExecutionEventSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_rpc-api:rpcexecutionevent-detail",
    )

    class Meta:
        model = RPCExecutionEvent
        fields = (
            "id",
            "url",
            "display",
            "execution",
            "sequence",
            "level",
            "event",
            "message",
            "data",
            "payload_hash",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "execution", "sequence", "event")
        read_only_fields = fields


class RPCExecutionSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_rpc-api:rpcexecution-detail",
    )
    procedure = RPCProcedureSerializer(read_only=True)
    procedure_id = serializers.PrimaryKeyRelatedField(
        queryset=RPCProcedure.objects.all(),
        source="procedure",
        write_only=True,
    )
    assigned_object_type = ContentTypeField(queryset=ContentType.objects.all())
    assigned_object = GFKSerializerField(read_only=True)
    backend_id = serializers.IntegerField(
        source="backend",
        required=False,
        allow_null=True,
        write_only=True,
    )
    target_display = serializers.CharField(read_only=True)
    target_model_label = serializers.CharField(read_only=True)

    class Meta:
        model = RPCExecution
        fields = (
            "id",
            "url",
            "display",
            "procedure",
            "procedure_id",
            "assigned_object_type",
            "assigned_object_id",
            "assigned_object",
            "target_model_label",
            "target_display",
            "requested_by",
            "backend",
            "backend_id",
            "status",
            "params",
            "normalized_params",
            "result",
            "error_code",
            "error_message",
            "resolved_command_hash",
            "request_id",
            "trace_id",
            "job_id",
            "started_at",
            "finished_at",
            "comments",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        read_only_fields = (
            "requested_by",
            "status",
            "normalized_params",
            "result",
            "error_code",
            "error_message",
            "resolved_command_hash",
            "job_id",
            "started_at",
            "finished_at",
        )
        brief_fields = ("id", "url", "display", "procedure", "status")

    def validate(self, data: dict) -> dict:
        data = super().validate(data)
        procedure = data.get("procedure") or getattr(self.instance, "procedure", None)
        content_type = data.get("assigned_object_type") or getattr(
            self.instance,
            "assigned_object_type",
            None,
        )
        object_id = data.get("assigned_object_id") or getattr(
            self.instance,
            "assigned_object_id",
            None,
        )
        if not procedure or not content_type or not object_id:
            return data

        target_label = f"{content_type.app_label}.{content_type.model}"
        allowed = set(procedure.target_models or [])
        if allowed and target_label not in allowed:
            raise serializers.ValidationError(
                {
                    "assigned_object_type": (
                        f"{target_label} is not an allowed target for {procedure.name}."
                    )
                }
            )
        return data
