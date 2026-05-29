from django import forms
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.forms.fields import CommentField, DynamicModelChoiceField

from .models import RPCExecution, RPCExecutionEvent, RPCLinuxServiceAllowlist, RPCProcedure


class RPCProcedureForm(NetBoxModelForm):
    comments = CommentField()

    class Meta:
        model = RPCProcedure
        fields = (
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
            "description",
            "tags",
            "comments",
        )


class RPCLinuxServiceAllowlistForm(NetBoxModelForm):
    comments = CommentField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from netbox_nms.models import DeviceCredential
        self.fields["ssh_credential_override"] = DynamicModelChoiceField(
            queryset=DeviceCredential.objects.all(),
            required=False,
            label="SSH Credential Override",
        )

    class Meta:
        model = RPCLinuxServiceAllowlist
        fields = (
            "slug",
            "systemd_unit",
            "enabled",
            "target_models",
            "ssh_credential_override",
            "description",
            "tags",
            "comments",
        )


# ── Filter forms ─────────────────────────────────────────────────────────────


class RPCProcedureFilterForm(NetBoxModelFilterSetForm):
    model = RPCProcedure
    enabled = forms.NullBooleanField(required=False)
    approval_required = forms.NullBooleanField(required=False)


class RPCLinuxServiceAllowlistFilterForm(NetBoxModelFilterSetForm):
    model = RPCLinuxServiceAllowlist
    enabled = forms.NullBooleanField(required=False)


class RPCExecutionFilterForm(NetBoxModelFilterSetForm):
    model = RPCExecution
    procedure_id = DynamicModelChoiceField(
        queryset=RPCProcedure.objects.all(),
        required=False,
        label="Procedure",
    )
    status = forms.ChoiceField(
        choices=[("", "---------")] + list(RPCExecution.STATUS_CHOICES),
        required=False,
    )


class RPCExecutionEventFilterForm(NetBoxModelFilterSetForm):
    model = RPCExecutionEvent
    execution_id = DynamicModelChoiceField(
        queryset=RPCExecution.objects.all(),
        required=False,
        label="Execution",
    )
    level = forms.ChoiceField(
        choices=[("", "---------")] + list(RPCExecutionEvent.LEVEL_CHOICES),
        required=False,
    )
