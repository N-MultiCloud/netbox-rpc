from typing import Protocol, cast

from django import forms
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.forms.fields import CommentField, DynamicModelChoiceField

from .models import (
    RPCBackend,
    RPCExecution,
    RPCExecutionEvent,
    RPCProcedureCommand,
    RPCLinuxServiceAllowlist,
    RPCProcedure,
)

REQUEST_ATTR = "_netbox_rpc_request"


class _PermissionUser(Protocol):
    def has_perm(self, permission: str) -> bool: ...


def _request_user(instance: object) -> _PermissionUser | None:
    request = getattr(instance, REQUEST_ATTR, None)
    user = getattr(request, "user", None)
    if user is None or not hasattr(user, "has_perm"):
        return None
    return cast(_PermissionUser, user)


class RPCProcedureForm(NetBoxModelForm):
    comments = CommentField()

    def clean(self) -> dict[str, object] | None:
        cleaned_data = super().clean()
        if not cleaned_data:
            return cleaned_data

        if not self.instance.pk:
            return cleaned_data

        if self.instance.approval_required is not True:
            return cleaned_data

        if cleaned_data.get("approval_required") is not False:
            return cleaned_data

        user = _request_user(self.instance)
        if user is not None and user.has_perm("netbox_rpc.approve_rpcprocedure"):
            return cleaned_data

        raise forms.ValidationError(
            {
                "approval_required": (
                    "Only users with netbox_rpc.approve_rpcprocedure can disable "
                    "approval for an existing RPC procedure."
                )
            }
        )

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
            "transport_driver",
            "output_parser",
            "output_schema",
            "description",
            "tags",
            "comments",
        )


class RPCBackendForm(NetBoxModelForm):
    comments = CommentField()

    class Meta:
        model = RPCBackend
        fields = (
            "name",
            "base_url",
            "verify_ssl",
            "auth_header_name",
            "auth_token",
            "tags",
            "comments",
        )


class RPCProcedureCommandForm(NetBoxModelForm):
    class Meta:
        model = RPCProcedureCommand
        fields = (
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
        )


class RPCLinuxServiceAllowlistForm(NetBoxModelForm):
    comments = CommentField()

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        try:
            from netbox_nms.models import DeviceCredential
        except ImportError:
            self.fields["ssh_credential_override"] = forms.IntegerField(
                required=False,
                label="SSH Credential Override (DeviceCredential PK)",
            )
            return

        user = _request_user(self.instance)
        credential_queryset = (
            DeviceCredential.objects.none()
            if user is None
            else DeviceCredential.objects.restrict(user, "view")
        )
        self.fields["ssh_credential_override"] = DynamicModelChoiceField(
            queryset=credential_queryset,
            required=False,
            label="SSH Credential Override",
        )

    def clean_ssh_credential_override(self) -> int | None:
        value = self.cleaned_data.get("ssh_credential_override")
        if value in (None, ""):
            return None
        return int(getattr(value, "pk", value))

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


class RPCBackendFilterForm(NetBoxModelFilterSetForm):
    model = RPCBackend
    name = forms.CharField(required=False)


class RPCProcedureCommandFilterForm(NetBoxModelFilterSetForm):
    model = RPCProcedureCommand
    procedure_id = DynamicModelChoiceField(
        queryset=RPCProcedure.objects.all(),
        required=False,
        label="Procedure",
    )
    step_type = forms.ChoiceField(
        choices=[("", "---------")] + list(RPCProcedureCommand.STEP_TYPE_CHOICES),
        required=False,
    )


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
