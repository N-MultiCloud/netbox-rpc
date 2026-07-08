from typing import Protocol, cast

from django import forms
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.forms.fields import (
    CommentField,
    DynamicModelChoiceField,
    DynamicModelMultipleChoiceField,
)

from .models import (
    RPCBackend,
    RPCExecution,
    RPCExecutionEvent,
    RPCIntent,
    RPCIntentProcedure,
    RPCLinuxServiceAllowlist,
    RPCProcedure,
    RPCProcedureCommand,
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


class RPCIntentForm(NetBoxModelForm):
    """Create/edit an intent: pick procedures + declare the execution mode.

    ``procedures`` is a declared form field (not a Meta model field) because the
    M2M uses a ``through`` model with an extra ``sequence`` column, which Django's
    default ``_save_m2m`` cannot populate. The through rows are reconciled in
    ``save()``, renumbering ``sequence`` from 1 in the submitted selection order
    so sequential/nested intents run in the operator's chosen order.
    """

    procedures = DynamicModelMultipleChoiceField(
        queryset=RPCProcedure.objects.all(),
        required=False,
        label="Procedures",
        help_text=(
            "Procedures grouped by this intent. In sequential mode they are "
            "nested and triggered one after another in selection order; in "
            "parallel mode they are triggered concurrently."
        ),
    )
    comments = CommentField()

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["procedures"].initial = [
                ip.procedure_id for ip in self.instance.intent_procedures.all()
            ]

    def _save_intent_procedures(self) -> None:
        selected = list(self.cleaned_data.get("procedures") or [])
        # Preserve the submitted selection order (when the widget provides it) so
        # the through `sequence` reflects the operator's ordering.
        getlist = getattr(self.data, "getlist", None)
        submitted = getlist(self.add_prefix("procedures")) if getlist else []
        if submitted:
            order = {str(pk): index for index, pk in enumerate(submitted)}
            selected.sort(key=lambda proc: order.get(str(proc.pk), len(order)))
        # Reconcile the through rows to exactly the selected set and renumber
        # `sequence` from 1 in the resolved order.
        self.instance.intent_procedures.all().delete()
        RPCIntentProcedure.objects.bulk_create(
            [
                RPCIntentProcedure(
                    intent=self.instance, procedure=proc, sequence=index
                )
                for index, proc in enumerate(selected, start=1)
            ]
        )

    def save(self, commit: bool = True) -> RPCIntent:
        if commit and self.instance.pk:
            # Update path: reconcile the ordered through rows BEFORE the model
            # save so the changelog postchange (RPCIntent.serialize_object) is
            # serialized at post_save with the new membership/order — otherwise a
            # reorder-only change is not captured in the ObjectChange diff.
            self._save_intent_procedures()
            return super().save(commit=commit)

        instance = super().save(commit=commit)
        if commit:
            # Create path: the instance now has a PK; attach the ordered rows.
            self._save_intent_procedures()
        else:
            # Defer ordered through-row reconciliation onto save_m2m() so the
            # standard `obj = form.save(commit=False); obj.save(); form.save_m2m()`
            # pattern still persists the grouping in submitted order once the
            # instance has a PK.
            original_save_m2m = self.save_m2m

            def save_m2m() -> None:
                original_save_m2m()
                self._save_intent_procedures()

            self.save_m2m = save_m2m
        return instance

    class Meta:
        model = RPCIntent
        fields = (
            "name",
            "execution_mode",
            "enabled",
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


class RPCIntentFilterForm(NetBoxModelFilterSetForm):
    model = RPCIntent
    enabled = forms.NullBooleanField(required=False)
    execution_mode = forms.ChoiceField(
        choices=[("", "---------")] + list(RPCIntent.EXECUTION_MODE_CHOICES),
        required=False,
    )
    procedure_id = DynamicModelMultipleChoiceField(
        queryset=RPCProcedure.objects.all(),
        required=False,
        label="Procedures",
    )


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
