from typing import Protocol, cast

from django import forms
from django.db import transaction
from dcim.models import Device
from ipam.models import IPAddress
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.exceptions import AbortRequest
from utilities.forms.fields import (
    CommentField,
    DynamicModelChoiceField,
    DynamicModelMultipleChoiceField,
)

from .constants import RPC_TARGET_BINDING_SLUG_CHOICES
from .current_access import reload_requesting_user
from .transport import UNPIN_DENIED_MESSAGE, may_approve_procedure, unpin_is_refused
from .transport import lowering_is_refused
from .models import (
    RPCBackend,
    RPCExecution,
    RPCExecutionEvent,
    RPCIntent,
    RPCIntentProcedure,
    RPCLinuxServiceAllowlist,
    RPCNetBoxPluginAllowlist,
    RPCProcedure,
    RPCProcedureCommand,
    RPCTargetBinding,
    RpcPluginSettings,
)

REQUEST_ATTR = "_netbox_rpc_request"
APPROVAL_DENIED_MESSAGE = (
    "Only users with netbox_rpc.approve_rpcprocedure can disable "
    "approval for an existing RPC procedure."
)


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
        super().clean()
        # NetBox's form mixins return None from clean(), which would skip the
        # checks below. Django keeps the validated values in self.cleaned_data,
        # so the checks read that dict.
        cleaned_data = self.cleaned_data
        if not cleaned_data:
            return cleaned_data

        if not self.instance.pk:
            return cleaned_data

        self._refuse_transport_unpin(cleaned_data)

        if self.instance.approval_required is not True:
            return cleaned_data

        if cleaned_data.get("approval_required") is not False:
            return cleaned_data

        user = _request_user(self.instance)
        if may_approve_procedure(user, self.instance):
            return cleaned_data

        raise forms.ValidationError({"approval_required": APPROVAL_DENIED_MESSAGE})

    def save(self, commit: bool = True):
        if not self.instance.pk:
            return super().save(commit=commit)
        # The edit view calls save() inside its transaction. The gate runs again
        # here under a row lock, because the copy read in clean() can be stale.
        with transaction.atomic():
            self._refuse_unpin_under_lock()
            return super().save(commit=commit)

    def _refuse_unpin_under_lock(self) -> None:
        # The approve scope is read from the locked row as it is now, not from the
        # copy read in clean(), because the scope can change before the lock is taken.
        stored = RPCProcedure.objects.select_for_update().get(pk=self.instance.pk)
        # Reloaded after the lock: NetBox caches grants on the request user.
        user = reload_requesting_user(_request_user(self.instance))
        may_approve = may_approve_procedure(user, stored)
        if unpin_is_refused(
            previously_pinned=stored.transport_pinned,
            requested_pinned=self.cleaned_data.get("transport_pinned"),
            may_approve=may_approve,
        ):
            raise AbortRequest(UNPIN_DENIED_MESSAGE)
        if lowering_is_refused(
            previously_set=stored.approval_required,
            requested=self.cleaned_data.get("approval_required"),
            may_approve=may_approve,
        ):
            raise AbortRequest(APPROVAL_DENIED_MESSAGE)

    def _refuse_transport_unpin(self, cleaned_data: dict[str, object]) -> None:
        user = _request_user(self.instance)
        may_approve = may_approve_procedure(user, self.instance)
        if unpin_is_refused(
            previously_pinned=self.instance.transport_pinned,
            requested_pinned=cleaned_data.get("transport_pinned"),
            may_approve=may_approve,
        ):
            raise forms.ValidationError({"transport_pinned": UNPIN_DENIED_MESSAGE})

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
            "transport_driver_chain",
            "transport_pinned",
            "output_parser",
            "output_schema",
            "description",
            "tags",
            "comments",
        )


class RPCBackendForm(NetBoxModelForm):
    comments = CommentField()
    ip_address = DynamicModelChoiceField(
        queryset=IPAddress.objects.all(),
        required=False,
        label="IP address",
    )

    class Meta:
        model = RPCBackend
        fields = (
            "name",
            "ip_address",
            "domain",
            "port",
            "use_https",
            "base_url",
            "verify_ssl",
            "auth_header_name",
            "auth_token",
            "executor_identity",
            "tags",
            "comments",
        )


class RPCTargetBindingForm(NetBoxModelForm):
    slug = forms.ChoiceField(choices=RPC_TARGET_BINDING_SLUG_CHOICES)
    device = DynamicModelChoiceField(queryset=Device.objects.all())

    class Meta:
        model = RPCTargetBinding
        fields = (
            "slug",
            "device",
            "description",
            "tags",
        )


class RPCProcedureCommandForm(NetBoxModelForm):
    class Meta:
        model = RPCProcedureCommand
        fields = (
            "procedure",
            "sequence",
            "step_type",
            "device_cli_mode",
            "render_mode",
            "argv",
            "produces_var",
            "capture_kind",
            "capture_expression",
            "description",
            "condition_param",
            "condition_negate",
            "for_each_param",
            "continue_on_error",
            "tags",
        )
        help_texts = {
            "argv": (
                "JSON list of tokens. In 'literal' mode each token may carry one "
                "{param} placeholder. In 'jinja' mode each token is a Jinja2 "
                'expression, e.g. ["--id", "{{ vars.vmid }}", "--host", '
                '"{{ target.name }}"]. Reference declared params as '
                "{{ params.x }}, the NetBox target object as {{ target.field }}, "
                "an earlier command's captured output as {{ vars.name }}, the SSH "
                "runtime keys as {{ runtime.rpc_ssh_host }}, and the for-each "
                "element as {{ item }}."
            ),
        }


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

    openbao_assignment_id = forms.IntegerField(
        required=False,
        min_value=1,
        label="OpenBao Credential Assignment (netbox_openbao.CredentialAssignment PK)",
        help_text=(
            "Optional replacement for ssh_credential_override, once a "
            "CredentialAssignment binding the migrated credential to this "
            "row's target for purpose=login exists in netbox-openbao."
        ),
    )

    class Meta:
        model = RPCLinuxServiceAllowlist
        fields = (
            "slug",
            "systemd_unit",
            "environment_file",
            "enabled",
            "target_models",
            "ssh_credential_override",
            "openbao_assignment_id",
            "description",
            "tags",
            "comments",
        )


class RPCNetBoxPluginAllowlistForm(NetBoxModelForm):
    """Operator-managed authorization for a plugin `netbox.plugin.install` may install.

    Editing a row here decides what a future execution actually installs and
    imports, so it is the real authorization surface for that procedure -- the
    caller only names the slug.
    """

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

    openbao_assignment_id = forms.IntegerField(
        required=False,
        min_value=1,
        label="OpenBao Credential Assignment (netbox_openbao.CredentialAssignment PK)",
        help_text=(
            "Optional replacement for ssh_credential_override, once a "
            "CredentialAssignment binding the migrated credential to this "
            "row's target for purpose=login exists in netbox-openbao."
        ),
    )

    class Meta:
        model = RPCNetBoxPluginAllowlist
        fields = (
            "slug",
            "distribution",
            "module",
            "venv_python",
            "manage_py",
            "settings_file",
            "service_slugs",
            "enabled",
            "target_models",
            "ssh_credential_override",
            "openbao_assignment_id",
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


class RPCTargetBindingFilterForm(NetBoxModelFilterSetForm):
    model = RPCTargetBinding
    slug = forms.ChoiceField(
        choices=[("", "---------")] + list(RPC_TARGET_BINDING_SLUG_CHOICES),
        required=False,
    )
    device_id = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        label="Device",
    )


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


class RPCNetBoxPluginAllowlistFilterForm(NetBoxModelFilterSetForm):
    model = RPCNetBoxPluginAllowlist


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


class RpcPluginSettingsForm(NetBoxModelForm):
    """Edit the opt-in netbox-rpc integration settings singleton."""

    comments = CommentField()
    backend = DynamicModelChoiceField(
        queryset=RPCBackend.objects.all(),
        required=False,
        label="RPC backend",
        help_text="RPCBackend used to reach the netbox-rpc-backend service.",
    )

    class Meta:
        model = RpcPluginSettings
        fields = (
            "enabled",
            "backend",
            "default_transport_driver_chain",
            "default_network_driver_chain",
            "ansible_platform_map",
            "comments",
            "tags",
        )
