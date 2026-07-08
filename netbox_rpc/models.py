from __future__ import annotations

import hashlib
import json
import re

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from netbox.models import NetBoxModel

from .command_contract import (
    COMMAND_RUNTIME_KEYS,
    extract_placeholders,
    token_has_balanced_placeholders,
    token_is_safe,
)
from .domain.value_objects import Effect, ExecutionMode, ExecutionStatus

# Matches a valid systemd service unit name with an optional .service suffix.
# Rules enforced:
#   - no double dots anywhere (nginx..service rejected)
#   - no double .service suffix (nginx.service.service rejected)
#   - must start with alphanumeric/underscore/dash/@ (no leading dot)
#   - must end with alphanumeric/underscore/dash/@ before the optional .service suffix
# Valid: "nginx", "nginx.service", "user@1000.service", "org.example.service"
# Invalid: "nginx..service", "nginx.service.service", ".nginx", "nginx."
SYSTEMD_UNIT_RE = re.compile(
    r"^(?!.*\.\.)"
    r"(?!.*\.service\.service)"
    r"[A-Za-z0-9_@-]"
    r"(?:[A-Za-z0-9_.@-]*[A-Za-z0-9_@-])?"
    r"(?:\.service)?$"
)


class RPCBackend(NetBoxModel):
    """Standalone backend target.

    auth_token is stored in plaintext. Security-conscious deployments should
    provide a custom PLUGINS_CONFIG["netbox_rpc"]["backend_resolver"] instead.
    """

    name = models.CharField(max_length=255, unique=True)
    base_url = models.URLField(max_length=500)
    verify_ssl = models.BooleanField(default=True)
    auth_header_name = models.CharField(max_length=100, default="Authorization")
    auth_token = models.CharField(max_length=4096, blank=True)
    comments = models.TextField(blank=True)

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("name",)
        verbose_name = "RPC Backend"

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        from django.urls import reverse

        return reverse("plugins:netbox_rpc:rpcbackend", args=[self.pk])

    @property
    def backend_url(self) -> str:
        return self.base_url

    def get_auth_headers(self) -> dict[str, str]:
        if not self.auth_token:
            return {}
        return {self.auth_header_name: self.auth_token}


class RPCProcedure(NetBoxModel):
    # Effect vocabulary is single-sourced from the domain value object.
    EFFECT_READ = Effect.READ.value
    EFFECT_WRITE = Effect.WRITE.value
    EFFECT_DESTRUCTIVE = Effect.DESTRUCTIVE.value
    EFFECT_CHOICES = (
        (EFFECT_READ, "Read"),
        (EFFECT_WRITE, "Write"),
        (EFFECT_DESTRUCTIVE, "Destructive"),
    )

    # Transport driver selected for the execution pipeline on nms-backend. This is
    # explicit data on the procedure (never encoded inside handler_id). "asyncssh"
    # is the historical default and reproduces the legacy single-/multi-command SSH
    # behaviour; the other drivers opt into the pluggable driver layer.
    TRANSPORT_ASYNCSSH = "asyncssh"
    TRANSPORT_SCRAPLI = "scrapli"
    TRANSPORT_NETMIKO = "netmiko"
    TRANSPORT_PARAMIKO = "paramiko"
    TRANSPORT_NAPALM = "napalm"
    TRANSPORT_DRIVER_CHOICES = (
        (TRANSPORT_ASYNCSSH, "AsyncSSH (default)"),
        (TRANSPORT_SCRAPLI, "Scrapli"),
        (TRANSPORT_NETMIKO, "Netmiko"),
        (TRANSPORT_PARAMIKO, "Paramiko"),
        (TRANSPORT_NAPALM, "NAPALM"),
    )

    # Output parser the nms-backend pipeline applies to raw command output when the
    # driver did not already return structured data. "none" leaves output untouched
    # (legacy behaviour); "auto" runs the native-JSON/XML -> jc -> TextFSM -> TTP ->
    # Genie -> regex chain; the explicit values pin a single parser backend.
    PARSER_NONE = "none"
    PARSER_AUTO = "auto"
    PARSER_JSON = "json"
    PARSER_XML = "xml"
    PARSER_JC = "jc"
    PARSER_TEXTFSM = "textfsm"
    PARSER_TTP = "ttp"
    PARSER_GENIE = "genie"
    PARSER_REGEX = "regex"
    OUTPUT_PARSER_CHOICES = (
        (PARSER_NONE, "None (raw output)"),
        (PARSER_AUTO, "Auto (native JSON/XML, then jc/TextFSM/TTP/Genie/regex)"),
        (PARSER_JSON, "Native JSON"),
        (PARSER_XML, "Native XML"),
        (PARSER_JC, "jc"),
        (PARSER_TEXTFSM, "TextFSM"),
        (PARSER_TTP, "TTP"),
        (PARSER_GENIE, "Genie"),
        (PARSER_REGEX, "Regex"),
    )

    name = models.CharField(max_length=255, unique=True)
    handler_id = models.CharField(max_length=255)
    version = models.PositiveIntegerField(default=1)
    enabled = models.BooleanField(default=True)
    target_models = models.JSONField(
        default=list,
        blank=True,
        help_text="Allowed target model labels such as dcim.device or netbox_gpon.olt.",
    )
    effect = models.CharField(
        max_length=20, choices=EFFECT_CHOICES, default=EFFECT_READ
    )
    timeout_seconds = models.PositiveIntegerField(default=30)
    approval_required = models.BooleanField(default=False)
    params_schema = models.JSONField(default=dict, blank=True)
    result_schema = models.JSONField(default=dict, blank=True)
    transport_driver = models.CharField(
        max_length=20,
        choices=TRANSPORT_DRIVER_CHOICES,
        default=TRANSPORT_ASYNCSSH,
        help_text=(
            "Transport driver the nms-backend execution pipeline uses for this "
            "procedure. AsyncSSH preserves the legacy behaviour."
        ),
    )
    output_parser = models.CharField(
        max_length=20,
        choices=OUTPUT_PARSER_CHOICES,
        default=PARSER_NONE,
        help_text=(
            "Parser applied to raw command output when the driver returns "
            "unstructured text. 'none' keeps raw output; 'auto' runs the parser "
            "chain (native JSON/XML first, then jc/TextFSM/TTP/Genie/regex)."
        ),
    )
    output_schema = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Optional parser hints / target internal schema (e.g. a TextFSM "
            "template reference, jc parser name, or regex field map) consumed by "
            "the nms-backend output pipeline."
        ),
    )
    description = models.CharField(max_length=255, blank=True)
    comments = models.TextField(blank=True)

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("name", "version")
        permissions = (
            ("execute_rpcprocedure", "Can execute RPC procedure"),
            ("approve_rpcprocedure", "Can approve RPC procedure"),
        )
        verbose_name = "RPC Procedure"

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        from django.urls import reverse

        return reverse("plugins:netbox_rpc:rpcprocedure", args=[self.pk])

    @property
    def ordered_commands(self):
        """Return this procedure's command steps in execution order."""

        return self.commands.all().order_by("sequence")


class RPCProcedureCommand(NetBoxModel):
    """Structured command step owned by an RPC procedure.

    Commands are fixed argv/CLI token lists. Caller input may only flow through
    declared placeholders; arbitrary shell text is never accepted here.
    """

    STEP_TYPE_SHELL_ARGV = "shell_argv"
    STEP_TYPE_DEVICE_CLI = "device_cli"
    STEP_TYPE_CHOICES = (
        (STEP_TYPE_SHELL_ARGV, "Shell argv"),
        (STEP_TYPE_DEVICE_CLI, "Device CLI"),
    )

    DEVICE_CLI_EXEC = "exec"
    DEVICE_CLI_CONFIG = "config"
    DEVICE_CLI_MODE_CHOICES = (
        (DEVICE_CLI_EXEC, "Exec"),
        (DEVICE_CLI_CONFIG, "Config"),
    )

    procedure = models.ForeignKey(
        RPCProcedure,
        related_name="commands",
        on_delete=models.CASCADE,
    )
    sequence = models.PositiveIntegerField()
    step_type = models.CharField(
        max_length=20,
        choices=STEP_TYPE_CHOICES,
        default=STEP_TYPE_SHELL_ARGV,
    )
    device_cli_mode = models.CharField(
        max_length=20,
        choices=DEVICE_CLI_MODE_CHOICES,
        blank=True,
    )
    argv = models.JSONField(default=list)
    description = models.CharField(max_length=255, blank=True)
    condition_param = models.CharField(max_length=100, blank=True)
    condition_negate = models.BooleanField(default=False)
    for_each_param = models.CharField(max_length=100, blank=True)
    continue_on_error = models.BooleanField(default=False)

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("procedure", "sequence")
        unique_together = (("procedure", "sequence"),)
        verbose_name = "RPC Procedure Command"

    def __str__(self) -> str:
        return f"{self.procedure.name}#{self.sequence}"

    def get_absolute_url(self) -> str:
        from django.urls import reverse

        return reverse("plugins:netbox_rpc:rpcprocedurecommand", args=[self.pk])

    def clean(self) -> None:
        super().clean()
        errors: dict[str, object] = {}
        allowed_placeholders = self._allowed_placeholder_names()

        if self.step_type != self.STEP_TYPE_DEVICE_CLI and self.device_cli_mode:
            errors["device_cli_mode"] = (
                "device_cli_mode is only valid for device_cli steps."
            )

        if not isinstance(self.argv, list) or not self.argv:
            errors["argv"] = "argv must be a non-empty list of non-empty string tokens."
        else:
            token_errors = []
            for index, token in enumerate(self.argv, start=1):
                if not isinstance(token, str) or not token:
                    token_errors.append(f"token {index} must be a non-empty string")
                    continue
                if not token_is_safe(token):
                    token_errors.append(f"{token!r} contains unsafe characters")
                    continue
                placeholders = extract_placeholders(token)
                if len(placeholders) > 1:
                    token_errors.append(f"{token!r} contains more than one placeholder")
                if not token_has_balanced_placeholders(token):
                    token_errors.append(
                        f"{token!r} contains malformed placeholder braces"
                    )
                for placeholder in placeholders:
                    if placeholder not in allowed_placeholders:
                        token_errors.append(
                            f"{token!r} references unknown placeholder {placeholder!r}"
                        )
            if token_errors:
                errors["argv"] = token_errors

        for field_name in ("condition_param", "for_each_param"):
            value = getattr(self, field_name)
            if value and value not in allowed_placeholders:
                errors[field_name] = (
                    f"{value!r} is not declared in the procedure params schema."
                )

        if errors:
            raise ValidationError(errors)

    def _allowed_placeholder_names(self) -> set[str]:
        schema = self.procedure.params_schema if self.procedure_id else {}
        properties = schema.get("properties") if isinstance(schema, dict) else {}
        names = set(properties) if isinstance(properties, dict) else set()
        names.update(COMMAND_RUNTIME_KEYS)
        return names


class RPCLinuxServiceAllowlist(NetBoxModel):
    slug = models.SlugField(max_length=100, unique=True)
    systemd_unit = models.CharField(max_length=200)
    enabled = models.BooleanField(default=True)
    target_models = models.JSONField(
        default=list,
        blank=True,
        help_text="Optional model labels this service may be restarted on.",
    )
    description = models.CharField(max_length=255, blank=True)
    comments = models.TextField(blank=True)
    ssh_credential_override = models.PositiveBigIntegerField(
        null=True,
        blank=True,
        db_column="ssh_credential_override_id",
        db_index=True,
        help_text=(
            "Override the device-level DeviceService SSH credential for RPC jobs "
            "targeting this service. Leave blank to use the target device's default "
            "SSH DeviceService credential resolved by device name."
        ),
    )

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("slug",)
        verbose_name = "RPC Linux Service Allowlist Entry"

    def __str__(self) -> str:
        return self.slug

    def get_absolute_url(self) -> str:
        from django.urls import reverse

        return reverse("plugins:netbox_rpc:rpclinuxserviceallowlist", args=[self.pk])

    @property
    def ssh_credential_override_id(self) -> int | None:
        return self.ssh_credential_override

    @ssh_credential_override_id.setter
    def ssh_credential_override_id(self, value: int | None) -> None:
        self.ssh_credential_override = value

    def clean(self) -> None:
        super().clean()
        if not SYSTEMD_UNIT_RE.fullmatch(self.systemd_unit or ""):
            raise ValidationError(
                {
                    "systemd_unit": (
                        "Systemd unit must contain only letters, numbers, underscore, "
                        "dash, dot, or @, with an optional .service suffix."
                    )
                }
            )


class RPCExecution(NetBoxModel):
    # Status vocabulary is single-sourced from the domain value object.
    STATUS_QUEUED = ExecutionStatus.QUEUED.value
    STATUS_RUNNING = ExecutionStatus.RUNNING.value
    STATUS_SUCCEEDED = ExecutionStatus.SUCCEEDED.value
    STATUS_FAILED = ExecutionStatus.FAILED.value
    STATUS_CANCELLED = ExecutionStatus.CANCELLED.value
    STATUS_CHOICES = (
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_FAILED, "Failed"),
        (STATUS_CANCELLED, "Cancelled"),
    )

    procedure = models.ForeignKey(
        RPCProcedure,
        on_delete=models.PROTECT,
        related_name="executions",
    )
    assigned_object_type = models.ForeignKey(
        ContentType,
        on_delete=models.PROTECT,
        related_name="+",
        verbose_name="Target type",
    )
    assigned_object_id = models.PositiveBigIntegerField(verbose_name="Target ID")
    assigned_object = GenericForeignKey(
        ct_field="assigned_object_type",
        fk_field="assigned_object_id",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    backend = models.PositiveBigIntegerField(
        null=True,
        blank=True,
        db_column="backend_id",
        db_index=True,
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_QUEUED
    )
    params = models.JSONField(default=dict, blank=True)
    normalized_params = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=100, blank=True)
    error_message = models.TextField(blank=True)
    resolved_command_hash = models.CharField(max_length=128, blank=True)
    request_id = models.CharField(max_length=100, blank=True)
    trace_id = models.CharField(max_length=100, blank=True)
    job_id = models.PositiveBigIntegerField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    comments = models.TextField(blank=True)

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("-created", "-id")
        indexes = (
            models.Index(fields=("assigned_object_type", "assigned_object_id")),
            models.Index(fields=("status", "created")),
        )
        verbose_name = "RPC Execution"

    def __str__(self) -> str:
        return f"{self.procedure.name} #{self.pk}"

    def get_absolute_url(self) -> str:
        from django.urls import reverse

        return reverse("plugins:netbox_rpc:rpcexecution", args=[self.pk])

    @property
    def backend_id(self) -> int | None:
        return self.backend

    @backend_id.setter
    def backend_id(self, value: int | None) -> None:
        self.backend = value

    @property
    def target_model_label(self) -> str:
        return (
            f"{self.assigned_object_type.app_label}.{self.assigned_object_type.model}"
        )

    @property
    def target_display(self) -> str:
        target = self.assigned_object
        if target is None:
            return f"{self.target_model_label}:{self.assigned_object_id}"
        return str(getattr(target, "name", None) or target)

    # Underscore-prefixed internal keys a future intent executor may stamp into
    # ``params`` to record that a run originated from an ``RPCIntent`` rather
    # than a direct API/UI request. Prefixed to avoid colliding with a
    # procedure's own declared parameters.
    _INTENT_PARAM_KEYS = ("_intent_name", "_intent")

    @property
    def intent_reference(self) -> str | None:
        """Best-effort intent name when this run was dispatched via an intent.

        Executing an ``RPCIntent`` is intentionally out of scope for the
        aggregate today (see ``AGENTS.md`` → Intents), so no run currently
        carries an intent marker and this returns ``None`` — such runs read as
        directly issued. When a future intent executor records its origin in
        ``params`` under one of ``_INTENT_PARAM_KEYS``, this surfaces the intent
        name so the procedure Runs tab can attribute the run to it.
        """
        params = self.params or {}
        for key in self._INTENT_PARAM_KEYS:
            value = params.get(key)
            if value:
                return str(value)
        return None

    @property
    def source_label(self) -> str:
        """How the run was issued: ``"Intent: <name>"`` or ``"Direct"``."""
        reference = self.intent_reference
        if reference:
            return f"Intent: {reference}"
        return "Direct"

    @property
    def result_steps(self) -> list:
        """Ordered per-command results (``result.steps[]``) for detail rendering.

        Each step records the exact command issued on the target plus its
        ``stdout``/``stderr``/``exit_code``/``ok`` (see
        ``docs/rpc-generated-core-jobs.md``). Returns an empty list when the run
        has not produced structured step output.
        """
        result = self.result or {}
        steps = result.get("steps")
        return steps if isinstance(steps, list) else []


class RPCExecutionEvent(NetBoxModel):
    LEVEL_DEBUG = "debug"
    LEVEL_INFO = "info"
    LEVEL_WARNING = "warning"
    LEVEL_ERROR = "error"
    LEVEL_CHOICES = (
        (LEVEL_DEBUG, "Debug"),
        (LEVEL_INFO, "Info"),
        (LEVEL_WARNING, "Warning"),
        (LEVEL_ERROR, "Error"),
    )

    execution = models.ForeignKey(
        RPCExecution,
        on_delete=models.CASCADE,
        related_name="events",
    )
    sequence = models.PositiveIntegerField(default=1)
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default=LEVEL_INFO)
    event = models.CharField(max_length=100)
    message = models.TextField(blank=True)
    data = models.JSONField(default=dict, blank=True)
    payload_hash = models.CharField(max_length=128, blank=True)

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("execution", "sequence", "created")
        constraints = (
            models.UniqueConstraint(
                fields=("execution", "sequence"),
                name="netbox_rpc_event_unique_sequence",
            ),
        )
        verbose_name = "RPC Execution Event"

    def __str__(self) -> str:
        return f"{self.execution_id}:{self.sequence}:{self.event}"

    @staticmethod
    def hash_payload(payload: object) -> str:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def save(self, *args, **kwargs) -> None:
        if not self._state.adding:
            raise ValidationError("RPCExecutionEvent rows are append-only.")
        if not self.payload_hash:
            self.payload_hash = self.hash_payload(
                {
                    "level": self.level,
                    "event": self.event,
                    "message": self.message,
                    "data": self.data or {},
                }
            )
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs) -> None:
        raise ValidationError("RPCExecutionEvent rows are append-only.")


class RPCIntent(NetBoxModel):
    """Declarative grouping of RPCProcedures — the "what" of an operation.

    An intent declares *what* needs to be done; the grouped ``RPCProcedure``s
    (together with their commands) declare *how*. ``execution_mode`` declares the
    trigger topology:

    - ``sequential`` — the grouped procedures are nested and triggered one after
      another in the declared ``sequence`` order;
    - ``parallel`` — the grouped procedures are triggered concurrently, with no
      nesting at all (``sequence`` is then informational).

    Intents are declarative reference-data/configuration: plain NetBox CRUD,
    ObjectChange-audited, and NOT event-sourced — consistent with
    ``RPCProcedure``, ``RPCLinuxServiceAllowlist``, and ``RPCBackend``.

    Actually *executing* an intent (fanning out one child ``RPCExecution`` per
    grouped procedure) is intentionally out of scope for this model. Any future
    executor MUST continue to honour each procedure's ``approval_required`` /
    ``effect`` gating and the LLM Agent Safety Guardrails; an intent must never
    become a way to bypass approval on a destructive procedure.
    """

    # Execution-mode vocabulary is single-sourced from the domain value object.
    MODE_SEQUENTIAL = ExecutionMode.SEQUENTIAL.value
    MODE_PARALLEL = ExecutionMode.PARALLEL.value
    EXECUTION_MODE_CHOICES = (
        (MODE_SEQUENTIAL, "Sequential (nested, ordered)"),
        (MODE_PARALLEL, "Parallel (concurrent, not nested)"),
    )

    name = models.CharField(max_length=255, unique=True)
    execution_mode = models.CharField(
        max_length=20,
        choices=EXECUTION_MODE_CHOICES,
        default=MODE_SEQUENTIAL,
        help_text=(
            "How the grouped procedures are triggered. 'sequential' nests and "
            "runs them one after another in sequence order; 'parallel' runs them "
            "concurrently with no nesting."
        ),
    )
    enabled = models.BooleanField(default=True)
    procedures = models.ManyToManyField(
        RPCProcedure,
        through="RPCIntentProcedure",
        related_name="intents",
        blank=True,
    )
    description = models.CharField(max_length=255, blank=True)
    comments = models.TextField(blank=True)

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("name",)
        permissions = (("execute_rpcintent", "Can execute RPC intent"),)
        verbose_name = "RPC Intent"

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        from django.urls import reverse

        return reverse("plugins:netbox_rpc:rpcintent", args=[self.pk])

    @property
    def ordered_intent_procedures(self):
        """Through rows in declared execution order (``sequence`` then id)."""
        return self.intent_procedures.select_related("procedure").all()

    @property
    def procedure_count(self) -> int:
        return self.procedures.count()

    def serialize_object(self, exclude=None):
        # Include the ordered grouped procedures so membership/order changes are
        # captured in the object's changelog. Django never fires ``m2m_changed``
        # for a ``through``-M2M with extra fields, so this is how a reorder shows
        # up in the ObjectChange diff — RPCIntentForm/RPCIntentSerializer
        # reconcile the through rows *before* the model save on the update path so
        # this postchange snapshot reflects the new order.
        data = super().serialize_object(exclude=exclude)
        data["intent_procedures"] = [
            {"procedure": ip.procedure_id, "sequence": ip.sequence}
            for ip in self.intent_procedures.all()
        ]
        return data


class RPCIntentProcedure(models.Model):
    """Through model ordering the procedures grouped by an ``RPCIntent``.

    ``sequence`` orders the procedures for ``sequential`` (nested) execution; it
    is informational when the intent's ``execution_mode`` is ``parallel``.
    """

    intent = models.ForeignKey(
        RPCIntent,
        on_delete=models.CASCADE,
        related_name="intent_procedures",
    )
    procedure = models.ForeignKey(
        RPCProcedure,
        on_delete=models.PROTECT,
        related_name="intent_procedures",
    )
    sequence = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        help_text="Execution order within the intent (used in sequential mode).",
    )

    class Meta:
        app_label = "netbox_rpc"
        ordering = ("intent", "sequence", "id")
        constraints = (
            models.UniqueConstraint(
                fields=("intent", "procedure"),
                name="netbox_rpc_intent_unique_procedure",
            ),
            models.CheckConstraint(
                condition=models.Q(sequence__gte=1),
                name="netbox_rpc_intentprocedure_sequence_gte_1",
            ),
        )
        verbose_name = "RPC Intent Procedure"

    def __str__(self) -> str:
        return f"{self.intent_id}:{self.sequence}:{self.procedure_id}"
