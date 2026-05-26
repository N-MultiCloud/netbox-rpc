from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("contenttypes", "0002_remove_content_type_name"),
        ("netbox_nms", "0015_pfsense_service_type"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCProcedure",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict)),
                ("name", models.CharField(max_length=255, unique=True)),
                ("handler_id", models.CharField(max_length=255)),
                ("version", models.PositiveIntegerField(default=1)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "target_models",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Allowed target model labels such as dcim.device or netbox_gpon.olt.",
                    ),
                ),
                (
                    "effect",
                    models.CharField(
                        choices=[
                            ("read", "Read"),
                            ("write", "Write"),
                            ("destructive", "Destructive"),
                        ],
                        default="read",
                        max_length=20,
                    ),
                ),
                ("timeout_seconds", models.PositiveIntegerField(default=30)),
                ("approval_required", models.BooleanField(default=False)),
                ("params_schema", models.JSONField(blank=True, default=dict)),
                ("result_schema", models.JSONField(blank=True, default=dict)),
                ("description", models.CharField(blank=True, max_length=255)),
                ("comments", models.TextField(blank=True)),
            ],
            options={
                "verbose_name": "RPC Procedure",
                "ordering": ("name", "version"),
                "permissions": (
                    ("execute_rpcprocedure", "Can execute RPC procedure"),
                    ("approve_rpcprocedure", "Can approve RPC procedure"),
                ),
            },
        ),
        migrations.CreateModel(
            name="RPCLinuxServiceAllowlist",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict)),
                ("slug", models.SlugField(max_length=100, unique=True)),
                ("systemd_unit", models.CharField(max_length=200)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "target_models",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Optional model labels this service may be restarted on.",
                    ),
                ),
                ("description", models.CharField(blank=True, max_length=255)),
                ("comments", models.TextField(blank=True)),
            ],
            options={
                "verbose_name": "RPC Linux Service Allowlist Entry",
                "ordering": ("slug",),
            },
        ),
        migrations.CreateModel(
            name="RPCExecution",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict)),
                ("assigned_object_id", models.PositiveBigIntegerField(verbose_name="Target ID")),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                        ],
                        default="queued",
                        max_length=20,
                    ),
                ),
                ("params", models.JSONField(blank=True, default=dict)),
                ("normalized_params", models.JSONField(blank=True, default=dict)),
                ("result", models.JSONField(blank=True, default=dict)),
                ("error_code", models.CharField(blank=True, max_length=100)),
                ("error_message", models.TextField(blank=True)),
                ("resolved_command_hash", models.CharField(blank=True, max_length=128)),
                ("request_id", models.CharField(blank=True, max_length=100)),
                ("trace_id", models.CharField(blank=True, max_length=100)),
                ("job_id", models.PositiveBigIntegerField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("comments", models.TextField(blank=True)),
                (
                    "assigned_object_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="+",
                        to="contenttypes.contenttype",
                        verbose_name="Target type",
                    ),
                ),
                (
                    "backend",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="rpc_executions",
                        to="netbox_nms.nmsbackend",
                    ),
                ),
                (
                    "procedure",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="executions",
                        to="netbox_rpc.rpcprocedure",
                    ),
                ),
                (
                    "requested_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Execution",
                "ordering": ("-created", "-id"),
            },
        ),
        migrations.CreateModel(
            name="RPCExecutionEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict)),
                ("sequence", models.PositiveIntegerField(default=1)),
                (
                    "level",
                    models.CharField(
                        choices=[
                            ("debug", "Debug"),
                            ("info", "Info"),
                            ("warning", "Warning"),
                            ("error", "Error"),
                        ],
                        default="info",
                        max_length=20,
                    ),
                ),
                ("event", models.CharField(max_length=100)),
                ("message", models.TextField(blank=True)),
                ("data", models.JSONField(blank=True, default=dict)),
                (
                    "execution",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="events",
                        to="netbox_rpc.rpcexecution",
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Execution Event",
                "ordering": ("execution", "sequence", "created"),
            },
        ),
        migrations.AddIndex(
            model_name="rpcexecution",
            index=models.Index(
                fields=["assigned_object_type", "assigned_object_id"],
                name="netbox_rpc_assigned_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="rpcexecution",
            index=models.Index(fields=["status", "created"], name="netbox_rpc_status_idx"),
        ),
        migrations.AddConstraint(
            model_name="rpcexecutionevent",
            constraint=models.UniqueConstraint(
                fields=("execution", "sequence"),
                name="netbox_rpc_event_unique_sequence",
            ),
        ),
    ]
