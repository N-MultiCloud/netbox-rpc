import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0035_seed_ookla_diagnostic_procedures"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCProcedureCommand",
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
                ("sequence", models.PositiveIntegerField()),
                (
                    "step_type",
                    models.CharField(
                        choices=[
                            ("shell_argv", "Shell argv"),
                            ("device_cli", "Device CLI"),
                        ],
                        default="shell_argv",
                        max_length=20,
                    ),
                ),
                (
                    "device_cli_mode",
                    models.CharField(
                        blank=True,
                        choices=[("exec", "Exec"), ("config", "Config")],
                        max_length=20,
                    ),
                ),
                ("argv", models.JSONField(default=list)),
                ("description", models.CharField(blank=True, max_length=255)),
                ("condition_param", models.CharField(blank=True, max_length=100)),
                ("condition_negate", models.BooleanField(default=False)),
                ("for_each_param", models.CharField(blank=True, max_length=100)),
                ("continue_on_error", models.BooleanField(default=False)),
                (
                    "procedure",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="commands",
                        to="netbox_rpc.rpcprocedure",
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Procedure Command",
                "ordering": ("procedure", "sequence"),
                "unique_together": {("procedure", "sequence")},
            },
        ),
    ]
