import django.db.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        # Final extras migration in NetBox 4.5.8; also an ancestor in 4.6.x.
        ("extras", "0134_owner"),
        ("netbox_rpc", "0043_rpcbackend_ip_domain"),
    ]

    operations = [
        migrations.CreateModel(
            name="RpcPluginSettings",
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
                (
                    "custom_field_data",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        encoder=utilities.json.CustomFieldJSONEncoder,
                    ),
                ),
                (
                    "singleton_key",
                    models.CharField(
                        default="default",
                        editable=False,
                        max_length=32,
                        unique=True,
                    ),
                ),
                ("enabled", models.BooleanField(default=False)),
                ("comments", models.TextField(blank=True)),
                (
                    "backend",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="netbox_rpc.rpcbackend",
                    ),
                ),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem", to="extras.Tag"
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC plugin settings",
                "verbose_name_plural": "RPC plugin settings",
            },
        ),
    ]
