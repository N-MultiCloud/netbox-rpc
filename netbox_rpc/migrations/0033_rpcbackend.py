import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        # Final extras migration in NetBox 4.5.8; also an ancestor in 4.6.x.
        ("extras", "0134_owner"),
        ("netbox_rpc", "0032_merge_payload_hash_and_pipeline_exemplars"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCBackend",
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
                ("name", models.CharField(max_length=255, unique=True)),
                ("base_url", models.URLField(max_length=500)),
                ("verify_ssl", models.BooleanField(default=True)),
                (
                    "auth_header_name",
                    models.CharField(default="Authorization", max_length=100),
                ),
                ("auth_token", models.CharField(blank=True, max_length=4096)),
                ("comments", models.TextField(blank=True)),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem", to="extras.Tag"
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Backend",
                "ordering": ("name",),
            },
        ),
    ]
