"""Additive foundation for the two-person RPC approval workflow (issue #164).

Creates the immutable ``RPCApprovalRequest`` snapshot model. No existing table
is altered and no data is migrated, so this applies cleanly on a populated
production database and does not change current execution behaviour (routing
approval-required work through the request/pending path lands in #165).

The ``extras`` dependency is pinned to ``0134_owner`` — a node present in BOTH
NetBox 4.5.8 and 4.6.x — so the migration graph stays installable on the
plugin's real ``min_version = "4.5.8"`` floor (the taggit ``tags`` M2M only
needs ``extras.Tag`` / ``extras.TaggedItem``, which exist well before 0134).
"""

import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("extras", "0134_owner"),
        ("netbox_rpc", "0048_seed_passbolt_migration_procedures"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCApprovalRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
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
                ("procedure_id", models.PositiveBigIntegerField()),
                ("procedure_version", models.CharField(blank=True, max_length=64)),
                ("effect", models.CharField(max_length=20)),
                ("target_type_id", models.PositiveBigIntegerField()),
                ("target_id", models.PositiveBigIntegerField()),
                (
                    "target_snapshot_hash",
                    models.CharField(blank=True, max_length=128),
                ),
                ("normalized_params", models.JSONField(blank=True, default=dict)),
                ("command_fingerprint", models.JSONField(blank=True, default=dict)),
                (
                    "backend_id",
                    models.PositiveBigIntegerField(blank=True, null=True),
                ),
                (
                    "credential_policy_ref",
                    models.CharField(blank=True, max_length=200),
                ),
                (
                    "requested_by_id",
                    models.PositiveBigIntegerField(blank=True, null=True),
                ),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("stream_version", models.PositiveIntegerField(default=0)),
                ("payload_hash", models.CharField(blank=True, max_length=128)),
                (
                    "execution",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="approval_request",
                        to="netbox_rpc.rpcexecution",
                    ),
                ),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem",
                        to="extras.Tag",
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Approval Request",
                "verbose_name_plural": "RPC Approval Requests",
            },
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
    ]
