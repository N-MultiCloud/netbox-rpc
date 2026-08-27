"""Persist one durable conflict fence per canonical Gitea runner token scope."""

import django.db.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models
from django.db.migrations.exceptions import IrreversibleError


_CANONICAL_SCOPES = (
    "N-MultiCloud",
    "emersonfelipesp/netbox-proxbox",
    "emersonfelipesp/proxbox-api",
)


def seed_scope_fences(apps, schema_editor):
    Fence = apps.get_model("netbox_rpc", "RPCGiteaRunnerScopeFence")
    if Fence.objects.exists():
        raise RuntimeError(
            "Migration 0081 cannot adopt existing Gitea runner scope fences."
        )
    Fence.objects.bulk_create(
        [Fence(canonical_scope=scope, state="clear") for scope in _CANONICAL_SCOPES]
    )


def refuse_scope_fence_removal(apps, schema_editor):
    raise IrreversibleError(
        "Migration 0081 is intentionally irreversible because deleting durable "
        "Gitea token reconciliation state can permit unsafe credential reuse."
    )


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0134_owner"),
        ("netbox_rpc", "0080_seed_gitea_runner_register"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCGiteaRunnerScopeFence",
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
                ("canonical_scope", models.CharField(max_length=200, unique=True)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("clear", "Clear"),
                            ("pending", "Pending token acquisition"),
                            ("blocked", "Reset reconciliation required"),
                        ],
                        default="clear",
                        max_length=16,
                    ),
                ),
                (
                    "expected_token_sha256",
                    models.CharField(blank=True, max_length=64),
                ),
                ("last_reset_state", models.CharField(blank=True, max_length=64)),
                (
                    "last_prior_token_id",
                    models.PositiveBigIntegerField(blank=True, null=True),
                ),
                (
                    "last_replacement_token_id",
                    models.PositiveBigIntegerField(blank=True, null=True),
                ),
                (
                    "last_prior_active_sha256",
                    models.CharField(blank=True, max_length=64),
                ),
                (
                    "blocking_execution",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="+",
                        to="netbox_rpc.rpcexecution",
                    ),
                ),
                (
                    "reconciliation_execution",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
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
                "verbose_name": "RPC Gitea Runner Scope Fence",
                "verbose_name_plural": "RPC Gitea Runner Scope Fences",
                "ordering": ("canonical_scope",),
                "constraints": [
                    models.CheckConstraint(
                        condition=(
                            models.Q(
                                state="clear",
                                blocking_execution__isnull=True,
                                expected_token_sha256="",
                            )
                            | models.Q(
                                state__in=("pending", "blocked"),
                                blocking_execution__isnull=False,
                            )
                        ),
                        name="netbox_rpc_gitea_scope_fence_state_consistent",
                    ),
                    models.CheckConstraint(
                        condition=(
                            models.Q(reconciliation_execution__isnull=True)
                            | models.Q(state="blocked")
                        ),
                        name="netbox_rpc_gitea_scope_fence_reconcile_consistent",
                    ),
                ],
            },
        ),
        migrations.RunPython(
            seed_scope_fences,
            reverse_code=refuse_scope_fence_removal,
        ),
    ]
