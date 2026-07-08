"""Add the RPCIntent declarative grouping model and its ordered through table.

An ``RPCIntent`` groups one or more ``RPCProcedure``s (each of which, with its
commands, declares *how* work is done) and declares *what* needs to be done, plus
an ``execution_mode`` (sequential/nested vs parallel/concurrent). Intents are
declarative reference-data — plain NetBox CRUD, not event-sourced. This migration
is additive (two new models + an ordered M2M) and has no ``netbox_nms``
dependency, preserving standalone boot.
"""

import django.db.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0138_customfieldchoiceset_choice_colors"),
        ("netbox_rpc", "0038_merge_rpc_procedure_commands"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCIntent",
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
                (
                    "execution_mode",
                    models.CharField(
                        choices=[
                            ("sequential", "Sequential (nested, ordered)"),
                            ("parallel", "Parallel (concurrent, not nested)"),
                        ],
                        default="sequential",
                        help_text=(
                            "How the grouped procedures are triggered. "
                            "'sequential' nests and runs them one after another "
                            "in sequence order; 'parallel' runs them concurrently "
                            "with no nesting."
                        ),
                        max_length=20,
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                ("description", models.CharField(blank=True, max_length=255)),
                ("comments", models.TextField(blank=True)),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem", to="extras.Tag"
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Intent",
                "ordering": ("name",),
                "permissions": (
                    ("execute_rpcintent", "Can execute RPC intent"),
                ),
            },
        ),
        migrations.CreateModel(
            name="RPCIntentProcedure",
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
                (
                    "sequence",
                    models.PositiveIntegerField(
                        default=1,
                        help_text=(
                            "Execution order within the intent "
                            "(used in sequential mode)."
                        ),
                    ),
                ),
                (
                    "intent",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="intent_procedures",
                        to="netbox_rpc.rpcintent",
                    ),
                ),
                (
                    "procedure",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="intent_procedures",
                        to="netbox_rpc.rpcprocedure",
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Intent Procedure",
                "ordering": ("intent", "sequence", "id"),
                "constraints": [
                    models.UniqueConstraint(
                        fields=("intent", "procedure"),
                        name="netbox_rpc_intent_unique_procedure",
                    ),
                ],
            },
        ),
        migrations.AddField(
            model_name="rpcintent",
            name="procedures",
            field=models.ManyToManyField(
                blank=True,
                related_name="intents",
                through="netbox_rpc.RPCIntentProcedure",
                to="netbox_rpc.rpcprocedure",
            ),
        ),
    ]
