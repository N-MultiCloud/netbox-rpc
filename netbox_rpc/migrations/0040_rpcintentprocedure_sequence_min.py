"""Enforce RPCIntentProcedure.sequence >= 1 at the model and DB level.

The form and API always renumber ``sequence`` from 1, but a direct ORM/fixture
write could create ``sequence=0``. This migration first normalizes any existing
``sequence < 1`` rows to 1 (defensive; a no-op in practice) so the added
``CheckConstraint`` is safe to apply on populated production databases, then adds
the ``MinValueValidator(1)`` field validator and the DB check constraint.
"""

import django.core.validators
from django.db import migrations, models


def _normalize_sequences(apps, schema_editor):
    model = apps.get_model("netbox_rpc", "RPCIntentProcedure")
    model.objects.filter(sequence__lt=1).update(sequence=1)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0039_rpcintent"),
    ]

    operations = [
        migrations.RunPython(_normalize_sequences, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="rpcintentprocedure",
            name="sequence",
            field=models.PositiveIntegerField(
                default=1,
                help_text=(
                    "Execution order within the intent (used in sequential mode)."
                ),
                validators=[django.core.validators.MinValueValidator(1)],
            ),
        ),
        migrations.AddConstraint(
            model_name="rpcintentprocedure",
            constraint=models.CheckConstraint(
                condition=models.Q(sequence__gte=1),
                name="netbox_rpc_intentprocedure_sequence_gte_1",
            ),
        ),
    ]
