"""Store execution intent attribution outside caller params."""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0078_seed_openbao_procedures")]

    operations = [
        migrations.AddField(
            model_name="rpcexecution",
            name="source_intent",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                help_text="Intent that created this execution; null for direct runs.",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="source_executions",
                to="netbox_rpc.rpcintent",
            ),
        ),
    ]
