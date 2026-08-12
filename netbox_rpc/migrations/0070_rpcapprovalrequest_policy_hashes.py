"""Bind approval snapshots to immutable procedure policy and schema hashes."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0069_rpcexecution_approved_by"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpcapprovalrequest",
            name="backend_target_sha256",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="rpcapprovalrequest",
            name="params_schema_sha256",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="rpcapprovalrequest",
            name="procedure_policy_sha256",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="rpcapprovalrequest",
            name="result_schema_sha256",
            field=models.CharField(blank=True, max_length=128),
        ),
    ]
