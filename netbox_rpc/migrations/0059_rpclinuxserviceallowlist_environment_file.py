from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0058_seed_netbox_service_allowlist"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpclinuxserviceallowlist",
            name="environment_file",
            field=models.CharField(
                blank=True,
                help_text=(
                    "Optional operator-managed environment file associated with "
                    "this service. RPC normalizers derive this path from the "
                    "allowlist; callers cannot provide or override it."
                ),
                max_length=255,
                null=True,
            ),
        ),
    ]
