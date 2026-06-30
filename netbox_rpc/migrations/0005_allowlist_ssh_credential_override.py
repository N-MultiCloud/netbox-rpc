from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0004_seed_systemd_management_procedures"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpclinuxserviceallowlist",
            name="ssh_credential_override",
            field=models.PositiveBigIntegerField(
                blank=True,
                db_column="ssh_credential_override_id",
                db_index=True,
                help_text=(
                    "Override the device-level DeviceService SSH credential for RPC jobs "
                    "targeting this service. Leave blank to use the target device's default "
                    "SSH DeviceService credential resolved by device name."
                ),
                null=True,
            ),
        ),
    ]
