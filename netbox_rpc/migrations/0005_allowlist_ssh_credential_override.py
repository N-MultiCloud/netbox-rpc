from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0004_seed_systemd_management_procedures"),
        ("netbox_nms", "0027_device_credential_ssh_key_auth"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpclinuxserviceallowlist",
            name="ssh_credential_override",
            field=models.ForeignKey(
                blank=True,
                help_text=(
                    "Override the device-level DeviceService SSH credential for RPC jobs "
                    "targeting this service."
                ),
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="rpc_allowlist_entries",
                to="netbox_nms.devicecredential",
            ),
        ),
    ]
