from django.db import migrations


def seed_influxdb_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model(
        "netbox_rpc", "RPCLinuxServiceAllowlist"
    )
    RPCLinuxServiceAllowlist.objects.update_or_create(
        slug="influxdb",
        defaults={
            "systemd_unit": "influxdb.service",
            "enabled": True,
            "target_models": ["dcim.device", "virtualization.virtualmachine"],
            "description": "InfluxDB OSS 2.x systemd service",
        },
    )


def unseed_influxdb_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model(
        "netbox_rpc", "RPCLinuxServiceAllowlist"
    )
    RPCLinuxServiceAllowlist.objects.filter(slug="influxdb").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0052_seed_samba_write_commands"),
    ]

    operations = [
        migrations.RunPython(
            seed_influxdb_service_allowlist,
            reverse_code=unseed_influxdb_service_allowlist,
        ),
    ]
