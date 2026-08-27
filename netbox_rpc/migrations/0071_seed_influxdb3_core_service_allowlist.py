"""Seed the InfluxDB 3 Core systemd unit into the Linux service allowlist.

Migration ``0053`` seeded ``slug="influxdb"`` -> ``influxdb.service``, which is the
**OSS 2** unit. InfluxDB 3 Core ships a different unit, ``influxdb3-core.service``,
so the generic Linux systemd procedures could not reach it. This row closes that gap;
it is additive and leaves the existing OSS 2 row untouched.
"""

from django.db import migrations

SLUG = "influxdb3-core"


def seed_influxdb3_core_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model("netbox_rpc", "RPCLinuxServiceAllowlist")
    RPCLinuxServiceAllowlist.objects.update_or_create(
        slug=SLUG,
        defaults={
            "systemd_unit": "influxdb3-core.service",
            "enabled": True,
            "target_models": ["dcim.device", "virtualization.virtualmachine"],
            "description": "InfluxDB 3 Core systemd service",
        },
    )


def unseed_influxdb3_core_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model("netbox_rpc", "RPCLinuxServiceAllowlist")
    RPCLinuxServiceAllowlist.objects.filter(slug=SLUG).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0070_rpcapprovalrequest_policy_hashes"),
    ]

    operations = [
        migrations.RunPython(
            seed_influxdb3_core_service_allowlist,
            reverse_code=unseed_influxdb3_core_service_allowlist,
        ),
    ]
