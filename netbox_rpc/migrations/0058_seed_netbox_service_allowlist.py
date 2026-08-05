from django.db import migrations

# NetBox stack systemd units, controllable through the generic Ubuntu-24 systemd
# procedures (os.linux.ubuntu.24.restart_service / status_service / journal_tail
# / start_service / stop_service) once present in the allowlist -- exactly like
# the InfluxDB row seeded in 0053. No new procedure or nms-backend handler is
# needed; these rows are reference data the existing restart_service normalizer
# and handler consume. Restarting netbox-rq also sweeps orphaned/zombie RQ jobs.
NETBOX_SERVICE_ALLOWLIST = (
    {
        "slug": "netbox",
        "systemd_unit": "netbox.service",
        "description": "NetBox WSGI (gunicorn) service",
    },
    {
        "slug": "netbox-rq",
        "systemd_unit": "netbox-rq.service",
        "description": "NetBox RQ background-worker service "
        "(restart to clear stuck/zombie jobs)",
    },
)


def seed_netbox_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model(
        "netbox_rpc", "RPCLinuxServiceAllowlist"
    )
    for item in NETBOX_SERVICE_ALLOWLIST:
        RPCLinuxServiceAllowlist.objects.update_or_create(
            slug=item["slug"],
            defaults={
                "systemd_unit": item["systemd_unit"],
                "enabled": True,
                "target_models": ["dcim.device", "virtualization.virtualmachine"],
                "description": item["description"],
            },
        )


def unseed_netbox_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model(
        "netbox_rpc", "RPCLinuxServiceAllowlist"
    )
    RPCLinuxServiceAllowlist.objects.filter(
        slug__in=[item["slug"] for item in NETBOX_SERVICE_ALLOWLIST]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0057_seed_fileserver_samba_intents"),
    ]

    operations = [
        migrations.RunPython(
            seed_netbox_service_allowlist,
            reverse_code=unseed_netbox_service_allowlist,
        ),
    ]
