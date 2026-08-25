"""Allow the generic Ubuntu service procedures to manage OpenBao."""

from django.db import migrations


def _seed(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model(
        "netbox_rpc", "RPCLinuxServiceAllowlist"
    )
    RPCLinuxServiceAllowlist.objects.update_or_create(
        slug="openbao",
        defaults={
            "systemd_unit": "openbao.service",
            "enabled": True,
            "target_models": [
                "dcim.device",
                "virtualization.virtualmachine",
            ],
            "description": "OpenBao server service",
        },
    )


def _remove(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model(
        "netbox_rpc", "RPCLinuxServiceAllowlist"
    )
    RPCLinuxServiceAllowlist.objects.filter(slug="openbao").delete()


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0076_merge_gitea_upgrade_and_ansible_policy")]
    operations = [migrations.RunPython(_seed, reverse_code=_remove)]
