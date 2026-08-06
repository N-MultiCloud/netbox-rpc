"""Seed the ordered Ubuntu 24.04 to 26.04 LTS upgrade intent.

Intent and through-row data is inline so this migration remains stable across
runtime constant changes.
"""

from django.db import migrations


_INTENT_NAME = "Update Ubuntu OS from 24 LTS to 26 LTS"
_PROCEDURE_NAMES = (
    "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade",
    "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state",
    "os.linux.ubuntu.24.upgrade_26.run_upgrade",
    "os.linux.ubuntu.24.upgrade_26.verify_postupgrade",
)


def _seed_ubuntu_upgrade_26_intent(apps, schema_editor):
    RPCIntent = apps.get_model("netbox_rpc", "RPCIntent")
    RPCIntentProcedure = apps.get_model("netbox_rpc", "RPCIntentProcedure")
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")

    intent, _ = RPCIntent.objects.update_or_create(
        name=_INTENT_NAME,
        defaults={
            "execution_mode": "sequential",
            "enabled": True,
            "description": "Analyze, preserve, upgrade, and verify an Ubuntu LTS host.",
            "comments": (
                "The v1 intent runner creates children synchronously but does not "
                "serialize their RQ execution; operators must gate each procedure "
                "on the prior result."
            ),
        },
    )
    for sequence, procedure_name in enumerate(_PROCEDURE_NAMES, start=1):
        procedure = RPCProcedure.objects.get(name=procedure_name)
        RPCIntentProcedure.objects.update_or_create(
            intent=intent,
            procedure=procedure,
            defaults={"sequence": sequence},
        )


def _remove_ubuntu_upgrade_26_intent(apps, schema_editor):
    RPCIntent = apps.get_model("netbox_rpc", "RPCIntent")
    RPCIntent.objects.filter(name=_INTENT_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0064_seed_ubuntu_upgrade_26_commands"),
    ]

    operations = [
        migrations.RunPython(
            _seed_ubuntu_upgrade_26_intent,
            reverse_code=_remove_ubuntu_upgrade_26_intent,
        ),
    ]
