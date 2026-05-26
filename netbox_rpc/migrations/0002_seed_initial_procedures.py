from django.db import migrations

from netbox_rpc.constants import INITIAL_PROCEDURES


def seed_initial_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for item in INITIAL_PROCEDURES:
        defaults = dict(item)
        name = defaults.pop("name")
        RPCProcedure.objects.update_or_create(name=name, defaults=defaults)


def unseed_initial_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[item["name"] for item in INITIAL_PROCEDURES]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_initial_procedures, unseed_initial_procedures),
    ]
