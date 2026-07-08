from django.contrib.postgres.fields import ArrayField
from django.db import migrations, models

_DRIVER_CHOICES = [
    ("asyncssh", "AsyncSSH (default)"),
    ("paramiko", "Paramiko"),
    ("subprocess", "subprocess (OpenSSH)"),
    ("fabric", "Fabric"),
    ("scrapli", "Scrapli"),
    ("netmiko", "Netmiko"),
    ("napalm", "NAPALM"),
    ("nornir", "Nornir"),
]

_CHAIN_HELP = (
    "Ordered transport-driver priority + fallback chain (index 0 is tried first). "
    "Leave empty to use the single Transport driver above. The execution backend "
    "advances to the next capable driver when one is unavailable or a connection "
    "fails; a command-level failure stops the chain."
)

_DRIVER_HELP = (
    "Transport driver the nms-backend execution pipeline uses for this procedure. "
    "AsyncSSH preserves the legacy behaviour."
)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0041_rpcprocedurecommand_templating"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpcprocedure",
            name="transport_driver_chain",
            field=ArrayField(
                base_field=models.CharField(choices=_DRIVER_CHOICES, max_length=32),
                blank=True,
                default=list,
                help_text=_CHAIN_HELP,
                size=None,
            ),
        ),
        migrations.AlterField(
            model_name="rpcprocedure",
            name="transport_driver",
            field=models.CharField(
                choices=_DRIVER_CHOICES,
                default="asyncssh",
                help_text=_DRIVER_HELP,
                max_length=20,
            ),
        ),
    ]
