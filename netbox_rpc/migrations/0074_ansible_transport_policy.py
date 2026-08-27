"""Add the Ansible transport vocabulary and the estate-wide transport policy.

Schema only — the policy is seeded by ``0075``. Splitting them keeps each
independently reversible: rolling back the seed restores raw-driver behaviour
without dropping the columns, and rolling back this one removes the columns after
the seed is already gone.

Choices are inlined rather than imported from the model, per Django migration
convention: a migration must keep describing the schema as it was at this point
in history even after the model's vocabulary changes again.
"""

from django.db import migrations, models
import django.contrib.postgres.fields

TRANSPORT_DRIVER_CHOICES = [
    ("ansible", "Ansible (default)"),
    ("ansible-network", "Ansible (network CLI)"),
    ("asyncssh", "AsyncSSH"),
    ("paramiko", "Paramiko"),
    ("subprocess", "subprocess (OpenSSH)"),
    ("fabric", "Fabric"),
    ("scrapli", "Scrapli"),
    ("netmiko", "Netmiko"),
    ("napalm", "NAPALM"),
    ("nornir", "Nornir"),
]


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0073_seed_gitea_runner_service_allowlist"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpcprocedure",
            name="transport_pinned",
            field=models.BooleanField(
                default=False,
                verbose_name="Transport driver pinned",
                help_text=(
                    "This procedure's transport driver is fixed and must not be "
                    "changed by estate-wide defaults or by driver migrations. Set "
                    "it for procedures whose backend handler depends on one "
                    "specific driver — for example one that disables fallback and "
                    "relies on AsyncSSH's credential isolation, or that streams a "
                    "long-running command's output live. Leaving the driver chain "
                    "empty is not enough on its own: the plugin-wide default chain "
                    "would still apply."
                ),
            ),
        ),
        migrations.AlterField(
            model_name="rpcprocedure",
            name="transport_driver",
            field=models.CharField(
                choices=TRANSPORT_DRIVER_CHOICES,
                default="ansible",
                max_length=20,
                help_text=(
                    "Transport driver the netbox-rpc-backend execution pipeline "
                    "uses for this procedure. Ansible is the default; AsyncSSH "
                    "preserves the legacy raw-SSH behaviour."
                ),
            ),
        ),
        migrations.AlterField(
            model_name="rpcprocedure",
            name="transport_driver_chain",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(
                    choices=TRANSPORT_DRIVER_CHOICES, max_length=32
                ),
                blank=True,
                default=list,
                size=None,
                help_text=(
                    "Ordered transport-driver priority + fallback chain (index 0 "
                    "is tried first). Leave empty to use the single Transport "
                    "driver above. The execution backend advances to the next "
                    "capable driver when one is unavailable or a connection "
                    "fails; a command-level failure stops the chain."
                ),
            ),
        ),
        migrations.AddField(
            model_name="rpcpluginsettings",
            name="default_transport_driver_chain",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(
                    choices=TRANSPORT_DRIVER_CHOICES, max_length=32
                ),
                blank=True,
                default=list,
                size=None,
                verbose_name="Default Linux driver chain",
                help_text=(
                    "Ordered driver priority + fallback chain applied to "
                    "procedures that define no chain of their own and whose "
                    "driver serves the Linux shell capability. Leave empty to "
                    "keep each procedure's single driver. Recommended: ansible, "
                    "asyncssh."
                ),
            ),
        ),
        migrations.AddField(
            model_name="rpcpluginsettings",
            name="default_network_driver_chain",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(
                    choices=TRANSPORT_DRIVER_CHOICES, max_length=32
                ),
                blank=True,
                default=list,
                size=None,
                verbose_name="Default network CLI driver chain",
                help_text=(
                    "Ordered driver priority + fallback chain applied to "
                    "procedures that define no chain of their own and whose "
                    "driver serves the network CLI capability. Recommended: "
                    "ansible-network, scrapli."
                ),
            ),
        ),
        migrations.AddField(
            model_name="rpcpluginsettings",
            name="ansible_platform_map",
            field=models.JSONField(
                blank=True,
                default=dict,
                verbose_name="Ansible platform map",
                help_text=(
                    "Maps a NetBox Platform slug to the Ansible connection "
                    "settings for devices on that platform, following the "
                    "netbox.netbox collection's conventions: "
                    '{"junos": {"network_os": "junipernetworks.junos.junos", '
                    '"connection": "ansible.netcommon.netconf"}}. Recognised '
                    "keys per entry: network_os, connection, become, "
                    "become_method. A platform that is not mapped simply gets no "
                    "network OS, and the execution backend then falls back to a "
                    "raw driver instead of guessing a vendor CLI dialect."
                ),
            ),
        ),
    ]
