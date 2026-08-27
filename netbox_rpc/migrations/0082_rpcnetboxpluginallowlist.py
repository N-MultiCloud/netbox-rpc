"""Add the operator-managed allowlist of NetBox plugins installable by RPC.

This table is what keeps ``netbox.plugin.install`` from being remote code
execution. The caller names a row; the row supplies the distribution, the
module written into ``PLUGINS``, the interpreter, the settings file, and the
services to restart. A caller-supplied distribution would be a string handed to
``pip install`` and then imported by a NetBox restart -- pip accepts URLs,
paths, VCS references and options, any of which would run code from wherever
the caller pointed.

Same shape and reasoning as ``RPCLinuxServiceAllowlist``: the procedure names
what to act on, an operator decides what that means.
"""

from django.db import migrations, models
import taggit.managers
import utilities.json


class Migration(migrations.Migration):

    dependencies = [
        # Anchored to extras.0134_owner, the final NetBox 4.5.8 migration and an
        # ancestor in 4.6.x, per the compatibility rule in AGENTS.md. Do not
        # re-anchor to a newer leaf without preserving the 4.5.8 floor.
        ("extras", "0134_owner"),
        ("netbox_rpc", "0081_gitea_runner_scope_fence"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCNetBoxPluginAllowlist",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "custom_field_data",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        encoder=utilities.json.CustomFieldJSONEncoder,
                    ),
                ),
                ("slug", models.SlugField(max_length=100, unique=True)),
                (
                    "distribution",
                    models.CharField(
                        help_text=(
                            "Distribution name passed to pip, e.g. `netbox-openbao`. "
                            "Never caller-supplied; this row is the only source."
                        ),
                        max_length=100,
                    ),
                ),
                (
                    "module",
                    models.CharField(
                        help_text=(
                            "Python module appended to PLUGINS, e.g. `netbox_openbao`. "
                            "Must be importable after the distribution is installed."
                        ),
                        max_length=200,
                    ),
                ),
                (
                    "venv_python",
                    models.CharField(
                        help_text=(
                            "Absolute path to the NetBox virtualenv interpreter, e.g. "
                            "`/opt/netbox/venv/bin/python3`. Installs and migrations run "
                            "through this interpreter, never a bare `python`."
                        ),
                        max_length=255,
                    ),
                ),
                (
                    "manage_py",
                    models.CharField(
                        help_text="Absolute path to NetBox's manage.py.",
                        max_length=255,
                    ),
                ),
                (
                    "settings_file",
                    models.CharField(
                        help_text=(
                            "Absolute path to the settings file holding "
                            "PLUGINS/PLUGINS_CONFIG. Edited in place and restored if "
                            "NetBox fails to start."
                        ),
                        max_length=255,
                    ),
                ),
                (
                    "service_slugs",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text=(
                            "RPCLinuxServiceAllowlist slugs to restart after installing, "
                            "in order -- typically the NetBox service and its RQ worker. "
                            "Restarts go through that allowlist rather than naming units "
                            "here, so a unit this procedure can restart is a unit an "
                            "operator already approved."
                        ),
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                (
                    "target_models",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Optional model labels this plugin may be installed on.",
                    ),
                ),
                ("description", models.CharField(blank=True, max_length=255)),
                ("comments", models.TextField(blank=True)),
                (
                    "ssh_credential_override",
                    models.PositiveBigIntegerField(
                        blank=True,
                        db_column="ssh_credential_override_id",
                        db_index=True,
                        help_text=(
                            "Override the device-level DeviceService SSH credential for "
                            "RPC jobs targeting this plugin host. Leave blank to use the "
                            "target device's default SSH DeviceService credential "
                            "resolved by device name."
                        ),
                        null=True,
                    ),
                ),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem", to="extras.Tag"
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC NetBox Plugin Allowlist Entry",
                "verbose_name_plural": "RPC NetBox Plugin Allowlist Entries",
                "ordering": ("slug",),
            },
        ),
    ]
