"""Add RPCTargetBinding, replacing the round-3 NetBox-tag target binding.

Round-4 adversarial review of #326 found the tag approach had two highs:
(1) any user holding the generic ``dcim.change_device`` permission could move
a device's ``netbox-openbao-import-*`` tag, so a plugin tag did not restrict
who controls the importer's target -- and this backend independently re-read
that same mutable tag, so its "independent" check was not actually
independent of the first read; (2) the backend read the tag once, before
lease consumption, so a binding moved after that read but before dispatch
still executed. This model does not fix (2) by itself (the backend now reads
it twice -- once before lease consumption, once immediately before the
remote process starts), but it fixes (1): ``RPCTargetBinding`` is an ordinary
NetBoxModel with its own ``view``/``add``/``change``/``delete_rpctargetbinding``
permissions, so moving a binding requires an operator explicitly granted
``change_rpctargetbinding`` -- never merely ``dcim.change_device``.

Deliberately generic, not netbox-openbao-specific: `slug` is a closed choice
registry in `constants.py` so any procedure family needing a fixed
one-device binding can register a new slug and reuse this exact model/API
(see the planned `service.nmulticloud.deploy.release_marker_*` procedures,
issue #605).
"""

import taggit.managers
import utilities.json
from django.db import migrations, models

# Inlined, not imported from netbox_rpc.constants (round-2 #326 review fix):
# migrations must not depend on live application code that can change
# independently of the migration -- see "Migration Safety" in AGENTS.md
# ("Seed data migrations inline their data directly; they must not import
# live Python modules such as netbox_rpc.constants"). Keep byte-for-byte in
# sync with RPC_TARGET_BINDING_SLUG_CHOICES; a future registered slug adds a
# new additive migration's own field `choices=`, it does not edit this one.
_RPC_TARGET_BINDING_SLUG_CHOICES = (
    ("netbox-openbao-import-staging", "netbox-openbao import (staging)"),
    ("netbox-openbao-import-production", "netbox-openbao import (production)"),
    ("nmulticloud-deploy-host", "N-MultiCloud deploy host"),
)


class Migration(migrations.Migration):

    dependencies = [
        # Anchored to extras.0134_owner, the final NetBox 4.5.8 migration and an
        # ancestor in 4.6.x, per the compatibility rule in AGENTS.md. Do not
        # re-anchor to a newer leaf without preserving the 4.5.8 floor.
        ("extras", "0134_owner"),
        ("dcim", "0001_initial"),
        ("netbox_rpc", "0096_seed_netbox_openbao_import_procedures"),
    ]

    operations = [
        migrations.CreateModel(
            name="RPCTargetBinding",
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
                (
                    "slug",
                    models.SlugField(
                        choices=list(_RPC_TARGET_BINDING_SLUG_CHOICES),
                        help_text=(
                            "Fixed procedure slot this binding fills. See "
                            "constants.py for the registry."
                        ),
                        max_length=100,
                        unique=True,
                    ),
                ),
                (
                    "device",
                    models.ForeignKey(
                        help_text="The single device this slot is bound to.",
                        on_delete=models.deletion.PROTECT,
                        related_name="rpc_target_bindings",
                        to="dcim.device",
                    ),
                ),
                ("description", models.CharField(blank=True, max_length=255)),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem", to="extras.Tag"
                    ),
                ),
            ],
            options={
                "verbose_name": "RPC Target Binding",
                "ordering": ("slug",),
            },
        ),
    ]
