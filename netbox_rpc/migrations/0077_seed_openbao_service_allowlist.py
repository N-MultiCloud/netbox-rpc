"""Allow generic Ubuntu service procedures to manage device-hosted OpenBao.

The migration is deliberately irreversible because it has no durable ownership
ledger for the canonical ``openbao`` row.  A future removal or repair must be a
reviewed forward migration that can preserve operator state and audit history.
"""

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError


def _seed(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model(
        "netbox_rpc", "RPCLinuxServiceAllowlist"
    )
    if RPCLinuxServiceAllowlist.objects.filter(slug="openbao").exists():
        raise RuntimeError(
            "Migration 0077 cannot seed the OpenBao service allowlist because "
            "a row with the canonical slug already exists; preserve and "
            "reconcile the operator-owned row before retrying."
        )
    RPCLinuxServiceAllowlist.objects.create(
        slug="openbao",
        systemd_unit="openbao.service",
        enabled=True,
        # The paired backend currently resolves identity-checked OpenBao SSH
        # credentials only for dcim.device. VM support must not be advertised
        # until it has an identity-checked VM credential resolver there.
        target_models=["dcim.device"],
        description="OpenBao server service",
    )


def _remove(apps, schema_editor):
    """Abort before inspecting or mutating a potentially operator-owned row."""

    raise IrreversibleError(
        "Migration 0077 is intentionally irreversible because OpenBao "
        "allowlist ownership cannot be proven after operator mutation; keep "
        "the migration applied and use a reviewed forward repair migration."
    )


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0076_merge_gitea_upgrade_and_ansible_policy")]
    operations = [migrations.RunPython(_seed, reverse_code=_remove)]
