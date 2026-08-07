"""Merge the Huawei BGP and Ubuntu-upgrade migration branches.

Both ``0066`` migrations descend from
``0065_seed_ubuntu_upgrade_26_intent``.  They are independent data migrations,
so this no-op merge preserves both histories while restoring a single Django
migration leaf for ``netbox_rpc``.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0066_fix_ubuntu_upgrade_26_result_schema_limits"),
        ("netbox_rpc", "0066_seed_huawei_ne8000_bgp_procedures"),
    ]

    operations = []
