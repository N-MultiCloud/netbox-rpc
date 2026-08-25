"""Merge the Gitea-upgrade and Ansible-policy migration branches.

``0073_seed_gitea_production_upgrade_1271`` and
``0075_seed_ansible_first_policy`` are independent migration leaves.  This
no-op merge preserves both histories while restoring a single Django migration
leaf for ``netbox_rpc``.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0073_seed_gitea_production_upgrade_1271"),
        ("netbox_rpc", "0075_seed_ansible_first_policy"),
    ]

    operations = []
