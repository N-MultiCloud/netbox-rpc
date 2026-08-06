"""Merge the Akvorado-catalog and Linux-env-file migration branches.

``0057_seed_akvorado_procedures`` (Akvorado RPC catalog series, landed on the
integration branch) and ``0061_linux_env_file_upsert_var_force_disabled``
(Samba/fileserver/env-file seed series, landed on the release branch) both
descend from ``0054_merge_approval_and_samba``. Django requires a single leaf
per app, so this no-op merge ties the two branches together.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0057_seed_akvorado_procedures"),
        ("netbox_rpc", "0061_linux_env_file_upsert_var_force_disabled"),
    ]

    operations = []
