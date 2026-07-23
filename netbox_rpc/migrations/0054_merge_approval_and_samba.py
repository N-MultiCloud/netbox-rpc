"""Merge the approval-series and Samba/InfluxDB migration branches.

``0049_approval_aggregate_snapshot`` (approval feature series, landed on the
release branch) and ``0049_seed_samba_read_procedures`` (Samba/InfluxDB seed
series, landed on the integration branch) both descend from
``0048_seed_passbolt_migration_procedures``. Django requires a single leaf per
app, so this no-op merge ties the two branches together.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0050_rpc_optin_preserve_behavior"),
        ("netbox_rpc", "0053_seed_influxdb_service_allowlist"),
    ]

    operations = []
