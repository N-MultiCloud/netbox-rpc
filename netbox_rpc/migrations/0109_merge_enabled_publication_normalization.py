"""Merge the exact enabled protected-publication normalization branch."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_disable_enabled_protected_publication_pair"),
        ("netbox_rpc", "0108_merge_publication_drift_report"),
    ]
    operations = []  # noqa: RUF012
