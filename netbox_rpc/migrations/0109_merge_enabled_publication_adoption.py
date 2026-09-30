"""Merge enabled protected-publication adoption into one graph leaf."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_adopt_enabled_unmarked_publication_pair"),
        ("netbox_rpc", "0108_merge_publication_drift_report"),
    ]
    operations = []  # noqa: RUF012
