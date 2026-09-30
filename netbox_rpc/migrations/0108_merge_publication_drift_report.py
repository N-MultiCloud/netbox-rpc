"""Merge the protected-publication drift-report migration branch."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_report_protected_publication_drift"),
        ("netbox_rpc", "0107_merge_publication_provenance_normalization"),
    ]
    operations = []  # noqa: RUF012
