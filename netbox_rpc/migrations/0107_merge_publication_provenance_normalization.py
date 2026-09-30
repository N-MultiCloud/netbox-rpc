"""Merge publication provenance normalization into the single catalog leaf."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_normalize_protected_publication_provenance"),
        ("netbox_rpc", "0106_merge_unmarked_publication_adoption"),
    ]

    operations = []  # noqa: RUF012
