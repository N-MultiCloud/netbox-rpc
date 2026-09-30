"""Merge unmarked publication adoption into the single catalog leaf."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_adopt_unmarked_protected_publication_pair"),
        ("netbox_rpc", "0105_merge_protected_publication_predecessor"),
    ]

    operations = []  # noqa: RUF012
