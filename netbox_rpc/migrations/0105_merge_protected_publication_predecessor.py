"""Merge the protected-publication predecessor adoption into the catalog leaf."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_adopt_protected_publication_predecessor"),
        ("netbox_rpc", "0104_seed_protected_publication_pair"),
    ]

    operations = []  # noqa: RUF012
