"""Merge the restart-service target branch into the canonical migration chain."""

from django.db import migrations

class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0100_extend_openbao_import_timeout_budget"),
        ("netbox_rpc", "0068_widen_ubuntu_restart_service_targets"),
    ]

    operations = []
