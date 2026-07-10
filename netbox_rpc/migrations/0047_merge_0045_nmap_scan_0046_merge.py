from django.db import migrations


class Migration(migrations.Migration):
    """Merge the ``0045_seed_nmap_scan_procedure`` leaf into the graph tip.

    ``0045_seed_nmap_scan_procedure`` was authored on a separate branch in
    parallel with the ``0046_merge_pluginsettings_systemctl`` merge, leaving the
    ``netbox_rpc`` migration graph with two leaf nodes. Running
    ``manage.py migrate`` therefore failed with a conflicting-leaves error,
    which blocked every production plugin deploy. This empty merge migration
    reconciles the two leaves so the graph has a single tip again.
    """

    dependencies = [
        ("netbox_rpc", "0045_seed_nmap_scan_procedure"),
        ("netbox_rpc", "0046_merge_pluginsettings_systemctl"),
    ]

    operations = []
