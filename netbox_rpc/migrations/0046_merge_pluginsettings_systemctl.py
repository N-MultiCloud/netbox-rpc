"""Merge the two 0044 migration leaves.

`0044_rpcpluginsettings` and `0044_seed_proxmox_show_systemctl_services`
(the latter followed by `0045_seed_show_systemctl_services_command`) were added
in parallel off `0043_rpcbackend_ip_domain`, leaving two leaf nodes in the
netbox_rpc migration graph. Django refuses to `migrate` with multiple leaves,
which breaks deployment. This empty merge migration re-converges the graph.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0044_rpcpluginsettings"),
        ("netbox_rpc", "0045_seed_show_systemctl_services_command"),
    ]

    operations = []
