"""Merge the packer and Proxmox-QEMU procedure branches.

`0018_seed_packer_procedures` (netbox-packer post-build verification) and the
Proxmox QEMU lifecycle chain `0019_seed_proxmox_qemu_vm_lifecycle` …
`0025_add_proxmox_qemu_pbs_zabbix` are two independent feature branches that
both build on `0017_seed_allow_third_party_optical_modules`. They were developed
in parallel and applied independently in production. This is a no-op merge
migration that joins the two leaves into a single linear tip so the migration
graph has exactly one leaf again.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0018_seed_packer_procedures"),
        ("netbox_rpc", "0025_add_proxmox_qemu_pbs_zabbix"),
    ]

    operations = []
