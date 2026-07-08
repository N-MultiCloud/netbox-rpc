from django.db import migrations


class Migration(migrations.Migration):
    """Merge the two 0035-descended migration branches into a single leaf.

    ``0036_harden_rpc_ssh_host_schemas`` (SSH host-schema hardening) and
    ``0036_rpcprocedurecommand`` -> ``0037_seed_rpc_procedure_commands`` (the RPC
    procedure command source-of-truth model and its seed data) both fork off
    ``0035_seed_ookla_diagnostic_procedures``. This empty merge migration
    re-linearizes the graph so ``manage.py migrate`` has a single leaf. The two
    branches touch disjoint state (SSH override validation vs. a new command
    table plus seed rows), so no ordering-sensitive operations are required.
    """

    dependencies = [
        ("netbox_rpc", "0036_harden_rpc_ssh_host_schemas"),
        ("netbox_rpc", "0037_seed_rpc_procedure_commands"),
    ]

    operations = []
