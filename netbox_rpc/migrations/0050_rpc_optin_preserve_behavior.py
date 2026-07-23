"""Preserve current behaviour when the #166 opt-in gate becomes authoritative.

Issue #166 makes ``RpcPluginSettings.enabled`` (and the selected backend)
authoritative at execution creation and worker claim. An install that is
already **using** RPC (it has execution history) but never explicitly opted in
would otherwise have all new/in-flight work rejected the moment the gate is
enforced.

This data migration opts such installs in idempotently: for an existing,
currently-disabled singleton on an install that has any ``RPCExecution`` rows,
set ``enabled=True`` and — when exactly one ``RPCBackend`` exists and none is
selected — pin it as the authoritative backend (matching the pre-enforcement
single-backend resolver). Fresh installs (no execution history) keep the
opt-in default of ``enabled=False``.

DB-only (no live imports), no schema change, reversible to a no-op.
"""

from django.db import migrations


def opt_in_active_installs(apps, schema_editor):
    RpcPluginSettings = apps.get_model("netbox_rpc", "RpcPluginSettings")
    RPCBackend = apps.get_model("netbox_rpc", "RPCBackend")
    RPCExecution = apps.get_model("netbox_rpc", "RPCExecution")

    settings_row = RpcPluginSettings.objects.filter(singleton_key="default").first()
    if settings_row is None or settings_row.enabled:
        # No singleton yet (fresh install → keep opt-in default) or already
        # opted in (nothing to preserve).
        return
    if not RPCExecution.objects.exists():
        # Not actively using RPC → keep the opt-in gate off by default.
        return

    settings_row.enabled = True
    if settings_row.backend_id is None and RPCBackend.objects.count() == 1:
        settings_row.backend = RPCBackend.objects.first()
    settings_row.save()


def noop_reverse(apps, schema_editor):
    # Opting out again is an operator decision, not a rollback concern.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_rpc", "0049_approval_aggregate_snapshot"),
    ]

    operations = [
        migrations.RunPython(opt_in_active_installs, noop_reverse),
    ]
