"""Allow the Ubuntu 24 restart-service procedure to target virtual machines.

Issue #339: ``os.linux.ubuntu.24.restart_service`` was originally seeded by
migration 0002 with only ``dcim.device`` in ``target_models``. This prevented
the procedure from restarting services on hosts represented in NetBox as
``virtualization.virtualmachine`` objects, unlike the other Ubuntu 24 service
procedures.

This migration is additive per the catalog's migration-safety rule: 0002 is
already merged and deployed to production, so the procedure is patched in
place here via a fresh ``RunPython`` step rather than editing the original
seed migration.
"""

from django.db import migrations

_PROCEDURE_NAME = "os.linux.ubuntu.24.restart_service"
_ORIGINAL_TARGET_MODELS = ["dcim.device"]
_WIDENED_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]


def widen_ubuntu_restart_service_targets(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    try:
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
    except RPCProcedure.DoesNotExist:
        return
    if procedure.target_models != _ORIGINAL_TARGET_MODELS:
        return
    procedure.target_models = _WIDENED_TARGET_MODELS
    procedure.save(update_fields=["target_models"])


def revert_ubuntu_restart_service_targets(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    try:
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
    except RPCProcedure.DoesNotExist:
        return
    if procedure.target_models != _WIDENED_TARGET_MODELS:
        return
    procedure.target_models = _ORIGINAL_TARGET_MODELS
    procedure.save(update_fields=["target_models"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0067_merge_huawei_bgp_and_upgrade_result_limits"),
    ]

    operations = [
        migrations.RunPython(
            widen_ubuntu_restart_service_targets,
            reverse_code=revert_ubuntu_restart_service_targets,
        ),
    ]
