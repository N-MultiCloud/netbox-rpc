"""Extend both OpenBao importer procedure timeout envelopes.

The backend owns a 1,050-second outer route budget. The catalog must remain
alive beyond that boundary so the worker can receive and persist the backend's
closed result, including cancellation and indeterminate outcomes. Both rows
therefore use 1,200 seconds: the route budget plus a bounded 150-second margin
for request handling, cancellation, and result persistence. Queue residence is
bounded separately by the execution lease and is not part of this margin.

Only ``timeout_seconds`` is changed. Every approval, lease, target, transport,
schema, command, and enablement field remains byte-for-byte untouched.
"""

from django.db import migrations

_DRY_RUN_NAME = "service.netbox.openbao_import.dry_run"
_APPLY_NAME = "service.netbox.openbao_import.apply"
_BACKEND_ROUTE_BUDGET_SECONDS = 1050
_REQUEST_CANCELLATION_RESULT_MARGIN_SECONDS = 150
_TIMEOUT_SECONDS = (
    _BACKEND_ROUTE_BUDGET_SECONDS + _REQUEST_CANCELLATION_RESULT_MARGIN_SECONDS
)
_OLD_TIMEOUTS = {
    _DRY_RUN_NAME: 300,
    _APPLY_NAME: 900,
}


def _swap_timeouts(apps, expected_by_name, replacement_by_name):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    procedures = {}
    for name in (_DRY_RUN_NAME, _APPLY_NAME):
        procedure = RPCProcedure.objects.filter(name=name).first()
        if procedure is None:
            raise RuntimeError(f"{name}: required procedure row is missing")
        replacement = replacement_by_name[name]
        if procedure.timeout_seconds not in {expected_by_name[name], replacement}:
            raise RuntimeError(f"{name}: timeout_seconds was modified")
        procedures[name] = procedure

    for name, procedure in procedures.items():
        replacement = replacement_by_name[name]
        if procedure.timeout_seconds == replacement:
            continue
        procedure.timeout_seconds = replacement
        procedure.save(update_fields=["timeout_seconds"])


def forwards(apps, schema_editor):
    del schema_editor
    replacements = {name: _TIMEOUT_SECONDS for name in _OLD_TIMEOUTS}
    _swap_timeouts(apps, _OLD_TIMEOUTS, replacements)


def backwards(apps, schema_editor):
    del schema_editor
    expected = {name: _TIMEOUT_SECONDS for name in _OLD_TIMEOUTS}
    _swap_timeouts(apps, expected, _OLD_TIMEOUTS)


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0099_fix_openbao_import_nullable_summary")]  # noqa: RUF012

    operations = [migrations.RunPython(forwards, backwards)]  # noqa: RUF012
