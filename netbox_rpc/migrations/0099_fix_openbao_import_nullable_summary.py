"""Allow a null summary in the netbox-openbao importer result schema.

Migration 0096 declared the result ``summary`` as
``{"type": ["object", "null"], **_SUMMARY_SCHEMA}``. The spread's own
``"type": "object"`` replaced the nullable type, so the ``summary: null`` that
netbox-rpc-backend returns for every failed run was rejected as a result schema
mismatch and the backend's failure details were discarded. This migration
rewrites only rows that still hold that exact schema; any other value is left
untouched and reported by refusing.

Schemas are inlined so the migration stays deterministic if runtime constants
change later.
"""

import copy

from django.db import migrations

_NAMES = (
    "service.netbox.openbao_import.dry_run",
    "service.netbox.openbao_import.apply",
)
_SOURCE_MODEL_KEYS = [
    "device_credential",
    "device_service",
    "user_ssh_key",
    "proxmox_binding",
    "cloud_vm_credential",
    "observability_secret",
]
_SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": _SOURCE_MODEL_KEYS,
    "properties": {
        key: {"type": "integer", "minimum": 0, "maximum": 1000000}
        for key in _SOURCE_MODEL_KEYS
    },
}
_BROKEN_SUMMARY = {"type": ["object", "null"], **_SUMMARY_SCHEMA}
_FIXED_SUMMARY = {"anyOf": [{"type": "null"}, _SUMMARY_SCHEMA]}


def _swap_summary(apps, current, replacement):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for name in _NAMES:
        procedure = RPCProcedure.objects.filter(name=name).first()
        if procedure is None:
            continue
        schema = copy.deepcopy(procedure.result_schema)
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(properties, dict):
            raise RuntimeError(f"{name}: unexpected result schema shape")
        if properties.get("summary") == replacement:
            continue
        if properties.get("summary") != current:
            raise RuntimeError(f"{name}: result schema summary was modified")
        properties["summary"] = copy.deepcopy(replacement)
        procedure.result_schema = schema
        procedure.save(update_fields=["result_schema"])


def forwards(apps, schema_editor):
    _swap_summary(apps, _BROKEN_SUMMARY, _FIXED_SUMMARY)


def backwards(apps, schema_editor):
    _swap_summary(apps, _FIXED_SUMMARY, _BROKEN_SUMMARY)


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0098_seed_release_marker_procedures")]

    operations = [migrations.RunPython(forwards, backwards)]
