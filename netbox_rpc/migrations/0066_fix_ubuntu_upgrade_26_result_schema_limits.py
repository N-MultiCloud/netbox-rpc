"""Fix silent output truncation on the Ubuntu 24.04 to 26.04 upgrade procedure.

Issue #215: ``run_upgrade``'s ``result_schema`` (seeded by migration 0063)
never declared an explicit ``maxLength`` on ``upgrade_log_tail``, so
``record_execution_succeeded()`` / ``record_backend_response()`` in
``event_store.py`` fell back to the 4096-char default in
``_collect_schema_string_limits()`` and silently clamped it -- the one field
where an operator needs to see what a 2-hour upgrade actually did.

This migration is additive per the catalog's migration-safety rule: 0063 is
already merged and deployed to production, so it is patched in place here via
a fresh ``RunPython`` step rather than edited directly. Only
``upgrade_log_tail`` is touched: the schema's other free-form strings
(``new_version_id``, ``backup_dir``, ``manifest_sha256``, ``disk_free_root``,
``kernel``) were never near the 4096-char default -- none of them were
actually being truncated -- so raising their bounds would only widen the
fail-closed surface of schema validation (see the warning below) with no
corresponding bug fixed.

NOTE for whoever implements the ``run_upgrade`` backend handler (nms-backend
issue #623): as originally written, this migration would have made
``record_backend_response()`` validate the *raw* backend result against this
bound before any clamping happened, so a result whose ``upgrade_log_tail``
exceeded ``_LOG_TAIL_MAX_LENGTH`` would fail schema validation and land the
execution in FAILED with ``RPC_RESULT_SCHEMA_MISMATCH`` -- even if the
upgrade itself succeeded on the host. Issue #215 round 2 (adversarial review)
closed that gap directly in ``event_store.py`` by validating a length-clamped
*copy* of the result; round 3 replaced that with a schema-relaxation approach
instead (``_relax_schema_string_lengths()`` / ``_strip_max_length_at_paths()``
in ``event_store.py``): ``record_backend_response()`` now validates the
complete, untouched raw result against a copy of the schema with
``maxLength`` removed only at ``upgrade_log_tail`` (and any other
deliberately-widened path), so every other validator on the result still runs
at full fidelity while a backend returning more than ``_LOG_TAIL_MAX_LENGTH``
characters no longer fails validation on length alone. The persisted/redacted
result is separately clamped to fit back within ``_LOG_TAIL_MAX_LENGTH`` --
with ``_result_schema_string_limits()`` reserving headroom for the
``"...[truncated]"`` marker so the truncated value can never itself exceed
the schema bound it was validated against. This is now a safety net, not a
correctness requirement placed on the handler -- but the handler SHOULD still
cap the tail it returns well below this bound (e.g. emit at most the last
~32KB of the upgrade log) as a matter of efficiency, so a 2-hour upgrade's
full log never needs to cross the wire only to be truncated on arrival.

A further round-3 follow-up (a second, final adversarial-review pass on the
same branch) closed one more gap in this mechanism: passing the raw-value
validation only proves the *raw* result is schema-valid, not that the
persisted/truncated copy stays schema-valid too -- a field carrying both a
wide ``maxLength`` override and a ``pattern`` could have a raw value that
satisfies ``pattern`` while oversized, yet a persisted
``content[:limit] + "...[truncated]"`` copy that violates it.
``record_backend_response()`` now runs a second validation pass against the
real, unrelaxed schema on the already-redacted/truncated result before
marking ``ExecutionSucceeded``. ``upgrade_log_tail`` itself has no
``pattern``, so this is not reachable through this procedure today, but the
fix is unconditional in ``event_store.py`` since the underlying mechanism is
shared by every wide-override result field in the catalog.
"""

from django.db import migrations

# Comfortably above MAX_EVENT_STRING_LENGTH (4096) so
# _collect_schema_string_limits() registers an override, and large enough to
# hold a realistic do-release-upgrade log tail without silent clamping, while
# still leaving headroom below it for the handler's own cap (see module
# docstring: the handler must emit well under this bound, not right up to it).
_LOG_TAIL_MAX_LENGTH = 65536

_PROCEDURE_NAME = "os.linux.ubuntu.24.upgrade_26.run_upgrade"
_PROPERTY_NAME = "upgrade_log_tail"


def _fix_run_upgrade_log_tail_limit(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    try:
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
    except RPCProcedure.DoesNotExist:
        return
    schema = procedure.result_schema
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    prop_schema = properties.get(_PROPERTY_NAME)
    if not isinstance(prop_schema, dict):
        return
    if prop_schema.get("maxLength") == _LOG_TAIL_MAX_LENGTH:
        return
    prop_schema["maxLength"] = _LOG_TAIL_MAX_LENGTH
    procedure.save(update_fields=["result_schema"])


def _revert_run_upgrade_log_tail_limit(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    try:
        procedure = RPCProcedure.objects.get(name=_PROCEDURE_NAME)
    except RPCProcedure.DoesNotExist:
        return
    schema = procedure.result_schema
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    prop_schema = properties.get(_PROPERTY_NAME)
    if not isinstance(prop_schema, dict):
        return
    if prop_schema.get("maxLength") != _LOG_TAIL_MAX_LENGTH:
        return
    del prop_schema["maxLength"]
    procedure.save(update_fields=["result_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0065_seed_ubuntu_upgrade_26_intent"),
    ]

    operations = [
        migrations.RunPython(
            _fix_run_upgrade_log_tail_limit,
            reverse_code=_revert_run_upgrade_log_tail_limit,
        ),
    ]
