"""Re-assert ``os.linux_env_file.upsert_var`` is disabled after in-place edits.

Migration ``0060`` was originally published with ``enabled=True`` in its
``_PROCEDURE_DEFAULTS`` and later edited in place, in a subsequent commit, to
``enabled=False`` -- ship the procedure disabled until its execution handler,
issue #203, and issue #163's approval-snapshot routing all land (see
``0060``'s module docstring and ``AGENTS.md`` for the full precondition
list).

Django tracks an applied migration by name only, not by content: any database
that already ran the original ``0060`` (``enabled=True``) will never
re-execute the edited version and keeps that stale default forever. Editing
``0060`` again would repeat the same mistake for databases that already
migrated past *this* point, so the fix is this additive, idempotent data
migration instead -- it force-sets ``enabled=False`` on the existing
procedure row regardless of which ``0060`` variant a given database applied.
"""

from django.db import migrations


_PROCEDURE_NAME = "os.linux_env_file.upsert_var"


def force_disable_linux_env_file_upsert_var(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_PROCEDURE_NAME).update(enabled=False)


def noop_reverse(apps, schema_editor):
    # Intentionally a no-op: reversing to "restore whatever enabled value
    # 0060 last wrote" is not recoverable, and re-enabling the procedure on
    # rollback would defeat the safety gate this migration exists to enforce.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0060_seed_linux_env_file_upsert_var"),
    ]

    operations = [
        migrations.RunPython(
            force_disable_linux_env_file_upsert_var,
            reverse_code=noop_reverse,
        ),
    ]
