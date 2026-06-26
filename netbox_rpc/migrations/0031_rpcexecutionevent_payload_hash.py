import hashlib
import json

from django.db import migrations, models


def _stable_hash(value):
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def backfill_payload_hash(apps, schema_editor):
    event_model = apps.get_model("netbox_rpc", "RPCExecutionEvent")
    for event in event_model.objects.all().iterator():
        event.payload_hash = _stable_hash(
            {
                "level": event.level,
                "event": event.event,
                "message": event.message,
                "data": event.data or {},
            }
        )
        event.save(update_fields=["payload_hash"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0030_rpcprocedure_driver_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpcexecutionevent",
            name="payload_hash",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.RunPython(backfill_payload_hash, migrations.RunPython.noop),
        migrations.RunSQL(
            sql="""
            CREATE OR REPLACE FUNCTION netbox_rpc_rpcexecutionevent_append_only()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'RPCExecutionEvent rows are append-only.';
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS netbox_rpc_rpcexecutionevent_no_update
            ON netbox_rpc_rpcexecutionevent;
            DROP TRIGGER IF EXISTS netbox_rpc_rpcexecutionevent_no_delete
            ON netbox_rpc_rpcexecutionevent;

            CREATE TRIGGER netbox_rpc_rpcexecutionevent_no_update
            BEFORE UPDATE ON netbox_rpc_rpcexecutionevent
            FOR EACH ROW
            EXECUTE FUNCTION netbox_rpc_rpcexecutionevent_append_only();

            CREATE TRIGGER netbox_rpc_rpcexecutionevent_no_delete
            BEFORE DELETE ON netbox_rpc_rpcexecutionevent
            FOR EACH ROW
            EXECUTE FUNCTION netbox_rpc_rpcexecutionevent_append_only();
            """,
            reverse_sql="""
            DROP TRIGGER IF EXISTS netbox_rpc_rpcexecutionevent_no_update
            ON netbox_rpc_rpcexecutionevent;
            DROP TRIGGER IF EXISTS netbox_rpc_rpcexecutionevent_no_delete
            ON netbox_rpc_rpcexecutionevent;
            DROP FUNCTION IF EXISTS netbox_rpc_rpcexecutionevent_append_only();
            """,
        ),
    ]
