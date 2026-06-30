from django.db import migrations


def drop_stale_fks(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return

    targets = (
        ("netbox_rpc_rpcexecution", "backend_id"),
        ("netbox_rpc_rpclinuxserviceallowlist", "ssh_credential_override_id"),
    )
    quote_name = schema_editor.quote_name
    with schema_editor.connection.cursor() as cursor:
        for table, column in targets:
            cursor.execute(
                """
                SELECT con.conname
                FROM pg_constraint con
                JOIN pg_attribute attr
                  ON attr.attrelid = con.conrelid
                 AND attr.attnum = ANY(con.conkey)
                WHERE con.contype = 'f'
                  AND con.conrelid = to_regclass(%s)
                  AND attr.attname = %s
                """,
                [table, column],
            )
            constraint_names = [row[0] for row in cursor.fetchall()]
            for constraint_name in constraint_names:
                cursor.execute(
                    f"ALTER TABLE {quote_name(table)} "
                    f"DROP CONSTRAINT IF EXISTS {quote_name(constraint_name)}"
                )


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0033_rpcbackend"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[],
            database_operations=[
                migrations.RunPython(drop_stale_fks, migrations.RunPython.noop),
            ],
        ),
    ]
