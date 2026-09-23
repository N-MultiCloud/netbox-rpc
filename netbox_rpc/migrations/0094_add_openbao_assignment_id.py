"""Add an optional netbox-openbao CredentialAssignment reference alongside
the legacy netbox-nms DeviceCredential ``ssh_credential_override`` field.

Squashed history note (#321 round-2 review): earlier commits on this same
unreleased branch added a raw ``openbao_credential_id`` integer, then
replaced it with this assignment-based field across two more migrations.
None of those intermediate migrations were ever applied to any shared or
production database, so this single migration adds the field directly rather
than preserving that churn in the migration graph.

Purely additive: two nullable ``PositiveBigIntegerField`` columns, no
constraints, no FK, no data migration. netbox-openbao remains an optional
dependency -- this plugin never imports it and resolves the reference (if at
all) through ``apps.get_model`` guarded by ``apps.is_installed``. Safe to run
on a production NetBox that runs ``migrate`` on every start.
"""

from django.db import migrations, models

_HELP_TEXT = (
    "Optional netbox_openbao.CredentialAssignment PK to use instead of the "
    "legacy netbox-nms DeviceCredential referenced by ssh_credential_override. "
    "Unlike a raw Credential PK, an assignment already binds a credential to "
    "one target object for a stated purpose (see "
    "netbox_openbao.CredentialAssignment), so the normalizer can verify at "
    "dispatch time that the assignment is actually bound to the execution's "
    "target and that the requester can view the credential -- not just that "
    "some integer exists. netbox-openbao stays an optional dependency: this "
    "is a plain integer reference, resolved (if at all) through "
    "apps.get_model, never a hard FK. Leave blank while netbox-openbao is not "
    "installed or the legacy credential has not been migrated yet."
)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0093_seed_proxmox_oci_registry_pull"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpclinuxserviceallowlist",
            name="openbao_assignment_id",
            field=models.PositiveBigIntegerField(
                null=True, blank=True, db_index=True, help_text=_HELP_TEXT
            ),
        ),
        migrations.AddField(
            model_name="rpcnetboxpluginallowlist",
            name="openbao_assignment_id",
            field=models.PositiveBigIntegerField(
                null=True, blank=True, db_index=True, help_text=_HELP_TEXT
            ),
        ),
    ]
