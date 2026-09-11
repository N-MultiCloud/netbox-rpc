"""Add immutable metadata-only credential authority and executor identities."""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

_FORWARD = """
CREATE FUNCTION netbox_rpc_credential_authority_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.credential_references IS DISTINCT FROM OLD.credential_references
       OR NEW.credential_authority IS DISTINCT FROM OLD.credential_authority THEN
        RAISE EXCEPTION 'Execution credential authority is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER netbox_rpc_credential_authority_immutable
BEFORE UPDATE ON netbox_rpc_rpcexecution
FOR EACH ROW EXECUTE FUNCTION netbox_rpc_credential_authority_immutable();
"""
_REVERSE = """
DROP TRIGGER netbox_rpc_credential_authority_immutable ON netbox_rpc_rpcexecution;
DROP FUNCTION netbox_rpc_credential_authority_immutable();
"""


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0089_seed_openbao_netbox_approle"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.AddField(
            model_name="rpcbackend",
            name="executor_identity",
            field=models.ForeignKey(
                to=settings.AUTH_USER_MODEL,
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name="rpc_executor_backends",
                help_text="Authenticated service identity permitted to resolve execution credentials.",
            ),
        ),
        migrations.AddField(
            model_name="rpcexecution",
            name="credential_references",
            field=models.JSONField(default=dict, db_default={}, blank=True),
        ),
        migrations.AddField(
            model_name="rpcexecution",
            name="credential_authority",
            field=models.JSONField(
                default=dict, db_default={}, blank=True, editable=False
            ),
        ),
        migrations.RunSQL(_FORWARD, _REVERSE),
    ]
