"""Seed declarative fileserver.samba RPCIntents (#160).

Intents are pure reference-data groupings — declaring *what* set of
procedures belongs together and in what order/mode, never *how* they run.
Executing an intent (fan-out via command_handlers.execute_intent(), issue
#130) already exists and routes every child procedure through
create_execution(), re-applying the full gating stack per child; this
migration adds no executor and no new mutation surface.

fileserver.samba.collect_state groups the read-only observability family
(execution_mode="parallel" — no nesting, sequence is informational).
fileserver.samba.deploy_config groups the config-lifecycle write path
(execution_mode="sequential" — validate, then deploy, then reload, then
re-check status), ordered by RPCIntentProcedure.sequence.

Data (intent names, execution modes, and grouped procedure names) is inlined
so this migration remains stable across future netbox_rpc.constants changes.
"""

from django.db import migrations

_COLLECT_STATE_NAME = "fileserver.samba.collect_state"
_DEPLOY_CONFIG_NAME = "fileserver.samba.deploy_config"

_COLLECT_STATE_PROCEDURES = (
    "service.samba.1.version",
    "service.samba.1.service_status",
    "service.samba.1.config_read",
    "service.samba.1.config_test",
    "service.samba.1.list_shares",
    "service.samba.1.status_report",
    "service.samba.1.user_list",
    "service.samba.1.group_list",
    "service.samba.1.domain_info",
)

_DEPLOY_CONFIG_PROCEDURES = (
    "service.samba.1.config_test",
    "service.samba.1.config_deploy",
    "service.samba.1.service_control",
    "service.samba.1.service_status",
)

_INTENTS = (
    {
        "name": _COLLECT_STATE_NAME,
        "execution_mode": "parallel",
        "description": (
            "Read-only Samba observability sweep: version, service status, "
            "config content/validation, share list, live status, user/group "
            "directory listing, and domain info."
        ),
        "procedure_names": _COLLECT_STATE_PROCEDURES,
    },
    {
        "name": _DEPLOY_CONFIG_NAME,
        "execution_mode": "sequential",
        "description": (
            "Validate the running config, deploy a new smb.conf candidate, "
            "reload the Samba service, then re-check service status."
        ),
        "procedure_names": _DEPLOY_CONFIG_PROCEDURES,
    },
)


def _seed_fileserver_samba_intents(apps, schema_editor):
    RPCIntent = apps.get_model("netbox_rpc", "RPCIntent")
    RPCIntentProcedure = apps.get_model("netbox_rpc", "RPCIntentProcedure")
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")

    for intent_spec in _INTENTS:
        intent, _ = RPCIntent.objects.update_or_create(
            name=intent_spec["name"],
            defaults={
                "execution_mode": intent_spec["execution_mode"],
                "description": intent_spec["description"],
                "enabled": True,
            },
        )
        procedure_names = intent_spec["procedure_names"]
        procedures_by_name = {
            procedure.name: procedure
            for procedure in RPCProcedure.objects.filter(name__in=procedure_names)
        }
        for sequence, procedure_name in enumerate(procedure_names, start=1):
            procedure = procedures_by_name.get(procedure_name)
            if procedure is None:
                # A prerequisite seed migration did not run (should not happen
                # given the dependency graph below); skip rather than fail the
                # whole migration so partial installs stay diagnosable.
                continue
            RPCIntentProcedure.objects.update_or_create(
                intent=intent,
                procedure=procedure,
                defaults={"sequence": sequence},
            )
        RPCIntentProcedure.objects.filter(intent=intent).exclude(
            procedure__name__in=procedure_names
        ).delete()


def _remove_fileserver_samba_intents(apps, schema_editor):
    RPCIntent = apps.get_model("netbox_rpc", "RPCIntent")
    RPCIntent.objects.filter(
        name__in=[intent_spec["name"] for intent_spec in _INTENTS]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0056_seed_samba_identity_commands"),
    ]

    operations = [
        migrations.RunPython(
            _seed_fileserver_samba_intents,
            reverse_code=_remove_fileserver_samba_intents,
        ),
    ]
