"""Seed the representative command row for os.linux.proxmox.show_systemctl_services.

The read-only systemctl-service-state procedure (seeded by 0044) is a
backend-orchestrated diagnostic — the backend runs `systemctl show -p ...` per
unit (or a backend-defined default unit set) and parses the key=value output —
so it cannot be reduced to a single faithful fixed-argv row. It is therefore
listed in netbox_rpc.command_contract.EXEMPT_HANDLER_RATIONALE and, like the
other exempt handlers, receives one representative RPCProcedureCommand row so
the object view and API surface that backend-owned orchestration exists.

Data is inlined here (migrations must not import netbox_rpc constants or runtime
helpers). Handler IDs are the stable bridge to the execution backend. Idempotent
via update_or_create so re-application is safe.
"""

from django.db import migrations

_HANDLER_ID = "os.linux_proxmox.show_systemctl_services"

_COMMAND_STEPS = [
    {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "proxmox-show-systemctl-services"],
        "description": (
            "Backend runs `systemctl show -p Id,LoadState,ActiveState,SubState,"
            "Result,...` per requested unit (or a backend default unit set) and "
            "parses the service state."
        ),
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
    },
]


def _seed_command(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for procedure in RPCProcedure.objects.filter(handler_id=_HANDLER_ID):
        for index, step in enumerate(_COMMAND_STEPS, start=1):
            RPCProcedureCommand.objects.update_or_create(
                procedure=procedure,
                sequence=index,
                defaults=step,
            )


def _remove_command(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    procedures = RPCProcedure.objects.filter(handler_id=_HANDLER_ID)
    RPCProcedureCommand.objects.filter(procedure__in=procedures).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0044_seed_proxmox_show_systemctl_services"),
    ]

    operations = [
        migrations.RunPython(
            _seed_command,
            reverse_code=_remove_command,
        ),
    ]
