"""Seed command rows for Samba/AD identity management RPC procedures (#160).

user_create and user_set_password are backend-orchestrated because the
password travels to samba-tool over stdin and must never be represented as an
argv token or persisted anywhere in netbox-rpc; both handler IDs are
EXEMPT_HANDLER_RATIONALE entries. The remaining seven procedures reduce to
concrete fixed samba-tool argv rows, since every parameter is confined by both
the procedure params_schema and the normalizer before dispatch.
"""

from django.db import migrations


def c(
    argv,
    description="",
    *,
    continue_on_error=False,
):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": argv,
        "description": description,
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": continue_on_error,
    }


def representative(slug, description):
    return [c(["backend-orchestrated", slug], description)]


_COMMAND_STEPS_BY_HANDLER_ID = {
    "service.samba_1.user_create": representative(
        "samba-user-create",
        (
            "Backend runs samba-tool user create with the password delivered "
            "over stdin; the password is never represented as an argv token."
        ),
    ),
    "service.samba_1.user_delete": [
        c(
            ["sudo", "/usr/bin/samba-tool", "user", "delete", "{username}"],
            "Delete one Samba/AD user by username.",
        ),
    ],
    "service.samba_1.user_set_password": representative(
        "samba-user-set-password",
        (
            "Backend runs samba-tool user setpassword with the new password "
            "delivered over stdin; the password is never represented as an "
            "argv token."
        ),
    ),
    "service.samba_1.user_enable": [
        c(
            ["sudo", "/usr/bin/samba-tool", "user", "enable", "{username}"],
            "Enable one Samba/AD user account.",
        ),
    ],
    "service.samba_1.user_disable": [
        c(
            ["sudo", "/usr/bin/samba-tool", "user", "disable", "{username}"],
            "Disable one Samba/AD user account.",
        ),
    ],
    "service.samba_1.group_create": [
        c(
            ["sudo", "/usr/bin/samba-tool", "group", "add", "{group_name}"],
            "Create one Samba/AD group.",
        ),
    ],
    "service.samba_1.group_delete": [
        c(
            ["sudo", "/usr/bin/samba-tool", "group", "delete", "{group_name}"],
            "Delete one Samba/AD group by name.",
        ),
    ],
    "service.samba_1.group_add_members": [
        c(
            [
                "sudo",
                "/usr/bin/samba-tool",
                "group",
                "addmembers",
                "{group_name}",
                "{members_csv}",
            ],
            "Add one or more comma-separated members to a Samba/AD group.",
        ),
    ],
    "service.samba_1.group_remove_members": [
        c(
            [
                "sudo",
                "/usr/bin/samba-tool",
                "group",
                "removemembers",
                "{group_name}",
                "{members_csv}",
            ],
            "Remove one or more comma-separated members from a Samba/AD group.",
        ),
    ],
}


def _seed_samba_identity_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for handler_id, steps in _COMMAND_STEPS_BY_HANDLER_ID.items():
        for procedure in RPCProcedure.objects.filter(handler_id=handler_id):
            for index, step in enumerate(steps, start=1):
                RPCProcedureCommand.objects.update_or_create(
                    procedure=procedure,
                    sequence=index,
                    defaults=step,
                )


def _remove_samba_identity_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    procedures = RPCProcedure.objects.filter(
        handler_id__in=list(_COMMAND_STEPS_BY_HANDLER_ID)
    )
    RPCProcedureCommand.objects.filter(procedure__in=procedures).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0055_seed_samba_identity_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_samba_identity_commands,
            reverse_code=_remove_samba_identity_commands,
        ),
    ]
