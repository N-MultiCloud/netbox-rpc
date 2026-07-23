"""Seed command rows for Samba config write and lifecycle RPC procedures.

Config mutation handlers are backend-orchestrated because they must combine
stdin content, temporary files, testparm validation, snapshots, atomic
activation, reloads, and rollback. service_control is expressible as fixed argv
because both unit and action are enum-constrained by the procedure schema and
the NetBox normalizer.
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


_SYSTEMCTL_PROPERTIES = "Id,LoadState,ActiveState,SubState,UnitFileState"

_COMMAND_STEPS_BY_HANDLER_ID = {
    "service.samba_1.config_deploy": representative(
        "samba-config-deploy",
        (
            "Backend writes smb.conf via stdin to a temp path, validates with "
            "testparm, snapshots the active config, activates the candidate, "
            "reloads Samba, and restores the snapshot on any post-snapshot "
            "failure."
        ),
    ),
    "service.samba_1.config_rollback": representative(
        "samba-config-rollback",
        (
            "Backend restores a selected config snapshot, validates it with "
            "testparm, activates it, and reloads Samba."
        ),
    ),
    "service.samba_1.include_file_write": representative(
        "samba-include-file-write",
        (
            "Backend writes include content via stdin to a confined temp path, "
            "validates the full Samba config, then atomically activates it."
        ),
    ),
    "service.samba_1.include_file_delete": representative(
        "samba-include-file-delete",
        (
            "Backend snapshots config state, removes one confined include file, "
            "validates the full Samba config, reloads, or restores on failure."
        ),
    ),
    "service.samba_1.share_upsert": representative(
        "samba-share-upsert",
        (
            "Backend renders one share definition from structured params, "
            "validates, snapshots, activates, and reloads Samba."
        ),
    ),
    "service.samba_1.share_delete": representative(
        "samba-share-delete",
        (
            "Backend removes one safe share definition, validates, snapshots, "
            "activates, and reloads Samba."
        ),
    ),
    "service.samba_1.service_control": [
        c(
            ["sudo", "/bin/systemctl", "{action}", "--", "{unit}.service"],
            "Run the requested enum-constrained Samba systemd action.",
        ),
        c(
            [
                "/bin/systemctl",
                "show",
                "-p",
                _SYSTEMCTL_PROPERTIES,
                "--",
                "{unit}.service",
            ],
            "Read Samba systemd state after the action.",
            continue_on_error=True,
        ),
    ],
}


def _seed_samba_write_commands(apps, schema_editor):
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


def _remove_samba_write_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    procedures = RPCProcedure.objects.filter(
        handler_id__in=list(_COMMAND_STEPS_BY_HANDLER_ID)
    )
    RPCProcedureCommand.objects.filter(procedure__in=procedures).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0051_seed_samba_write_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_samba_write_commands,
            reverse_code=_remove_samba_write_commands,
        ),
    ]
