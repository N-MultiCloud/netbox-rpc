"""Seed command rows for read-only Samba RPC procedures.

Most Samba read procedures reduce to concrete fixed argv rows. The recursive
configuration inventory and group/member expansion remain backend-orchestrated
and are documented in netbox_rpc.command_contract.EXEMPT_HANDLER_RATIONALE.
Data is inline so migrations remain stable across runtime constant changes.
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
    "service.samba_1.config_read": [
        c(["/bin/cat", "/etc/samba/smb.conf"], "Read /etc/samba/smb.conf."),
        c(
            ["/usr/bin/sha256sum", "/etc/samba/smb.conf"],
            "Compute /etc/samba/smb.conf sha256.",
        ),
    ],
    "service.samba_1.config_test": [
        c(["/usr/bin/testparm", "-s"], "Validate and print effective Samba config."),
    ],
    "service.samba_1.config_list_files": representative(
        "samba-config-list-files",
        (
            "Backend recursively enumerates /etc/samba/**/*.conf, stats each "
            "file, and computes per-file sha256 values."
        ),
    ),
    "service.samba_1.include_file_read": [
        c(["/bin/cat", "{include_path}"], "Read one confined Samba include file."),
        c(
            ["/usr/bin/sha256sum", "{include_path}"],
            "Compute the confined include file sha256.",
        ),
    ],
    "service.samba_1.service_status": [
        c(
            ["/bin/systemctl", "show", "-p", _SYSTEMCTL_PROPERTIES, "smbd.service"],
            "Read smbd systemd state.",
        ),
        c(
            ["/bin/systemctl", "show", "-p", _SYSTEMCTL_PROPERTIES, "nmbd.service"],
            "Read nmbd systemd state.",
        ),
        c(
            [
                "/bin/systemctl",
                "show",
                "-p",
                _SYSTEMCTL_PROPERTIES,
                "winbind.service",
            ],
            "Read winbind systemd state.",
        ),
        c(
            [
                "/bin/systemctl",
                "show",
                "-p",
                _SYSTEMCTL_PROPERTIES,
                "samba-ad-dc.service",
            ],
            "Read samba-ad-dc systemd state.",
        ),
    ],
    "service.samba_1.version": [
        c(["/usr/sbin/smbd", "-V"], "Read Samba server version."),
    ],
    "service.samba_1.list_shares": [
        c(
            ["/usr/bin/testparm", "-s"],
            "Read effective Samba share definitions for parser extraction.",
        ),
    ],
    "service.samba_1.status_report": [
        c(["/usr/bin/smbstatus", "--json"], "Read smbstatus JSON report."),
    ],
    "service.samba_1.domain_info": [
        c(
            ["/usr/bin/samba-tool", "domain", "info", "127.0.0.1"],
            "Read Samba domain information.",
        ),
        c(
            ["/usr/bin/samba-tool", "domain", "level", "show"],
            "Read Samba domain and forest functional levels.",
        ),
    ],
    "service.samba_1.user_list": [
        c(
            ["/usr/bin/samba-tool", "user", "list"],
            "List Active Directory users.",
            continue_on_error=True,
        ),
        c(
            ["/usr/bin/pdbedit", "-L"],
            "List local Samba passdb users.",
            continue_on_error=True,
        ),
    ],
    "service.samba_1.group_list": representative(
        "samba-group-list",
        (
            "Backend lists groups, then expands members for each discovered "
            "group with Samba-native tooling."
        ),
    ),
    "service.samba_1.share_acl_read": [
        c(
            ["/usr/bin/sharesec", "--view", "{share_name}"],
            "Read share ACL for one safe Samba share name.",
        ),
    ],
}


def _seed_samba_read_commands(apps, schema_editor):
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


def _remove_samba_read_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    procedures = RPCProcedure.objects.filter(
        handler_id__in=list(_COMMAND_STEPS_BY_HANDLER_ID)
    )
    RPCProcedureCommand.objects.filter(procedure__in=procedures).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0049_seed_samba_read_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_samba_read_commands,
            reverse_code=_remove_samba_read_commands,
        ),
    ]
