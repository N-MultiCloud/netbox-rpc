"""Seed command rows for the Ubuntu 24.04 to 26.04 upgrade lifecycle.

Read-only analysis and verification use fixed argv. State capture and the
long-running upgrade remain documented backend-owned orchestration. Data is
inline so migrations remain stable across runtime constant changes.
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
    "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade": [
        c(["/bin/cat", "/etc/os-release"], "Read the current Ubuntu release."),
        c(["/bin/uname", "-r"], "Read the current kernel release."),
        c(["/usr/bin/df", "-h", "/"], "Read root filesystem free space."),
        c(["/usr/bin/apt-mark", "showhold"], "List held APT packages."),
        c(
            ["/bin/ls", "-1", "/etc/apt/sources.list.d"],
            "Enumerate third-party APT source files.",
        ),
        c(
            ["/usr/bin/dpkg", "-s", "ubuntu-release-upgrader-core"],
            "Confirm that the Ubuntu release upgrader is installed.",
        ),
        c(
            ["/usr/bin/test", "-f", "/var/run/reboot-required"],
            "Check whether a reboot is already required.",
            continue_on_error=True,
        ),
        c(
            ["/bin/cat", "/var/run/reboot-required.pkgs"],
            "Read packages that require a reboot when the file exists.",
            continue_on_error=True,
        ),
        c(
            ["/usr/bin/crontab", "-l"],
            "Read the current user's crontab when one exists.",
            continue_on_error=True,
        ),
        c(["/usr/bin/who"], "List active login sessions."),
    ],
    "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state": representative(
        "ubuntu-upgrade-26-save-preupgrade-state",
        (
            "Backend creates a timestamped backup directory and manifest from "
            "APT sources, package selections, held packages, and analysis state."
        ),
    ),
    "os.linux.ubuntu.24.upgrade_26.run_upgrade": representative(
        "ubuntu-upgrade-26-run-upgrade",
        (
            "Backend orchestrates dry-run or live do-release-upgrade and reboots "
            "only when the separately confirmed reboot flag is enabled."
        ),
    ),
    "os.linux.ubuntu.24.upgrade_26.verify_postupgrade": [
        c(["/bin/cat", "/etc/os-release"], "Read the upgraded Ubuntu release."),
        c(["/bin/uname", "-r"], "Read the post-upgrade kernel release."),
        c(
            ["/usr/bin/apt-get", "check"],
            "Check package dependency health.",
            continue_on_error=True,
        ),
        c(
            ["/usr/bin/dpkg", "--audit"],
            "Audit partially installed or inconsistent packages.",
            continue_on_error=True,
        ),
        c(["/usr/bin/apt-mark", "showhold"], "List held packages after upgrade."),
        c(
            ["/usr/bin/test", "-f", "/var/run/reboot-required"],
            "Check whether a post-upgrade reboot is required.",
            continue_on_error=True,
        ),
    ],
}


def _seed_ubuntu_upgrade_26_commands(apps, schema_editor):
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


def _remove_ubuntu_upgrade_26_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    procedures = RPCProcedure.objects.filter(
        handler_id__in=list(_COMMAND_STEPS_BY_HANDLER_ID)
    )
    RPCProcedureCommand.objects.filter(procedure__in=procedures).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0058_seed_ubuntu_upgrade_26_procedures"),
    ]

    operations = [
        migrations.RunPython(
            _seed_ubuntu_upgrade_26_commands,
            reverse_code=_remove_ubuntu_upgrade_26_commands,
        ),
    ]
