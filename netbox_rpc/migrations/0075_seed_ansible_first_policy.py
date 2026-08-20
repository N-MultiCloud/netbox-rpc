"""Make Ansible the estate-wide default transport, and pin what must not move.

This is the migration that actually delivers "Ansible is the default way to reach
devices and VMs". It does so **without rewriting a single procedure's driver**:

* Seeding ``RpcPluginSettings.default_*_driver_chain`` makes every procedure that
  has no chain of its own resolve to "Ansible first, then the procedure's own
  driver as fallback" — computed at dispatch time by
  ``domain.normalization.resolve_driver_chain``.
* Rolling the policy back is therefore one settings edit, with no per-row
  rewrite to undo and nothing to redeploy. A per-row rewrite would have flipped
  ~100 rows irreversibly-in-practice and lost the operator's own values.

**Two procedures are pinned and must never be moved onto Ansible.** Both disable
transport fallback, which truncates the chain to its first entry — so an
Ansible-first chain would remove their required driver entirely, with no fallback
tier to catch it:

``service.netbox.staging.rotate_backend_token``
    Runs with ``strict_auth=True`` and ``capture_output=False``. ``strict_auth``
    maps to AsyncSSH options that disable every ambient credential and config
    discovery path, including trivial-auth rejection, which OpenSSH has no
    equivalent of. The execution backend refuses ``strict_auth`` on Ansible for
    exactly this reason, so leaving it unpinned would break the procedure loudly
    rather than weaken it silently — but broken is still broken.

``os.linux.ubuntu.24.upgrade_26.run_upgrade``
    The live (non-dry-run) upgrade must never be redispatched onto a second
    driver — that risks running ``do-release-upgrade`` twice — and it streams the
    upgrade's terminal output live, which the Ansible driver cannot provide
    incrementally (its report is read once, at exit).

The pin is a **declared property** (``transport_pinned``), not a name list
consulted at dispatch time, so a future procedure with the same requirement opts
out by setting the flag rather than by being remembered here.
"""

from django.db import migrations

# Procedures whose backend handler depends on one specific transport driver.
PINNED_HANDLER_IDS = (
    "service.netbox.staging.rotate_backend_token",
    "os.linux.ubuntu.24.upgrade_26.run_upgrade",
)

# "Ansible first, then whatever the procedure already used." The procedure's own
# driver is appended by the resolver, so this stays a one-entry policy and never
# reorders an operator's existing fallback preference.
DEFAULT_LINUX_CHAIN = ["ansible"]
DEFAULT_NETWORK_CHAIN = ["ansible-network"]

# Platform slug -> Ansible connection settings, following the netbox.netbox
# collection's conventions. An unmapped platform gets no network OS, and the
# backend then falls back to a raw driver rather than guessing a CLI dialect.
ANSIBLE_PLATFORM_MAP = {
    "junos": {
        "network_os": "junipernetworks.junos.junos",
        # Junos configuration modules speak NETCONF; the raw-CLI driver ignores
        # this hint and stays on network_cli, which Junos also serves.
        "connection": "ansible.netcommon.netconf",
        "become": False,
    },
    "huawei-vrp": {
        "network_os": "community.network.ce",
        "connection": "ansible.netcommon.network_cli",
        "become": False,
    },
    "ios": {
        "network_os": "cisco.ios.ios",
        "connection": "ansible.netcommon.network_cli",
        "become": True,
        "become_method": "enable",
    },
    "iosxr": {
        "network_os": "cisco.iosxr.iosxr",
        "connection": "ansible.netcommon.network_cli",
        "become": False,
    },
    "nxos": {
        "network_os": "cisco.nxos.nxos",
        "connection": "ansible.netcommon.network_cli",
        "become": True,
        "become_method": "enable",
    },
    "eos": {
        "network_os": "arista.eos.eos",
        "connection": "ansible.netcommon.network_cli",
        "become": True,
        "become_method": "enable",
    },
    "dellos10": {
        "network_os": "dellemc.os10.os10",
        "connection": "ansible.netcommon.network_cli",
        "become": False,
    },
    "linux": {
        "connection": "ansible.builtin.ssh",
        "become": False,
    },
}


def apply_policy(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RpcPluginSettings = apps.get_model("netbox_rpc", "RpcPluginSettings")

    RPCProcedure.objects.filter(handler_id__in=PINNED_HANDLER_IDS).update(
        transport_pinned=True
    )

    settings_row, _created = RpcPluginSettings.objects.get_or_create(
        singleton_key="default"
    )
    changed = False
    # Only seed what the operator has not already set, so re-running the
    # migration (or applying it to an estate that already tuned its policy)
    # cannot clobber a deliberate choice.
    if not settings_row.default_transport_driver_chain:
        settings_row.default_transport_driver_chain = list(DEFAULT_LINUX_CHAIN)
        changed = True
    if not settings_row.default_network_driver_chain:
        settings_row.default_network_driver_chain = list(DEFAULT_NETWORK_CHAIN)
        changed = True
    if not settings_row.ansible_platform_map:
        settings_row.ansible_platform_map = dict(ANSIBLE_PLATFORM_MAP)
        changed = True
    if changed:
        settings_row.save()


def revert_policy(apps, schema_editor):
    """Restore raw-driver behaviour estate-wide.

    Clears only the values this migration seeds, and only when they still match
    what was seeded — an operator who has since edited the policy keeps their
    edit rather than having it silently discarded by a rollback.
    """

    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RpcPluginSettings = apps.get_model("netbox_rpc", "RpcPluginSettings")

    RPCProcedure.objects.filter(handler_id__in=PINNED_HANDLER_IDS).update(
        transport_pinned=False
    )

    settings_row = RpcPluginSettings.objects.filter(singleton_key="default").first()
    if settings_row is None:
        return
    changed = False
    if list(settings_row.default_transport_driver_chain or []) == DEFAULT_LINUX_CHAIN:
        settings_row.default_transport_driver_chain = []
        changed = True
    if list(settings_row.default_network_driver_chain or []) == DEFAULT_NETWORK_CHAIN:
        settings_row.default_network_driver_chain = []
        changed = True
    if dict(settings_row.ansible_platform_map or {}) == ANSIBLE_PLATFORM_MAP:
        settings_row.ansible_platform_map = {}
        changed = True
    if changed:
        settings_row.save()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0074_ansible_transport_policy"),
    ]

    operations = [
        migrations.RunPython(apply_policy, revert_policy),
    ]
