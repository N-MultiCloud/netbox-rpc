"""Transport-driver vocabulary and estate-wide chain policy helpers.

Single source of truth shared by ``models.RPCProcedure`` (which sources its
``TRANSPORT_DRIVER_CHOICES`` from here) and ``domain.normalization`` (which
resolves the effective chain). Kept in its own module — rather than on the model
or in ``constants`` — for two reasons:

* the resolver stays importable, and therefore testable, without Django;
* ``constants`` is procedure-name reference data, and a static guard forbids
  shell-execution tokens there. One of the driver names is literally
  ``"subprocess"`` (the OpenSSH transport), so putting the vocabulary in
  ``constants`` would trip that guard for an unrelated reason.

**The capability sets mirror the capability each driver declares in
netbox-rpc-backend's ``drivers/`` registry.** That is a cross-repo contract: the
backend only falls back to a driver whose capability matches the request, so a
wrong classification here silently produces a chain the backend skips over.
"""

from __future__ import annotations

# Ansible control node.
TRANSPORT_ANSIBLE = "ansible"
TRANSPORT_ANSIBLE_NETWORK = "ansible-network"
# Linux/server SSH.
TRANSPORT_ASYNCSSH = "asyncssh"
TRANSPORT_PARAMIKO = "paramiko"
TRANSPORT_SUBPROCESS = "subprocess"
TRANSPORT_FABRIC = "fabric"
# Network CLI / orchestration.
TRANSPORT_SCRAPLI = "scrapli"
TRANSPORT_NETMIKO = "netmiko"
TRANSPORT_NAPALM = "napalm"
TRANSPORT_NORNIR = "nornir"

TRANSPORT_DRIVER_CHOICES = (
    (TRANSPORT_ANSIBLE, "Ansible (default)"),
    (TRANSPORT_ANSIBLE_NETWORK, "Ansible (network CLI)"),
    (TRANSPORT_ASYNCSSH, "AsyncSSH"),
    (TRANSPORT_PARAMIKO, "Paramiko"),
    (TRANSPORT_SUBPROCESS, "subprocess (OpenSSH)"),
    (TRANSPORT_FABRIC, "Fabric"),
    (TRANSPORT_SCRAPLI, "Scrapli"),
    (TRANSPORT_NETMIKO, "Netmiko"),
    (TRANSPORT_NAPALM, "NAPALM"),
    (TRANSPORT_NORNIR, "Nornir"),
)

CAPABILITY_LINUX_SHELL = "linux_shell"
CAPABILITY_NETWORK_CLI = "network_cli"

LINUX_SHELL_DRIVERS = frozenset(
    {
        TRANSPORT_ANSIBLE,
        TRANSPORT_ASYNCSSH,
        TRANSPORT_PARAMIKO,
        TRANSPORT_SUBPROCESS,
        TRANSPORT_FABRIC,
    }
)
NETWORK_CLI_DRIVERS = frozenset(
    {
        TRANSPORT_ANSIBLE_NETWORK,
        TRANSPORT_SCRAPLI,
        TRANSPORT_NETMIKO,
        TRANSPORT_NAPALM,
        TRANSPORT_NORNIR,
    }
)

# Drivers that route through an Ansible control node. A chain made up entirely
# of these has no raw fallback, which would turn an optional dependency into a
# hard one — the resolver appends the capability's raw default to prevent that.
ANSIBLE_DRIVERS = frozenset({TRANSPORT_ANSIBLE, TRANSPORT_ANSIBLE_NETWORK})

# What netbox-rpc-backend uses when neither a chain nor a driver reaches it.
RAW_CAPABILITY_DEFAULT = {
    CAPABILITY_LINUX_SHELL: TRANSPORT_ASYNCSSH,
    CAPABILITY_NETWORK_CLI: TRANSPORT_SCRAPLI,
}

# Keys an Ansible platform-map entry may carry. Mirrors what
# netbox-rpc-backend's ``drivers/context.py`` accepts — anything else is dropped
# here rather than sent and silently ignored there.
ANSIBLE_CONTEXT_STRING_KEYS = ("network_os", "connection", "become_method")


def normalize_driver_name(driver: object) -> str:
    """Normalize a driver name the same way the backend registry does."""

    return str(driver or "").strip().lower().replace("_", "-")


def driver_capability(driver: object) -> str:
    """Backend capability a driver serves, or ``""`` when it is unknown.

    Returning empty rather than guessing is deliberate: a wrong capability
    produces a chain entry the backend silently skips over.
    """

    normalized = normalize_driver_name(driver)
    if normalized in LINUX_SHELL_DRIVERS:
        return CAPABILITY_LINUX_SHELL
    if normalized in NETWORK_CLI_DRIVERS:
        return CAPABILITY_NETWORK_CLI
    return ""


def ansible_context_from_platform_map(mapping: object, platform_slug: object) -> dict:
    """Ansible connection settings for a NetBox Platform slug.

    Returns ``{}`` for an unmapped platform, a malformed map, or a malformed
    entry. Degrading to "no context" is deliberate: the execution backend then
    reports its network driver unavailable and the chain falls back to a raw
    driver, which is far better than guessing a vendor CLI dialect. The map is
    operator-editable, so this must never raise.
    """

    slug = str(platform_slug or "").strip().lower()
    if not slug or not isinstance(mapping, dict):
        return {}
    entry = mapping.get(slug)
    if not isinstance(entry, dict):
        return {}

    context: dict = {}
    for key in ANSIBLE_CONTEXT_STRING_KEYS:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            context[key] = value.strip()
    become = entry.get("become")
    if isinstance(become, bool):
        context["become"] = become
    return context
