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

import copy
from collections.abc import Mapping

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


def lowering_is_refused(
    *,
    previously_set: object,
    requested: object,
    may_approve: bool,
) -> bool:
    """Return True when an edit lowers a protected safety flag without approval.

    The protected flags are ``transport_pinned`` and ``approval_required``. Only a
    change from True to a falsy value is governed. Keeping the flag, omitting the
    field, creating a procedure, and lowering the flag with the approve permission
    are all allowed. A present falsy value is treated as lowering, so an unexpected
    type fails closed.
    """
    if previously_set is not True or requested is None:
        return False
    if requested:
        return False
    return not may_approve


def unpin_is_refused(
    *,
    previously_pinned: object,
    requested_pinned: object,
    may_approve: bool,
) -> bool:
    """Return True when an edit would un-pin a transport-pinned procedure."""
    return lowering_is_refused(
        previously_set=previously_pinned,
        requested=requested_pinned,
        may_approve=may_approve,
    )


APPROVE_RPC_PROCEDURE = "netbox_rpc.approve_rpcprocedure"
UNPIN_DENIED_MESSAGE = (
    "Only users with netbox_rpc.approve_rpcprocedure can un-pin a "
    "transport-pinned RPC procedure."
)
# The REST serializer and the admin form both report this message.
APPROVAL_DENIED_MESSAGE = (
    "Only users with netbox_rpc.approve_rpcprocedure can disable "
    "approval for an existing RPC procedure."
)


# Effect levels in increasing order of risk. A stored value outside this table is
# treated as the most dangerous level, and a requested value outside it as the
# least dangerous one, so an unknown value always counts as lowering.
EFFECT_RANKS = {"read": 0, "write": 1, "destructive": 2}


def effect_lowering_is_refused(
    *,
    previous: object,
    requested: object,
    may_approve: bool,
) -> bool:
    """Return True when an edit lowers ``effect`` without the approve permission.

    Raising the effect (for example from read to destructive), keeping it,
    omitting the field, and creating a procedure are allowed.
    """
    if previous is None or requested is None or requested == previous:
        return False
    previous_rank = EFFECT_RANKS.get(str(previous), len(EFFECT_RANKS))
    requested_rank = EFFECT_RANKS.get(str(requested), -1)
    if requested_rank >= previous_rank:
        return False
    return not may_approve


def enabling_is_refused(
    *,
    previously_enabled: object,
    requested: object,
    may_approve: bool,
) -> bool:
    """Return True when an edit enables a disabled procedure without approval.

    Only a change from False is governed. Disabling a procedure stays allowed,
    because disabling the catalog row is the first rollback step. Any present
    value other than False counts as enabling, so an unexpected type fails closed.
    """
    if previously_enabled is not False or requested is None or requested is False:
        return False
    return not may_approve


def _as_comparable(value: object) -> object:
    """Return a type-exact canonical form of ``value`` for the change check.

    Every scalar is tagged with its exact type, so True and 1, 1 and 1.0, and
    0 and False differ (Python's ``==`` treats them as equal). Dictionary keys
    are tagged the same way. Only a tuple and a list with the same items are
    the same value, because a form or serializer may return either.
    """
    if isinstance(value, (list, tuple)):
        return ("sequence", tuple(_as_comparable(item) for item in value))
    if isinstance(value, dict):
        return (
            "mapping",
            frozenset((_as_comparable(key), _as_comparable(item)) for key, item in value.items()),
        )
    return (type(value).__qualname__, value)


def change_is_refused(
    *,
    previous: object,
    requested: object,
    may_approve: bool,
) -> bool:
    """Return True when an edit changes a fixed value without the approve permission.

    Used for every protected field without a direction (the driver, the chain,
    the handler, the schemas, and the others in PROTECTED_PROCEDURE_FIELD_RULES):
    any change on an existing procedure needs approval. A list and a tuple with
    the same items are the same value.
    """
    if previous is None or requested is None:
        return False
    if _as_comparable(previous) == _as_comparable(requested):
        return False
    return not may_approve


EFFECT_DENIED_MESSAGE = (
    "Only users with netbox_rpc.approve_rpcprocedure can lower the effect "
    "of an existing RPC procedure."
)
ENABLE_DENIED_MESSAGE = (
    "Only users with netbox_rpc.approve_rpcprocedure can enable a disabled "
    "RPC procedure."
)
DRIVER_DENIED_MESSAGE = (
    "Only users with netbox_rpc.approve_rpcprocedure can change the transport "
    "driver of an existing RPC procedure."
)
DRIVER_CHAIN_DENIED_MESSAGE = (
    "Only users with netbox_rpc.approve_rpcprocedure can change the transport "
    "driver chain of an existing RPC procedure."
)


def _lowering_rule(previous: object, requested: object, may_approve: bool) -> bool:
    return lowering_is_refused(
        previously_set=previous, requested=requested, may_approve=may_approve
    )


def _effect_rule(previous: object, requested: object, may_approve: bool) -> bool:
    return effect_lowering_is_refused(
        previous=previous, requested=requested, may_approve=may_approve
    )


def _enabling_rule(previous: object, requested: object, may_approve: bool) -> bool:
    return enabling_is_refused(
        previously_enabled=previous, requested=requested, may_approve=may_approve
    )


def _change_rule(previous: object, requested: object, may_approve: bool) -> bool:
    return change_is_refused(
        previous=previous, requested=requested, may_approve=may_approve
    )


def _change_denied_message(label: str) -> str:
    return (
        f"Only users with netbox_rpc.approve_rpcprocedure can change the {label} "
        "of an existing RPC procedure."
    )


# Each safety-relevant RPCProcedure field, the rule that decides whether an edit
# by a user without the scoped approve permission is refused, and the message.
# The REST serializer and the admin form both apply this one table. A field
# changes what runs, where it runs, how its result is stored, or who may approve
# it. Only description and comments stay open to the change permission, because
# nothing reads them at admission, approval, or dispatch. An edit that would bring
# the procedure into the editor's approve scope is refused separately
# (current_access.refuse_approval_scope_gain), because a constraint can match any field.
PROTECTED_PROCEDURE_FIELD_RULES = {
    "transport_pinned": (_lowering_rule, UNPIN_DENIED_MESSAGE),
    "approval_required": (_lowering_rule, APPROVAL_DENIED_MESSAGE),
    "effect": (_effect_rule, EFFECT_DENIED_MESSAGE),
    "enabled": (_enabling_rule, ENABLE_DENIED_MESSAGE),
    "transport_driver": (_change_rule, DRIVER_DENIED_MESSAGE),
    "transport_driver_chain": (_change_rule, DRIVER_CHAIN_DENIED_MESSAGE),
    # Dispatch identity: the handler the backend runs, the name that protected
    # contracts, approval scopes, and object permissions match, and the version that
    # the capability contract hash and the dispatch lease bind.
    "handler_id": (_change_rule, _change_denied_message("handler")),
    "name": (_change_rule, _change_denied_message("name")),
    "version": (_change_rule, _change_denied_message("version")),
    # Where it runs and with what input.
    "target_models": (_change_rule, _change_denied_message("target models")),
    "params_schema": (_change_rule, _change_denied_message("parameter schema")),
    "timeout_seconds": (_change_rule, _change_denied_message("timeout")),
    # How the result is validated, parsed, and stored.
    "result_schema": (_change_rule, _change_denied_message("result schema")),
    "output_parser": (_change_rule, _change_denied_message("output parser")),
    "output_schema": (_change_rule, _change_denied_message("output schema")),
    # Tags and custom fields can appear in the constraints of an object permission,
    # including a scoped approve grant, so changing them can confer approval scope.
    "tags": (_change_rule, _change_denied_message("tags")),
    "custom_field_data": (_change_rule, _change_denied_message("custom fields")),
}
PROTECTED_PROCEDURE_FIELDS = tuple(PROTECTED_PROCEDURE_FIELD_RULES)
# Protected fields that are not plain model attributes: tags are a many-to-many
# relation and custom fields are stored as one mapping. They are never restored by
# assignment, and tags are compared by primary key.
RELATION_PROTECTED_FIELDS = frozenset({"tags", "custom_field_data"})


def tag_keys(value: object) -> tuple[object, ...] | None:
    """Return the sorted primary keys of a tag collection, or None when it is absent.

    Accepts a related manager or queryset (anything with ``all()``) or an iterable of
    tags or primary keys.
    """
    if value is None:
        return None
    all_items = getattr(value, "all", None)
    items = all_items() if callable(all_items) else value
    return tuple(sorted(getattr(item, "pk", item) for item in items))


def protected_field_snapshot(procedure: object) -> dict[str, object] | None:
    """Return the stored protected fields of an existing procedure, or None.

    None means a new procedure, which no rule governs. Take the snapshot before
    anything copies requested values onto the instance.
    """
    if procedure is None or getattr(procedure, "pk", None) is None:
        return None
    # A deep copy, so a later in-place change to the instance cannot alter it.
    snapshot = {
        field: copy.deepcopy(getattr(procedure, field, None))
        for field in PROTECTED_PROCEDURE_FIELDS
        if field != "tags"
    }
    snapshot["tags"] = tag_keys(getattr(procedure, "tags", None))
    return snapshot


def protected_field_refusals(
    stored: dict[str, object] | None,
    requested: Mapping[str, object],
    may_approve: bool,
) -> dict[str, str]:
    """Return ``{field: message}`` for each protected field the edit may not change.

    ``stored`` comes from protected_field_snapshot(). A field absent from
    ``requested`` is not being changed.
    """
    if stored is None:
        return {}
    refused: dict[str, str] = {}
    for field, (rule, message) in PROTECTED_PROCEDURE_FIELD_RULES.items():
        value = requested.get(field)
        if field == "tags":
            value = tag_keys(value)
        if rule(stored.get(field), value, may_approve):
            refused[field] = message
    return refused


def may_approve_procedure(user: object, procedure: object) -> bool:
    """Return True when ``user`` may approve changes to ``procedure``.

    NetBox's has_perm() ignores object constraints when no object is passed, so
    the check names the stored procedure. A missing user or procedure fails
    closed.
    """
    if user is None or procedure is None:
        return False
    has_perm = getattr(user, "has_perm", None)
    if not callable(has_perm):
        return False
    return bool(has_perm(APPROVE_RPC_PROCEDURE, procedure))
