"""Normalizer for netbox-packer ``packer.vm.*`` post-build verification procedures.

Dependency direction (hard constraint):

    netbox-rpc  --soft, one-way-->  netbox-packer
    netbox-packer  --(nothing)-->   netbox-rpc

This module is the ONLY place netbox-rpc references netbox-packer, and it does
so through a **function-local lazy import** guarded by ``try/except
ImportError``. NetBox therefore boots normally when netbox-packer is not
installed; only an actual ``packer.vm.*`` execution touches the plugin. The
coupling is otherwise purely string-based (``target_models`` content-type
labels). netbox-packer never imports, depends on, or references netbox-rpc.

The ``packer.vm.*`` procedures are read-only checks run over SSH against the
Proxmox node that built the template. A :class:`PackerTemplate` has no
``ProxmoxEndpoint`` reference, so SSH is resolved from exactly one of
``rpc_ssh_credential_pk`` (a netbox-nms DeviceCredential PK) or
``openbao_assignment_id`` (a netbox-openbao ``CredentialAssignment`` PK,
mutually exclusive with the former), plus the template's own ``proxmox_node``
— emitted as the same ``rpc_ssh_*`` host-override keys that ``nms-backend``
consumes for any host-scoped procedure.

**Target binding and host authority (#321 round-2 review).** The
``openbao_assignment_id`` path requires the referenced assignment's
``assigned_object`` to equal ``execution.assigned_object`` -- this exact
``PackerTemplate`` -- so a credential assigned to template A can never be
used dispatching against template B's execution. A caller-supplied
``ssh_host`` override must equal the template's own ``proxmox_node``; it no
longer has any power to redirect where a template-bound credential is used.
Both invariants exist together: template-binding alone would be moot if the
host could still be redirected out from under it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .constants import PACKER_VM_VERIFY_SERVICES
from .domain.normalization import (
    RPCExecutionError,
    _optional_int_range,
    resolve_openbao_assignment_reference,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .models import RPCExecution

# Default systemd units checked by packer.vm.verify_services when the caller
# does not supply an explicit ``services`` list. These are the agents that the
# netbox-packer cloud-init bake typically installs.
_DEFAULT_VERIFY_SERVICES = ("qemu-guest-agent",)

# systemd unit-name safe charset (mirrors the params_schema pattern). Kept here
# as a defense-in-depth re-validation after JSON-Schema validation at the API.
_SERVICE_NAME_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@:-"
)


def _coerce_services(raw: Any) -> list[str]:
    """Validate and normalize an optional list of systemd unit names."""
    if raw in (None, ""):
        return list(_DEFAULT_VERIFY_SERVICES)
    if not isinstance(raw, (list, tuple)):
        raise RPCExecutionError(
            "services must be a list of systemd unit names.",
            code="RPC_PARAM_INVALID",
        )
    services: list[str] = []
    for item in raw:
        name = str(item or "").strip()
        if not name or len(name) > 100 or not set(name) <= _SERVICE_NAME_ALLOWED:
            raise RPCExecutionError(
                "each services entry must be a valid systemd unit name.",
                code="RPC_PARAM_INVALID",
            )
        services.append(name)
    return services or list(_DEFAULT_VERIFY_SERVICES)


def _resolve_credential_reference(
    params: dict[str, Any], execution: RPCExecution
) -> tuple[int | None, dict[str, int] | None]:
    """Resolve exactly one of the two mutually-exclusive credential params.

    The params_schema's ``oneOf`` already enforces this at creation time, but
    a row written outside schema validation (fixture, data migration, bulk
    update, or a params_schema edited out from under an existing row) must
    not reach the backend unvalidated -- so this is re-checked here, in the
    pure domain, exactly like every other allowlist/schema invariant this
    plugin re-validates defensively.
    """
    legacy_credential_pk = _optional_int_range(params, "rpc_ssh_credential_pk", 1, None)
    openbao_assignment_id = _optional_int_range(
        params, "openbao_assignment_id", 1, None
    )
    if (legacy_credential_pk is None) == (openbao_assignment_id is None):
        raise RPCExecutionError(
            "Exactly one of rpc_ssh_credential_pk or openbao_assignment_id "
            "is required.",
            code="RPC_PARAM_INVALID",
        )
    if legacy_credential_pk is not None:
        return legacy_credential_pk, None
    # Template-bound: a credential assigned to one PackerTemplate must never
    # be usable dispatching against a different template's execution.
    openbao_reference = resolve_openbao_assignment_reference(
        openbao_assignment_id, execution, enforce_target_binding=True
    )
    return None, openbao_reference


def _resolve_ssh_host(params: dict[str, Any], template: Any, *, bound: bool) -> str:
    """Resolve the SSH host, binding it to the template for OpenBao credentials.

    When the credential is a netbox-openbao assignment bound to this template
    (`bound`), the template's own proxmox_node is the sole host authority: a
    caller-supplied ssh_host must match it exactly, so a template-bound
    credential can never be used against a host its assignment says nothing
    about. The legacy credential path keeps its existing override, which
    operators use to reach a node by address rather than by name.
    """
    proxmox_node = str(getattr(template, "proxmox_node", "") or "").strip()
    host_override = str(params.get("ssh_host") or "").strip()
    if host_override and not bound:
        return host_override
    if host_override and host_override != proxmox_node:
        raise RPCExecutionError(
            "ssh_host must match the template's own proxmox_node.",
            code="RPC_PACKER_HOST_MISMATCH",
        )
    if not proxmox_node:
        raise RPCExecutionError(
            "The PackerTemplate has no proxmox_node; cannot resolve an SSH host.",
            code="RPC_PACKER_HOST_UNRESOLVED",
        )
    return proxmox_node


def normalize_packer_vm_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for the read-only ``packer.vm.*`` verification procedures.

    Lazy-imports netbox-packer (raising a structured error when absent), confirms
    the execution targets a :class:`PackerTemplate`, resolves the SSH host from
    the template's own ``proxmox_node`` and exactly one of
    ``rpc_ssh_credential_pk`` or a template-bound ``openbao_assignment_id``, and
    emits the ``rpc_ssh_*`` host-override keys plus an auditable
    ``command_fingerprint``.
    """
    try:
        from netbox_packer.models import PackerTemplate
    except ImportError as exc:  # netbox-packer not installed
        raise RPCExecutionError(
            "netbox-packer is not installed; packer.vm.* procedures require it.",
            code="RPC_PACKER_PLUGIN_MISSING",
        ) from exc

    template = getattr(execution, "assigned_object", None)
    if not isinstance(template, PackerTemplate):
        raise RPCExecutionError(
            "packer.vm.* procedures must target a netbox-packer PackerTemplate.",
            code="RPC_PARAM_INVALID",
        )

    params = execution.params or {}
    legacy_credential_pk, openbao_reference = _resolve_credential_reference(
        params, execution
    )
    host = _resolve_ssh_host(params, template, bound=openbao_reference is not None)
    ssh_port = _optional_int_range(params, "ssh_port", 1, 65535) or 22

    raw_template_id = getattr(template, "proxmox_template_id", None)
    try:
        template_vmid = int(raw_template_id) if raw_template_id is not None else None
    except (TypeError, ValueError):
        template_vmid = None

    normalized: dict[str, Any] = {
        "target": target,
        "rpc_ssh_host": host,
        "rpc_ssh_port": ssh_port,
        "proxmox_node": host,
        "proxmox_template_id": template_vmid,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "proxmox_node": host,
            "proxmox_template_id": template_vmid,
        },
    }
    if openbao_reference is not None:
        normalized.update(openbao_reference)
        normalized["command_fingerprint"].update(openbao_reference)
    else:
        normalized["rpc_ssh_credential_pk"] = legacy_credential_pk
        normalized["command_fingerprint"]["rpc_ssh_credential_pk"] = (
            legacy_credential_pk
        )

    if execution.procedure.name == PACKER_VM_VERIFY_SERVICES:
        services = _coerce_services(params.get("services"))
        normalized["services"] = services
        normalized["command_fingerprint"]["services"] = services

    return normalized
