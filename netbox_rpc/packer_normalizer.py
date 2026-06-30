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
``ProxmoxEndpoint`` reference, so SSH is resolved from an explicit
``rpc_ssh_credential_pk`` (a netbox-nms DeviceCredential PK) plus the template's
``proxmox_node`` (overridable with ``ssh_host``) — emitted as the same
``rpc_ssh_*`` host-override keys that ``nms-backend`` consumes for any
host-scoped procedure.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .constants import PACKER_VM_VERIFY_SERVICES
from .domain.normalization import RPCExecutionError, _int_range, _optional_int_range

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


def normalize_packer_vm_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for the read-only ``packer.vm.*`` verification procedures.

    Lazy-imports netbox-packer (raising a structured error when absent), confirms
    the execution targets a :class:`PackerTemplate`, resolves the SSH host from
    the template's ``proxmox_node`` (or an ``ssh_host`` override) and the required
    ``rpc_ssh_credential_pk``, and emits the ``rpc_ssh_*`` host-override keys plus
    an auditable ``command_fingerprint``.
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
    credential_pk = _int_range(params, "rpc_ssh_credential_pk", 1, None)

    host_override = str(params.get("ssh_host") or "").strip()
    host = host_override or str(getattr(template, "proxmox_node", "") or "").strip()
    if not host:
        raise RPCExecutionError(
            "The PackerTemplate has no proxmox_node and no ssh_host override was "
            "provided; cannot resolve an SSH host.",
            code="RPC_PACKER_HOST_UNRESOLVED",
        )

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
        "rpc_ssh_credential_pk": credential_pk,
        "proxmox_node": str(getattr(template, "proxmox_node", "") or ""),
        "proxmox_template_id": template_vmid,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "proxmox_node": host,
            "proxmox_template_id": template_vmid,
        },
    }

    if execution.procedure.name == PACKER_VM_VERIFY_SERVICES:
        services = _coerce_services(params.get("services"))
        normalized["services"] = services
        normalized["command_fingerprint"]["services"] = services

    return normalized
