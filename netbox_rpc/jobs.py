from __future__ import annotations

import hashlib
import json
import logging
import re
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any

import requests
from django.db import IntegrityError
from django.utils import timezone
from netbox.constants import RQ_QUEUE_DEFAULT
from netbox.jobs import JobRunner

from netbox_nms.backend import get_backend

from .constants import (
    DELL_OS10_S5232F_ALLOW_THIRD_PARTY_TRANSCEIVER,
    DELL_OS10_S5232F_BOOTSTRAP_RESTCONF,
    DELL_OS10_S5232F_CONFIGURE_INTERFACE_BREAKOUT,
    DELL_OS10_S5232F_CONFIGURE_INTERFACE_FEC,
    DELL_OS10_S5232F_CONFIGURE_INTERFACE_LACP,
    DELL_OS10_S5232F_CONFIGURE_PORT_CHANNEL,
    DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN,
    DELL_OS10_S5232F_CONFIGURE_VLT_PEER,
    DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION,
    DELL_OS10_S5232F_SET_VLAN_DESCRIPTION,
    DELL_OS10_S5232F_SHOW_VERSION,
    DELL_OS10_S5232F_SHOW_VLT,
    DELL_OS10_S5232F_WRITE_MEMORY,
    DNS_HOST_DEPLOY_PROCEDURE,
    DNS_HOST_STATUS_PROCEDURE,
    HUAWEI_MA5800_R024_START_ONT,
    LINUX_INSTALL_SSH_KEY,
    LINUX_PROXMOX_CONVERT_MELLANOX_NIC,
    LINUX_PROXMOX_QEMU_VM_LIFECYCLE,
    NGINX_1_CONFIG_DEPLOY,
    PTERODACTYL_ARTISAN,
    PTERODACTYL_BOOTSTRAP_API_KEY,
    PTERODACTYL_CONTAINER_LOGS,
    NGINX_1_CONFIG_TEST,
    NGINX_1_RELOAD,
    NGINX_1_ROLLBACK,
    PACKER_PROCEDURE_NAMES,
    UBUNTU_24_DAEMON_RELOAD,
    UBUNTU_24_DISABLE_SERVICE,
    UBUNTU_24_ENABLE_SERVICE,
    UBUNTU_24_JOURNAL_TAIL,
    UBUNTU_24_RELOAD_SERVICE,
    UBUNTU_24_RESTART_SERVICE,
    UBUNTU_24_START_SERVICE,
    UBUNTU_24_STATUS_SERVICE,
    UBUNTU_24_STOP_SERVICE,
)
from .models import RPCLinuxServiceAllowlist, RPCExecution, RPCExecutionEvent

if TYPE_CHECKING:
    from netbox_nms.models import NMSBackend
    from rq.job import Job

logger = logging.getLogger(__name__)

RPC_QUEUE_NAME = RQ_QUEUE_DEFAULT
RPC_JOB_TIMEOUT = 600
_PROXMOX_NODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PROXMOX_STORAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROXMOX_BRIDGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_PROXMOX_VM_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_PROXMOX_DISK_RE = re.compile(r"(?:scsi|virtio|sata|ide)[0-9]+$")
_PROXMOX_NO_COMMA_SPACE_RE = re.compile(r"[^\s,]{1,64}$")
_DNS_SEARCH_DOMAIN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)
_PROXMOX_QEMU_OPERATIONS = {
    "nextid",
    "clone",
    "migrate",
    "configure",
    "resize",
    "start",
    "stop",
    "status",
    "agent_ping",
    "agent_network_get_interfaces",
    "agent_configure_debian_network",
    "agent_set_user_password",
    "agent_pbs_zabbix_status",
    "agent_configure_zabbix_agent2",
}
_PROXMOX_QEMU_NIC_MODELS = {"virtio", "e1000", "e1000e", "vmxnet3", "rtl8139"}
_POSIX_USERNAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}$")
_DELL_OS10_INTERFACE_RE = re.compile(r"[A-Za-z][A-Za-z0-9/._:-]{0,63}$")
_DELL_OS10_IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_DELL_OS10_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")
_DELL_OS10_TRUNK_VLANS_RE = re.compile(
    r"\d{1,4}(?:-\d{1,4})?(?:,\d{1,4}(?:-\d{1,4})?)*"
)
_DELL_OS10_BREAKOUT_PORT_RE = re.compile(r"\d+/\d+/\d+")
_DELL_OS10_BREAKOUT_MODE_RE = re.compile(r"\d+g-\d+x")
_PTERODACTYL_CONTAINER_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_DNS_HOST_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}")
_DNS_HOST_COMPOSE_PROJECT = "powerdns-dns-api"
_PTERODACTYL_ARTISAN_ALLOWLIST = frozenset(
    {"queue:status", "schedule:run", "cache:clear", "config:clear", "queue:restart", "migrate"}
)


class RPCExecutionError(RuntimeError):
    def __init__(self, message: str, *, code: str = "RPC_EXECUTION_FAILED") -> None:
        super().__init__(message)
        self.code = code


class RPCExecutionJob(JobRunner):
    class Meta:
        name = "RPC Execution"

    @classmethod
    def enqueue(cls, *args: Any, **kwargs: Any) -> Job:
        backend_pk = kwargs.pop("backend_pk", None)
        execution_pk = kwargs.get("execution_pk")
        kwargs.setdefault("queue_name", RPC_QUEUE_NAME)
        kwargs.setdefault("job_timeout", RPC_JOB_TIMEOUT)
        # Embed identifiers in job data before enqueueing so workers can read
        # them without a race between super().enqueue() and a subsequent save.
        if backend_pk is not None or execution_pk is not None:
            data = dict(kwargs.get("data") or {})
            if backend_pk is not None:
                data["backend_pk"] = backend_pk
            if execution_pk is not None:
                data["execution_pk"] = execution_pk
            kwargs["data"] = data
        job = super().enqueue(*args, **kwargs)
        # Persist as a safety fallback in case super().enqueue() ignored the data kwarg.
        needs_data_save = False
        job.data = dict(job.data or {})
        if backend_pk is not None and job.data.get("backend_pk") != backend_pk:
            job.data["backend_pk"] = backend_pk
            needs_data_save = True
        if execution_pk is not None and job.data.get("execution_pk") != execution_pk:
            job.data["execution_pk"] = execution_pk
            needs_data_save = True
        if needs_data_save:
            job.save(update_fields=["data"])
        return job

    def run(self, *args: object, **kwargs: object) -> None:
        runtime_data = (
            kwargs.get("data") if isinstance(kwargs.get("data"), dict) else {}
        )
        execution = self._get_execution(
            execution_pk=kwargs.get("execution_pk") or runtime_data.get("execution_pk")
        )
        self._mark_running(execution)
        backend_pk = (
            runtime_data.get("backend_pk")
            or (self.job.data or {}).get("backend_pk")
            or execution.backend_id
        )
        backend = get_backend(backend_pk)
        if backend is None:
            self._mark_failed(
                execution,
                "No NMSBackend configured for RPC execution.",
                "RPC_BACKEND_NOT_CONFIGURED",
            )
            raise RPCExecutionError(
                "No NMSBackend configured for RPC execution.",
                code="RPC_BACKEND_NOT_CONFIGURED",
            )

        try:
            normalized = normalize_execution_params(execution)
            execution.normalized_params = normalized
            execution.resolved_command_hash = _hash_json(
                normalized.get("command_fingerprint")
            )
            execution.save(update_fields=["normalized_params", "resolved_command_hash"])
            _event(
                execution,
                "info",
                "normalized",
                "Execution parameters normalized by NetBox.",
            )

            response = _call_backend(backend, execution)
            _store_backend_response(execution, response)
        except Exception as exc:
            code = getattr(exc, "code", "RPC_EXECUTION_FAILED")
            self._mark_failed(execution, str(exc), code)
            raise

    def _get_execution(self, execution_pk: object | None = None) -> RPCExecution:
        raw_pk = execution_pk
        if raw_pk is None:
            raw_pk = (self.job.data or {}).get("execution_pk")
        if raw_pk is None:
            # Legacy fallback for jobs queued before RPC executions stopped
            # using NetBox's attached-object fields.
            raw_pk = self.job.object_id
        if raw_pk is None:
            raise RuntimeError("RPCExecutionJob requires an RPCExecution primary key.")
        try:
            pk = int(raw_pk)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "RPCExecutionJob received an invalid RPCExecution primary key."
            ) from exc
        return RPCExecution.objects.select_related(
            "procedure",
            "assigned_object_type",
            "backend",
        ).get(pk=pk)

    def _mark_running(self, execution: RPCExecution) -> None:
        execution.status = RPCExecution.STATUS_RUNNING
        execution.started_at = timezone.now()
        execution.save(update_fields=["status", "started_at"])
        _event(execution, "info", "started", "RPC execution started.")

    def _mark_failed(self, execution: RPCExecution, message: str, code: str) -> None:
        execution.status = RPCExecution.STATUS_FAILED
        execution.error_code = code
        execution.error_message = message
        execution.finished_at = timezone.now()
        execution.save(
            update_fields=["status", "error_code", "error_message", "finished_at"]
        )
        _event(execution, "error", "failed", message, {"code": code})


def normalize_execution_params(execution: RPCExecution) -> dict[str, Any]:
    procedure_name = execution.procedure.name
    target = execution.target_display

    if procedure_name in {
        UBUNTU_24_RESTART_SERVICE,
        UBUNTU_24_STATUS_SERVICE,
        UBUNTU_24_START_SERVICE,
        UBUNTU_24_STOP_SERVICE,
        UBUNTU_24_RELOAD_SERVICE,
        UBUNTU_24_ENABLE_SERVICE,
        UBUNTU_24_DISABLE_SERVICE,
        UBUNTU_24_JOURNAL_TAIL,
    }:
        normalized = _normalize_linux_service_execution(execution, target)
        if procedure_name == UBUNTU_24_JOURNAL_TAIL:
            lines = int((execution.params or {}).get("lines", 100))
            normalized["lines"] = lines
        return normalized

    if procedure_name == UBUNTU_24_DAEMON_RELOAD:
        return {
            "target": target,
            "command_fingerprint": {"handler_id": execution.procedure.handler_id},
        }

    if procedure_name == HUAWEI_MA5800_R024_START_ONT:
        params = execution.params or {}
        normalized = {
            "target": target,
            "frame": _int_range(params, "frame", 0, None),
            "slot": _int_range(params, "slot", 1, 17),
            "port": _int_range(params, "port", 0, 15),
            "ont_id": _int_range(params, "ont_id", 0, 127),
        }
        normalized["command_fingerprint"] = {
            "handler_id": execution.procedure.handler_id,
            "frame": normalized["frame"],
            "slot": normalized["slot"],
            "port": normalized["port"],
            "ont_id": normalized["ont_id"],
        }
        return normalized

    if procedure_name == LINUX_INSTALL_SSH_KEY:
        return _normalize_ssh_install_key_execution(execution, target)

    if procedure_name == DNS_HOST_DEPLOY_PROCEDURE:
        return _normalize_dns_host_deploy_execution(execution)

    if procedure_name == DNS_HOST_STATUS_PROCEDURE:
        return _normalize_dns_host_status_execution(execution)

    if procedure_name == LINUX_PROXMOX_CONVERT_MELLANOX_NIC:
        return _normalize_convert_mellanox_nic_execution(execution, target)

    if procedure_name in PACKER_PROCEDURE_NAMES:
        # Function-local import keeps the netbox-packer reference lazy: this
        # module imports packer_normalizer only when a packer.vm.* execution is
        # actually normalized, and packer_normalizer in turn lazy-imports
        # netbox_packer. netbox-rpc never hard-depends on netbox-packer.
        from .packer_normalizer import normalize_packer_vm_execution

        return normalize_packer_vm_execution(execution, target)

    if procedure_name == LINUX_PROXMOX_QEMU_VM_LIFECYCLE:
        return _normalize_proxmox_qemu_vm_lifecycle_execution(execution, target)

    if procedure_name == DELL_OS10_S5232F_BOOTSTRAP_RESTCONF:
        return _normalize_dell_os10_bootstrap_execution(execution, target)

    if procedure_name in {
        DELL_OS10_S5232F_ALLOW_THIRD_PARTY_TRANSCEIVER,
        DELL_OS10_S5232F_SHOW_VERSION,
        DELL_OS10_S5232F_WRITE_MEMORY,
    }:
        return _normalize_dell_os10_simple_execution(execution, target)

    if procedure_name == DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION:
        params = execution.params or {}
        interface_name = str(params.get("interface_name") or "").strip()
        if not _DELL_OS10_INTERFACE_RE.fullmatch(interface_name):
            raise RPCExecutionError(
                "interface_name must be a valid OS10 interface identifier.",
                code="RPC_PARAM_INVALID",
            )
        description = _dell_os10_description(params)
        write_memory = _bool_param(params, "write_memory", False)
        normalized = {
            "target": target,
            "interface_name": interface_name,
            "description": description,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_name": interface_name,
                "description_sha256": _hash_text(description),
                "write_memory": write_memory,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_SET_VLAN_DESCRIPTION:
        params = execution.params or {}
        vlan_id = _int_range(params, "vlan_id", 1, 4094)
        description = _dell_os10_description(params)
        write_memory = _bool_param(params, "write_memory", False)
        normalized = {
            "target": target,
            "vlan_id": vlan_id,
            "description": description,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "vlan_id": vlan_id,
                "description_sha256": _hash_text(description),
                "write_memory": write_memory,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_SHOW_VLT:
        params = execution.params or {}
        domain_id = _optional_int_range(params, "domain_id", 1, 255)
        if domain_id is None:
            domain_id = 1
        normalized = {
            "target": target,
            "domain_id": domain_id,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "domain_id": domain_id,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN:
        params = execution.params or {}
        domain_id = _int_range(params, "domain_id", 1, 255)
        # unit_id is optional — Dell OS10 10.5.x auto-negotiates the unit role
        # and does not recognise the 'unit-id' CLI command; omit it when absent.
        unit_id = _optional_int_range(params, "unit_id", 1, 2)
        primary_priority = _optional_int_range(params, "primary_priority", 1, 65535)
        if primary_priority is None:
            primary_priority = 32768
        discovery_port_channel = _int_range(params, "discovery_port_channel", 1, 4096)
        backup_destination = str(params.get("backup_destination") or "").strip()
        if not _DELL_OS10_IP_RE.fullmatch(backup_destination):
            raise RPCExecutionError(
                "backup_destination must be a valid IPv4 address.",
                code="RPC_PARAM_INVALID",
            )
        vlt_mac = str(params.get("vlt_mac") or "").strip()
        if vlt_mac and not _DELL_OS10_MAC_RE.fullmatch(vlt_mac):
            raise RPCExecutionError(
                "vlt_mac must be a valid MAC address (XX:XX:XX:XX:XX:XX).",
                code="RPC_PARAM_INVALID",
            )
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "domain_id": domain_id,
            "primary_priority": primary_priority,
            "discovery_port_channel": discovery_port_channel,
            "backup_destination": backup_destination,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "domain_id": domain_id,
                "primary_priority": primary_priority,
                "discovery_port_channel": discovery_port_channel,
                "backup_destination": backup_destination,
            },
        }
        if unit_id is not None:
            normalized["unit_id"] = unit_id
            normalized["command_fingerprint"]["unit_id"] = unit_id
        if vlt_mac:
            normalized["vlt_mac"] = vlt_mac
            normalized["command_fingerprint"]["vlt_mac"] = vlt_mac
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_VLT_PEER:
        params = execution.params or {}
        port_channel_id = _int_range(params, "port_channel_id", 1, 4096)
        vlt_port_channel_id = _int_range(params, "vlt_port_channel_id", 1, 4096)
        remove = _bool_param(params, "remove", False)
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "port_channel_id": port_channel_id,
            "vlt_port_channel_id": vlt_port_channel_id,
            "remove": remove,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "port_channel_id": port_channel_id,
                "vlt_port_channel_id": vlt_port_channel_id,
                "remove": remove,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_PORT_CHANNEL:
        params = execution.params or {}
        port_channel_id = _int_range(params, "port_channel_id", 1, 4096)
        trunk_vlans = str(params.get("trunk_vlans") or "").strip()
        if trunk_vlans and not _DELL_OS10_TRUNK_VLANS_RE.fullmatch(trunk_vlans):
            raise RPCExecutionError(
                "trunk_vlans must be a comma-separated list of VLAN IDs or ranges "
                "(e.g. '20,111' or '10-20,100').",
                code="RPC_PARAM_INVALID",
            )
        description = _dell_os10_description(params)
        remove = _bool_param(params, "remove", False)
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "port_channel_id": port_channel_id,
            "remove": remove,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "port_channel_id": port_channel_id,
                "remove": remove,
            },
        }
        if trunk_vlans:
            normalized["trunk_vlans"] = trunk_vlans
            normalized["command_fingerprint"]["trunk_vlans"] = trunk_vlans
        if description:
            normalized["description"] = description
            normalized["command_fingerprint"]["description_sha256"] = _hash_text(
                description
            )
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_INTERFACE_LACP:
        params = execution.params or {}
        interface_name = str(params.get("interface_name") or "").strip()
        if not _DELL_OS10_INTERFACE_RE.fullmatch(interface_name):
            raise RPCExecutionError(
                "interface_name must be a valid OS10 interface identifier.",
                code="RPC_PARAM_INVALID",
            )
        port_channel_id = _int_range(params, "port_channel_id", 1, 4096)
        lacp_mode = str(params.get("lacp_mode") or "active").strip().lower()
        if lacp_mode not in {"active", "passive", "on"}:
            raise RPCExecutionError(
                "lacp_mode must be 'active', 'passive', or 'on'.",
                code="RPC_PARAM_INVALID",
            )
        description = _dell_os10_description(params)
        remove = _bool_param(params, "remove", False)
        write_memory = _bool_param(params, "write_memory", False)
        normalized = {
            "target": target,
            "interface_name": interface_name,
            "port_channel_id": port_channel_id,
            "lacp_mode": lacp_mode,
            "remove": remove,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_name": interface_name,
                "port_channel_id": port_channel_id,
                "lacp_mode": lacp_mode,
                "remove": remove,
            },
        }
        if description:
            normalized["description"] = description
            normalized["command_fingerprint"]["description_sha256"] = _hash_text(
                description
            )
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_INTERFACE_BREAKOUT:
        params = execution.params or {}
        interface_port = str(params.get("interface_port") or "").strip()
        if not _DELL_OS10_BREAKOUT_PORT_RE.fullmatch(interface_port):
            raise RPCExecutionError(
                "interface_port must be in slot/port/subport format, e.g. '1/1/1'.",
                code="RPC_PARAM_INVALID",
            )
        breakout_mode = str(params.get("breakout_mode") or "").strip()
        if not _DELL_OS10_BREAKOUT_MODE_RE.fullmatch(breakout_mode):
            raise RPCExecutionError(
                "breakout_mode must be in Ng-Mx format, e.g. '40g-1x' or '10g-4x'.",
                code="RPC_PARAM_INVALID",
            )
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "interface_port": interface_port,
            "breakout_mode": breakout_mode,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_port": interface_port,
                "breakout_mode": breakout_mode,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == DELL_OS10_S5232F_CONFIGURE_INTERFACE_FEC:
        params = execution.params or {}
        interface_name = str(params.get("interface_name") or "").strip()
        if not _DELL_OS10_INTERFACE_RE.fullmatch(interface_name):
            raise RPCExecutionError(
                "interface_name must be a valid OS10 interface identifier.",
                code="RPC_PARAM_INVALID",
            )
        fec_mode = str(params.get("fec_mode") or "cl91").strip().lower()
        if fec_mode not in {"cl91", "cl108", "auto", "none"}:
            raise RPCExecutionError(
                "fec_mode must be one of: cl91, cl108, auto, none.",
                code="RPC_PARAM_INVALID",
            )
        write_memory = _bool_param(params, "write_memory", True)
        normalized = {
            "target": target,
            "interface_name": interface_name,
            "fec_mode": fec_mode,
            "write_memory": write_memory,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "interface_name": interface_name,
                "fec_mode": fec_mode,
            },
        }
        _copy_optional_credential_override(params, normalized)
        return normalized

    if procedure_name == NGINX_1_CONFIG_TEST:
        return _normalize_nginx_node_execution(execution, target, extra_params={})

    if procedure_name == NGINX_1_CONFIG_DEPLOY:
        params = execution.params or {}
        config_content = str(params.get("config_content") or "").strip()
        if not config_content:
            raise RPCExecutionError(
                "config_content must be a non-empty string.", code="RPC_PARAM_INVALID"
            )
        deployment_id = _int_range(params, "deployment_id", 1, None)
        extra: dict[str, Any] = {
            "config_content": config_content,
            "deployment_id": deployment_id,
        }
        config_path = str(params.get("config_path") or "").strip()
        if config_path:
            extra["config_path"] = config_path
        return _normalize_nginx_node_execution(execution, target, extra_params=extra)

    if procedure_name == NGINX_1_RELOAD:
        return _normalize_nginx_node_execution(execution, target, extra_params={})

    if procedure_name == NGINX_1_ROLLBACK:
        params = execution.params or {}
        deployment_id = _int_range(params, "deployment_id", 1, None)
        previous_config = str(params.get("previous_config") or "").strip()
        if not previous_config:
            raise RPCExecutionError(
                "previous_config must be a non-empty string.", code="RPC_PARAM_INVALID"
            )
        extra = {"deployment_id": deployment_id, "previous_config": previous_config}
        return _normalize_nginx_node_execution(execution, target, extra_params=extra)

    if procedure_name == PTERODACTYL_BOOTSTRAP_API_KEY:
        params = execution.params or {}
        container_name = str(params.get("container_name") or "pterodactyl-panel-1").strip()
        if not _PTERODACTYL_CONTAINER_NAME_RE.fullmatch(container_name):
            raise RPCExecutionError(
                "container_name contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        return {
            "target": target,
            "container_name": container_name,
            "command_fingerprint": {"handler_id": execution.procedure.handler_id},
        }

    if procedure_name == PTERODACTYL_ARTISAN:
        params = execution.params or {}
        command = str(params.get("command") or "").strip()
        if command not in _PTERODACTYL_ARTISAN_ALLOWLIST:
            raise RPCExecutionError(
                f"command must be one of: {', '.join(sorted(_PTERODACTYL_ARTISAN_ALLOWLIST))}",
                code="RPC_PARAM_INVALID",
            )
        container_name = str(params.get("container_name") or "pterodactyl-panel-1").strip()
        if not _PTERODACTYL_CONTAINER_NAME_RE.fullmatch(container_name):
            raise RPCExecutionError(
                "container_name contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        return {
            "target": target,
            "command": command,
            "container_name": container_name,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "command": command,
                "container_name": container_name,
            },
        }

    if procedure_name == PTERODACTYL_CONTAINER_LOGS:
        params = execution.params or {}
        container_name = str(params.get("container_name") or "pterodactyl-panel-1").strip()
        if not _PTERODACTYL_CONTAINER_NAME_RE.fullmatch(container_name):
            raise RPCExecutionError(
                "container_name contains invalid characters.", code="RPC_PARAM_INVALID"
            )
        lines = max(1, min(500, int(params.get("lines", 100))))
        return {
            "target": target,
            "container_name": container_name,
            "lines": lines,
            "command_fingerprint": {
                "handler_id": execution.procedure.handler_id,
                "container_name": container_name,
                "lines": lines,
            },
        }

    raise RPCExecutionError(
        f"Procedure {procedure_name!r} has no NetBox normalizer.",
        code="RPC_PROCEDURE_NOT_NORMALIZABLE",
    )


def _normalize_nginx_node_execution(
    execution: RPCExecution,
    target: str,
    extra_params: dict[str, Any],
) -> dict[str, Any]:
    params = execution.params or {}
    node_id = _int_range(params, "node_id", 1, None)
    result: dict[str, Any] = {
        "target": target,
        "node_id": node_id,
        **extra_params,
    }
    result["command_fingerprint"] = {
        "handler_id": execution.procedure.handler_id,
        "node_id": node_id,
    }
    return result


def _normalize_linux_service_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    slug = str((execution.params or {}).get("service_slug") or "").strip()
    allow = RPCLinuxServiceAllowlist.objects.filter(slug=slug, enabled=True).first()
    if allow is None:
        raise RPCExecutionError(
            f"Linux service {slug!r} is not allowlisted.",
            code="RPC_LINUX_SERVICE_NOT_ALLOWLISTED",
        )
    target_models = set(allow.target_models or [])
    if target_models and execution.target_model_label not in target_models:
        raise RPCExecutionError(
            f"Linux service {slug!r} is not allowed for {execution.target_model_label}.",
            code="RPC_LINUX_SERVICE_TARGET_DENIED",
        )
    unit = allow.systemd_unit
    result = {
        "target": target,
        "service_slug": slug,
        "systemd_unit": unit,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "systemd_unit": unit,
        },
    }
    if allow.ssh_credential_override_id is not None:
        result["rpc_ssh_credential_pk"] = allow.ssh_credential_override_id
    return result


def _normalize_ssh_install_key_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for os.linux.ubuntu.24.install_ssh_key.

    Validates that public_key is a single-line OpenSSH key (no newlines),
    extracts the optional username, and builds the normalized dict for
    nms-backend to execute the authorized_keys append via SSH.
    """
    params = execution.params or {}
    public_key = str(params.get("public_key") or "").strip()
    if not public_key:
        raise RPCExecutionError("public_key is required.", code="RPC_PARAM_INVALID")
    if "\n" in public_key or "\r" in public_key:
        raise RPCExecutionError(
            "public_key must be a single line without newlines.",
            code="RPC_PARAM_INVALID",
        )
    if not any(
        public_key.startswith(prefix)
        for prefix in ("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")
    ):
        raise RPCExecutionError(
            "public_key must start with a supported key type prefix.",
            code="RPC_PARAM_INVALID",
        )
    # Strip any comment field — only key-type + base64-blob is forwarded to nms-backend.
    # This eliminates comment-field characters from the authorized_keys append path.
    key_parts = public_key.split(None, 2)
    public_key = " ".join(key_parts[:2]) if len(key_parts) >= 2 else public_key

    result: dict[str, Any] = {
        "target": target,
        "public_key": public_key,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "public_key_prefix": public_key[:64],
        },
    }

    username = str(params.get("username") or "").strip()
    if username:
        if not _POSIX_USERNAME_RE.fullmatch(username):
            raise RPCExecutionError(
                "username must be a valid POSIX username "
                "(lowercase letters, digits, _ or -; starts with letter or _; max 32 chars).",
                code="RPC_PARAM_INVALID",
            )
        result["username"] = username

    return result


def _normalize_dns_host_deploy_execution(execution: RPCExecution) -> dict[str, Any]:
    """Normalize the audited DNS stack deploy procedure for an arbitrary SSH host."""
    normalized = _normalize_dns_host_execution(execution)
    force_recreate = _bool_param(execution.params or {}, "force_recreate", False)
    normalized["force_recreate"] = force_recreate
    normalized["command_fingerprint"]["force_recreate"] = force_recreate
    return normalized


def _normalize_dns_host_status_execution(execution: RPCExecution) -> dict[str, Any]:
    """Normalize the read-only DNS stack status procedure for an arbitrary SSH host."""
    return _normalize_dns_host_execution(execution)


def _normalize_dns_host_execution(execution: RPCExecution) -> dict[str, Any]:
    params = execution.params or {}
    target = str(params.get("target") or "").strip()
    if not _DNS_HOST_TARGET_RE.fullmatch(target):
        raise RPCExecutionError(
            "target must be a short DNS host name such as dns01 or dns02.",
            code="RPC_PARAM_INVALID",
        )

    credential_pk = _int_range(params, "rpc_ssh_credential_pk", 1, None)
    host = str(params.get("rpc_ssh_host") or "").strip() or f"{target}.nmulti.cloud"
    _validate_dns_host_ssh_host(host)
    ssh_port = _optional_int_range(params, "rpc_ssh_port", 1, 65535) or 22
    known_hosts_entry = str(params.get("rpc_ssh_known_hosts_entry") or "")
    if "\n" in known_hosts_entry or "\r" in known_hosts_entry:
        raise RPCExecutionError(
            "rpc_ssh_known_hosts_entry must be a single line.",
            code="RPC_PARAM_INVALID",
        )
    if len(known_hosts_entry) > 8192:
        raise RPCExecutionError(
            "rpc_ssh_known_hosts_entry may contain at most 8192 characters.",
            code="RPC_PARAM_INVALID",
        )

    return {
        "target": target,
        "rpc_ssh_host": host,
        "rpc_ssh_port": ssh_port,
        "rpc_ssh_credential_pk": credential_pk,
        "rpc_ssh_known_hosts_entry": known_hosts_entry,
        "rpc_ssh_strict_host_key_checking": _bool_param(
            params, "rpc_ssh_strict_host_key_checking", True
        ),
        "compose_project": _DNS_HOST_COMPOSE_PROJECT,
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "procedure": execution.procedure.name,
            "target": target,
            "compose_project": _DNS_HOST_COMPOSE_PROJECT,
            "rpc_ssh_host": host,
            "rpc_ssh_port": ssh_port,
        },
    }


def _validate_dns_host_ssh_host(host: str) -> None:
    if not host:
        raise RPCExecutionError(
            "rpc_ssh_host could not be resolved from params.",
            code="RPC_PARAM_INVALID",
        )
    if len(host) > 255:
        raise RPCExecutionError(
            "rpc_ssh_host may contain at most 255 characters.",
            code="RPC_PARAM_INVALID",
        )
    if any(ch.isspace() or ord(ch) < 32 for ch in host):
        raise RPCExecutionError(
            "rpc_ssh_host must not contain whitespace or control characters.",
            code="RPC_PARAM_INVALID",
        )


def _normalize_convert_mellanox_nic_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize params for os.linux.proxmox.convert_mellanox_nic_to_ethernet.

    Resolves SSH connection details for the selected ProxmoxEndpoint through the
    netbox-nms ``resolve_proxmox_endpoint_ssh`` helper and emits the
    ``rpc_ssh_*`` host-override keys that nms-backend consumes. The import is
    function-local so importing this module never requires the (possibly older)
    installed netbox-nms to expose ``proxmox_ssh`` — only an actual Mellanox
    execution does.
    """
    params = execution.params or {}
    endpoint_id = _int_range(params, "proxmox_endpoint_id", 1, None)
    resolved = _resolve_proxmox_ssh_binding(endpoint_id)

    reboot = bool(params.get("reboot", False))
    apply_network = bool(params.get("apply_network", False))
    dry_run = bool(params.get("dry_run", False))
    interfaces_content = str(params.get("interfaces_content") or "")
    # Operator bond parameters. The params_schema (migration 0010) gates the
    # accepted shapes at execution creation, and nms-backend re-validates them
    # strictly in Pydantic before any shell embedding.
    bond_name = str(params.get("bond_name") or "bond1").strip() or "bond1"
    bond_vlans = str(params.get("bond_vlans") or "").strip().replace(" ", "")
    bond_mtu = _int_range(
        {"bond_mtu": params.get("bond_mtu", 9216)}, "bond_mtu", 576, 9216
    )

    normalized: dict[str, Any] = {
        "target": target,
        "rpc_ssh_host": resolved["host"],
        "rpc_ssh_port": int(resolved.get("port") or 22),
        "rpc_ssh_credential_pk": int(resolved["credential_pk"]),
        "rpc_ssh_known_hosts_entry": str(resolved.get("known_hosts_entry") or ""),
        "rpc_ssh_strict_host_key_checking": bool(
            resolved.get("strict_host_key_checking", True)
        ),
        "reboot": reboot,
        "apply_network": apply_network,
        "interfaces_content": interfaces_content,
        "dry_run": dry_run,
        "bond_name": bond_name,
        "bond_vlans": bond_vlans,
        "bond_mtu": bond_mtu,
    }
    normalized["command_fingerprint"] = {
        "handler_id": execution.procedure.handler_id,
        "proxmox_endpoint_id": endpoint_id,
        "reboot": reboot,
        "apply_network": apply_network,
        "dry_run": dry_run,
        "bond_name": bond_name,
        "bond_vlans": bond_vlans,
        "bond_mtu": bond_mtu,
        # Hash (not the body) of any custom interfaces content keeps the
        # fingerprint stable-sized while still reflecting content changes.
        "interfaces_content_sha": _hash_json(interfaces_content)
        if interfaces_content
        else "",
    }
    return normalized


def _normalize_proxmox_qemu_vm_lifecycle_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    """Normalize a constrained Proxmox QEMU VM lifecycle request."""
    params = execution.params or {}
    endpoint_id = _int_range(params, "proxmox_endpoint_id", 1, None)
    resolved = _resolve_proxmox_ssh_binding(endpoint_id)
    operations = _proxmox_operations(params)
    vmid = _optional_int_range(params, "vmid", 100, 999999999)

    normalized: dict[str, Any] = {
        "target": target,
        "rpc_ssh_host": resolved["host"],
        "rpc_ssh_port": int(resolved.get("port") or 22),
        "rpc_ssh_credential_pk": int(resolved["credential_pk"]),
        "rpc_ssh_known_hosts_entry": str(resolved.get("known_hosts_entry") or ""),
        "rpc_ssh_strict_host_key_checking": bool(
            resolved.get("strict_host_key_checking", True)
        ),
        "proxmox_endpoint_id": endpoint_id,
        "operations": operations,
    }
    if vmid is not None:
        normalized["vmid"] = vmid

    command_fingerprint: dict[str, Any] = {
        "handler_id": execution.procedure.handler_id,
        "proxmox_endpoint_id": endpoint_id,
        "operations": operations,
    }
    if vmid is not None:
        command_fingerprint["vmid"] = vmid

    for key, regex in (
        ("name", _PROXMOX_VM_NAME_RE),
        ("source_node", _PROXMOX_NODE_RE),
        ("node", _PROXMOX_NODE_RE),
        ("target_node", _PROXMOX_NODE_RE),
        ("storage", _PROXMOX_STORAGE_RE),
        ("target_storage", _PROXMOX_STORAGE_RE),
    ):
        value = _optional_regex_param(params, key, regex)
        if value:
            normalized[key] = value
            command_fingerprint[key] = value

    for key, minimum, maximum in (
        ("template_vmid", 100, 999999999),
        ("memory_mb", 128, 1048576),
        ("cores", 1, 512),
        ("disk_gb", 1, 262144),
        ("guest_credential_pk", 1, None),
    ):
        value = _optional_int_range(params, key, minimum, maximum)
        if value is not None:
            normalized[key] = value
            command_fingerprint[key] = value

    if "full_clone" in params:
        normalized["full_clone"] = _bool_param(params, "full_clone", True)
    else:
        normalized["full_clone"] = True
    command_fingerprint["full_clone"] = normalized["full_clone"]

    normalized["agent_enabled"] = _bool_param(params, "agent_enabled", True)
    command_fingerprint["agent_enabled"] = normalized["agent_enabled"]

    ciuser = str(params.get("ciuser") or "").strip()
    if ciuser:
        if not _POSIX_USERNAME_RE.fullmatch(ciuser):
            raise RPCExecutionError("ciuser must be a valid POSIX username.", code="RPC_PARAM_INVALID")
        normalized["ciuser"] = ciuser
        command_fingerprint["ciuser"] = ciuser

    search_domain = _normalize_dns_search_domain(params.get("search_domain"))
    if search_domain:
        normalized["search_domain"] = search_domain
        command_fingerprint["search_domain"] = search_domain
    dns_servers = _normalize_dns_servers(params.get("dns_servers") or [])
    if dns_servers:
        normalized["dns_servers"] = dns_servers
        command_fingerprint["dns_servers"] = dns_servers

    resize_disk = str(params.get("resize_disk") or "scsi0").strip()
    if "resize" in operations:
        if not _PROXMOX_DISK_RE.fullmatch(resize_disk):
            raise RPCExecutionError("resize_disk must be a valid Proxmox disk key.", code="RPC_PARAM_INVALID")
        normalized["resize_disk"] = resize_disk
        command_fingerprint["resize_disk"] = resize_disk

    networks = _normalize_proxmox_networks(params.get("networks") or [])
    if networks:
        normalized["networks"] = networks
        command_fingerprint["networks"] = networks
    ipconfigs = _normalize_proxmox_ipconfigs(params.get("ipconfigs") or [])
    if ipconfigs:
        normalized["ipconfigs"] = ipconfigs
        command_fingerprint["ipconfigs"] = ipconfigs
    guest_networks = _normalize_proxmox_guest_networks(params.get("guest_networks") or [])
    if guest_networks:
        normalized["guest_networks"] = guest_networks
        command_fingerprint["guest_networks"] = guest_networks

    if {"agent_pbs_zabbix_status", "agent_configure_zabbix_agent2"} & set(operations):
        zabbix_server = _normalize_zabbix_server(
            params.get("zabbix_server") or "zabbix.nmulti.cloud"
        )
        normalized["zabbix_server"] = zabbix_server
        command_fingerprint["zabbix_server"] = zabbix_server

    _require_proxmox_fields(operations, normalized)
    normalized["command_fingerprint"] = command_fingerprint
    return normalized


def _resolve_proxmox_ssh_binding(endpoint_id: int) -> dict[str, Any]:
    try:
        from netbox_nms.proxmox_ssh import resolve_proxmox_endpoint_ssh
    except ImportError as exc:
        raise RPCExecutionError(
            "netbox-nms does not expose the Proxmox SSH resolver; "
            "upgrade netbox-nms to a version with ProxmoxEndpointSSHBinding.",
            code="RPC_PROXMOX_SSH_RESOLVER_MISSING",
        ) from exc

    resolved = resolve_proxmox_endpoint_ssh(endpoint_id)
    if not resolved:
        raise RPCExecutionError(
            f"No Proxmox Endpoint SSH binding is configured for endpoint "
            f"{endpoint_id}. Create one in NetBox NMS "
            "(Proxmox Endpoint SSH Bindings) before running this procedure.",
            code="RPC_PROXMOX_SSH_BINDING_NOT_FOUND",
        )
    host = str(resolved.get("host") or "").strip()
    if not host:
        raise RPCExecutionError(
            f"The Proxmox Endpoint SSH binding for endpoint {endpoint_id} has no "
            "resolvable host. Set an SSH host override or an endpoint IP/domain.",
            code="RPC_PROXMOX_SSH_HOST_UNRESOLVED",
        )
    if resolved.get("credential_pk") is None:
        raise RPCExecutionError(
            f"The Proxmox Endpoint SSH binding for endpoint {endpoint_id} has no "
            "linked SSH credential.",
            code="RPC_PROXMOX_SSH_CREDENTIAL_MISSING",
        )
    return {**resolved, "host": host}


def _proxmox_operations(params: dict[str, Any]) -> list[str]:
    raw = params.get("operations")
    if not isinstance(raw, list) or not raw:
        raise RPCExecutionError("operations must be a non-empty list.", code="RPC_PARAM_INVALID")
    operations: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if value not in _PROXMOX_QEMU_OPERATIONS:
            raise RPCExecutionError(f"Unsupported Proxmox QEMU operation: {value}", code="RPC_PARAM_INVALID")
        if value in operations:
            raise RPCExecutionError("operations must not contain duplicates.", code="RPC_PARAM_INVALID")
        operations.append(value)
    return operations


def _optional_regex_param(
    params: dict[str, Any],
    key: str,
    regex: re.Pattern[str],
) -> str:
    value = str(params.get(key) or "").strip()
    if not value:
        return ""
    if not regex.fullmatch(value):
        raise RPCExecutionError(f"{key} contains invalid characters.", code="RPC_PARAM_INVALID")
    return value


def _normalize_proxmox_networks(raw: Any) -> list[dict[str, Any]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError("networks must be a list.", code="RPC_PARAM_INVALID")
    if len(raw) > 8:
        raise RPCExecutionError("networks may contain at most 8 entries.", code="RPC_PARAM_INVALID")
    seen: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RPCExecutionError("network entries must be objects.", code="RPC_PARAM_INVALID")
        index = _int_range(item, "index", 0, 31)
        if index in seen:
            raise RPCExecutionError("network indexes must be unique.", code="RPC_PARAM_INVALID")
        seen.add(index)
        model = str(item.get("model") or "virtio").strip()
        if model not in _PROXMOX_QEMU_NIC_MODELS:
            raise RPCExecutionError("network model is not allowlisted.", code="RPC_PARAM_INVALID")
        bridge = str(item.get("bridge") or "").strip()
        if not _PROXMOX_BRIDGE_RE.fullmatch(bridge):
            raise RPCExecutionError("network bridge contains invalid characters.", code="RPC_PARAM_INVALID")
        entry: dict[str, Any] = {"index": index, "model": model, "bridge": bridge}
        if item.get("tag") not in (None, ""):
            entry["tag"] = _int_range(item, "tag", 1, 4094)
        if "firewall" in item:
            entry["firewall"] = _bool_param(item, "firewall", False)
        normalized.append(entry)
    return sorted(normalized, key=lambda entry: int(entry["index"]))


def _normalize_proxmox_ipconfigs(raw: Any) -> list[dict[str, Any]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError("ipconfigs must be a list.", code="RPC_PARAM_INVALID")
    if len(raw) > 8:
        raise RPCExecutionError("ipconfigs may contain at most 8 entries.", code="RPC_PARAM_INVALID")
    seen: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RPCExecutionError("ipconfig entries must be objects.", code="RPC_PARAM_INVALID")
        index = _int_range(item, "index", 0, 31)
        if index in seen:
            raise RPCExecutionError("ipconfig indexes must be unique.", code="RPC_PARAM_INVALID")
        seen.add(index)
        ip = str(item.get("ip") or "").strip()
        if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(ip):
            raise RPCExecutionError("ipconfig ip contains invalid characters.", code="RPC_PARAM_INVALID")
        entry: dict[str, Any] = {"index": index, "ip": ip}
        gw = str(item.get("gw") or "").strip()
        if gw:
            if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(gw):
                raise RPCExecutionError("ipconfig gw contains invalid characters.", code="RPC_PARAM_INVALID")
            entry["gw"] = gw
        normalized.append(entry)
    return sorted(normalized, key=lambda entry: int(entry["index"]))


def _normalize_proxmox_guest_networks(raw: Any) -> list[dict[str, Any]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError("guest_networks must be a list.", code="RPC_PARAM_INVALID")
    if len(raw) > 8:
        raise RPCExecutionError("guest_networks may contain at most 8 entries.", code="RPC_PARAM_INVALID")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RPCExecutionError("guest_network entries must be objects.", code="RPC_PARAM_INVALID")
        interface = str(item.get("interface") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,31}", interface):
            raise RPCExecutionError("guest_network interface contains invalid characters.", code="RPC_PARAM_INVALID")
        if interface in seen:
            raise RPCExecutionError("guest_network interfaces must be unique.", code="RPC_PARAM_INVALID")
        seen.add(interface)
        address = str(item.get("address") or "").strip()
        if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(address):
            raise RPCExecutionError("guest_network address contains invalid characters.", code="RPC_PARAM_INVALID")
        entry: dict[str, Any] = {"interface": interface, "address": address}
        gateway = str(item.get("gateway") or "").strip()
        if gateway:
            if not _PROXMOX_NO_COMMA_SPACE_RE.fullmatch(gateway):
                raise RPCExecutionError("guest_network gateway contains invalid characters.", code="RPC_PARAM_INVALID")
            entry["gateway"] = gateway
        normalized.append(entry)
    return sorted(normalized, key=lambda entry: str(entry["interface"]))


def _normalize_dns_search_domain(raw: Any) -> str:
    value = str(raw or "").strip().rstrip(".")
    if not value:
        return ""
    if len(value) > 253 or not _DNS_SEARCH_DOMAIN_RE.fullmatch(value):
        raise RPCExecutionError("search_domain must be a valid DNS search domain.", code="RPC_PARAM_INVALID")
    return value


def _normalize_dns_servers(raw: Any) -> list[str]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RPCExecutionError("dns_servers must be a list.", code="RPC_PARAM_INVALID")
    if len(raw) > 3:
        raise RPCExecutionError("dns_servers may contain at most 3 entries.", code="RPC_PARAM_INVALID")
    normalized: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if not value:
            raise RPCExecutionError("dns_servers must not contain empty entries.", code="RPC_PARAM_INVALID")
        try:
            ip_address(value)
        except ValueError as exc:
            raise RPCExecutionError("dns_servers entries must be valid IP addresses.", code="RPC_PARAM_INVALID") from exc
        if value in normalized:
            raise RPCExecutionError("dns_servers must not contain duplicates.", code="RPC_PARAM_INVALID")
        normalized.append(value)
    return normalized


def _normalize_zabbix_server(raw: Any) -> str:
    value = str(raw or "").strip().rstrip(".")
    if not value:
        raise RPCExecutionError("zabbix_server is required.", code="RPC_PARAM_INVALID")
    try:
        ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not _DNS_SEARCH_DOMAIN_RE.fullmatch(value):
        raise RPCExecutionError(
            "zabbix_server must be a valid DNS name or IP address.",
            code="RPC_PARAM_INVALID",
        )
    return value


def _require_proxmox_fields(operations: list[str], params: dict[str, Any]) -> None:
    if "nextid" in operations:
        if len(operations) != 1:
            raise RPCExecutionError("nextid must be run as a standalone operation.", code="RPC_PARAM_INVALID")
        return
    _require_keys(params, ["vmid"])
    if "clone" in operations:
        _require_keys(params, ["template_vmid", "source_node", "name"])
    if "migrate" in operations:
        _require_keys(params, ["source_node", "target_node"])
    if {
        "configure",
        "resize",
        "start",
        "stop",
        "status",
        "agent_ping",
        "agent_network_get_interfaces",
        "agent_configure_debian_network",
        "agent_set_user_password",
        "agent_pbs_zabbix_status",
        "agent_configure_zabbix_agent2",
    } & set(operations):
        _require_keys(params, ["node"])
    if "resize" in operations:
        _require_keys(params, ["disk_gb", "resize_disk"])
    if "agent_configure_debian_network" in operations:
        _require_keys(params, ["guest_networks"])
    if "agent_set_user_password" in operations:
        _require_keys(params, ["guest_credential_pk"])


def _require_keys(params: dict[str, Any], keys: list[str]) -> None:
    missing = [key for key in keys if params.get(key) in (None, "", [])]
    if missing:
        raise RPCExecutionError(
            f"Missing required Proxmox lifecycle field(s): {', '.join(missing)}.",
            code="RPC_PARAM_INVALID",
        )


def _normalize_dell_os10_simple_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    result: dict[str, Any] = {
        "target": target,
        "command_fingerprint": {"handler_id": execution.procedure.handler_id},
    }
    _copy_optional_credential_override(params, result)
    return result


def _normalize_dell_os10_bootstrap_execution(
    execution: RPCExecution,
    target: str,
) -> dict[str, Any]:
    params = execution.params or {}
    configure_user = _bool_param(params, "configure_user", False)
    restconf_credential_pk = _optional_int_range(
        params,
        "restconf_credential_pk",
        1,
        None,
    )
    if configure_user and restconf_credential_pk is None:
        raise RPCExecutionError(
            "restconf_credential_pk is required when configure_user is true.",
            code="RPC_PARAM_INVALID",
        )
    session_timeout = _optional_int_range(params, "session_timeout", 1, 1440)
    cipher_suites = params.get("cipher_suites") or []
    if not isinstance(cipher_suites, list):
        raise RPCExecutionError(
            "cipher_suites must be a list of OS10 cipher suite names.",
            code="RPC_PARAM_INVALID",
        )
    cipher_suites = [str(item).strip() for item in cipher_suites if str(item).strip()]
    if len(cipher_suites) > 12:
        raise RPCExecutionError(
            "cipher_suites may contain at most 12 entries.",
            code="RPC_PARAM_INVALID",
        )
    certificate_name = str(params.get("certificate_name") or "").strip()
    if any(
        any(ch.isspace() or ord(ch) < 32 for ch in item)
        for item in [certificate_name, *cipher_suites]
    ):
        raise RPCExecutionError(
            "Dell OS10 RESTCONF bootstrap parameters must not contain whitespace or control characters.",
            code="RPC_PARAM_INVALID",
        )

    normalized: dict[str, Any] = {
        "target": target,
        "configure_user": configure_user,
        "enable_ssh": _bool_param(params, "enable_ssh", True),
        "enable_restconf": _bool_param(params, "enable_restconf", True),
        "write_memory": _bool_param(params, "write_memory", True),
        "command_fingerprint": {
            "handler_id": execution.procedure.handler_id,
            "configure_user": configure_user,
            "enable_ssh": _bool_param(params, "enable_ssh", True),
            "enable_restconf": _bool_param(params, "enable_restconf", True),
            "write_memory": _bool_param(params, "write_memory", True),
        },
    }
    if restconf_credential_pk is not None:
        normalized["restconf_credential_pk"] = restconf_credential_pk
        normalized["command_fingerprint"]["restconf_credential_pk"] = (
            restconf_credential_pk
        )
    if certificate_name:
        normalized["certificate_name"] = certificate_name
        normalized["command_fingerprint"]["certificate_name"] = certificate_name
    if session_timeout is not None:
        normalized["session_timeout"] = session_timeout
        normalized["command_fingerprint"]["session_timeout"] = session_timeout
    if cipher_suites:
        normalized["cipher_suites"] = cipher_suites
        normalized["command_fingerprint"]["cipher_suites"] = cipher_suites
    _copy_optional_credential_override(params, normalized)
    return normalized


def _copy_optional_credential_override(
    params: dict[str, Any],
    normalized: dict[str, Any],
) -> None:
    credential_pk = _optional_int_range(params, "rpc_ssh_credential_pk", 1, None)
    if credential_pk is not None:
        normalized["rpc_ssh_credential_pk"] = credential_pk
        normalized["command_fingerprint"]["rpc_ssh_credential_pk"] = credential_pk


def _dell_os10_description(params: dict[str, Any]) -> str:
    description = str(params.get("description") or "")
    if len(description) > 240:
        raise RPCExecutionError(
            "description may contain at most 240 characters.",
            code="RPC_PARAM_INVALID",
        )
    if any(ord(ch) < 32 and ch not in ("\t",) for ch in description):
        raise RPCExecutionError(
            "description must not contain control characters.",
            code="RPC_PARAM_INVALID",
        )
    return description


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _optional_int_range(
    params: dict[str, Any],
    key: str,
    minimum: int,
    maximum: int | None,
) -> int | None:
    if key not in params or params.get(key) in (None, ""):
        return None
    return _int_range(params, key, minimum, maximum)


def _bool_param(params: dict[str, Any], key: str, default: bool) -> bool:
    if key not in params or params.get(key) is None:
        return default
    value = params.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    raise RPCExecutionError(
        f"{key} must be a boolean.",
        code="RPC_PARAM_INVALID",
    )


def _int_range(
    params: dict[str, Any], key: str, minimum: int, maximum: int | None
) -> int:
    try:
        value = int(params[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise RPCExecutionError(
            f"{key} must be an integer.", code="RPC_PARAM_INVALID"
        ) from exc
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" and <= {maximum}" if maximum is not None else ""
        raise RPCExecutionError(
            f"{key} must be >= {minimum}{suffix}.",
            code="RPC_PARAM_OUT_OF_RANGE",
        )
    return value


def _call_backend(backend: NMSBackend, execution: RPCExecution) -> dict[str, Any]:
    url = f"{backend.backend_url.rstrip('/')}/rpc/executions/{execution.pk}/run"
    timeout = (10, max(execution.procedure.timeout_seconds + 10, 30))
    try:
        resp = requests.post(
            url,
            headers=backend.get_auth_headers(),
            json={},
            verify=backend.verify_ssl,
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        raise RPCExecutionError(
            f"nms-backend is unreachable: {exc}",
            code="RPC_BACKEND_UNREACHABLE",
        ) from exc
    if resp.status_code == 401:
        raise RPCExecutionError(
            "nms-backend returned 401 Unauthorized.",
            code="RPC_BACKEND_UNAUTHORIZED",
        )
    try:
        data = resp.json()
    except ValueError as exc:
        raise RPCExecutionError(
            f"nms-backend returned non-JSON response: HTTP {resp.status_code}",
            code="RPC_BACKEND_BAD_RESPONSE",
        ) from exc
    if resp.status_code >= 400:
        if not isinstance(data, dict):
            raise RPCExecutionError(
                f"nms-backend returned HTTP {resp.status_code}",
                code="RPC_BACKEND_ERROR",
            )
        detail = data.get("detail")
        message = (
            detail
            if isinstance(detail, str)
            else data.get("error", f"HTTP {resp.status_code}")
        )
        raise RPCExecutionError(
            str(message), code=str(data.get("code") or "RPC_BACKEND_ERROR")
        )
    return data


def _store_backend_response(execution: RPCExecution, response: dict[str, Any]) -> None:
    ok = bool(response.get("ok"))
    execution.result = response.get("result") or {}
    execution.error_code = str(response.get("error_code") or "")
    execution.error_message = str(response.get("error_message") or "")
    execution.status = (
        RPCExecution.STATUS_SUCCEEDED if ok else RPCExecution.STATUS_FAILED
    )
    execution.finished_at = timezone.now()
    execution.save(
        update_fields=["result", "error_code", "error_message", "status", "finished_at"]
    )
    for item in response.get("events") or []:
        _event(
            execution,
            str(item.get("level") or "info"),
            str(item.get("event") or "backend"),
            str(item.get("message") or ""),
            item.get("data") if isinstance(item.get("data"), dict) else {},
        )
    if ok:
        _event(execution, "info", "completed", "RPC execution completed.")
    else:
        _event(
            execution,
            "error",
            "failed",
            execution.error_message or "RPC execution failed.",
        )


def _event(
    execution: RPCExecution,
    level: str,
    event: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    from django.db.models import Max
    from django.db.models.functions import Coalesce

    max_seq = execution.events.aggregate(m=Coalesce(Max("sequence"), 0))["m"]
    # Retry up to 3 times on sequence collisions from concurrent RQ workers.
    # Always attempt max_seq+1 after re-reading — never add the loop counter,
    # which would skip valid sequence numbers on re-reads.
    for _ in range(3):
        try:
            RPCExecutionEvent.objects.create(
                execution=execution,
                sequence=max_seq + 1,
                level=level,
                event=event,
                message=message,
                data=data or {},
            )
            return
        except IntegrityError:
            max_seq = execution.events.aggregate(m=Coalesce(Max("sequence"), 0))["m"]
    # Final attempt after exhausting retries; log instead of propagating if this
    # also collides, so an event loss under extreme concurrency doesn't abort the job.
    try:
        RPCExecutionEvent.objects.create(
            execution=execution,
            sequence=max_seq + 1,
            level=level,
            event=event,
            message=message,
            data=data or {},
        )
    except IntegrityError:
        logger.warning(
            "RPCExecutionEvent sequence collision exhausted retries for execution %s "
            "(event=%r). Event dropped.",
            execution.pk,
            event,
        )


def _hash_json(value: object) -> str:
    if value is None:
        return ""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
