from __future__ import annotations

import re
from typing import Literal, TypedDict

CommandStepType = Literal["shell_argv", "device_cli"]
DeviceCliMode = Literal["exec", "config"]


RenderMode = Literal["literal", "jinja"]
CaptureKind = Literal["", "stdout", "stdout_stripped", "json", "regex", "line"]


class CommandStep(TypedDict):
    """Serialized command step served to nms-backend."""

    sequence: int
    step_type: CommandStepType
    device_cli_mode: DeviceCliMode | None
    argv: list[str]
    description: str
    condition_param: str
    condition_negate: bool
    for_each_param: str
    continue_on_error: bool
    # Templating + output-capture contract (see ``command_templating``). The
    # nms-backend executor renders ``argv`` per ``render_mode`` and captures this
    # command's output into ``produces_var`` for later ``{{ vars.<name> }}`` use.
    render_mode: RenderMode
    produces_var: str
    capture_kind: CaptureKind
    capture_expression: str


SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_@%+=:,./{}-]+$")
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

COMMAND_RUNTIME_KEYS = frozenset(
    {
        "rpc_ssh_host",
        "rpc_ssh_port",
        "rpc_ssh_credential_pk",
        "rpc_ssh_known_hosts_entry",
        "rpc_ssh_strict_host_key_checking",
        "target",
        "item",
        # Normalizer-derived (never caller-supplied) substitution values. Like
        # ``target``/``item`` these are produced at normalization time, not
        # declared in ``params_schema``, so they must be allowed here for
        # ``RPCProcedureCommand.clean()``/``full_clean()`` to accept a seeded
        # argv that references them. ``members_csv`` is the comma-joined form of
        # the Samba identity ``members`` list param (safe-charset-validated
        # per-entry by ``_normalize_samba_member_list`` before the join), used by
        # ``service.samba_1.group_add_members``/``group_remove_members``. It is
        # deliberately NOT a ``params_schema`` property: declaring it there would
        # let a caller pass a pre-joined string and bypass per-member validation.
        "members_csv",
    }
)

# Handler IDs that cannot be faithfully reduced to a fixed argv / device-CLI
# list without losing backend orchestration semantics. Each still receives a
# representative RPCProcedureCommand row so the object view and API expose the
# fact that backend-owned orchestration exists.
EXEMPT_HANDLER_RATIONALE = {
    "network.dell_os10_s5232f_on.bootstrap_restconf": (
        "Includes backend-decrypted RESTCONF username/password material and a "
        "variable cipher-suite join that must stay backend-orchestrated."
    ),
    "network.dell_os10_s5232f_on.configure_interface_fec": (
        "The current command contract has truthy/negated conditions only; the "
        "fec_mode=none branch emits 'no fec' and cannot be faithfully expressed."
    ),
    "os.linux_ubuntu_24.install_ssh_key": (
        "Installs key material through stdin to a guarded bash script; the public "
        "key body is intentionally never represented as argv."
    ),
    "os.linux_ubuntu_24.install_zabbix_agent2": (
        "Runs a multi-line install/configuration script through sudo bash -s with "
        "repository setup and config-file edits."
    ),
    "os.linux_proxmox.convert_mellanox_nic_to_ethernet": (
        "Destructive Proxmox host workflow with discovery, interface-file rewrite, "
        "driver loading, optional network apply, and optional reboot."
    ),
    "os.linux_proxmox.qemu_vm_lifecycle": (
        "Destructive structured lifecycle orchestrator with operation loops, QEMU "
        "guest-agent JSON-RPC, dynamic config lists, and secret password resolution."
    ),
    "service.nginx.1.config_deploy": (
        "Writes caller-provided config via stdin, tests it, and rolls back through "
        "backend-owned shell orchestration."
    ),
    "service.nginx.1.rollback": (
        "Restores backend-selected snapshot content and validates/reloads nginx."
    ),
    "os.linux.dns_host.deploy_dns_stack": (
        "Bootstraps secrets and writes a full Docker Compose document through "
        "backend-owned scripts and stdin."
    ),
    "services.pterodactyl.bootstrap_api_key": (
        "Uses a backend-owned fallback sequence for php artisan about/version."
    ),
    "services.passbolt.export_secrets": (
        "Exports DB/GPG/JWT material into staged files without returning file "
        "contents; the workflow uses backend-owned Docker/tar/stat/checksum steps."
    ),
    "services.passbolt.transfer_secrets": (
        "Transfers staged files host-to-host via rsync/ssh and verifies checksums; "
        "file bytes must never pass through netbox-rpc or nms-backend storage."
    ),
    "services.passbolt.import_secrets": (
        "Imports DB and archive material on the target VM, fixes ownership and "
        "permissions, then runs Passbolt cake migration/healthcheck as www-data."
    ),
    "services.passbolt.cleanup": (
        "Removes operator-approved staging directories on source and target hosts "
        "after a successful migration."
    ),
    "service.samba_1.config_list_files": (
        "Recursively enumerates /etc/samba/**/*.conf, stats each file, and "
        "computes per-file sha256 values; the loop and path confinement are "
        "backend-owned rather than a single fixed argv invocation."
    ),
    "service.samba_1.group_list": (
        "Lists groups and then expands members for each discovered group; the "
        "dynamic per-group member loop depends on previous command output."
    ),
    "service.samba_1.config_deploy": (
        "Writes caller-provided smb.conf content through stdin to a temp path, "
        "validates that candidate with testparm, snapshots the active config, "
        "and only then activates and reloads it. On any failure after the "
        "snapshot is taken (activation, reload, timeout, or lost response), the "
        "backend must restore the snapshot, re-validate and reload the restored "
        "config, and report rolled_back plus rollback_error."
    ),
    "service.samba_1.config_rollback": (
        "Restores a backend-owned Samba config snapshot, validates the restored "
        "candidate, and reloads Samba without exposing snapshot paths as argv; "
        "the result reports lifecycle and rollback-outcome fields."
    ),
    "service.samba_1.include_file_write": (
        "Writes caller-provided include-file content through stdin to a confined "
        "temp path, validates the resulting Samba config, and atomically "
        "activates or rolls back through backend-owned orchestration."
    ),
    "service.samba_1.include_file_delete": (
        "Deletes one confined include file only after backend snapshot/validation "
        "guardrails can restore the previous config on failure."
    ),
    "service.samba_1.share_upsert": (
        "Renders an allowlisted share definition from structured params, validates "
        "the generated Samba config, snapshots, activates, and reloads it."
    ),
    "service.samba_1.share_delete": (
        "Removes one safe share definition from Samba config through backend-owned "
        "parse/edit/validate/snapshot/reload orchestration."
    ),
    "service.samba_1.user_create": (
        "Creates a Samba/AD user with a caller-supplied password delivered to "
        "samba-tool over stdin. The password is scrubbed to a sha256+byte-count "
        "fingerprint at execution-creation time and is never persisted or "
        "represented as an argv token."
    ),
    "service.samba_1.user_set_password": (
        "Resets a Samba/AD user password delivered to samba-tool over stdin. The "
        "password is scrubbed to a sha256+byte-count fingerprint at "
        "execution-creation time and is never persisted or represented as an "
        "argv token."
    ),
    "services.minecraft.plugin.install_url": (
        "URL-download installer with destination-safe temp file handling under the "
        "Pterodactyl Wings volume."
    ),
    "services.minecraft.viaversion.install": (
        "Resolves hard-coded GitHub release metadata before running per-plugin URL "
        "installers."
    ),
    "services.minecraft.papermc.install": (
        "Resolves PaperMC Fill API metadata before installing a server jar."
    ),
    "os.linux.ubuntu.24.ookla.diagnose": (
        "Aggregates several read-only bash-s probe scripts and parsers."
    ),
    "os.linux.ubuntu.24.ookla.check_service": (
        "Runs the fixed Ookla discovery bash-s probe and parses service/config state."
    ),
    "os.linux.ubuntu.24.ookla.check_listeners": (
        "Runs discovery plus a listener-inspection bash-s probe."
    ),
    "os.linux.ubuntu.24.ookla.check_tls": (
        "Runs discovery plus TLS certificate and live-handshake bash-s probes."
    ),
    "os.linux.ubuntu.24.ookla.check_firewall": (
        "Runs discovery plus firewall-state bash-s probes."
    ),
    "os.linux_proxmox.show_systemctl_services": (
        "Read-only agentless pull: the backend runs `systemctl show -p ...` per "
        "unit (or a backend-defined default unit set when none is requested) and "
        "parses the key=value output; SSH is resolved backend-side from the "
        "endpoint's own credential, so it cannot be faithfully reduced to a "
        "single fixed argv row."
    ),
}
EXEMPT_HANDLER_IDS = frozenset(EXEMPT_HANDLER_RATIONALE)


def extract_placeholders(token: str) -> tuple[str, ...]:
    """Return placeholder names embedded in one argv token."""

    return tuple(match.group(1) for match in PLACEHOLDER_RE.finditer(token))


def token_has_balanced_placeholders(token: str) -> bool:
    """Return True when any braces in token form valid {placeholder} spans."""

    stripped = PLACEHOLDER_RE.sub("", token)
    return "{" not in stripped and "}" not in stripped


def token_is_safe(token: str) -> bool:
    """Return True when a literal argv token uses the conservative charset."""

    return bool(SAFE_TOKEN_RE.fullmatch(token))
