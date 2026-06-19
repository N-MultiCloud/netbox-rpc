# netbox-rpc Agent Notes

`netbox-rpc` owns procedure policy and audit state. It must never store or
accept arbitrary SSH command text from API clients.

## LLM Agent Safety Guardrails

**STOP — read this section before creating any `RPCExecution` record.**

These rules apply to all LLM agents (Claude Code, Codex, or any automated
system) that interact with the `netbox-rpc` REST API.

### Destructive Proxmox Operations

The `os.linux.proxmox.convert_mellanox_nic_to_ethernet` procedure
(`effect="destructive"`, `approval_required=True`) targets a **live Proxmox
hypervisor node** via SSH. It can:

- Permanently flip InfiniBand NICs to Ethernet (irreversible without hardware reset)
- Rewrite `/etc/network/interfaces`, breaking active network connectivity
- Reboot the hypervisor, dropping all running VMs and containers
- Disrupt the entire Proxmox cluster if the affected node is a quorum member

**An LLM agent MUST NOT autonomously create or approve an RPCExecution for any
procedure with `approval_required=True` or `effect="destructive"` without
explicit, in-session confirmation from a human operator.** Before dispatching,
the agent must confirm with the user:

1. The exact `ProxmoxEndpoint` ID (`proxmox_endpoint_id` param) — verify by name
2. The full `params` object including `reboot`, `apply_network`, `dry_run`
3. The expected network impact on the hypervisor and its guests
4. That the operator has a working out-of-band (IPMI/iDRAC) connection to the node

**Minimum safe workflow:**

```
1. Run with dry_run=True first and show the user the planned changes.
2. If and only if the user explicitly confirms, run with dry_run=False.
3. Never pass reboot=True without separate explicit user confirmation.
```

### Other Write Procedures

The procedures below are `approval_required=False` but still modify production
infrastructure. An LLM agent should present the intended action to the user
before dispatching, not after:

| Procedure | Risk |
|---|---|
| `os.linux.ubuntu.24.restart_service` | Service downtime |
| `os.linux.ubuntu.24.start_service` / `stop_service` | Service downtime |
| `network.device.dell_os10.s5232f_on.configure_vlt_domain` | Network partition risk |
| `services.pterodactyl.bootstrap_api_key` | Credential rotation |

### Permission Invariant

Do not request or accept the `netbox_rpc.approve_rpcprocedure` permission unless
a human operator has explicitly granted it for a specific, bounded task. Holding
this permission allows bypassing the `approval_required` API gate — it must never
be used autonomously on destructive procedures.

---

- Procedure records map canonical names to backend `handler_id` values.
- NetBox RQ jobs normalize params and delegate execution to `nms-backend`.
- SSH credentials and host-key pinning live in `netbox-nms.DeviceService`.
  `RPCLinuxServiceAllowlist.ssh_credential_override` can point at a
  `netbox-nms.DeviceCredential` for per-service SSH key overrides; when set,
  `rpc_ssh_credential_pk` in `normalized_params` tells `nms-backend` to fetch
  that credential by PK instead of resolving credentials by target device name.
- Keep procedure names in the documented canonical dotted forms:
  `os.<family>.<distro>.<version>.<action>` and
  `network.device.<manufacturer>.<device-family>.<model>.<version>.<action>`.
- Ubuntu 24 systemd procedures currently include read procedures
  `os.linux.ubuntu.24.status_service` and `os.linux.ubuntu.24.journal_tail`,
  plus write procedures `os.linux.ubuntu.24.start_service`,
  `os.linux.ubuntu.24.stop_service`, `os.linux.ubuntu.24.reload_service`,
  `os.linux.ubuntu.24.enable_service`, `os.linux.ubuntu.24.disable_service`,
  and `os.linux.ubuntu.24.daemon_reload`.
- SSH key management: `os.linux.ubuntu.24.install_ssh_key` (write, no approval
  required). Appends a user's SSH public key to the target device's
  `authorized_keys` using the DeviceService SSH credential.
- `os.linux.ubuntu.24.install_ssh_key` is seeded by migration `0006`. It
  accepts `{public_key, username?}` and instructs nms-backend to append the
  public key to the target user's `authorized_keys` via the device's
  DeviceService SSH credential. Handler ID: `os.linux_ubuntu_24.install_ssh_key`.
  Approval not required; the procedure is initiated automatically during NMS CLI
  key registration. Target models: `dcim.device` and
  `virtualization.virtualmachine`. Migration `0006` depends on
  `netbox_nms.0029_user_ssh_key`.
- Mellanox NIC conversion: `os.linux.proxmox.convert_mellanox_nic_to_ethernet`
  (write/`destructive`, approval required) is seeded by migration `0008`. It
  targets a **netbox-proxbox `ProxmoxEndpoint`**
  (`target_models = ["netbox_proxbox.proxmoxendpoint"]`), not a `dcim.device`.
  Its normalizer (`_normalize_convert_mellanox_nic_execution` in `jobs.py`)
  resolves SSH details via a **function-local** import of
  `netbox_nms.proxmox_ssh.resolve_proxmox_endpoint_ssh` (netbox-rpc must never
  import netbox-proxbox; netbox-nms owns the soft `ProxmoxEndpoint` reference)
  and emits the `rpc_ssh_host`/`rpc_ssh_port`/`rpc_ssh_credential_pk`/
  `rpc_ssh_known_hosts_entry`/`rpc_ssh_strict_host_key_checking` host-override
  keys plus `reboot`/`apply_network`/`interfaces_content`/`dry_run` and the operator bond
  parameters `bond_name` (default `bond1`), `bond_vlans` (optional comma-separated VLAN
  IDs/ranges), and `bond_mtu` (default 9216) — accepted by the params_schema since
  migration `0010` and re-validated strictly by nms-backend. Handler ID:
  `os.linux_proxmox.convert_mellanox_nic_to_ethernet` (in nms-backend). Keep the
  resolver import function-local so NetBox still boots when the installed
  netbox-nms predates `ProxmoxEndpointSSHBinding`.
- Dell SmartFabric OS10 S5232F-ON procedures are seeded by migration `0009`.
  They are fixed SSH fallback/bootstrap procedures for a RESTCONF-first driver:
  `network.device.dell_os10.s5232f_on.bootstrap_restconf`,
  `show_version`, `set_interface_description`, `set_vlan_description`, and
  `write_memory`. Bootstrap accepts `restconf_credential_pk` by reference; the
  RESTCONF password is resolved by `nms-backend` and must never appear in
  `normalized_params` or `command_fingerprint`.
- Dell OS10 VLT procedures are seeded by migration `0011`. Three procedures for
  Virtual Link Trunking on S5232F-ON switches:
  - `network.device.dell_os10.s5232f_on.show_vlt` (read, 30s, no approval):
    shows VLT domain status; optional `domain_id` (1–255, default 1).
    Handler: `network.dell_os10_s5232f_on.show_vlt`.
  - `network.device.dell_os10.s5232f_on.configure_vlt_domain` (write, 90s, approval required):
    configures domain ID, unit ID (1–2), VLTi discovery port channel (1–4096),
    backup-destination IPv4, primary priority (default 32768), optional shared
    VLT MAC (XX:XX:XX:XX:XX:XX), and write-memory (default true).
    Normalizer validates `backup_destination` against `_DELL_OS10_IP_RE` and
    `vlt_mac` against `_DELL_OS10_MAC_RE`.
    Handler: `network.dell_os10_s5232f_on.configure_vlt_domain`.
  - `network.device.dell_os10.s5232f_on.configure_vlt_peer` (write, 60s, approval required):
    binds or removes a port-channel as a VLT LAG; accepts `port_channel_id`,
    `vlt_port_channel_id` (1–4096), `remove` (default false), `write_memory` (default true).
    Handler: `network.dell_os10_s5232f_on.configure_vlt_peer`.
- netbox-packer post-build verification procedures are seeded by migration
  `0012`. They are **read-only** (`effect="read"`, `approval_required=False`,
  `timeout_seconds=120`) and target a **netbox-packer `PackerTemplate`**
  (`target_models = ["netbox_packer.packertemplate"]`, lowercase content-type
  label). They run read-only diagnostics over SSH against the Proxmox node that
  built the template:
  - `packer.vm.test_ssh_connectivity` — SSH connectivity probe.
  - `packer.vm.check_agent_running` — QEMU guest-agent responsiveness (read-only
    `qm config <vmid>` when a template VMID is known, else
    `systemctl is-active qemu-guest-agent`).
  - `packer.vm.verify_services` — `systemctl is-active` for an optional list of
    charset-validated systemd unit names (defaults to `qemu-guest-agent`).
  - `packer.vm.collect_info` — `cat /etc/os-release` + `uname -a`.

  **Dependency direction (hard constraint): netbox-rpc → netbox-packer is a
  one-way SOFT dependency.** netbox-packer is open-source; netbox-rpc is
  proprietary. netbox-rpc references netbox-packer ONLY through (1) the string
  `target_models` content-type label and (2) a **function-local lazy import** of
  `netbox_packer.models.PackerTemplate` inside `packer_normalizer.py`
  (`normalize_packer_vm_execution`), guarded by `try/except ImportError`
  (`RPC_PACKER_PLUGIN_MISSING`). `jobs.py` never imports `netbox_packer` at
  module level — it imports `packer_normalizer` function-locally in the dispatch
  branch. **netbox-packer MUST NOT import, depend on, or reference netbox-rpc in
  any way** (enforced by `tests/test_static_contract.py`). A `PackerTemplate`
  has no `ProxmoxEndpoint`, so SSH is resolved from an explicit
  `rpc_ssh_credential_pk` (a netbox-nms `DeviceCredential` PK) plus the
  template's `proxmox_node` (overridable with `ssh_host`); the normalizer emits
  the `rpc_ssh_host`/`rpc_ssh_port`/`rpc_ssh_credential_pk` host-override keys.
  Handler IDs equal the procedure names; the SSH handlers live in nms-backend
  (`automation/rpc/handlers.py`).
- Nginx proxy procedures (`service.nginx.1.*`) are seeded by this plugin's own
  migration `0003_seed_nginx_procedures` (canonical source) and also by
  `netbox-proxy` migration `0002` via `update_or_create` (idempotent duplicate).
  Both seeds produce identical data; the `0003` entry is the authoritative one.
  Normalizers live in the `NGINX_1_*` branches of
  `normalize_execution_params()` in `jobs.py`.
- Keep `README.md` updated when procedure policy, handler IDs, execution
  routing, audit behavior, or security constraints change.
- Tests must use mocks and fixtures only; do not connect to real Linux hosts,
  containers, VMs, or Huawei OLTs.

## CI

`.gitea/workflows/ci.yml` runs on every push and pull request via the
`mirror-host` self-hosted runner. It installs pytest (no other deps needed
because tests stub out Django/NetBox via `monkeypatch`), runs `py_compile` on
all Python files, and executes `pytest tests/ -q`. This is the pre-merge gate.

Tests must never connect to real Linux hosts, containers, VMs, or Huawei OLTs.
Use `monkeypatch` and `SimpleNamespace` stubs as demonstrated in
`tests/test_jobs_systemd_normalization.py` and
`tests/test_jobs_ssh_normalization.py`.

## Adding New Procedures

Every procedure seeded via migration must have a corresponding branch in
`normalize_execution_params()` in `jobs.py`. If a procedure is seeded (by this
plugin or a sibling plugin's migration) but has no normalizer, executions will
fail at runtime with `RPC_PROCEDURE_NOT_NORMALIZABLE`.

- Add the procedure name constant to `constants.py`.
- Add the normalizer branch to `normalize_execution_params()` in `jobs.py`.
- Update this file and `README.md` to document the new procedure.

## API Validation Guards

`RPCExecutionViewSet.create()` enforces three guards before enqueueing:

1. **Enabled check** — rejects disabled procedures with a 400.
2. **Approval check** — procedures with `approval_required=True` require the
   caller to hold the `netbox_rpc.approve_rpcprocedure` permission.
3. **Params schema** — when a procedure defines `params_schema` (JSON Schema),
   the submitted `params` dict is validated with `jsonschema.validate()` before
   the execution record is created.

If the RQ/Redis enqueue call fails, `create()` marks the execution
`STATUS_FAILED` with `error_code="RPC_ENQUEUE_FAILED"` instead of leaving it
permanently in `STATUS_QUEUED`.

RPC execution jobs must not be enqueued with `instance=execution`. NetBox 4.6
validates attached job objects against the `jobs` feature, and `RPCExecution` is
not job-capable. Pass `execution_pk=execution.pk` to `RPCExecutionJob.enqueue()`;
the job runner mirrors that value into job `data` and falls back to the legacy
`job.object_id` only for older queued jobs.

When the RQ worker dispatches an execution, `jobs._call_backend()` wraps the
`requests.post()` to `nms-backend` in `try/except requests.exceptions.RequestException`
and raises `RPCExecutionError(code="RPC_BACKEND_UNREACHABLE")` on any network
failure (connection refused, timeout, DNS) — so a backend-unreachable condition
surfaces as a structured, alertable error code instead of an opaque traceback.

## Admin Form Security

RPC object edit views must preserve the `RequestAwareObjectEditView` pattern so
forms can evaluate the active user without duplicating NetBox's generic edit
flow. `RPCProcedureForm` must fail closed when an existing procedure is changed
from `approval_required=True` to `False` unless the user has
`netbox_rpc.approve_rpcprocedure`. `RPCLinuxServiceAllowlistForm` must scope the
`ssh_credential_override` field with `DeviceCredential.objects.restrict(user,
"view")`; never use an unrestricted `DeviceCredential.objects.all()` queryset.

## Migration Safety

- Seed data migrations inline their data directly; they must not import live
  Python modules such as `netbox_rpc.constants`.
- The initial migration depends on `netbox_nms` migration `0015` — verify this
  if `netbox-nms` adds new migrations.
- Migration `0005` depends on `netbox_nms.0027_device_credential_ssh_key_auth`.
  Migration `0006` depends on `netbox_nms.0029_user_ssh_key`.
  When `netbox-nms` squashes its migrations, update both dependency names before
  running `migrate`.

## Event Sequence Integrity

`_event()` in `jobs.py` uses an atomic `Coalesce(Max("sequence"), 0)` aggregate
plus an IntegrityError retry loop (3 attempts) to prevent TOCTOU sequence
collisions under concurrent RQ workers.

Implementation rules:
- Each retry re-reads `max_seq` via aggregate after a collision. Always try
  `max_seq + 1` — never add the loop counter to `max_seq`, which would skip
  valid sequence numbers.
- The fallback after the loop is wrapped in `try/except IntegrityError` and
  logs a warning instead of propagating, so an event loss under extreme
  concurrency does not abort the RPC job.

## SYSTEMD_UNIT_RE Invariants

`SYSTEMD_UNIT_RE` rejects:
- leading dots
- trailing dots
- double dots (`nginx..service`)
- double `.service` suffix (`nginx.service.service`)
- empty strings

Only `.service` is a permitted suffix. When adding new allowlist entry types
that use other unit types (`.socket`, `.timer`), the regex must be extended.
