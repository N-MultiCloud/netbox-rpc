# netbox-rpc Agent Notes

`netbox-rpc` owns procedure policy and audit state. It must never store or
accept arbitrary SSH command text from API clients. It can boot and migrate
without `netbox-nms`; NMS support is an optional auto-detected adapter.

## Standalone Usage

Install `netbox-rpc` without `netbox-nms` when only the audited RPC catalog and
execution framework are needed. Standalone deployments use the local
`RPCBackend` model for `base_url`, `verify_ssl`, and an optional static auth
header. `auth_token` is plaintext storage; security-conscious deployments
should configure `PLUGINS_CONFIG["netbox_rpc"]["backend_resolver"]` to resolve a
`netbox_rpc.backends.BackendTarget` from an external secret store or service
registry.

When no custom resolver is configured and `netbox-nms` is importable,
`netbox-rpc` adapts `netbox_nms.backend.get_backend(pk)` to the tiny backend
runtime contract: `backend_url`, `get_auth_headers()`, and `verify_ssl`. When
`netbox-nms` is absent, `RPCBackend` is the default backend source. The
N-MultiCloud procedure catalog remains in-repo as an optional guarded layer.

## DDD / CQRS / Event Sourcing

- Treat `RPCExecution` as the command aggregate and current-state read
  projection.
- All status/result/error transitions must go through
  `netbox_rpc.event_store`; do not mutate execution state directly in jobs,
  API views, or serializers.
- `RPCExecutionEvent` is the append-only event stream. Preserve ordered
  sequences per execution and keep collision handling in the event-store layer.
  The event API is read-only, model saves reject update/delete, and database
  triggers protect the ledger below the ORM.
- Event append failures must fail closed. Do not log-and-drop an execution
  event after sequence collisions or database errors.
- API create/enqueue paths are command-side behavior. Execution detail/list and
  execution-events endpoints are query-side behavior, and the event API must
  remain read-only.
- Event data and backend result projections must be redacted and bounded. Store
  credential references, `payload_hash` values, and command fingerprints, not
  secrets, private key material, or unbounded raw command output.
- Network device procedures should delegate protocol execution to the
  network command/query gateway service as drivers migrate out of
  `nms-backend`.

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
| `os.linux.ubuntu.24.install_qemu_guest_agent` | Package install and service enablement |
| `os.linux.ubuntu.24.install_zabbix_agent2` | Package install, config write, and service restart |
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
  `virtualization.virtualmachine`. Migration `0006` is standalone and has no
  `netbox_nms` migration dependency.
- Direct-SSH Ubuntu 24 agent installers are seeded by migration `0028` and
  target `dcim.device` plus `virtualization.virtualmachine`.
  `os.linux.ubuntu.24.install_qemu_guest_agent`
  (`os.linux_ubuntu_24.install_qemu_guest_agent`, write, no approval, 300s)
  installs/enables `qemu-guest-agent` over SSH without requiring QGA first.
  `os.linux.ubuntu.24.install_zabbix_agent2`
  (`os.linux_ubuntu_24.install_zabbix_agent2`, write, no approval, 600s)
  installs/configures Zabbix Agent 2 over SSH and defaults `zabbix_server` to
  `zabbix.example.com`. Their schemas accept only the standard
  `rpc_ssh_*` connection override keys, plus `zabbix_server` for Zabbix; never
  add arbitrary package, command, or shell text parameters.
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
- Proxmox QEMU VM lifecycle: `os.linux.proxmox.qemu_vm_lifecycle`
  (write/`destructive`, approval required) is seeded by migration `0012`. It
  targets a **netbox-proxbox `ProxmoxEndpoint`** and resolves SSH details
  through `netbox_nms.proxmox_ssh.resolve_proxmox_endpoint_ssh`. Its normalizer
  forwards only structured, validated lifecycle fields: operation enum values
  (`nextid`, `clone`, `migrate`, `configure`, `resize`, `start`, `stop`,
  `status`, `agent_ping`, `agent_network_get_interfaces`,
  `agent_configure_debian_network`, `agent_set_user_password`), VMIDs,
  node/storage names, CPU/memory, QEMU Guest Agent enablement, NIC bridge/tag
  objects, cloud-init IP configs, DNS search domain/resolver defaults, Debian
  guest interface stanzas, disk resize size, and `guest_credential_pk` for password rotation. Guest passwords are
  resolved by `nms-backend` from `netbox-nms.DeviceCredential` and must not
  appear in RPC params beyond the credential id. It must never accept arbitrary
  shell command text. Handler ID: `os.linux_proxmox.qemu_vm_lifecycle` (in
  nms-backend).
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
    configures domain ID, optional unit ID (1–2 — omit on OS10 10.5.x where the
    command is unrecognised and role is auto-negotiated), VLTi discovery port channel
    (1–4096), backup-destination IPv4, primary priority (default 32768), optional
    shared VLT MAC (XX:XX:XX:XX:XX:XX), and write-memory (default true).
    Normalizer validates `backup_destination` against `_DELL_OS10_IP_RE` and
    `vlt_mac` against `_DELL_OS10_MAC_RE`.
    Handler: `network.dell_os10_s5232f_on.configure_vlt_domain`.
  - `network.device.dell_os10.s5232f_on.configure_vlt_peer` (write, 60s, approval required):
    binds or removes a port-channel as a VLT LAG; accepts `port_channel_id`,
    `vlt_port_channel_id` (1–4096), `remove` (default false), `write_memory` (default true).
    Handler: `network.dell_os10_s5232f_on.configure_vlt_peer`.
- Dell OS10 port-channel and LACP procedures are seeded by migration `0012`. Two write
  procedures for LAG configuration on S5232F-ON switches:
  - `network.device.dell_os10.s5232f_on.configure_port_channel` (write, 60s, approval required):
    creates, updates, or removes a port-channel (LAG); accepts `port_channel_id` (1–4096),
    optional `trunk_vlans` (comma-separated VLAN IDs or ranges, e.g. `20,111`),
    optional `description` (max 240 chars), `remove` (default false), `write_memory` (default true).
    Handler: `network.dell_os10_s5232f_on.configure_port_channel`.
  - `network.device.dell_os10.s5232f_on.configure_interface_lacp` (write, 60s, approval required):
    adds or removes an Ethernet interface from a port-channel with LACP negotiation or static LAG;
    accepts `interface_name` (OS10 identifier, e.g. `ethernet1/1/1`), `port_channel_id` (1–4096),
    `lacp_mode` (enum `active`/`passive`/`on`, default `active` — use `on` for static LAG,
    required when the port-channel is used as a VLT VLTi discovery-interface), optional
    `description`, `remove` (default false), `write_memory` (default false — batch all interface
    assignments before the final `write memory` via a separate `configure_port_channel` call).
    Handler: `network.dell_os10_s5232f_on.configure_interface_lacp`.
- Dell OS10 interface breakout procedure is seeded by migration `0013`. One write procedure
  for configuring physical port breakout mode on S5232F-ON switches:
  - `network.device.dell_os10.s5232f_on.configure_interface_breakout` (write, 60s, approval required):
    runs `interface breakout <port> map <mode>` in global config mode; accepts
    `interface_port` (physical port in `slot/port/subport` format, e.g. `1/1/1` — no
    `ethernet` prefix), `breakout_mode` (e.g. `40g-1x`, `100g-1x`, `10g-4x`, `25g-4x`),
    `write_memory` (default true).
    Handler: `network.dell_os10_s5232f_on.configure_interface_breakout`.
- Dell OS10 interface FEC procedure is seeded by migration `0014`. One write procedure
  for configuring Forward Error Correction on a physical interface:
  - `network.device.dell_os10.s5232f_on.configure_interface_fec` (write, 30s, approval required):
    sets or removes FEC on a physical port; accepts `interface_name` (OS10 identifier with
    `ethernet` prefix, e.g. `ethernet1/1/31`), `fec_mode` (enum `cl91` / `cl108` / `auto` /
    `none`, default `cl91` — `none` emits `no fec`), `write_memory` (default true).
    Use `cl91` (RS-FEC, Clause 91) for QSFP28 100G SR4/LR4 optics; `cl108` (FC-FEC, Clause 108)
    for SFP28 25G DAC/SR; `auto` to negotiate with the peer.
    Handler: `network.dell_os10_s5232f_on.configure_interface_fec`.
- Pterodactyl Panel procedures are seeded by migration `0016`. Three procedures for
  managing a Pterodactyl Panel Docker deployment via `docker exec` on the host:
  - `services.pterodactyl.bootstrap_api_key` (write, 60s, approval required):
    bootstraps Pterodactyl Panel application and client API keys. Optional
    `container_name` (default `pterodactyl-panel-1`).
    Handler: `services.pterodactyl.bootstrap_api_key`.
  - `services.pterodactyl.artisan` (write, 60s, no approval):
    runs an allowlisted Laravel Artisan command. Required `command` (enum:
    `queue:status`, `schedule:run`, `cache:clear`, `config:clear`,
    `queue:restart`, `migrate`). Optional `container_name`
    (default `pterodactyl-panel-1`).
    Handler: `services.pterodactyl.artisan`.
  - `services.pterodactyl.container_logs` (read, 30s, no approval):
    fetches recent log output from the Pterodactyl Panel container. Optional
    `container_name` (default `pterodactyl-panel-1`) and `lines`
    (1–500, default 100).
    Handler: `services.pterodactyl.container_logs`.
  Target models for all three: `dcim.device` and `virtualization.virtualmachine`.
- Minecraft stack procedures are seeded by migration `0029`. They provide
  structured SSH fallback operations for game nodes and server volumes; none
  accepts arbitrary shell command text.
  See `docs/MINECRAFT_STACK_RPC.md` for the full operator/maintainer guardrail
  contract. Any change to procedure names, handler IDs, JSON schemas,
  normalizers, approval flags, URL rules, filename rules, or SSH override
  handling must update that guide and the static contract tests in the same
  branch.
  - `services.minecraft.plugin.install_url` (write, 180s, no approval):
    downloads a validated public http(s) `.jar` URL into
    `/var/lib/pterodactyl/volumes/<server_uuid>/plugins/<filename>` on the
    Wings node. Required `server_uuid`, `source_url`, and safe `.jar`
    `filename`; optional `restart` and `rpc_ssh_*` overrides. Handler:
    `services.minecraft.plugin.install_url`.
  - `services.minecraft.viaversion.install` (write, 240s, no approval):
    installs ViaVersion-family plugins from fixed ViaVersion GitHub project
    mappings. Accepts `server_uuid`, either `preset` (`minimal`, `standard`,
    `full`) or explicit `plugins` (`viaversion`, `viabackwards`, `viarewind`),
    optional `restart`, and optional `rpc_ssh_*` overrides. Handler:
    `services.minecraft.viaversion.install`.
  - `services.minecraft.papermc.install` (write, 240s, no approval):
    installs a PaperMC Fill API server JAR into the server root. Accepts
    `server_uuid`, `project` (`paper`, `folia`, `velocity`), `version`,
    optional `build_id`, safe `server_jarfile` (default `server.jar`), optional
    `restart`, and optional `rpc_ssh_*` overrides. Handler:
    `services.minecraft.papermc.install`.
  - `services.pterodactyl.wings.status` and
    `services.pterodactyl.wings.logs` are read-only SSH service diagnostics for
    `wings.service`; logs accept `lines` (1–500).
  - `services.pterodactyl.wings.restart` restarts `wings.service` and is
    `approval_required=True` because it can interrupt node management.
  Target models for all six: `dcim.device` and
  `virtualization.virtualmachine`.
- DNS host procedures are seeded by migration `0027`. Two procedures manage the
  PowerDNS + dns-api Docker Compose stack on standalone DNS hosts:
  - `os.linux.dns_host.deploy_dns_stack` (write, 180s, approval required):
    deploys or updates the `powerdns-dns-api` Compose project. Required params:
    `target` (for example `dns01`/`dns02`) and `rpc_ssh_credential_pk`
    (`netbox-nms.DeviceCredential` PK). Optional params: `rpc_ssh_host`
    (if omitted, derived as `<target>.<dns_host_domain>` from the plugin setting), `rpc_ssh_port` (default 22),
    `rpc_ssh_known_hosts_entry`, `rpc_ssh_strict_host_key_checking` (default
    true), and `force_recreate` (default false). Handler:
    `os.linux.dns_host.deploy_dns_stack`.
  - `os.linux.dns_host.status_dns_stack` (read, 60s, no approval): reads stack
    status using the same SSH params minus `force_recreate`. Handler:
    `os.linux.dns_host.status_dns_stack`.
  Target models for both: `[]`. The normalizer emits only structured
  `rpc_ssh_*` host-override keys, `target`, `compose_project`, and
  deploy-only `force_recreate`; it must never accept arbitrary SSH command text.
- Dell OS10 third-party optical module unlock is seeded by migration `0017`. One write procedure
  for enabling non-Dell QSFP28-SR4 (and similar) transceivers on S5232F-ON switches:
  - `network.device.dell_os10.s5232f_on.allow_third_party_transceiver` (write, 45s, approval required):
    runs the fixed sequence `allow unsupported-transceiver` + `unlock third-party transceiver` +
    `write memory` in global config mode; accepts only the optional `rpc_ssh_credential_pk`
    override. Display name: "Allow third-part Optical Modules". Apply once after inserting
    non-Dell optics; the switch loses the setting only on a factory-reset.
    Handler: `network.dell_os10_s5232f_on.allow_third_party_transceiver`.
- netbox-packer post-build verification procedures are seeded by migration
  `0018`. They are **read-only** (`effect="read"`, `approval_required=False`,
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
- Add the normalizer branch to `_dispatch_normalize_execution_params()` in
  `jobs.py` (the public `normalize_execution_params()` wraps it).
- Update this file and `README.md` to document the new procedure.

## Transport Driver & Output Parser Selection

`RPCProcedure` carries explicit pluggable-driver routing for the nms-backend
execution pipeline. **Never encode the driver inside `handler_id`** — it is its
own model data:

- `transport_driver` — `asyncssh` (default), `scrapli`, `netmiko`, `paramiko`,
  `napalm`. AsyncSSH reproduces the legacy single-/multi-command SSH behaviour.
- `output_parser` — `none` (default, raw), `auto` (native JSON/XML → jc →
  TextFSM → TTP → Genie → regex chain), or a pinned backend (`json`, `xml`,
  `jc`, `textfsm`, `ttp`, `genie`, `regex`).
- `output_schema` — optional JSON parser hints / target internal schema
  (e.g. a TextFSM template ref, jc parser name, regex field map).

`normalize_execution_params()` is a thin wrapper: it calls the per-procedure
`_dispatch_normalize_execution_params()` and then
`_apply_driver_pipeline_overrides()` injects these fields **once, centrally**
into `normalized_params` (and `command_fingerprint`). Injection happens **only
for non-default values**, so legacy AsyncSSH/raw-output procedures keep a
byte-for-byte identical normalized payload (the cross-repo POST body is still
`{}`; nms-backend reads the fields from `normalized_params`). The actual
transport/parse/normalize/validate/store pipeline lives in nms-backend
`automation/rpc/` — this plugin only selects which driver/parser a procedure uses.

### Transport-driver & output-parser selection

Use [`docs/transport-and-parsing-selection.md`](docs/transport-and-parsing-selection.md)
as the authoring guide for driver choice, parser choice, production dependency
availability, inline parser templates, security boundaries, and deploy ordering.
The current read-only exemplars are `os.linux.proxmox.pvesh_json`,
`os.linux.collect_facts`, and
`network.device.dell_os10.s5232f_on.show_version_structured`.

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
- Fresh installs must not depend on `netbox-nms`. Historical migrations `0001`,
  `0005`, and `0006` intentionally have no `netbox_nms` dependency.
- Production databases that already applied the historical `netbox_nms` FKs are
  reconciled by forward migration `0034_decouple_netbox_nms_fk_constraints`,
  which drops only stale PostgreSQL foreign-key constraints and preserves the
  populated integer columns and indexes.

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
