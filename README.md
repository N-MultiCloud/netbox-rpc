# netbox-rpc

Licensed under Apache-2.0 (see `LICENSE`).

`netbox-rpc` is an audited RPC procedure catalog and execution framework for
NetBox. It stores procedure policy, JSON schemas, execution records, and audit
events. The plugin does not open SSH sessions directly; execution is delegated
to a backend target that exposes `backend_url`, `get_auth_headers()`, and
`verify_ssl`.

The in-repo N-MultiCloud procedure catalog remains available as an optional,
guarded layer. `netbox-nms` is one supported integration: when installed,
`netbox-rpc` auto-detects `netbox_nms.backend.get_backend()` and preserves the
existing nms-backend dispatch URL, auth headers, TLS verification flag, and
empty `{}` POST body.

The procedure catalog is intentionally narrow:

- `network.device.huawei.olt.ma5800.r024.start_ont`
- `network.device.dell_os10.s5232f_on.bootstrap_restconf`
- `network.device.dell_os10.s5232f_on.show_version`
- `network.device.dell_os10.s5232f_on.show_version_structured`
- `network.device.dell_os10.s5232f_on.set_interface_description`
- `network.device.dell_os10.s5232f_on.set_vlan_description`
- `network.device.dell_os10.s5232f_on.write_memory`
- `os.linux.collect_facts`
- `os.linux.ubuntu.24.install_qemu_guest_agent`
- `os.linux.ubuntu.24.install_zabbix_agent2`
- `os.linux.ubuntu.24.restart_service`
- `os.linux.dns_host.deploy_dns_stack`
- `os.linux.dns_host.status_dns_stack`
- `os.linux.proxmox.convert_mellanox_nic_to_ethernet`
- `os.linux.proxmox.pvesh_json`
- `os.linux.proxmox.qemu_vm_lifecycle`
- `services.pterodactyl.bootstrap_api_key`
- `services.pterodactyl.artisan`
- `services.pterodactyl.container_logs`

Operators call named procedures, not arbitrary SSH commands.

## Standalone usage

`netbox-rpc` can be installed without `netbox-nms`. In standalone deployments,
create an `RPCBackend` object in NetBox and set:

- `name`: operator-facing backend name.
- `base_url`: backend service base URL; dispatch uses
  `<base_url>/rpc/executions/<execution_id>/run`.
- `verify_ssl`: whether `requests.post()` verifies the backend TLS certificate.
- `auth_header_name` and `auth_token`: optional static auth header. The token is
  stored in plaintext, so security-conscious deployments should prefer a custom
  resolver.

For external secret stores or non-NMS backend discovery, set:

```python
PLUGINS_CONFIG = {
    "netbox_rpc": {
        "backend_resolver": "my_package.rpc.resolve_backend",
    }
}
```

The resolver is called as `resolver(pk)` and must return
`netbox_rpc.backends.BackendTarget` or `None`. If no custom resolver is set and
`netbox-nms` is installed, the NMS adapter is used automatically. If
`netbox-nms` is absent, `RPCBackend` is used as the self-contained default.

## DDD / CQRS / Event Sourcing

`netbox-rpc` is the Remote Command Policy bounded context for the NMS stack.
The core aggregate is `RPCExecution`: callers request a business procedure,
the aggregate records each transition as an append-only execution event, and
the mutable `RPCExecution` row is treated as a read projection for NetBox API
compatibility.

- **DDD**: procedure names use business language such as
  `network.device.dell_os10.s5232f_on.write_memory` and
  `os.linux.ubuntu.24.restart_service`; handler IDs are internal adapters.
- **CQRS**: execution creation is the command side; execution list/detail and
  `/events` endpoints are query-side projections. API clients may create
  executions, but execution event history is exposed read-only.
- **Event Sourcing**: `netbox_rpc.event_store` appends ordered
  `RPCExecutionEvent` rows and updates the projection in the same transactional
  helper. Job code must call the event-store helpers instead of mutating
  status/result fields inline.

Durable events include `ExecutionStarted`, `ParametersNormalized`,
`ExecutionSucceeded`, `ExecutionFailed`, and backend driver events. Events must
store redacted payloads, `payload_hash` values, and references only; never
store credentials, private keys, or unbounded raw command output. Event append
failures are fail-closed: if the per-execution sequence cannot be allocated,
the command state transition raises instead of silently dropping audit history.
The execution-event API is read-only, model saves reject normal update/delete,
and the migration installs PostgreSQL triggers so the event ledger remains
append-only below the ORM.

### `os.linux.dns_host.*`

Two procedures manage the PowerDNS + dns-api Docker Compose stack on the
standalone DNS hosts `dns01` and `dns02`. They are seeded by migration `0027`,
have no NetBox target model (`target_models=[]`), and use explicit SSH
host-override params instead of a `dcim.device` or Proxmox binding.

**`os.linux.dns_host.deploy_dns_stack`** deploys or updates the
`powerdns-dns-api` Compose project. Required params are `target` and
`rpc_ssh_credential_pk`; optional params are `rpc_ssh_host` (if omitted,
derived as `<target>.<dns_host_domain>` from the plugin setting), `rpc_ssh_port` (default `22`),
`rpc_ssh_known_hosts_entry`, `rpc_ssh_strict_host_key_checking` (default
`true`), and `force_recreate` (default `false`). `effect="write"` and
`approval_required=True`. Handler ID equals the procedure name.

**`os.linux.dns_host.status_dns_stack`** reads status for the same Compose
project with the same SSH params minus `force_recreate`. `effect="read"` and
`approval_required=False`. Handler ID equals the procedure name.

The normalizer emits only structured fields: the `rpc_ssh_*` host-override
keys, `target`, `compose_project="powerdns-dns-api"`, deploy-only
`force_recreate`, and an audit `command_fingerprint`. It does not accept raw
SSH command text.

### Direct-SSH Ubuntu agent installers

Two fixed Ubuntu 24 procedures install already-deployed Linux agents over direct
SSH, without rebuilding the instance and without depending on QEMU Guest Agent
being present:

| Procedure | Handler | Timeout |
|---|---|---:|
| `os.linux.ubuntu.24.install_qemu_guest_agent` | `os.linux_ubuntu_24.install_qemu_guest_agent` | 300s |
| `os.linux.ubuntu.24.install_zabbix_agent2` | `os.linux_ubuntu_24.install_zabbix_agent2` | 600s |

Both are `effect="write"`, `approval_required=False`, and target
`dcim.device` plus `virtualization.virtualmachine`. Their only SSH connection
parameters are the audited `rpc_ssh_*` overrides consumed by `nms-backend`
(`rpc_ssh_credential_pk`, `rpc_ssh_host`, `rpc_ssh_port`,
`rpc_ssh_known_hosts_entry`, and `rpc_ssh_strict_host_key_checking`).
`install_zabbix_agent2` also accepts `zabbix_server` (configure the default via
the `default_zabbix_server` plugin setting). No arbitrary package, command, or shell text parameter is
accepted. Seeded by migration `0028`.

### `os.linux.proxmox.convert_mellanox_nic_to_ethernet`

Converts Mellanox ConnectX-3 (`mlx4`) NIC ports from InfiniBand to Ethernet on a
Proxmox host. Unlike the Ubuntu procedures, this one targets a **netbox-proxbox
`ProxmoxEndpoint`** (`target_models = ["netbox_proxbox.proxmoxendpoint"]`). SSH
connection details are resolved at execution time through the **netbox-nms
`ProxmoxEndpointSSHBinding`** via `netbox_nms.proxmox_ssh.resolve_proxmox_endpoint_ssh()`
(a function-local import — `netbox-rpc` never imports `netbox-proxbox`). The
normalizer emits the `rpc_ssh_host` / `rpc_ssh_port` / `rpc_ssh_credential_pk` /
`rpc_ssh_known_hosts_entry` / `rpc_ssh_strict_host_key_checking` host-override
keys that `nms-backend` consumes, plus the behaviour flags `reboot`,
`apply_network`, `interfaces_content`, and `dry_run`, and the operator bond
parameters `bond_name` (default `bond1`), `bond_vlans` (optional comma-separated
VLAN IDs/ranges 1-4094, emitted as `bridge-vids`; empty default declares no VLAN
filtering), and `bond_mtu` (default jumbo `9216`, allowed 576-9216) — accepted by
the `params_schema` since migration `0010` and re-validated strictly by
`nms-backend` before any shell embedding. `effect="destructive"` and
`approval_required=True`. Seeded by migration `0008`; handler
`os.linux_proxmox.convert_mellanox_nic_to_ethernet` lives in `nms-backend`.

### Pterodactyl Panel procedures

Three procedures for managing a Pterodactyl Panel Docker deployment via SSH to
the container host. Seeded by migration `0016`. Target models: `dcim.device`
and `virtualization.virtualmachine`.

**`services.pterodactyl.bootstrap_api_key`** — runs `php artisan about
--no-interaction` (falling back to `php artisan --version`) inside the
container. Verifies that the Panel application is operational. Optional
`container_name` (default `pterodactyl-panel-1`). `approval_required=True`.
Handler ID: `services.pterodactyl.bootstrap_api_key` (in `nms-backend`).

**`services.pterodactyl.artisan`** — runs one allowlisted Laravel Artisan
command inside the container. Required `command` param; accepted values:
`queue:status`, `schedule:run`, `cache:clear`, `config:clear`,
`queue:restart`, `migrate`. The allowlist is enforced by the normalizer
(`_PTERODACTYL_ARTISAN_ALLOWLIST` in `jobs.py`) and again by the Pydantic
schema in `nms-backend`. Disallowed commands raise
`RPCExecutionError(code="RPC_PARAM_INVALID")`. Optional `container_name`
(default `pterodactyl-panel-1`). `approval_required=False`. Handler ID:
`services.pterodactyl.artisan` (in `nms-backend`).

**`services.pterodactyl.container_logs`** — runs `docker logs --tail <N>
<container>` on the SSH host to retrieve recent log output. Optional
`container_name` (default `pterodactyl-panel-1`); optional `lines`
(1–500, default 100; values outside that range are clamped, not rejected).
`approval_required=False`. Handler ID: `services.pterodactyl.container_logs`
(in `nms-backend`).

### Minecraft stack SSH procedures

Migration `0029` adds structured SSH fallback procedures for game nodes and
Pterodactyl Wings server volumes. Target models are `dcim.device` and
`virtualization.virtualmachine`; SSH credentials are resolved through the usual
DeviceService path or explicit `rpc_ssh_*` overrides. These procedures do not
accept raw shell commands.

| Procedure / handler | Effect | Purpose |
|---|---|---|
| `services.minecraft.plugin.install_url` | write | Install a validated public http(s) plugin `.jar` into `/plugins` for a server UUID |
| `services.minecraft.viaversion.install` | write | Install ViaVersion, ViaBackwards, and/or ViaRewind from fixed project mappings |
| `services.minecraft.papermc.install` | write | Install a PaperMC, Folia, or Velocity server JAR resolved from the PaperMC Fill API |
| `services.pterodactyl.wings.status` | read | Read `wings.service` status |
| `services.pterodactyl.wings.logs` | read | Tail `wings.service` journal output |
| `services.pterodactyl.wings.restart` | write, approval required | Restart `wings.service` when an operator explicitly approves node-management disruption |

The NetBox normalizer validates server UUIDs, safe `.jar` filenames, ViaVersion
presets/plugin enums, PaperMC project/version/build fields, and public URL
shape before an execution is queued. URL values are fingerprinted in the audit
hash rather than repeated in the command fingerprint.

Detailed operator and maintainer guardrails live in
[`docs/MINECRAFT_STACK_RPC.md`](docs/MINECRAFT_STACK_RPC.md). Keep that guide,
`AGENTS.md`, the migration seed data, and the static contract tests aligned any
time a Minecraft procedure schema, normalizer, handler ID, or approval boundary
changes.

### `packer.vm.*` — netbox-packer post-build verification

Four **read-only** procedures (`effect="read"`, `approval_required=False`,
`timeout_seconds=120`) that target a **netbox-packer `PackerTemplate`**
(`target_models = ["netbox_packer.packertemplate"]`) and run read-only
diagnostics over SSH against the Proxmox node that built the template:

| Procedure / handler | Checks |
|---|---|
| `packer.vm.test_ssh_connectivity` | SSH connectivity to the node |
| `packer.vm.check_agent_running` | QEMU guest agent (`qm config <vmid>` or `systemctl is-active qemu-guest-agent`) |
| `packer.vm.verify_services` | `systemctl is-active` for an optional list of systemd units (default `qemu-guest-agent`) |
| `packer.vm.collect_info` | `cat /etc/os-release` + `uname -a` |

**One-way soft dependency (hard constraint).** netbox-packer is open-source and
netbox-rpc is proprietary, so the coupling is strictly one-directional:
netbox-rpc depends on netbox-packer, but **netbox-packer must never reference
netbox-rpc**. netbox-rpc touches netbox-packer only through (1) the string
`target_models` label and (2) a **function-local lazy import** of
`netbox_packer.models.PackerTemplate` inside `packer_normalizer.py`, guarded by
`try/except ImportError` (so NetBox boots fine when netbox-packer is absent).
`jobs.py` never imports `netbox_packer` at module level. Because a
`PackerTemplate` has no `ProxmoxEndpoint`, SSH is resolved from an explicit
`rpc_ssh_credential_pk` (a netbox-nms `DeviceCredential` PK) plus the template's
`proxmox_node` (overridable via `ssh_host`); the normalizer emits the
`rpc_ssh_host` / `rpc_ssh_port` / `rpc_ssh_credential_pk` host-override keys.
Seeded by migration `0018`; handlers (same IDs) live in `nms-backend`.

### `os.linux.proxmox.qemu_vm_lifecycle`

Runs fixed Proxmox QEMU VM lifecycle operations through the same
`ProxmoxEndpointSSHBinding` path used by the Mellanox procedure. The procedure
targets `netbox_proxbox.proxmoxendpoint`, resolves SSH details through
`netbox_nms.proxmox_ssh.resolve_proxmox_endpoint_ssh()`, and forwards only
structured fields to `nms-backend`: operation enum values, Proxmox `nextid`
allocation, VMIDs, node/storage names, optional clone/migrate settings,
CPU/memory, QEMU Guest Agent enablement, network interface bridge/tag objects,
cloud-init IP config objects, DNS search domain/resolver defaults, disk resize
target, start/status/agent-ping requests, QGA interface inspection, constrained
Debian guest network repair, and guest password rotation by
`guest_credential_pk`. The guest password operation stores only a
`netbox-nms.DeviceCredential` reference in RPC params; `nms-backend` resolves
and redacts the secret at execution time. It never stores or accepts raw shell
command text. `effect="destructive"` and `approval_required=True`. Seeded by
migration `0012` and extended through `0017`; handler
`os.linux_proxmox.qemu_vm_lifecycle` lives in `nms-backend`.

## Architecture

```text
Client / nms UI
  -> netbox-rpc API
  -> NetBox RQ job
  -> nms-backend /rpc/executions/{execution_id}/run
  -> transport driver (AsyncSSH / Scrapli / Netmiko / Paramiko / NAPALM)
  -> network device or Linux host
```

`netbox-rpc` is deliberately the source of truth, not the SSH runtime. It
owns:

- procedure names, handler IDs, categories, and enabled/approval policy;
- JSON request and response schemas used to validate procedure parameters;
- execution records, normalized parameters, status, results, errors, and audit
  events;
- NetBox job orchestration that delegates execution to `nms-backend`.

`nms-backend` owns the hard-coded handler implementations and transport
libraries. It must execute only known handler IDs such as
`network.huawei_olt_ma5800_r024.start_ont` and
`network.dell_os10_s5232f_on.bootstrap_restconf` and
`os.linux_ubuntu_24.restart_service` and
`os.linux.dns_host.deploy_dns_stack` and
`os.linux_proxmox.qemu_vm_lifecycle`.

### Transport-driver & output-parser selection

Each `RPCProcedure` declares a pluggable **transport driver** and **output
parser** for the nms-backend execution pipeline as explicit model fields (never
encoded in `handler_id`):

- `transport_driver`: `asyncssh` (default), `scrapli`, `netmiko`, `paramiko`,
  `napalm`. `asyncssh` preserves the historical SSH behaviour.
- `output_parser`: `none` (default, raw), `auto` (native JSON/XML → jc →
  TextFSM → TTP → Genie → regex fallback chain), or a pinned backend (`json`,
  `xml`, `jc`, `textfsm`, `ttp`, `genie`, `regex`).
- `output_schema`: optional JSON parser hints / internal target schema.

These selections are threaded into `normalized_params` centrally — only when
non-default, so existing procedures are unaffected — and the cross-repo request
body is unchanged. The transport → parse → normalize → validate → store pipeline
itself lives in `nms-backend automation/rpc/`; this plugin only chooses which
driver and parser a procedure uses.

In the optional `netbox-nms` integration, SSH connection material comes from
`DeviceService` rows with `service_type="ssh"`. Those rows provide the
management host, port, linked `DeviceCredential`, `ssh_known_hosts_entry`, and
`ssh_strict_host_key_checking` values consumed by `nms-backend`. Per-service
Linux allowlist entries may set `ssh_credential_override` to a
`netbox-nms.DeviceCredential` PK; when present, the normalized execution params
include `rpc_ssh_credential_pk` so `nms-backend` fetches that credential by PK
instead of resolving SSH credentials by device name. Standalone deployments can
submit the same structured credential-reference params to a backend that
understands them.

For the authoring decision matrix, production dependency table, inline template
rules, and deploy ordering for new exemplars, see
[`docs/transport-and-parsing-selection.md`](docs/transport-and-parsing-selection.md).

### Pipeline exemplar procedures

Migration `0031` seeds three read-only procedures that demonstrate non-default
parser selection without accepting executable text:

| Procedure | Handler | Driver | Parser |
| --- | --- | --- | --- |
| `os.linux.proxmox.pvesh_json` | `os.linux.proxmox.pvesh_json` | `asyncssh` | `json` |
| `os.linux.collect_facts` | `os.linux.collect_facts` | `asyncssh` | `jc` |
| `network.device.dell_os10.s5232f_on.show_version_structured` | `network.dell_os10_s5232f_on.show_version_structured` | `scrapli` | `textfsm` |

Their normalizers emit only validated semantic params and credential references;
nms-backend handlers build the runtime actions server-side.

## Procedure Naming

Procedure names are canonical dotted strings:

| Domain | Shape | Example |
| --- | --- | --- |
| Operating system | `os.<family>.<distro>.<version>.<action>` | `os.linux.ubuntu.24.restart_service` |
| Network hardware | `network.device.<manufacturer>.<device-family>.<model>.<version>.<action>` | `network.device.huawei.olt.ma5800.r024.start_ont` |

The public contract is the procedure name plus validated parameters. API
clients must not submit arbitrary SSH command text.

## Security Rules

- Never add a procedure that stores user-provided shell commands.
- Dell OS10 procedures are fixed command templates used only as RESTCONF
  fallback/bootstrap paths. The RESTCONF automation user password is resolved
  in `nms-backend` from `restconf_credential_pk`; it must not be stored in
  `normalized_params` or `command_fingerprint`.
- Prefer enum or allowlist parameters for command fragments such as service
  names, board/slot identifiers, or ONT IDs.
- Keep SSH credentials outside `netbox-rpc`; this plugin stores execution
  metadata and credential references, not private keys or passwords.
- Keep strict host-key checking enabled unless an operator explicitly disables
  it for a lab or migration case.
- Treat stdout and stderr as audit data. Store full output only where policy
  allows; otherwise store redacted summaries or hashes in future extensions.

## API Validation

`RPCExecutionViewSet.create()` enforces three guards before an execution
record is created and the RQ job is enqueued:

1. **Enabled** — disabled procedures are rejected (HTTP 400).
2. **Approval** — procedures with `approval_required=True` require the caller
   to hold `netbox_rpc.approve_rpcprocedure`.
3. **Params schema** — when a procedure defines `params_schema`, submitted
   `params` are validated against the JSON Schema before proceeding.

These guards run at the API layer, not the model layer, because the serializer
receives the procedure as a foreign-key ID and the schema/enabled/approval
checks require the resolved object.

RPC execution jobs are queued without using NetBox's attached-object job fields.
NetBox 4.6 validates attached job object types against the `jobs` feature, and
`RPCExecution` is audit metadata rather than a job-capable operational object.
The worker receives the execution primary key through `execution_pk` and
persists it in the job `data` JSON for retry/debug recovery.

## Admin Form Security

NetBox edit views attach the active request to RPC form instances so form-level
security policy can evaluate the requesting user. `RPCProcedureForm` blocks
changing an existing procedure from `approval_required=True` to `False` unless
the user has `netbox_rpc.approve_rpcprocedure`. `RPCLinuxServiceAllowlistForm`
scopes `ssh_credential_override` choices with
`DeviceCredential.objects.restrict(user, "view")` and falls back to an empty
queryset if no request context is available.

## Testing

Default tests are static or mocked:

```bash
python -m pytest tests
```

Do not test this plugin against a real Linux host, Linux container/VM over SSH,
or a real Huawei OLT unless a separate explicit live-device test plan is
approved.
