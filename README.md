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
- `os.linux.ubuntu.24.ookla.diagnose`
- `os.linux.ubuntu.24.ookla.check_service`
- `os.linux.ubuntu.24.ookla.check_listeners`
- `os.linux.ubuntu.24.ookla.check_tls`
- `os.linux.ubuntu.24.ookla.check_firewall`
- `os.linux.proxmox.convert_mellanox_nic_to_ethernet`
- `os.linux.proxmox.pvesh_json`
- `os.linux.proxmox.qemu_vm_lifecycle`
- `os.linux.proxmox.show_systemctl_services`
- `services.pterodactyl.bootstrap_api_key`
- `services.pterodactyl.artisan`
- `services.pterodactyl.container_logs`

Operators call named procedures, not arbitrary SSH commands.

## Procedure command source of truth

Each `RPCProcedure` can own ordered `RPCProcedureCommand` rows. These rows are
the database source of truth for the fixed command or device-CLI steps that
nms-backend may run for a procedure. They are structured tokens, never arbitrary
shell text:

```json
{
  "sequence": 1,
  "step_type": "shell_argv",
  "device_cli_mode": null,
  "argv": ["sudo", "/bin/systemctl", "status", "--no-pager", "{service_slug}"],
  "description": "Read systemd status",
  "condition_param": "",
  "condition_negate": false,
  "for_each_param": "",
  "continue_on_error": false,
  "render_mode": "literal",
  "produces_var": "",
  "capture_kind": "",
  "capture_expression": ""
}
```

The serializer embeds `commands` on procedure responses, including the nested
`procedure` object inside execution responses. API clients can manage command
rows through `/api/plugins/rpc/procedure-commands/` or list/create rows for a
single procedure with `/api/plugins/rpc/procedures/{id}/commands/`. The NetBox
procedure object page renders the same data in a "Commands" card.

### Procedure Runs tab

The procedure object page has a **Runs** tab
(`/plugins/rpc/procedures/<pk>/runs/`) listing every `RPCExecution` for that
procedure, newest first, with a badge of the run count. Each row shows the run's
user owner (`requested_by`), how it was issued (**Source** — `Direct`, or
`Intent: <name>` when a future intent executor stamps an `_intent_name`/`_intent`
marker into `params`), status, target, backend, and timing, and links to the
execution detail. The execution detail additionally renders a **Command Output**
card built from `result.steps[]` — the exact command(s) issued on the target and
each command's stdout/stderr/exit code — so a run's issued commands and their
output are visible end-to-end. The `RPCExecution.source_label`,
`intent_reference`, and `result_steps` model properties back these surfaces.

Literal argv tokens are validated by `netbox_rpc.command_contract.SAFE_TOKEN_RE`;
dynamic values must be explicit `{placeholders}` backed by the procedure params
schema or the documented runtime keys. Handlers that cannot be represented
faithfully as fixed argv/device-CLI rows remain backend-orchestrated and are
listed in `EXEMPT_HANDLER_RATIONALE`. Current exemptions include destructive
Proxmox workflows, stdin-backed install/config scripts, URL-download
installers, Ookla diagnostic probe scripts, and enum branches that the current
truthy-only condition fields cannot express. Exempt procedures still get one
representative command row for API/UI discoverability.

### Command templating & output-variable chaining

A command can opt into **Jinja2 templating** (`render_mode="jinja"`) so each
`argv` token is a sandboxed Jinja2 expression rendered against the run's declared
`params`, the NetBox `target` object ("NetBox objects as variables"), an earlier
command's captured output `vars`, the `runtime` SSH keys, and the `for_each`
`item`. A command can also **capture** a value from its output into a named
variable (`produces_var` + `capture_kind` + `capture_expression`) that a later
command references as `{{ vars.<name> }}` — so command 2 can consume a value that
only exists in command 1's output, which command 1 derived from a NetBox object.
`RPCProcedureCommand.clean()` validates the templates (sandboxed, expression-only,
safe literals, no dunder access) and the chain ordering (an output variable must
be produced by a command with a smaller `sequence`). Legacy `literal` commands are
unchanged. Full contract — including the executor's shell-quoting/redaction
obligations — is in [`docs/command-templating.md`](docs/command-templating.md).

## Intents

An **intent** groups one or more procedures under a single declarative record.
Where a procedure (with its commands) declares *how* something is done, an
`RPCIntent` declares *what* needs to be done and how the grouped procedures are
triggered:

- **sequential** — the grouped procedures are nested and triggered one after
  another, in the declared `sequence` order;
- **parallel** — the grouped procedures are triggered concurrently, with no
  nesting at all (the per-procedure `sequence` is then informational).

Create intents at **RPC → Intents** (or `POST /api/plugins/rpc/intents/`),
selecting multiple procedures and choosing the execution mode. Ordering is
captured by the `RPCIntentProcedure` through model (`intent`, `procedure`,
`sequence`), with `(intent, procedure)` unique per intent.

Intents are declarative reference-data — plain NetBox CRUD, `ObjectChange`
audited, and not event-sourced. An intent only *declares* work; actually
executing it (fanning out one `RPCExecution` per grouped procedure) is a
separate, future capability. Any such executor MUST continue to honour each
procedure's `approval_required` / `effect` gating and the LLM Agent Safety
Guardrails — an intent must never be a way to bypass approval on a destructive
procedure.

### Intent API

- `GET`/`POST /api/plugins/rpc/intents/` — list/create intents.
- `GET`/`PATCH`/`PUT`/`DELETE /api/plugins/rpc/intents/{id}/` — retrieve, update,
  delete.
- On write, send an ordered `procedure_ids` list; the list order becomes the
  through `sequence`. The read representation returns `procedures` as an ordered
  list of `{id, name, handler_id, effect, approval_required, sequence}`.
- Filter with `?execution_mode=`, `?enabled=`, and `?procedure_id=`.

See [`docs/intents.md`](docs/intents.md) for the full model, ordering semantics,
and worked API examples.

## Standalone usage

`netbox-rpc` can be installed without `netbox-nms`. In standalone deployments,
create an `RPCBackend` object in NetBox and set:

- `name`: operator-facing backend name.
- `ip_address` / `domain` / `port` / `use_https`: point the plugin at the backend
  by **IP address or domain**; `backend_url` is composed as
  `{http|https}://{domain or ip}:{port}` (mirroring netbox-proxbox's
  `FastAPIEndpoint`).
- `base_url`: optional explicit URL override — when set it wins; when empty the
  URL is composed from the fields above. Dispatch uses
  `<backend_url>/rpc/executions/<execution_id>/run`.
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

### Opt-in settings + dashboard (optional Proxbox companion)

netbox-rpc can be adopted as an **optional companion** of the netbox-proxbox
family (like netbox-pdm / netbox-ceph / netbox-pbs) **without any hard
dependency** — it remains fully standalone. An easy, UI-based opt-in lives at
**RPC → Configuration**:

- **Dashboard** (`/plugins/rpc/`) shows whether the integration is enabled, the
  resolved backend, catalog counts, and a **Test connection** button that probes
  `GET {backend_url}/status/ping`.
- **Settings** edits the `RpcPluginSettings` singleton: `enabled` (opt-in,
  **off by default**) and an optional `backend` pointing at the `RPCBackend`
  used to reach `netbox-rpc-backend`. When disabled, netbox-rpc behaves exactly
  as before; when enabled, netbox-proxbox shows a companion card linking here.

The singleton can also be driven **programmatically**, not just from the UI:

- REST: `GET`/`PATCH` `/api/plugins/rpc/settings/` (e.g. `PATCH {"enabled": true}`).
- CLI: `python manage.py rpc_settings --enable` (also `--disable`, `--show`,
  `--backend <name-or-id>`, `--clear-backend`, `--dry-run`).

## DDD / CQRS / Event Sourcing

`netbox-rpc` is the Remote Command Policy bounded context for the NMS stack.
The detailed architecture contract lives in
[`docs/architecture.md`](docs/architecture.md). The core aggregate is
`RPCExecution`: callers request a business procedure, the aggregate records each
transition as an append-only execution event, and the mutable `RPCExecution` row
is treated as a read projection for NetBox API compatibility.

- **DDD**: procedure names use business language such as
  `network.device.dell_os10.s5232f_on.write_memory` and
  `os.linux.ubuntu.24.restart_service`; handler IDs are internal adapters.
- **CQRS**: execution creation, job enqueue, job execution, and cancellation are
  command-side handlers in `netbox_rpc.application.command_handlers`;
  execution list/detail and `/events` endpoints are query-side projections. API
  clients may create and cancel queued executions, but PUT/PATCH and DELETE are
  disabled for executions (immutable history) and event history is read-only.
- **Event Sourcing**: `netbox_rpc.event_store` appends ordered
  `RPCExecutionEvent` rows, folds typed domain events through
  `netbox_rpc.domain.projection.apply()`, and updates the projection in the
  same transactional helper. Job and API code must call command handlers or
  event-store helpers instead of mutating status/result fields inline.

Durable events include `ExecutionQueued`, `JobEnqueued`, `ExecutionStarted`,
`ParametersNormalized`, backend progress events, `ExecutionSucceeded`,
`ExecutionFailed`, `ExecutionEnqueueFailed`, and `ExecutionCancelled`.
`rebuild_projection(execution)` folds ordered events back into a
`ProjectionState`, and `reproject(execution)` writes that rebuilt state to the
model. Events must store redacted payloads, `payload_hash` values, credential
references, and command fingerprints only; never store secrets, private keys, or
unbounded raw command output. Event append failures are fail-closed: if the
per-execution sequence cannot be allocated, the command state transition raises
instead of silently dropping audit history. The execution-event API is read-only,
model saves reject normal update/delete, and the migration installs PostgreSQL
triggers so the event ledger remains append-only below the ORM.

`RPCProcedure`, `RPCLinuxServiceAllowlist`, `RPCBackend`, and `RPCIntent`
(with its `RPCIntentProcedure` through model) are deliberate
reference-data/configuration entities. They remain ordinary NetBox CRUD models,
audited by NetBox `ObjectChange`, and are not event-sourced.

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
SSH command text. Shared `rpc_ssh_host` overrides are trimmed, capped at 255
characters, and reject whitespace or control characters before backend dispatch
or normalized-parameter event recording.

### `os.linux.ubuntu.24.ookla.*`

Five **read-only** procedures diagnose a self-hosted OoklaServer (Ookla
Speedtest custom server) on Ubuntu over SSH. They are seeded by migration
`0035`, target `dcim.device` / `virtualization.virtualmachine`, are all
`effect="read"` with `approval_required=False`, and their handler IDs equal the
procedure names (handlers live in nms-backend).

- **`os.linux.ubuntu.24.ookla.diagnose`** (180s) — comprehensive run covering
  service/config, IPv4/IPv6 listeners, TLS certificate, and firewall.
- **`os.linux.ubuntu.24.ookla.check_service`** (60s) — OoklaServer
  process/service, binary + `OoklaServer.properties`, parsed ports, `useIPv6`,
  `allowedDomains`, and version.
- **`os.linux.ubuntu.24.ookla.check_listeners`** (60s) — actual IPv4 and IPv6
  listeners on the configured/discovered ports.
- **`os.linux.ubuntu.24.ookla.check_tls`** (60s) — TLS certificate validity,
  CN/SAN, issuer/chain, and live HTTPS on the SSL port.
- **`os.linux.ubuntu.24.ookla.check_firewall`** (60s) — ufw and
  iptables/nftables rules against the ookla ports.

SSH resolves from the target device's DeviceService **or**, for an ad-hoc/saved
speedtest server, from the `rpc_ssh_host` + `rpc_ssh_credential_pk` overrides
(the same override contract used by the agent installers). The normalizer also
forwards only validated `install_dir` / `config_path` (absolute-path charset)
and `ports` (integer list, at most 16) hints, plus an audit
`command_fingerprint`. No procedure accepts raw SSH command text.

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
(`_PTERODACTYL_ARTISAN_ALLOWLIST` in `netbox_rpc.domain.normalization`) and
again by the Pydantic schema in `nms-backend`. Disallowed commands raise
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
`netbox_rpc.domain.normalization` never imports `netbox_packer` at module level. Because a
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

Each RPC run enqueues a NetBox core RQ job (`/core/jobs/<N>/`) linked to the
`RPCExecution` by `job_id`. The core job page is thin — the issued command(s),
their output, and per-command timing live on the linked `RPCExecution`
(`result.steps[]`) and its event ledger. See
[`docs/rpc-generated-core-jobs.md`](docs/rpc-generated-core-jobs.md) for the
field map and a worked example.

### Transport-driver & output-parser selection

Each `RPCProcedure` declares a pluggable **transport driver** and **output
parser** for the nms-backend execution pipeline as explicit model fields (never
encoded in `handler_id`):

- `transport_driver`: the single default driver — `asyncssh` (default),
  `paramiko`, `subprocess`, `fabric` (Linux/server SSH) or `scrapli`, `netmiko`,
  `napalm`, `nornir` (network CLI). `asyncssh` preserves the historical SSH
  behaviour.
- `transport_driver_chain`: an ordered priority + fallback chain of the same
  driver names (index 0 tried first). Injected into
  `normalized_params["transport_driver_chain"]` only when non-empty (legacy
  procedures keep an identical payload); the netbox-rpc-backend executor tries
  them in order, advancing on an unavailable/connection error.
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

`netbox_rpc.application.command_handlers.create_execution()` enforces three
guards before an execution record is created and the RQ job is enqueued:

1. **Enabled** — disabled procedures are rejected (HTTP 400).
2. **Approval** — procedures with `approval_required=True` require the caller
   to hold `netbox_rpc.approve_rpcprocedure`.
3. **Params schema** — when a procedure defines `params_schema`, submitted
   `params` are validated against the JSON Schema before proceeding.

These guards run at the API layer, not the model layer, because the serializer
receives the procedure as a foreign-key ID and the schema/enabled/approval
checks require the resolved object.

The command emits `ExecutionQueued` before enqueueing. If RQ/Redis enqueue
fails, it emits `ExecutionEnqueueFailed` and projects
`error_code="RPC_ENQUEUE_FAILED"` instead of leaving a permanent queued record
with no job. Successful enqueue emits `JobEnqueued` and projects `job_id`.

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

The suite is two tiers (see `docs/architecture.md` → Testing):

```bash
# Tier 1 — fast pure-domain unit tests; stub Django/NetBox, no database
python -m pytest tests

# Tier 2 — DB-backed integration tests against a NetBox checkout + Postgres
python netbox/manage.py test netbox_rpc
```

Tier 1 (`tests/`) covers the domain logic (projection fold/rebuild, typed
events, aggregate invariants, value objects, queries, normalization) and runs in
the `ci.yml` workflow. Tier 2 (`netbox_rpc/tests/`) covers the ORM-bound
behavior — `event_store`, the rebuild oracle, the append-only ledger, the
command handlers, and the command-only REST API — and runs in the
`integration.yml` (self-hosted) and `.github/workflows/test.yml` (portable,
Postgres-service) workflows using `tests/ci/netbox_configuration.py`.

Do not test this plugin against a real Linux host, Linux container/VM over SSH,
or a real Huawei OLT unless a separate explicit live-device test plan is
approved.
