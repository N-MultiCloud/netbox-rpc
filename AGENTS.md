# netbox-rpc Agent Notes

`netbox-rpc` owns procedure policy and audit state. It must never store or
accept arbitrary SSH command text from API clients. It can boot and migrate
without `netbox-nms`; NMS support is an optional auto-detected adapter.

## Standalone Usage

Install `netbox-rpc` without `netbox-nms` when only the audited RPC catalog and
execution framework are needed. Standalone deployments use the local
`RPCBackend` model to reach the execution backend (`netbox-rpc-backend`): point
it at the backend by **IP address or domain** plus `port` / `use_https` — the
`backend_url` is composed from those structured fields, mirroring
netbox-proxbox's `FastAPIEndpoint` (`{scheme}://{domain or ip}:{port}`) — or set
an explicit `base_url`, which wins as an override. `verify_ssl` and an optional
static auth header (`auth_header_name` / `auth_token`) round out the target.
`auth_token` is plaintext storage; security-conscious deployments should
configure `PLUGINS_CONFIG["netbox_rpc"]["backend_resolver"]` to resolve a
`netbox_rpc.backends.BackendTarget` from an external secret store or service
registry. To route dispatch to the `netbox-rpc-backend` service (an `RPCBackend`
row) even when `netbox-nms` is installed, set
`backend_resolver = "netbox_rpc.backends.local_rpcbackend_resolver"`; it uses the
execution's `backend` pk, else the single configured `RPCBackend`.

When no custom resolver is configured and `netbox-nms` is importable,
`netbox-rpc` adapts `netbox_nms.backend.get_backend(pk)` to the tiny backend
runtime contract: `backend_url`, `get_auth_headers()`, and `verify_ssl`. When
`netbox-nms` is absent, `RPCBackend` is the default backend source. The
N-MultiCloud procedure catalog remains in-repo as an optional guarded layer.

## Opt-in settings + landing page (optional netbox-proxbox companion)

`netbox-rpc` presents itself as an **optional companion** of the netbox-proxbox
family (like netbox-pdm / netbox-ceph / netbox-pbs) **without any hard
dependency** — it still has **no `required_plugins`** and boots/migrates
standalone. The UI-based opt-in surface lives here:

- **`RpcPluginSettings`** (`models.py`) is a `get_solo()` singleton (mirrors
  `CephPluginSettings`/`PBSPluginSettings`): `enabled` (opt-in gate, **default
  `False`**) + an optional `backend` FK to an `RPCBackend`. `RPCBackend` stays
  the single source of truth for connection details; the settings row does not
  duplicate url/token fields. `resolved_backend_target()` returns a
  `backends.BackendTarget` — the selected FK when set, else the normal
  `backends.resolve_backend(None)` chain (custom resolver → netbox-nms → single
  local `RPCBackend`). Additive migration `0044_rpcpluginsettings` (no
  `netbox_nms`/`netbox_proxbox` migration dependency).
- **Landing page** at `/plugins/rpc/` (`RPCHomeView`, URL name `home`) shows the
  enabled state, resolved backend, catalog counts, and a **Test connection**
  button. **Settings** page is the singleton edit (`RpcPluginSettingsEditView`
  via `rpcpluginsettings_singleton_edit` redirect). Both are in the **RPC →
  Configuration** nav group.
- **Backend reachability** is `health.probe_backend()` — a single fixed
  `GET {backend_url}/status/ping` (never caller-controlled host/shell), shared by
  the landing view and the POST `rpcpluginsettings_test_connection` endpoint.
- **Programmatic control** of the singleton (beyond the UI): a **REST API** at
  `/api/plugins/rpc/settings/` (`RpcPluginSettingsViewSet`, **GET + PATCH only**;
  `get_queryset()` calls `get_solo()` so the row always exists; create/delete are
  405) and a **`manage.py rpc_settings`** command (`--enable`/`--disable`/`--show`,
  `--backend <name-or-id>`/`--clear-backend`, `--dry-run`). Both only touch
  netbox-rpc's own config — no Proxbox/NMS dependency.
- netbox-proxbox surfaces this as a soft companion card on its home dashboard via
  its own `integrations/rpc.py::rpc_dashboard_context()` — it reads
  `RpcPluginSettings` through a guarded `try/except ImportError` and degrades to
  nothing when netbox-rpc is absent. netbox-rpc never imports netbox-proxbox.

## RPC Procedure Commands

`netbox-rpc` is now the database source of truth for the structured command
steps attached to each `RPCProcedure`. The `RPCProcedureCommand` model stores
ordered, fixed-token command definitions; it must never store arbitrary shell
text. The command contract served to nms-backend is stable:

```python
procedure.commands[] = {
    "sequence": int,
    "step_type": "shell_argv" | "device_cli",
    "device_cli_mode": "exec" | "config" | None,
    "argv": ["token", "{param}", "..."],
    "description": str,
    "condition_param": str,
    "condition_negate": bool,
    "for_each_param": str,
    "continue_on_error": bool,
    # Templating + output-capture contract (see docs/command-templating.md).
    "render_mode": "literal" | "jinja",
    "produces_var": str,        # "" = captures nothing
    "capture_kind": "" | "stdout" | "stdout_stripped" | "json" | "regex" | "line",
    "capture_expression": str,  # regex (one group) / JSON path / line index
}
```

`argv` is an ordered token list, not a command string. In `render_mode="literal"`
(default, unchanged) literal token characters are constrained by
`netbox_rpc.command_contract.SAFE_TOKEN_RE`; placeholders are extracted with
`extract_placeholders()` and may reference procedure `params_schema.properties`
or the runtime keys documented in `COMMAND_RUNTIME_KEYS`. The API embeds
`commands` on `RPCProcedureSerializer`, so `RPCExecutionSerializer.procedure.commands`
is present in the execution payload nms-backend fetches. CRUD is available at
`/api/plugins/rpc/procedure-commands/`, and procedure-scoped list/create is
available at `/api/plugins/rpc/procedures/{id}/commands/`. The procedure object
page renders the same rows in the "Commands" card.

### Command templating & output-variable chaining

`render_mode="jinja"` makes each `argv` token a sandboxed Jinja2 *expression*
rendered — by the future nms-backend executor, at run time — against a fixed
context: `params.<name>` (declared params), `target.<field>` (the run's NetBox
target object, "NetBox objects as variables"), `vars.<name>` (a value captured
from an **earlier** command's output, the nesting chain), `runtime.<key>` (the
`rpc_ssh_*` connection keys), and `item` (the `for_each` element). Validation
lives in `netbox_rpc.command_templating` and is enforced in
`RPCProcedureCommand.clean()`:

- statement/comment blocks (`{% %}`/`{# #}`) and function/method calls are
  rejected — tokens are expressions, not programs;
- literal text outside `{{ }}` must use the conservative argv charset;
- every reference must resolve — `params.*` to a declared param, `runtime.*` to
  a known key, `vars.*` to a variable produced by a command with a strictly
  smaller `sequence` (referencing an output before it is produced is an error),
  and `target.*` to any non-dunder field;
- `produces_var` must be a unique snake_case name; `capture_kind`/`capture_expression`
  are validated (regex compiles with exactly one group, line index is an int, …).

netbox-rpc owns the NetBox target object, so when a procedure has any jinja
command the normalizer serializes a bounded, redacted, JSON-safe snapshot of the
target into `normalized_params["_target_object"]` (the `{{ target.* }}` context)
and adds `command_fingerprint["target_object_sha256"]`. This is gated on the
presence of a jinja command, so **legacy/literal procedures keep a byte-for-byte
identical normalized payload**. **Security boundary for the executor:** the
render context values are still substituted into a shell string over SSH, so the
executor MUST sandbox-render, shell-quote every rendered token, and re-validate
captured values before reuse — never store or accept arbitrary shell text here.
Full contract in [`docs/command-templating.md`](docs/command-templating.md).

Handlers that cannot be represented faithfully as fixed argv or device-CLI rows
must be listed in `EXEMPT_HANDLER_RATIONALE` in
`netbox_rpc.command_contract` and seeded with exactly one representative command
row. Current exemptions cover backend-orchestrated scripts, URL-download
installers, destructive Proxmox workflows, and command branches that the
truthy-only condition contract cannot express. Do not remove an exemption until
the backend command executor can consume an exact row-level representation.

## Procedure Runs Tab (query-side)

The `RPCProcedure` object view has a **Runs** tab (`RPCProcedureRunsView`,
registered as the `runs` action, `/plugins/rpc/procedures/<pk>/runs/`) that lists
that procedure's `RPCExecution` history — a pure query-side projection with no
new mutation surface. It reuses `RPCExecutionTable` (with a `source` column) and
three read-only `RPCExecution` presentation properties:

- `source_label` / `intent_reference` — how the run was issued. Executing an
  `RPCIntent` is out of scope for the aggregate today (see **Intents** below), so
  every run currently reads as `Direct`. The helpers are forward-compatible: when
  a future intent executor stamps an underscore-prefixed `_intent_name`/`_intent`
  marker into `params`, the tab attributes the run as `Intent: <name>`. Do **not**
  reuse a bare `intent` params key for a procedure's own parameter — only the
  underscore-prefixed internal keys are treated as origin markers.
- `result_steps` — returns `result.steps[]` (empty when absent/malformed). The
  execution detail template renders it as a **Command Output** card (command,
  operation, exit code, stdout, stderr). Keep this output bounded/redacted per the
  event-data rule above; never surface secrets or unbounded raw output.

Any future intent executor that records an origin marker in `params` must keep it
under the `_intent`-prefixed keys so this attribution stays correct.

## DDD / CQRS / Event Sourcing

- Treat `RPCExecution` as the command aggregate and current-state read
  projection. The detailed contract is in `docs/architecture.md`.
- Typed execution events live in `netbox_rpc.domain.events`; the canonical
  projection fold is `netbox_rpc.domain.projection.apply()` /
  `rebuild()`. `event_store.rebuild_projection()` and `reproject()` are the
  event-sourcing proof.
- All status/result/error transitions must go through
  `netbox_rpc.event_store`; do not mutate execution state directly in jobs,
  API views, or serializers.
- `RPCExecutionEvent` is the append-only event stream. Preserve ordered
  sequences per execution and keep collision handling in the event-store layer.
  The event API is read-only, model saves reject update/delete, and database
  triggers protect the ledger below the ORM.
- Event append failures must fail closed. Do not log-and-drop an execution
  event after sequence collisions or database errors.
- API create/enqueue/cancel paths and RQ execution dispatch are command-side
  behavior in `netbox_rpc.application.command_handlers`. Execution detail/list
  and execution-events endpoints are query-side behavior, PUT/PATCH and DELETE
  are disabled for `RPCExecutionViewSet` (the aggregate and its append-only
  ledger are immutable history), and the event API must remain read-only.
- Event data and backend result projections must be redacted and bounded. Store
  credential references, `payload_hash` values, and command fingerprints, not
  secrets, private key material, or unbounded raw command output.
- `RPCProcedure`, `RPCLinuxServiceAllowlist`, `RPCBackend`, and `RPCIntent`
  (with its `RPCIntentProcedure` through model) are intentional
  reference-data/configuration entities: plain NetBox CRUD, NetBox ObjectChange
  audited, and not event-sourced.
- Network device procedures should delegate protocol execution to the
  network command/query gateway service as drivers migrate out of
  `nms-backend`.

## Intents

`RPCIntent` groups one or more `RPCProcedure`s and declares *what* needs to be
done; the procedures (with their commands) declare *how*. See
[`docs/intents.md`](docs/intents.md) for the full model and API.

- `execution_mode` (`sequential`/`parallel`) is single-sourced from
  `ExecutionMode` in `netbox_rpc.domain.value_objects` (like `Effect`/
  `ExecutionStatus`). `sequential` = nested, ordered by the `RPCIntentProcedure.sequence`;
  `parallel` = concurrent, no nesting (sequence informational).
- Grouping is an ordered M2M through `RPCIntentProcedure`
  (`intent` CASCADE, `procedure` PROTECT, `sequence`), unique `(intent, procedure)`.
  The form and the API write channel (`procedure_ids`) both renumber `sequence`
  from 1 in submitted order.
- Intents are declarative reference-data (plain CRUD, not event-sourced). This
  model layer only **declares** intents; it does not execute them.
- **Execution is out of scope for the model and must stay gated.** A future
  intent executor MUST create each child run through
  `create_execution()` (so it is event-sourced) and MUST keep enforcing every
  grouped procedure's `approval_required`/`effect` gating and the LLM Agent
  Safety Guardrails below. An intent must never bypass approval on a destructive
  procedure. Seeded by additive migration `0039_rpcintent` (depends on the
  `0038_merge_rpc_procedure_commands` leaf; no live imports, no `netbox_nms`
  dependency). `0040_rpcintentprocedure_sequence_min` adds the `sequence >= 1`
  validator + DB `CheckConstraint`.
- `RPCIntentProcedure.sequence` must be `>= 1` (validator + check constraint);
  the form/API renumber from 1. Grouped-procedure add/remove/reorder is captured
  in the intent changelog because `RPCIntent.serialize_object()` includes the
  ordered `intent_procedures` and the form/serializer reconcile the through rows
  **before** the model save on the update path (Django never fires `m2m_changed`
  for a through-M2M with extra fields).
- The plugin's real floor is NetBox **4.6.0** (`min_version = "4.6.0"`): the
  migration graph depends on `extras.0138` (a 4.6 migration).

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
- NetBox RQ jobs normalize params and delegate execution to `nms-backend`. Each
  run's core RQ job (`/core/jobs/<N>/`) links to the `RPCExecution` by `job_id`;
  the issued command(s), their output, and per-command timing are read from
  `RPCExecution.result.steps[]` and the event ledger. See
  [`docs/rpc-generated-core-jobs.md`](docs/rpc-generated-core-jobs.md).
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
  Its normalizer (`_normalize_convert_mellanox_nic_execution` in
  `netbox_rpc.domain.normalization`)
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
- Proxmox systemctl service state: `os.linux.proxmox.show_systemctl_services`
  (**read**, no approval, 60s) is seeded by migration `0044` (representative
  command row in `0045`). It targets a **netbox-proxbox `ProxmoxEndpoint`**
  (`target_models = ["netbox_proxbox.proxmoxendpoint"]`) and drives the
  opt-in, agentless, pull-based service monitoring in netbox-proxbox. **Unlike
  the Mellanox/QEMU Proxmox procedures it does NOT resolve the netbox-nms
  `ProxmoxEndpointSSHBinding` and emits no `rpc_ssh_*` keys** — its normalizer
  (`_normalize_show_systemctl_services_execution`) forwards only
  `proxmox_endpoint_id` and a validated `units` list (each a string, charset
  `^[A-Za-z0-9_][A-Za-z0-9_.@:-]*$` — the first char cannot be `-`, so a value
  can never be read as a `systemctl` option — ≤32 entries, ≤100 chars each;
  empty ⇒ backend default set). For audit integrity the normalizer also requires
  `proxmox_endpoint_id` to match the execution's target object
  (`assigned_object_id`) when one is set, so the audited target and the resolved
  SSH target can never diverge. The execution backend resolves SSH downstream from the endpoint's OWN
  stored credential (fetched from netbox-proxbox's SSH-credential secrets API,
  gated on `allow_writes` + a registered SSH credential), runs
  `systemctl show -p …` per unit, and returns
  `{ok, procedure, target, reachable, services[…]}`. Handler ID:
  `os.linux_proxmox.show_systemctl_services` (exempt in
  `command_contract.EXEMPT_HANDLER_RATIONALE` because the per-unit /
  default-set / output-parsing orchestration is backend-owned).
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
  deploy-only `force_recreate`; shared `rpc_ssh_host` overrides are trimmed,
  capped at 255 characters, and reject whitespace/control characters. It must
  never accept arbitrary SSH command text.
- Ookla / Speedtest server diagnostics are seeded by migration `0035`. Five
  **read-only** procedures (`effect="read"`, `approval_required=False`,
  `target_models = ["dcim.device", "virtualization.virtualmachine"]`) diagnose a
  self-hosted OoklaServer over SSH; handler IDs equal the procedure names and
  the handlers live in nms-backend:
  - `os.linux.ubuntu.24.ookla.diagnose` (180s) — comprehensive: service/config,
    IPv4/IPv6 listeners, TLS certificate, and firewall in one run.
  - `os.linux.ubuntu.24.ookla.check_service` (60s) — process/service, binary +
    `OoklaServer.properties`, parsed ports, `useIPv6`, `allowedDomains`, version.
  - `os.linux.ubuntu.24.ookla.check_listeners` (60s) — actual IPv4/IPv6 listeners.
  - `os.linux.ubuntu.24.ookla.check_tls` (60s) — cert validity/CN/SAN/issuer +
    live HTTPS on the SSL port.
  - `os.linux.ubuntu.24.ookla.check_firewall` (60s) — ufw + iptables/nftables vs
    the ookla ports.
  Their normalizer (`_normalize_ookla_execution`) resolves SSH from the target
  device's DeviceService **or** from the ad-hoc/saved `rpc_ssh_host` +
  `rpc_ssh_credential_pk` overrides (the same override contract used by the
  agent-install procedures), and forwards only validated `install_dir` /
  `config_path` (absolute-path charset) and `ports` (int list, ≤16) hints. It
  must never accept arbitrary SSH command text.
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
  module level; `netbox_rpc.domain.normalization` imports `packer_normalizer`
  function-locally in the dispatch branch. **netbox-packer MUST NOT import,
  depend on, or reference netbox-rpc in
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
  `normalize_execution_params()` in `netbox_rpc.domain.normalization` (re-exported
  from `jobs.py` for compatibility).
- Keep `README.md` updated when procedure policy, handler IDs, execution
  routing, audit behavior, or security constraints change.
- Tests must use mocks and fixtures only; do not connect to real Linux hosts,
  containers, VMs, or Huawei OLTs.

## CI / Testing

Two tiers (see `docs/architecture.md` → Testing):

1. **Pure-domain unit tests** (`tests/`, `pytest`) — stub Django/NetBox, no
   database. `.gitea/workflows/ci.yml` runs `py_compile` + `pytest tests/ -q` on
   the `mirror-host` runner; the portable `.github/workflows/test.yml` `unit` job
   mirrors it. Cover the domain logic (projection fold/rebuild, typed events,
   aggregate invariants, value objects, queries, normalization). Add new
   domain/CQRS logic here. Use `monkeypatch`/`SimpleNamespace` stubs as in
   `tests/test_jobs_systemd_normalization.py`.

2. **DB-backed integration tests** (`netbox_rpc/tests/`, `manage.py test
   netbox_rpc`) — a real NetBox + PostgreSQL test database. Cover `event_store`,
   the rebuild oracle, the append-only ledger, the command handlers, and the
   command-only REST API. `.gitea/workflows/integration.yml` runs them against
   the self-hosted NetBox; `.github/workflows/test.yml` `integration` job runs
   them portably with a Postgres service. Config: `tests/ci/netbox_configuration.py`.

Tests must never connect to real Linux hosts, containers, VMs, or Huawei OLTs;
the integration tests mock the RQ enqueue and the backend dispatch.

## Continuous-Improvement Charter

`netbox-rpc` is the audited, ever-growing procedure catalog for every command
that must run on a managed host. **The catalog is meant to expand
continuously.** Whenever an agent needs a host operation (Proxmox, Linux,
network device, service) that has no procedure yet, treat that gap as the next
unit of work rather than reaching for ad-hoc SSH:

- Add the capability as a new `RPCProcedure` — seed migration (inline data, no
  live imports), `params_schema`, correct `effect`/`approval_required` gating,
  `target_models`, `transport_driver`/`output_parser` selection, and (for
  Linux service control) the `RPCLinuxServiceAllowlist` entry — plus the
  matching `@rpc_handler` in `nms-backend`, via `feature-workflow`.
- Prefer **fixed-argv, structured-param** handlers. Caller input must never
  reach a shell; never add a procedure that accepts arbitrary command text.
- Mark anything that mutates production infrastructure `effect="write"` (or
  `destructive`) with `approval_required=True` where warranted, so it is never
  dispatched autonomously.
- Surface every new procedure through `nms rpc procedures …` /
  `nms rpc executions …` so future agents **discover and reuse** it instead of
  re-deriving SSH.

The command surface should grow monotonically and auditably — the more agents
need, the richer this catalog becomes, never a pile of one-off SSH one-liners.

**Client-side rule:** agents interact with managed hosts and Proxmox **only
through `nms-cli`** (`nms rpc` for host operations, `nms virt`/`nms cloud` for
Proxmox/Proxbox data and lifecycle) — never ad-hoc `ssh`/`pvesh`/`qm` or direct
NetBox/Proxmox API calls. This mirrors the estate-wide policy in
`/root/personal-context/CLAUDE.md`.

## Adding New Procedures

Every procedure seeded via migration must have a corresponding branch in
`normalize_execution_params()` in `netbox_rpc.domain.normalization`. If a
procedure is seeded (by this plugin or a sibling plugin's migration) but has no
normalizer, executions will fail at runtime with
`RPC_PROCEDURE_NOT_NORMALIZABLE`.

- Add the procedure name constant to `constants.py`.
- Add the normalizer branch to `_dispatch_normalize_execution_params()` in
  `netbox_rpc.domain.normalization` (the public `normalize_execution_params()`
  wraps it and `jobs.py` re-exports it).
- Update this file and `README.md` to document the new procedure.

## Transport Driver & Output Parser Selection

`RPCProcedure` carries explicit pluggable-driver routing for the nms-backend
execution pipeline. **Never encode the driver inside `handler_id`** — it is its
own model data:

- `transport_driver` — the single default driver: `asyncssh` (default),
  `paramiko`, `subprocess`, `fabric` (Linux/server SSH) or `scrapli`, `netmiko`,
  `napalm`, `nornir` (network CLI). AsyncSSH reproduces the legacy
  single-/multi-command SSH behaviour.
- `transport_driver_chain` — an ordered **priority + fallback chain** of the
  same driver names (index 0 tried first), configured on the `RPCProcedure`
  page. `_apply_driver_pipeline_overrides()` injects it into
  `normalized_params["transport_driver_chain"]` (and `command_fingerprint`)
  **only when non-empty**, so legacy procedures keep a byte-for-byte identical
  payload. The `netbox-rpc-backend` executor tries the drivers in order, skips
  capability-mismatched entries, advances on an unavailable/connection error,
  and stops on a command-level result.
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

`netbox_rpc.application.command_handlers.create_execution()` enforces three
guards before enqueueing:

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

`append_execution_event()` in `netbox_rpc.event_store` allocates the next
per-execution sequence and retries IntegrityError collisions 3 times to prevent
TOCTOU sequence collisions under concurrent RQ workers.

Implementation rules:
- Each retry re-reads the latest sequence after a collision and tries the next
  contiguous number. Never skip valid sequence numbers.
- Exhausting retries raises `RPCEventStoreError`; event append failure is
  fail-closed and must abort the command transition.
- Projection writes must be derived from the typed event through
  `netbox_rpc.domain.projection.apply()`, not hand-mutated independently.

## SYSTEMD_UNIT_RE Invariants

`SYSTEMD_UNIT_RE` rejects:
- leading dots
- trailing dots
- double dots (`nginx..service`)
- double `.service` suffix (`nginx.service.service`)
- empty strings

Only `.service` is a permitted suffix. When adding new allowlist entry types
that use other unit types (`.socket`, `.timer`), the regex must be extended.
