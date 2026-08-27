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

- `source_label` / `intent_reference` — how the run was issued. A run created
  directly (API/UI `RPCExecution` POST) reads as `Direct`. A run created by the
  intent executor (`command_handlers.execute_intent()`, see **Intents** above)
  reads as `Intent: <name>` through the execution's read-only `source_intent`
  foreign key. Intent attribution is persisted in the original execution insert
  and never mixed into caller `params`. The underscore-prefixed `_intent_name` /
  `_intent` keys remain a read-only compatibility fallback for historical rows;
  new execution paths must not write them.
- `result_steps` — returns `result.steps[]` (empty when absent/malformed). The
  execution detail template renders it as a **Command Output** card (command,
  operation, exit code, stdout, stderr). Keep this output bounded/redacted per the
  event-data rule above; never surface secrets or unbounded raw output.

Any future intent executor must use `source_intent`; post-creation `params`
mutation is forbidden because it can bypass family-specific persistence guards.

## DDD / CQRS / Event Sourcing

- Treat `RPCExecution` as the command aggregate and current-state read
  projection. The detailed contract is in `docs/architecture.md`, whose
  **System Architecture** section diagrams the whole current path —
  component view, execution lifecycle, and driver-chain resolution.
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
- Every present backend `result` must validate against the procedure's
  `result_schema`, including false outer envelopes. A truthy response may append
  `ExecutionSucceeded` only after validation; a false response remains failed
  while projecting its valid closed result. Schema mismatch fails closed as
  `RPC_RESULT_SCHEMA_MISMATCH` without projecting malformed data and with a
  bounded, value-free diagnostic. Event messages have a separate redacted
  4096-character hard cap.
- `RPCProcedure`, `RPCLinuxServiceAllowlist`, `RPCBackend`, and `RPCIntent`
  (with its `RPCIntentProcedure` through model) are intentional
  reference-data/configuration entities: plain NetBox CRUD, NetBox ObjectChange
  audited, and not event-sourced.
- Network device procedures should delegate protocol execution to the
  network command/query gateway service as drivers migrate out of
  `nms-backend`.

### Two-person approval workflow (#164, #221/#224/#235 scoped enforcement)

The execution aggregate carries an additive **approval-workflow** surface (the
foundation of the P0 two-person-approval epic #163). Issues #221 and #224
activate the complete two-person route for
`service.netbox.staging.rotate_backend_token` and
`service.gitea.production.upgrade_1_27_1`, plus the disabled
`service.gitea.runner.register` and
`service.gitea.actions_runner.provision_org_ci_runner`; other legacy
`approval_required` procedures retain their existing requester permission gate
until they are migrated deliberately.

- **States** (`domain.value_objects.ExecutionStatus`): `requested`,
  `pending_approval`, `approved`, `rejected`, `expired` precede the existing
  `queued → running → …` lifecycle. `rejected`/`expired` are terminal
  (`ExecutionStatus.approval_terminal()`); the pre-existing direct flow still
  starts at `queued`.
- **Events** (`domain.events`): `ExecutionRequested`, `ApprovalRequested`,
  `ExecutionApproved`, `ExecutionRejected`, `ExecutionExpired`. As always,
  status folds only from the append-only stream via `projection.apply()`; all
  transitions go through `event_store` (never mutate status directly).
- **Immutable snapshot** (`models.RPCApprovalRequest`, one-to-one with the
  execution): pins procedure id/version/effect, target snapshot hash, normalized
  params + command fingerprint, backend, credential-policy *reference*,
  requester, expiry, and stream version, plus a tamper-evident `payload_hash`
  over the protected fields (`compute_approval_snapshot_hash`). It is append-only
  like `RPCExecutionEvent` (save-after-create and delete raise; execution-cascade
  still works), stores references not secrets, and `matches_current()` detects a
  snapshot-invalidating drift.
- **Aggregate transitions** (`domain.aggregate`): `request` → `request_approval`
  (never enqueues) → `approve` / `reject` / `expire`. A protected procedure's
  successful `approve` atomically adds `ExecutionApproved` then
  `ExecutionQueued`, after which the application enqueues one RQ job and adds
  `JobEnqueued`. `approve`/`reject` enforce
  **segregation of duties** (the requester cannot decide their own request) and
  `approve` re-checks the snapshot; the decision is serialised with a
  `select_for_update` row lock + in-transaction status recheck so
  double/concurrent approvals, approve-vs-cancel, and expiry-vs-decision resolve
  to a single deterministic event.
  For each protected procedure, validate the immutable backend target before
  sending authenticated capability traffic and reuse that exact resolved target
  through snapshot/lease/dispatch. Approval must obtain an uncached compatible
  capability while holding the row lock; failure leaves pending state and its
  event stream unchanged and must not enqueue.
- **Command-only decision API (#165)**: `RPCExecutionViewSet` exposes POST
  `approve` / `reject` actions (`command_handlers.approve_execution` /
  `reject_execution`) — no mutable status CRUD (PUT/PATCH/DELETE stay 405).
  Authorization layers `approve_rpcprocedure` **plus** object-scoped view access
  to the execution's procedure on top of the aggregate's segregation-of-duties
  and single-decision concurrency guards; `get_object()` already object-restricts
  the execution row. The staging rotation, production Gitea upgrade, and
  isolated-runner registration use
  this API: creation requires execute permission scoped to the exact procedure and never accepts
  a same-request bypass; a distinct actor with approval permission scoped to
  that procedure must decide it. Other procedures are not implicitly migrated
  to this lifecycle.
- **Authoritative opt-in + selected backend (#166)**: `RpcPluginSettings.enabled`
  and its selected backend are now enforced by `command_handlers`. At execution
  **creation** a disabled integration is rejected (403) and an unconfigured
  backend is rejected (400); a normal requester's `backend_id` is IGNORED — the
  singleton's selected backend always wins (no arbitrary backend selection). At
  the **worker claim** (`run_execution`) a disabled integration fails the run
  closed (`RPC_INTEGRATION_DISABLED`) rather than dispatching. Migration `0050`
  preserves current behaviour: an install that already has execution history is
  opted in idempotently (enabled + the single `RPCBackend` selected when
  unambiguous), so enforcing the gate never rejects an already-active install;
  fresh installs keep the `enabled=False` default. Tests that create/dispatch
  executions must call `_common.enable_rpc_integration()`.
  Once a queued execution is claimed, a resolver exception must be converted to
  bounded `RPC_BACKEND_RESOLUTION_FAILED` and appended as `ExecutionFailed`;
  never persist resolver text or leave the projection in `running`.
- **Backend capability handshake (#167)**: `capabilities.py` consumes a manifest
  the paired `netbox-rpc-backend` advertises at `GET {backend_url}/capabilities`
  (per handler: `handler_id`/`version`/`effect`/`contract_hash`, plus a top-level
  `envelope_version`). The fetch is bounded (≤512 KiB), authenticated (backend
  target headers), cached (30 s TTL), Pydantic-v2-validated, and **never trusted
  as command input**; `derive_command_contract_hash()` is the shared hash both
  sides compute over a procedure's identity + ordered command contract. Before
  enqueue, `create_execution` fails closed (400) on a capability **mismatch**
  (missing handler / version / effect / contract-hash / unsupported envelope),
  and `procedures/available` filters mismatched procedures out. **Graceful
  degradation:** when the backend advertises nothing (no route / unreachable /
  malformed / oversized), the fetch is `None`, verification is `UNKNOWN`, and
  callers proceed — so enforcement is inert until the paired backend advertises
  a manifest (prod-safe; the current backend advertises none). Capability tests
  that create executions must mock `capabilities.fetch_backend_capabilities`.
- **One-time signed dispatch leases (#168)**: `dispatch_lease.py` mints a
  short-lived **ed25519-signed** dispatch lease after the atomic *queued →
  claimed* (`start()`) transition and hands it to the paired `netbox-rpc-backend`
  (verifier, nms-backend#583) in the `/rpc/executions/{id}/run` body. The
  `LeaseClaims` envelope (Pydantic v2, `extra="forbid"`, all fields bounded)
  binds execution id, `stream_version`, one-time `nonce`, `audience`, handler
  contract + `effect`, `contract_hash` (the **same** value #167 verifies),
  target/params fingerprints, credential-policy *reference*, requester/approver,
  key `(key_id, key_version)` lineage, and a short expiry — **references and
  hashes only, never a secret or exception chain**, and never trusted as command
  input. `derive_command_contract_hash()` (#167) is reused so a lease and a
  capability manifest agree by construction on what will run. `verify_dispatch_lease`
  is the shared reference verifier (fail-closed on downgrade / unknown key
  lineage / bad signature / wrong audience / expiry / execution-stream-contract
  drift / replayed nonce). Issuance is audited as the **audit-only**
  `DispatchLeaseIssued` domain event (does not advance status). **Nonce
  ownership:** the issuer generates + ledgers the nonce; the verifier owns the
  consumed-nonce (accept-once) store. **Graceful degradation / prod-safe:** with
  no signing key configured (current prod), `issue_dispatch_lease` returns
  `None`, ordinary procedures POST `{}` byte-for-byte as before (ID-only
  dispatch). **Staging token rotation is the fail-closed exception:** a missing
  signing key produces `RPC_DISPATCH_LEASE_REQUIRED` and no backend request.
  It cannot run until the control plane provisions the issuer private key and
  verifier public key. Keys, audience, and TTL normally come
  from `PLUGINS_CONFIG["netbox_rpc"]` (`dispatch_lease_signing_keys` /
  `dispatch_lease_audience` / `dispatch_lease_ttl_seconds`). Threat model, ADR,
  and rotation/rollback/retirement ops live in
  [`docs/dispatch-lease.md`](docs/dispatch-lease.md); the deterministic
  cross-repo contract fixture (accept-once + reject replay/tamper/wrong-audience/
  lineage) is `netbox_rpc/tests/fixtures/dispatch_lease/`. Tests that mint a
  lease patch `dispatch_lease._plugin_setting`; crypto/DB-backed tests live in
  the integration tier (`cryptography` + pydantic are not in the pure-domain env).
  If and only if `dispatch_lease_signing_keys` is absent, the issuer may instead
  receive `NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_FILE`,
  `NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_ID`, and
  `NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_VERSION`. All three are required. The
  absolute file path is descriptor-walked without following symlinks, preflighted
  before a nonblocking open, and accepted only for a regular, single-link,
  root/current-euid-owned file no larger than 16 KiB with permissions no broader
  than `0640`; trusted path ancestors are root/current-euid-owned and not
  group/other writable (root-owned sticky directories are allowed). Reads are
  bounded and metadata is compared before/after. Missing OS primitives,
  malformed lineage/PEM, unsafe metadata, races, FIFOs/devices, or partial env
  configuration return no key without exposing contents. An explicit empty or
  malformed plugin setting remains authoritative and does not fall through to
  the environment.

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
  model layer only **declares** intents; *executing* one is a separate command,
  `command_handlers.execute_intent()` (issue #130), triggered via `POST
  /api/plugins/rpc/intents/{id}/run/` on `RPCIntentViewSet`.
- **Execution never bypasses gating — every child re-runs the full
  `create_execution()` gate stack.** `execute_intent()` creates one child
  `RPCExecution` per grouped procedure, in ascending `RPCIntentProcedure.sequence`
  order, exclusively through `create_execution()` — never a side channel — so
  each child independently re-checks the `execute_rpcprocedure` permission, the
  #166 authoritative opt-in + selected-backend enforcement, `procedure.enabled`,
  the `approval_required`/`approve_rpcprocedure` gate, `params_schema`
  validation, and the #167 capability check, exactly as a direct create would.
  An intent grouping an `approval_required` or destructive procedure does
  **not** auto-run that child: the same exception a direct create would raise
  propagates out of `execute_intent()` unmodified (fail-fast — no partial
  silent continuation past a refused child; earlier, already-created siblings
  are not rolled back, since each child is its own independent commit outside
  any shared outer transaction). This is the hard invariant — an intent must
  never bypass approval on a destructive procedure. `sequential` and `parallel`
  both fan out synchronously in sequence order today (v1); the mode distinction
  for true concurrent/chained dispatch is a documented future enhancement, not
  required by this safety contract. A successful child stores the intent in the
  read-only `RPCExecution.source_intent` foreign key in the same insert as the
  rest of the execution; attribution never enters or mutates `params`, so closed
  `params_schema` validation remains intact — see
  "Procedure Runs Tab" below and `docs/intents.md` → "Running an intent" for
  the full request/response contract. Seeded by additive migration `0039_rpcintent` (depends on the
  `0038_merge_rpc_procedure_commands` leaf; no live imports, no `netbox_nms`
  dependency). `0040_rpcintentprocedure_sequence_min` adds the `sequence >= 1`
  validator + DB `CheckConstraint`.
- `RPCIntentProcedure.sequence` must be `>= 1` (validator + check constraint);
  the form/API renumber from 1. Grouped-procedure add/remove/reorder is captured
  in the intent changelog because `RPCIntent.serialize_object()` includes the
  ordered `intent_procedures` and the form/serializer reconcile the through rows
  **before** the model save on the update path (Django never fires `m2m_changed`
  for a through-M2M with extra fields).
- The supported NetBox range is **4.5.8 through 4.6.x**
  (`min_version = "4.5.8"`, `max_version = "4.6.99"`), covering Django 5.2 and
  Django 6.0. External `extras` dependencies are intentionally anchored to
  `extras.0134_owner`, the final NetBox 4.5.8 migration and an ancestor in
  4.6.x. Do not regenerate them against a newer NetBox migration leaf without
  preserving the 4.5.8 floor.
- NetBox APIs used by the plugin must exist on 4.5.8. Guard or provide a
  fallback before adopting a 4.6-only model action, declarative UI/layout, or
  serializer resolver API.
- The plugin's real floor is NetBox **4.5.8** (`min_version = "4.5.8"`): the
  migration graph depends only on NetBox migration anchors present in both
  NetBox 4.5.8 and 4.6.x.

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

### Other Approval-Gated Destructive Procedures

| Procedure | Required operator confirmation |
|---|---|
| `os.linux.proxmox.convert_mellanox_nic_to_ethernet` | Confirm the exact endpoint, full parameters, network impact, dry-run result, and working out-of-band access as described above. |
| `os.linux.proxmox.qemu_vm_lifecycle` | Confirm the exact endpoint, VM, enum-constrained operation, expected guest impact, and recovery path. |
| `os.linux.ubuntu.24.upgrade_26.run_upgrade` | Run with `dry_run=true` first and review the analysis/backup results. A bad kernel or network-stack upgrade can kill the SSH transport netbox-rpc itself depends on, so operators must confirm working out-of-band console/IPMI access to the target before approving a non-dry-run execution. `reboot_after_upgrade=true` requires separate explicit confirmation. |
| `service.netbox.staging.rotate_backend_token` | Confirm the exact `nms-front-door` staging deploy host and recovery window. The operation invalidates the prior staging backend token and may leave staging unauthenticated if the fixed provisioner cannot install and verify the replacement. Never request or provide token or SSH-routing material in RPC params or operator notes. |
| `os.linux.debian.13.install_influxdb3_core` | Run `os.linux.debian.13.preflight_influxdb3_core` first and review its posture/`blockers[]`. Confirm the target host, the intended `http_bind` (a non-loopback bind additionally needs either TLS material or a deliberate `allow_plaintext_remote=true` on a firewalled network), and `data_dir`. It installs and holds a package, rewrites `/etc/influxdb3/influxdb3-core.conf` (backing up any prior file), adds a systemd drop-in, and restarts the unit — so on an existing instance it is service-affecting. `force_reconfigure=true` (adopting an unmanaged configuration) and `upgrade_package=true` (moving a held package's version) each need separate explicit confirmation. It never creates a credential; token bootstrap is a separate `service.influxdb.1.bootstrap` run. |
| `service.gitea.production.upgrade_1_27_1` | Confirm VM PK 170 (`Gitea`), VMID 222, cluster 6 / `PVE-CLUSTER-02`, node `pve03`, IPv4 `10.0.30.96`, the 1.26.2 → 1.27.1 maintenance window, tested backup/rollback path, and out-of-band recovery. Never enable, create, approve, or dispatch autonomously. |
| `service.gitea.runner.register` | Confirm stopped/accepted runner VM PK 399 (`nmultifibra-ci-untrusted-01`), exact `register`/`reconcile` operation and allowlisted scope, canonical durable fence, both pinned target-owned SSH identities, isolated scheduling domain, reviewed runner/reset helper generations, and expected-token invalidation proof. Never enable, create, approve, or dispatch autonomously. |

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

### Passbolt Migration Procedures

The `services.passbolt.export_secrets`, `services.passbolt.transfer_secrets`,
`services.passbolt.import_secrets`, and `services.passbolt.cleanup` procedures
are all `effect="destructive"` and `approval_required=True`. They are tools for
a one-time operator-run Passbolt CE migration and must never be created or
approved autonomously by an LLM agent. Agents must not ask for, fabricate,
print, log, or store real Passbolt DB contents, GPG/JWT material, or DB
passwords. The only permitted outputs are artifact paths, byte sizes, sha256
checksums, and migrate/healthcheck/cleanup status.

See [`docs/passbolt-migration-runbook.md`](docs/passbolt-migration-runbook.md)
for the operator command sequence. Use placeholder values in docs and tests.

### Staging Backend Token Rotation

`service.netbox.staging.rotate_backend_token` is a destructive,
approval-required recovery procedure for the staging backend's NetBox service
token. It targets only the existing, requester-viewable `nms-front-door`
`dcim.device` and accepts no caller parameters. The backend resolves the
device's enabled SSH service, credential reference, port, and strict pinned
known-host policy from managed inventory and invokes the fixed root-owned
provisioner. Token creation and installation stay entirely outside RPC params,
argv, results, events, and logs.

The result schema is closed and contains only `ok`, the constant procedure ID,
constant `target="nms-front-door"`, `rotated`, and `stage`. Exact states are:
success (`true/true/complete`), pre-commit failure
(`false/false/execute`), committed-but-recovery-failed
(`false/true/complete`), and post-dispatch uncertainty
(`false/null/indeterminate`). The nullable indeterminate state prevents
automation from treating a transport/timeout ambiguity as proof the old token
remains active and blindly retrying a destructive rotation. Operators and agents
must reconcile staging readiness before any new request. They must not attach raw
token values, upstream bodies, command output, or filesystem contents to the
execution. Approval is required even for recovery, and agents must never create
or approve this execution autonomously.

The envelope and nested result must use matching strict boolean `ok` values;
this privileged procedure accepts no backend progress events. Its approval
snapshot binds a concrete backend row and the non-secret backend URL/TLS
identity, plus the full transport/output/representative-command policy. A job
payload cannot override that destination after approval.

Creation records `ExecutionRequested` then `ApprovalRequested`, persists an
immutable non-secret approval snapshot, returns `pending_approval`, and does
not enqueue. It rejects backend/request/trace/comments/tags/custom-field
metadata (even empty values), and approval/rejection accept no caller reason;
fixed bounded phrases are the only durable decision messages. Both the execute and approve permissions must include this exact
procedure; an object permission constrained to some other procedure does not
grant access. The requester cannot approve their own request even if they hold
the approval permission. A distinct approver records an immutable
`approved_by` identity, then the same decision transaction records
`ExecutionApproved` and `ExecutionQueued`; only afterward is one RQ job
enqueued. The snapshot includes canonical hashes for the complete immutable
procedure policy, transport/output pipeline, representative command,
params/result schemas, and concrete backend URL/TLS identity. Admission,
approval, worker claim, and pre-lease validation require the exact enabled
name, handler, version, device target, destructive effect, 1800-second timeout,
approval bit, and schemas, as well as distinct non-null requester/approver identities. Those identities are exposed read-only
on the execution API and bound into the signed one-time dispatch lease.

Unlike ordinary procedures' backwards-compatible ID-only dispatch, this
procedure never falls back when dispatch-lease keys are absent or invalid.
`RPC_DISPATCH_LEASE_REQUIRED` is the expected fail-closed result until the root
deployment provisions coordinated issuer/verifier keys; the backend is not
called in that state.

### Production Gitea 1.27.1 Upgrade

`service.gitea.production.upgrade_1_27_1` is a disabled-by-default,
destructive, approval-required procedure for the exact production `Gitea`
`virtualization.virtualmachine` PK 170. It accepts no caller params. The server
normalizer validates VMID 222, cluster PK 6 / `PVE-CLUSTER-02`, node device PK
27 / `pve03`, primary IPv4 `10.0.30.96`, active status, and the production tag;
then it pins source 1.26.2, target 1.27.1, official artifact SHA-256
`86a7ac26e7f9c9cca0f56c4fac07fff205d5fc3bca0e54af23a204f07b833bc9`,
and the non-secret SSH policy reference
`target-owned-ssh:virtualization.virtualmachine:170` into normalized params and
the command fingerprint. It also resolves exactly one enabled target-owned
`netbox_network.DeviceService` in a single query and freezes its public
service/identity IDs and UTC revisions, principal/method, exact management
host/port, and pinned-known-host digest. Raw known-host and secret material are
never persisted. Callers cannot override any of these fields.

The Gitea capability hash extends the legacy command payload with
`gitea_upgrade_contract.SEMANTIC_CAPABILITY_EXTENSION`: static target/topology,
source/target/artifact, guest paths/unit/health URLs, handler/process budgets,
the exact Ed25519 host-pin parser, closed caller/normalized/fingerprint
schemas, all six result tuples, exact backend 1 at loopback URL
`http://127.0.0.1:16005` with TLS verification disabled, and versioned
length/SHA-256 identities for the exact 59,952-byte backend script and complete
63,492-byte canonical fixed argv. The public Nginx vhost is not a supported
dispatch path. The checked-in fixture is the byte-exact cross-repository
canonical JSON and digest. Never change or reserialize only one side. Other
handler capability hashes remain unchanged.

The exact target/fingerprint, complete immutable procedure/command/schema
policy, authoritative backend ID plus URL/TLS hash, SSH-policy
reference, and distinct actor identities are bound into the approval snapshot
and signed one-time dispatch lease. For Gitea only, the procedure-policy hash
also contains the canonical semantic-extension digest; executable-, backend-,
rollback-, or schema-only drift therefore invalidates requested, pending,
approved, and queued work before enqueue or lease issuance. The existing signed
lease `contract_hash` carries the same semantics; do not add a redundant caller
or lease field. No ID-only fallback is permitted. The
closed result has only `ok`, constant `procedure`, constant `target="Gitea"`,
`changed`, `healthy`, and `stage`, with six exact states documented in
[`docs/gitea-production-upgrade-1.27.1.md`](docs/gitea-production-upgrade-1.27.1.md).
Schema-valid false/indeterminate states remain on failed executions; malformed
results and all backend progress events fail closed. Capability and dispatch
redirects are forbidden. The catalog validates the exact five-key backend wire
envelope, discards backend `error_code`/`error_message`, and derives bounded
durable diagnostics only from the validated result tuple; remote diagnostic
text must never enter the event ledger or execution projection.

Migration `0073` seeds `enabled=False`. Ordered activation is backend gate and
exact capability first, then an explicit operator enables the catalog row.
For this procedure, an absent, unreachable, or malformed capability manifest is
not graceful: admission and the uncached worker pre-dispatch check both require
`COMPATIBLE`.
Rollback disables the catalog row first, reconciles in-flight work, then closes
the backend gate. Never create, approve, enable, or dispatch this production
procedure autonomously. Read-timeout, ambiguous HTTP, and non-JSON outcomes
after sending are persisted as the exact closed `indeterminate` tuple. A
post-dispatch indeterminate or committed unhealthy
state is not safe to retry until an operator reconciles the installed binary,
service/database health, and backup.

### Isolated Gitea Runner Registration

`service.gitea.runner.register` is a disabled-by-default, destructive,
two-person composite operation. The assigned object is exact runner VM PK 399;
the independently pinned token source is Gitea VM PK 170. The caller supplies
only `register` or `reconcile` plus one of eight reviewed scopes. Server
normalization and the signed lease
bind both target objects and separate target-owned SSH service/credential
identity snapshots. A canonical durable fence serializes aliases and blocks
retry after uncertainty. The backend verifies the exact native runner and
Gitea expected-token reset helpers, obtains the reusable token with fixed Gitea
argv, streams it only over bounded stdin, and attempts rotation before every
post-token return. No token, remote output, host override, label,
path, or command may enter params, fingerprints, argv, environment, events,
logs, or results.

Migrations `0080`/`0081`, the catalog code gate, and the backend configuration
gate all start dark. The operation depends on the deployed `netbox-network`
issue `#23` credential-identity response. Only a definitive pre-token failure or
an exact reset proof clears the fence; indeterminate outcomes require a fresh,
distinctly approved `reconcile` plus runner-list/local-state inspection before
retry. Reconciliation is not admitted from a fresh `pending` fence or before
the blocking execution's 360-second remote-quiescence interval has elapsed.
For stale `pending` recovery after that interval, reservation locks
the fence and original execution together, terminalizes a still-`running` lost
worker, moves the fence to `blocked`, and records the reconciliation owner in
the same transaction. Once it owns the fence, late original transitions are rejected.
Activation is forbidden while application repositories can schedule
`prod-deploy`, `mirror-host`, or equivalent privileged labels. Follow
[`docs/gitea-runner-registration.md`](docs/gitea-runner-registration.md) for the
closed states, deployment order, reset evidence, and rollback sequence. Agents
must never enable, create, approve, or dispatch it autonomously.

### Permission Invariant

Do not request or accept the `netbox_rpc.approve_rpcprocedure` permission unless
a human operator has explicitly granted it for a specific, bounded task. Holding
this permission satisfies the legacy single-actor gate for most
`approval_required` procedures — it must never be used autonomously on
destructive procedures. It does **not** bypass a protected procedure's
pending approval or distinct-actor check.

---

- Procedure records map canonical names to backend `handler_id` values.
- NetBox RQ jobs normalize params and delegate execution to the deployment's
  configured backend (`netbox-nms` adapter or first-class `RPCBackend`). Each
  run's core RQ job (`/core/jobs/<N>/`) links to the `RPCExecution` by `job_id`;
  the issued command(s), their output, and per-command timing are read from
  `RPCExecution.result.steps[]` and the event ledger. See
  [`docs/rpc-generated-core-jobs.md`](docs/rpc-generated-core-jobs.md).
- SSH credentials and host-key pinning live in `netbox-nms.DeviceService`.
  `RPCLinuxServiceAllowlist.ssh_credential_override` can point at a
  `netbox-nms.DeviceCredential` for per-service SSH key overrides; when set,
  `rpc_ssh_credential_pk` in `normalized_params` tells the configured backend to
  fetch that allowlist-owned credential by PK. This is not a general
  caller-supplied override; procedures such as Huawei NE8000 BGP explicitly
  forbid one and resolve only through their assigned device.
- Keep procedure names in the documented canonical dotted forms:
  `os.<family>.<distro>.<version>.<action>` and
  `network.device.<manufacturer>.<device-family>.<model>.<version>.<action>`.
- Ubuntu 24 systemd procedures currently include read procedures
  `os.linux.ubuntu.24.status_service` and `os.linux.ubuntu.24.journal_tail`,
  plus write procedures `os.linux.ubuntu.24.start_service`,
  `os.linux.ubuntu.24.stop_service`, `os.linux.ubuntu.24.reload_service`,
  `os.linux.ubuntu.24.enable_service`, `os.linux.ubuntu.24.disable_service`,
  and `os.linux.ubuntu.24.daemon_reload`.
- InfluxDB guest management uses the typed `service.influxdb.1.*` catalog seeded
  by migration `0055`, targeting `dcim.device` and
  `virtualization.virtualmachine`. It distinguishes `oss2` from `core3` and
  covers installation inspection, redacted/bounded config and file reads,
  confined file inventory, service state, health, journal reads, atomic config
  deployment/rollback, confined managed/plugin file writes/deletes, and
  enum-constrained service control. Every mutation requires approval;
  rollback/delete are destructive. Content travels outside argv and only its
  sha256/byte count enters the command fingerprint. Literal secret-shaped
  content, private keys, unsafe paths, and Core-only plugin scope on OSS 2 are
  rejected before persistence. The older generic allowlist row remains useful
  for compatibility, but new InfluxDB workflows must use this typed family.
- **Gitea Actions runner recovery** is seeded by migration `0073`, which adds all
  20 `gitea-act-runner-*.service` units to `RPCLinuxServiceAllowlist` so the
  generic Ubuntu-24 systemd procedures can control them. No new procedure or
  backend handler — these are reference data the existing `restart_service`
  normalizer and handler already consume.
  - **Why.** An `act_runner` executes with `maxParallel=1` — one job at a time,
    everything else queued behind it. If that job **hangs**, the process keeps
    heartbeating, so Gitea still reports the runner `online` with correct
    labels while no further job ever starts. Observed 2026-08-17 on
    `gitea-act-runner-nmc-netbox-rpc-backend`: claimed task 18865 at 17:04:59Z,
    logged nothing after 17:05:26Z, still holding its worker ~7 hours later with
    ten runs queued — including a `deploy-production.yml` for an already-merged
    `develop → main` promotion.
  - **Uptime is not the signal.** A sibling runner started in the same second was
    completing jobs normally. Diagnose from the journal: a runner holding a task
    while logging nothing for hours is hung; one emitting step output is working.
  - **Why it matters more than a crash.** A crashed runner is visibly down. A
    wedged one looks healthy, so a promotion merges, reports success, and never
    deploys: production keeps serving the previous build while the repository
    says otherwise. Before `0073` there was no audited way to restart one — the
    allowlist held only `netbox` and `netbox-rq` — and the estate rule is to
    extend the tooling rather than SSH to the host.
  - **Operational warning.** Restarting a runner **aborts any job it is
    currently executing**. Check `status_service` and the repository's
    queued/running runs before restarting one that may be mid-build.
  - **Do not restart a runner from a job running on it.** These runners are
    per-repository, so an Actions job that restarts its own runner kills its own
    execution, and the restart can be reported as a failed job even when it
    worked. Dispatch recovery with `nms rpc` against the runner **host**.
  - Slugs equal the unit basename (`gitea-act-runner-<repo>`), asserted by
    `tests/test_gitea_runner_service_allowlist_seed.py`, which also fails if the
    seeded set drifts from the runner **daemons** actually defined on disk.
  - **The drift check compares daemons, not every unit matching the glob.** The
    `gitea-act-runner-*` prefix is also used by maintenance units — currently
    `gitea-act-runner-recycle.service`, a `Type=oneshot` job driven by
    `gitea-act-runner-recycle.timer` that recycles idle-but-wedged runners. Those
    are the recovery mechanism, not a recoverable target, so they are deliberately
    **not** in the allowlist: `restart_service` on a one-shot is meaningless.
    `_is_runner_daemon()` classifies a unit by its `ExecStart` launching
    `gitea-runner … daemon` and not being `Type=oneshot`, and
    `EXPECTED_NON_DAEMON_UNITS` pins the exemption set exactly — so a **new**
    non-daemon unit fails the test and forces a deliberate decision rather than
    silently widening it. Adding a maintenance unit under this prefix therefore
    requires updating that set, not the seed migration.
- **Gitea Actions org CI runner provisioning** is seeded disabled by migration
  `0084` (depending on `0083`) as
  `service.gitea.actions_runner.provision_org_ci_runner`. It is a distinct
  protected two-person install/register/start/verify workflow for the two runner
  lanes on exact `Gitea-Runner` VM PK 416 (`10.0.30.241`), not a restart of an
  existing systemd unit. The
  closed `lane` enum freezes the name, ordered labels, image, executor, Compose
  directory, and trust posture. `untrusted-python312` uses the host executor,
  no Docker socket, `cap_drop: ALL`, no-new-privileges, and non-root `cirunner`;
  `general-ubuntu` uses Docker-executor labels and mounts the Docker socket only
  into the runner so jobs are socket-free sibling containers. The procedure
  requires `registration_token_secret_ref` as an `nms-secret:<uuid>`, rejects
  `rpc_ssh_*` routing overrides, freezes the Gitea origin and `N-MultiCloud`
  organization server-side, and resolves SSH only from the exact,
  requester-viewable assigned VM. A distinct approver, immutable approval
  snapshot, compatible capability, and signed one-time dispatch lease are
  mandatory. The hard gate `_GITEA_ORG_CI_RUNNER_AVAILABLE` must stay false until
  the paired `netbox-rpc-backend` handler and approved capability contract are
  deployed, then a forward migration may enable the row and open the gate. The
  complete frozen contract lives in
  [`docs/gitea-org-ci-runner-provision.md`](docs/gitea-org-ci-runner-provision.md).
- **Debian 13 InfluxDB 3 Core installation** is seeded by migrations `0071`
  (allowlist row) and `0072` (procedures). The `service.influxdb.1.*` family
  above manages an instance that already *exists*; these two stand one up, so a
  fresh Core 3 guest no longer requires an interactive SSH session. Both target
  `dcim.device` and `virtualization.virtualmachine`.
  - `os.linux.debian.13.preflight_influxdb3_core`
    (`os.linux_debian_13.preflight_influxdb3_core`, **read**, no approval, 60s)
    reports posture: `/etc/os-release` `ID`/`VERSION_ID`, dpkg architecture,
    systemd presence, whether `influxdb3-core` is installed/held and at which
    version, the managed-config marker, unit load/active/enabled state, the
    configured bind/node-id/data-dir, and TLS-material readability, plus a
    derived `ready` verdict and bounded `blockers[]`. It is deliberately **both**
    the pre-install gate and the post-install verification read — there is no
    separate `verify_*` procedure, because the operator installer's precondition
    block and its completion report read the same facts.
  - `os.linux.debian.13.install_influxdb3_core`
    (`os.linux_debian_13.install_influxdb3_core`, **write**,
    **`approval_required=True`**, 900s) is the audited installer:
    fingerprint-verified InfluxData repository key
    (`24C975CBA61A024EE1B631787C3D57159FC2F927`), pinned `influxdb3-core`
    install, managed `/etc/influxdb3/influxdb3-core.conf`, systemd drop-in,
    restart, readiness probe, and `apt-mark hold`. Optional params mirror the
    operator script's environment variables — `node_id`, `data_dir`, `http_bind`,
    `tls_cert`/`tls_key`, `enable_plugins`, `disable_telemetry`,
    `wal_flush_interval`, `log_filter`, `package_version`, `hold_package`,
    `upgrade_package`, `force_reconfigure`, `allow_plaintext_remote`. Its
    `result_schema` carries the installer's completion report (package/binary
    version, unit state, bind, node id, data dir, config path, plugins enabled,
    package held, `ready`, `stage`).

  **Neither procedure accepts the shared `rpc_ssh_*` connection overrides — this
  is deliberate and must not be "restored".** Unlike the agent-install, ookla, and
  nmap procedures, these two declare no `rpc_ssh_credential_pk`, `rpc_ssh_host`,
  `rpc_ssh_port`, `rpc_ssh_known_hosts_entry`, or
  `rpc_ssh_strict_host_key_checking`, and the normalizer rejects them explicitly
  (`RPC_PARAM_INVALID`, naming the offending keys) before the generic
  unknown-parameter check. The execution backend must resolve host, port,
  credential, and known-host policy from the execution's **assigned NetBox
  object** alone, exactly as
  `network.device.huawei.router.ne8000.f1a.show_bgp_peer` does. Reason: a
  caller-supplied `rpc_ssh_credential_pk` is not object-scoped against the
  requesting user (the open gap tracked in issue #203), so honouring one would let
  a requester use a credential they cannot view; and a caller-supplied
  `rpc_ssh_host` would move an approved installation off the audited target
  entirely. Because the installer is `approval_required=True`, both would be
  approved against one target and executed against another. Adding these params
  back requires #203 (or equivalent object-scoped authorization) to land first.

  **No credential, anywhere in this pair (hard invariant).** Neither
  `params_schema` declares a token, password, secret reference, or
  `generate_admin_token`-style flag, and neither `result_schema` returns one.
  The first administrative token is created and vaulted **only** by the
  pre-existing `service.influxdb.1.bootstrap` (`family="core3"`, migration
  `0056`), which stores the plaintext through the netbox-nms secret bridge and
  returns an `nms-secret:` reference. The sanctioned sequence is
  `preflight` → `install` → `service.influxdb.1.bootstrap`. Do not add token
  generation to the installer: one token contract per product family is the
  point, and `tests/test_influxdb3_debian13_procedures.py` asserts the absence
  of every secret-shaped key in params, results, and the normalized payload.

  **Normalizer invariants** (`_normalize_influxdb3_debian13_execution`): every
  value is re-validated in the pure domain, so a `params_schema` edit alone can
  never widen what reaches the backend. Every path parameter must be
  **canonical**: a segment equal to `.` or `..` is rejected, and the value must
  equal its own `posixpath.normpath()`. This is load-bearing, not cosmetic —
  `data_dir` is then compared against the forbidden roots `/home`, `/root`,
  `/run`, `/tmp`, `/var/tmp` (the packaged unit sandboxes those trees, so the
  service would not start), and a literal prefix comparison alone would let
  `/var/./tmp/influxdb3` or `/var/lib/../tmp/influxdb3` through while they resolve
  *inside* a forbidden root. Requiring canonical input rather than normalizing it
  also means the value that is stored, fingerprinted, approved, and executed is
  the same string the operator read. A dot **inside** a segment
  (`/etc/influxdb3/tls/server.crt`) stays legal. `tls_cert`/`tls_key` are
  both-or-neither absolute paths on *both* procedures. Unknown parameters are
  rejected here as well as by `additionalProperties: false`, tolerating the
  platform-stamped `_timeout_seconds_snapshot` key plus legacy `_intent` /
  `_intent_name` markers on historical executions. Most importantly the
  normalizer reproduces the installer's own security gate: **a remote
  `http_bind` with no TLS is refused** (`RPC_PARAM_INVALID`) unless the caller
  explicitly sets `allow_plaintext_remote=true`; an omitted `http_bind` is
  evaluated as the loopback default rather than left undefined. An
  out-of-family procedure name reaching this normalizer fails closed with
  `RPC_PROCEDURE_NOT_NORMALIZABLE` rather than inheriting the installer's
  parameter set. Every seed `pattern` is anchored with `(?![\s\S])`, not `$`,
  because `jsonschema` applies `pattern` via `re.search` and Python's `$` also
  matches before a single trailing newline.

  **Seeded `enabled=False` behind a three-point code gate.** No
  `os.linux_debian_13.*` handler exists in `netbox-rpc-backend` yet, so an enabled
  row would be advertised by `/procedures/available/` and every execution would
  queue only to fail on an unknown handler. Capability discovery does **not** cover
  this: a backend that advertises no manifest yields verification `UNKNOWN` and
  admission proceeds. `_INFLUXDB3_DEBIAN13_AVAILABLE = False` in
  `netbox_rpc.domain.normalization` is therefore checked through the shared
  `code_gate_unavailable_reason()` at all three enforcement points — admission
  (`create_execution()`), advertisement (`RPCProcedureViewSet.available()`), and
  worker claim (inside this normalizer) — so flipping the mutable
  `RPCProcedure.enabled` flag alone cannot make them dispatchable. Enable the gate
  and the flag **together**, in an *additive* migration, as part of the coordinated
  rollout that ships the handlers and their approved capability contract. Do not
  edit `0072`'s data defaults in place (Django tracks an applied migration by name,
  so an in-place edit silently skips databases that already ran it — the `0060`/
  `0061` lesson).

  **The assigned object is authorization-checked and pinned.** The requester
  chooses `assigned_object_id`, and these procedures derive their SSH target
  *exclusively* from it, so `create_execution()` resolves the exact device/VM
  through `model.objects.restrict(user, "view")` before the row is written —
  `_require_viewable_assigned_object()` in `command_handlers.py`, whose
  `_ASSIGNED_OBJECT_SCOPED_PROCEDURE_NAMES` set now covers both the Akvorado family
  and this one. (It was `_require_akvorado_assigned_object` before; the rename is
  the whole point — any family with no `rpc_ssh_*` escape hatch belongs in it.)
  Without that check a requester could aim an approval-gated installation at a
  device they cannot even view. The normalizer then **re-validates** the identity at
  worker claim and forwards `target_object = {content_type, object_id}`, with flat
  `target_content_type`/`target_object_id` scalars in the command fingerprint, so an
  approved run is pinned to the object that was approved. `target` remains an
  audit-only display value and must never be used for host resolution.

  **Result-schema invariants.** The installer's `result_schema` carries a closed
  `oneOf` envelope (same shape as
  `service.netbox.staging.rotate_backend_token`): a nested `ok=true` must also
  report `installed=true`, `ready=true`, and `stage="complete"`, and `installed`,
  `ready`, `stage`, and `package_held` are all **required**. On its own that is not
  enough, because a `result_schema` can only constrain the *nested* object while
  `event_store` selects `ExecutionSucceeded` from the **outer** response `ok` — so
  `record_backend_response()` additionally requires outer/nested `ok` agreement for
  this family via the shared `_envelope_ok_state_mismatch()` helper (extracted from
  the staging-rotation validator, which keeps its extra events prohibition). Both
  values must be strict booleans, so a truthy non-boolean cannot pass `bool()`
  coercion silently. Together these mean a response of `ok=true` wrapping a failed
  or partial install is rejected instead of recorded as a successful installation. A
  genuine failure stays fully representable through the `ok=false` branch, including
  a partial `stage` and a bounded `error`. Every result string additionally carries an
  explicit `maxLength` (or a closed `enum`/`const`), because `event_store` silently
  clamps unbounded strings at 4096 characters — an unbounded audit field would be
  truncated with no validation error, and an unbounded contract lets a malformed
  backend return an arbitrarily large valid result. `procedure` is a `const`, so a
  backend cannot relabel which procedure ran.

  **Reverse migration is non-destructive.** `0072`'s reverse is a single
  table-level `queryset.update(enabled=False)`; it never deletes. Two independent
  reasons, both recorded in the migration's own docstring: `RPCExecution.procedure`
  is `on_delete=PROTECT`, so deleting a procedure that has run raises
  `ProtectedError` and aborts the downgrade — and audited execution history must
  never be destroyed to allow one; and deleting through the historical model is
  unsafe *even when the row is unreferenced*, because the deletion collector walks
  related models and raises `ValueError` for a related app with no migrations
  (this actually failed the NetBox 4.5.8 compatibility job). An `except
  ProtectedError` guard catches only the first of those. See the historical-model
  rule under **CI / Testing**.

  Both handler IDs are `EXEMPT_HANDLER_RATIONALE` entries seeded with one
  representative `["backend-orchestrated", …]` command row each — key-fingerprint
  verification, `apt-cache madison` candidate resolution, and
  validate/write/restart/health/hold sequencing have no faithful fixed-argv
  form. Both procedures are also `_ASSIGNED_OBJECT_SCOPED_PROCEDURE_NAMES` and
  envelope-state-strict members, so adding a third procedure to this family means
  reviewing those three registries too, not just the seed migration.
  **Catalog-first: the matching `os.linux_debian_13.*` handler does not
  exist in `netbox-rpc-backend` yet** and lands separately, exactly as with the
  whole `service.influxdb.1.*` family and the Samba catalog. The paired
  `netbox-packer` profile `influxdb-core-3.11.0-debian-13` (VMID 9052) bakes the
  same production posture into a first-boot cloud-init template for new guests;
  this catalog is for hosts that already exist.
- Akvorado service management uses the typed `service.akvorado.1.*` catalog
  seeded by migration `0057`, targeting `dcim.device` and
  `virtualization.virtualmachine`. Four procedures: `config_read` (read, no
  approval, 30s) and `status_stack` (read, no approval, 60s) are queries;
  `config_deploy` (write, approval required, 120s) and `restart_stack` (write,
  approval required, 120s) are mutations. `config_deploy` accepts
  `config_content` as a structured `input_data` string payload (never
  argv-interpolated); only its sha256/byte count enters the command fingerprint.
  NUL/unsafe controls, inline secret material, credential URLs, and private keys
  are rejected before persistence/dispatch. The caller cannot provide a target
  host: every run requires an existing assigned NetBox device/VM and derives
  the backend target exclusively from that object. All four handler IDs are listed
  in `command_contract.EXEMPT_HANDLER_RATIONALE` (seeded with one
  `backend-orchestrated` representative command row each) because Akvorado
  config deployment is backend-orchestrated content handling, not fixed argv.
  This catalog is the *only* sanctioned way to read or change Akvorado config or
  stack lifecycle state — `netbox-observability`'s
  `AkvoradoIntegration`/`AkvoradoExporterProfile` models store non-secret
  metadata only and never perform config/lifecycle actions directly.
- InfluxDB service management is provided by the generic Ubuntu 24 systemd
  procedures through two seeded `RPCLinuxServiceAllowlist` rows, both targeting
  `dcim.device` and `virtualization.virtualmachine`:
  `slug="influxdb"` -> `systemd_unit="influxdb.service"` (**OSS 2**, migration
  `0053`) and `slug="influxdb3-core"` -> `systemd_unit="influxdb3-core.service"`
  (**Core 3**, migration `0071`). The two products ship different units, so pick
  the row that matches the family — the OSS 2 row cannot control a Core 3
  instance. Do not add InfluxDB-specific shell text; use the existing fixed
  systemctl handlers or add a new typed procedure if a future operation cannot be
  modeled as service lifecycle control.
- NetBox stack service management is provided the same way, through the allowlist
  rows seeded by migration `0058`: `slug="netbox"` -> `systemd_unit="netbox.service"`
  (WSGI/gunicorn) and `slug="netbox-rq"` -> `systemd_unit="netbox-rq.service"`
  (RQ background worker), both targeting `dcim.device` and
  `virtualization.virtualmachine`. Use the existing generic Ubuntu 24 systemd
  procedures (`os.linux.ubuntu.24.restart_service` / `status_service` /
  `journal_tail`, etc.) against a NetBox-host `dcim.device`/VM that carries a
  DeviceService SSH credential — never SSH the NetBox host directly.
  **Restarting `netbox-rq` also sweeps orphaned/zombie `core.Job` rows** left by a
  worker that died mid-job (its `job_timeout` never fires), so it is the audited
  recovery for a NetBox RQ job stuck in `running`. `restart_service` is
  `effect="write"`, no approval, but disruptive — present the action before
  dispatching per the write-procedure rule below.
- `os.linux_env_file.upsert_var` (migration `0059`/`0060`) upserts a
  credential-backed `KEY=VALUE` line into an allowlisted service's
  `environment_file`, then restarts its `systemd_unit`. `effect="write"`,
  `approval_required=True` — writes a credential to a production host file, so
  it is never dispatched autonomously. Params are `service_slug`, `var_name`
  (`^[A-Z][A-Z0-9_]*$`), and `credential_pk` (a `netbox_nms.DeviceCredential`
  reference); no raw secret value is ever accepted as a param, logged, or
  persisted to `RPCExecution`/`RPCExecutionEvent` — the backend resolves
  `credential_pk` and delivers the value over stdin, mirroring
  `install_ssh_key`'s stdin-delivery pattern. It is an `EXEMPT_HANDLER_RATIONALE`
  entry seeded with one `backend-orchestrated` command row, matching the Samba
  `user_create`/`user_set_password` pattern. Migration `0060` does **not** seed
  `environment_file` on the `netbox`/`netbox-rq` allowlist rows — confirm the
  real `EnvironmentFile=` path against the production systemd unit and set it
  via the `RPCLinuxServiceAllowlist` admin UI/API before dispatching this
  procedure against them; the normalizer fails closed with
  `RPC_LINUX_SERVICE_ENVIRONMENT_FILE_MISSING` while it is unset.
  `environment_file` must be an absolute path with no traversal or control
  characters — enforced both in `RPCLinuxServiceAllowlist.clean()` (model
  layer) and defensively re-checked in the normalizer (in case a row was
  written outside `full_clean()`). Migration `0060` seeds the procedure
  `enabled=False`: the paired nms-backend execution handler does not exist
  yet, and the caller-supplied `credential_pk` param is not yet
  object-scoped-authorization checked against the requesting user before
  the referenced `DeviceCredential`'s plaintext value is resolved — a
  pre-existing gap shared by every `*credential_pk` param in this plugin
  (`guest_credential_pk`, `restconf_credential_pk`, `rpc_ssh_credential_pk`),
  tracked in issue #203. **In addition to the `enabled=False` seed**,
  `_normalize_linux_env_file_upsert_execution()` carries a hard-coded
  module-level gate (`_LINUX_ENV_FILE_UPSERT_AVAILABLE = False` in
  `netbox_rpc.domain.normalization`) that unconditionally raises
  `RPCExecutionError(code="RPC_PROCEDURE_NOT_AVAILABLE")` before any
  allowlist or credential lookup — because `RPCProcedure.enabled` is ordinary
  mutable catalog data an operator could flip without knowing the
  authorization gap below is still open, this second gate enforces the same
  refusal in code. Do not flip either gate until the execution handler is
  deployed, #203 (or an equivalent scoped fix) has landed, **and** a third
  precondition: `run_execution()` resolves `RPCLinuxServiceAllowlist`
  (`environment_file`/`systemd_unit`/`target_models`/
  `ssh_credential_override_id`) at worker-claim time, not at the time an
  approver made their decision, so an approver can approve against one
  allowlist policy and have the worker execute against a different one an
  operator edited in between (`approval_required=True` on this procedure
  makes the gap concrete, not merely theoretical). Closing it needs the
  allowlist row snapshotted into the approval decision and re-validated for
  drift at claim time — the general mechanism for this is `#163`'s item 2
  ("persist a pending approval snapshot") and item 9 (post-approval,
  pre-dispatch invalidation on drift); `create_execution()` does not yet
  route `approval_required` executions through that snapshot workflow at all
  (it calls `RPCExecutionAggregate.queue()` directly — see
  `command_handlers.py`), so no procedure has this protection today. This
  procedure inherits that pre-existing gap; it is currently unreachable in
  practice because `_LINUX_ENV_FILE_UPSERT_AVAILABLE = False` prevents the
  allowlist lookup from running at all (see
  `test_upsert_var_gate_blocks_by_default`, which asserts the allowlist
  query is never made while the gate is closed), but the gate must stay
  closed until #163 lands for this class of procedure, not just until #203
  does. **Migration version-skew note:** `0060` originally shipped
  `enabled=True` and was edited in place to `enabled=False` in a later
  commit; because Django tracks an applied migration by name only, any
  database that already ran the original `0060` keeps the stale
  `enabled=True` default. Additive migration `0061` re-asserts
  `enabled=False` on the existing procedure row for exactly that case — do
  not fix a shipped migration's data defaults in place again; add a new
  additive migration instead. `0060`'s reverse migration deletes the
  procedure only via `procedures.delete()`; `RPCProcedureCommand.procedure`
  is `on_delete=CASCADE` so its command row is deleted automatically as part
  of the same cascade, and `RPCExecution.procedure` is
  `on_delete=PROTECT` so a `ProtectedError` is raised during collection,
  before any row is deleted — the procedure and its commands are never left
  in a partially-rolled-back state. **Three-layer gate enforcement:** the
  hard-coded code-level gate is checked through one shared function,
  `normalization.code_gate_unavailable_reason(procedure_name)`, at three
  points so they can never diverge — (1) admission time, in
  `command_handlers.create_execution()`, immediately after the
  `procedure.enabled` check, so a gated procedure can never even get an
  `RPCExecution` row created; (2) advertisement time, in
  `RPCProcedureViewSet.available()` (`/procedures/available/`), so a gated
  procedure never appears as dispatchable to a client; and (3) worker-claim
  time, inside `_normalize_linux_env_file_upsert_execution()`, retained as
  defense in depth for an `RPCExecution` row created by an older process
  before this gate existed (rolling deployment, mixed worker versions) or
  claimed by a worker running stale code. Round-4 adversarial review on PR
  #202 found the gate enforced only at layer (3); layers (1) and (2) close
  that gap so an operator flipping `RPCProcedure.enabled=True` — the only
  scenario in which the gap was reachable — cannot get an execution created
  or advertised while the code gate stays closed. Covered by
  `netbox_rpc/tests/test_linux_env_file_upsert_code_gate.py` (admission +
  advertisement, procedure forced `enabled=True`) alongside the existing
  `test_upsert_var_gate_blocks_by_default` (worker-claim layer).
- `netbox.plugin.install` (migrations `0082`/`0083`) installs an **allowlisted**
  NetBox plugin at an **exact** version on a managed NetBox host, registers it in
  `PLUGINS`, migrates, collects static, restarts the allowlisted services, health
  checks, and **restores the previous settings file if NetBox does not come
  back**. `effect="write"`, `approval_required=True`, 900s.

  It exists because nothing else could do this: `deploy-plugin` upgrades plugins
  already installed and already listed in `PLUGINS`, `restart_service` restarts
  one, and neither installs a distribution or runs a new app's migrations — so a
  first-time install was reachable only by SSH.

  **`RPCNetBoxPluginAllowlist` is what makes it safe.** Params are only
  `plugin_slug`, `version`, and optional `dry_run`; the row supplies the
  `distribution`, `module`, `venv_python`, `manage_py`, `settings_file`, and
  `service_slugs`. A caller-supplied distribution would be remote code execution
  with an audit trail attached — the string reaches `pip install`, which accepts
  URLs, paths, VCS references and options, and whatever it fetches is then
  imported by a NetBox restart. `version` is the one caller-supplied value that
  reaches pip and is constrained to an exact version, never a range, so the audit
  record names the precise artifact.

  Restart targets resolve through `RPCLinuxServiceAllowlist` (migration `0058`'s
  `netbox`/`netbox-rq` rows), not through unit names on the plugin row, so a unit
  this procedure can bounce is one an operator already approved for bouncing. A
  row listing no services is refused: installing without restarting leaves the
  plugin on disk and absent from the running process, which would report success
  and show no plugin.

  **It takes no `credential_pk`** — SSH resolves from the target device's own
  `DeviceService`, as `restart_service` does — so unlike
  `os.linux_env_file.upsert_var` it does **not** inherit #203. It does inherit
  #163's approval TOCTOU: an approver could approve against one
  `RPCNetBoxPluginAllowlist` row while the worker resolves a different one edited
  in between. That is recorded in the gate text.

  **Why the rollback is the point.** A plugin whose `min_version`/`max_version`
  window excludes the running NetBox does not degrade — NetBox refuses to start.
  Observed while testing `netbox-openbao` against 4.6: the container went from
  healthy to exited and stayed down until the entry was removed from `PLUGINS`.
  On production that is an outage whose fix requires editing the configuration of
  a host whose NetBox is already down. `dry_run=true` runs the version-window
  pre-flight and stops, turning that outage into a rejected request.

  **No `config` parameter, deliberately.** The settings file is Python and JSON
  is not a subset of it (`null`/`true`/`false` are not `None`/`True`/`False`), so
  writing caller-supplied JSON there either corrupts the file or needs a
  converter whose bugs are settings-file corruption on a production host. It is
  also unnecessary: a plugin with `required_settings = []` loads with no entry.

  Seeded `enabled=False` **and** hard-gated in code
  (`_NETBOX_PLUGIN_INSTALL_AVAILABLE = False`), enforced through
  `code_gate_unavailable_reason()` at admission, advertisement, and worker-claim
  time. Flip neither until the nms-backend handler is deployed and verified.
  Listed in `EXEMPT_HANDLER_RATIONALE` with one representative command row —
  the rollback alone has no fixed-argv form, since whether it runs depends on
  whether the health check passed.
- `network.device.huawei.router.ne8000.f1a.show_bgp_peer` (handler
  `network.huawei_ne8000_f1a.show_bgp_peer`, migration `0066`,
  `tests/test_huawei_ne8000_bgp_procedure.py`, and
  `tests/test_jobs_huawei_ne8000_bgp_normalization.py`) is a read-only BGP peer
  status fetch targeting `dcim.device`. `effect="read"`,
  `approval_required=False`, 45s timeout. Its strict normalizer derives
  `target` only from the assigned device (callers cannot override it), trims
  and validates optional `vrf` (default `""`; 1-31 safe characters when set;
  surrounding whitespace and control characters are rejected),
  rejects unknown params, and fingerprints the immutable `dcim.device` content
  type/object ID rather than treating its display name as authority. Credentials
  resolve only through that assigned device's `DeviceService`; caller-supplied
  credential overrides are forbidden. The matching specialized handler is
  planned for **`netbox-rpc-backend`**; `nms-backend automation/rpc` is
  retained reference/test code and is not the live executor. The separate
  nms-backend BGP feature owns NETCONF collection, SSH fallback orchestration,
  and netbox-bgp synchronization, not this procedure's RPC handler boundary.
  The migration remains deliberately **`enabled=False`**, with the same
  fail-closed code gate enforced at admission, advertisement, and worker claim,
  until the matching netbox-rpc-backend handler is deployed, its capability
  contract is approved, and the coordinated rollout is authorized. The dynamic
  multi-command workflow has one representative `device_cli` command row and a
  documented `EXEMPT_HANDLER_RATIONALE` entry. Do not enable the catalog row
  merely because the normalizer or retained nms-backend implementation exists.
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
- Passbolt CE migration procedures are seeded by migration `0048`. Four
  destructive, approval-gated procedures orchestrate a one-time migration from a
  source Docker deployment to an already-provisioned native VM using only
  runtime params and dedicated staging directories:
  - `services.passbolt.export_secrets` (destructive, 1800s, approval required):
    runs on the source Docker host, uses DB credential environment variable
    names from the DB container instead of a caller-supplied DB password, and
    creates `db.sql`, `gpg.tar`, and `jwt.tar` in `staging_dir`.
  - `services.passbolt.transfer_secrets` (destructive, 1800s, approval required):
    runs rsync from the source host to the target host and recomputes checksums
    on the target.
  - `services.passbolt.import_secrets` (destructive, 3600s, approval required):
    imports the DB dump on the target VM, extracts GPG/JWT archives to validated
    destination dirs, sets `www-data:www-data` ownership and locked-down
    permissions, then runs Passbolt migrate and healthcheck.
  - `services.passbolt.cleanup` (destructive, 300s, approval required): removes
    source and target staging directories after operator-confirmed success.
  Handler IDs equal procedure IDs. The normalizer and backend schemas validate
  every container, DB, env var, host, user, port, and path parameter; no real
  secret contents are accepted, returned, logged, or stored. Operator commands
  live in `docs/passbolt-migration-runbook.md`.
- Staging NetBox service-token recovery is seeded by migration `0068` as
  `service.netbox.staging.rotate_backend_token` (destructive, 1800s, approval
  required) for the `dcim.device` target. Its
  schema and normalizer reject every caller parameter, require the exact
  existing/viewable `nms-front-door` device, and expose only closed non-secret status
  metadata (`ok`, constant `procedure`, constant `target`, nullable `rotated`,
  and `execute`/`complete`/`indeterminate` `stage`). The indeterminate tuple is
  reserved for post-dispatch transport/timeout uncertainty and must not be
  treated as safe to retry. The backend owns the fixed root-only
  provisioner and target-owned SSH resolution; this catalog never transports
  the token itself.
  Creation rejects request/trace IDs, backend overrides, comments, tags,
  custom fields, and any other caller metadata outside the exact target plus
  empty-params shape. Approval/rejection bodies carry no operator note and use
  a fixed bounded audit reason. The exact enabled name/handler/version/target,
  destructive effect, 1800-second timeout, approval bit, and params/result
  schemas are enforced at admission, approval, worker claim, and pre-lease
  time. Canonical policy/schema hashes are protected by the immutable approval
  snapshot. Valid closed failure/indeterminate results remain on failed
  executions; malformed nested results are rejected and not projected. The
  reverse migration is non-destructive: it runs a table-level
  `queryset.update(enabled=False)` and never deletes, so it neither destroys
  audited history nor enters Django's deletion collector. It previously called
  `procedure.delete()` behind an `except ProtectedError` guard, which handled the
  PROTECT case but *not* the collector's `ValueError` (a `ValueError` is not a
  `ProtectedError`) — see the historical-model rule under **CI / Testing**.
- Production Gitea binary upgrade is seeded disabled by migration `0073` as
  `service.gitea.production.upgrade_1_27_1` (destructive, 1800s, approval
  required), targeting only `virtualization.virtualmachine` PK 170 (`Gitea`).
  Its exact empty params, six-state closed result, immutable VM/topology/version/
  artifact/credential fingerprint, concrete backend hash, two-person approval,
  mandatory signed lease, backend-event prohibition, activation ordering, and
  rollback rules are specified in
  [`docs/gitea-production-upgrade-1.27.1.md`](docs/gitea-production-upgrade-1.27.1.md).
  The representative command is backend-orchestrated because download,
  checksum, backup, service lifecycle, health, and rollback are one fixed
  transaction rather than one faithful argv. Migration `0073` is intentionally
  irreversible: its reverse raises before any catalog inspection or mutation,
  so operator replacement, rename, or references cannot produce a falsely
  unapplied migration with deleted, surviving, or orphaned rows. Removal or
  repair requires a reviewed forward migration with explicit ownership
  evidence.
- Gitea org CI runner provisioning is seeded disabled by migration `0084` as
  `service.gitea.actions_runner.provision_org_ci_runner` (write, 1800s,
  approval required), targeting only exact `virtualization.virtualmachine` PK
  416 (`Gitea-Runner`, `10.0.30.241`).
  Its required `lane` enum selects one of two fully frozen stacks:
  `untrusted-python312` has no Docker socket, drops all capabilities, enables
  no-new-privileges, and runs jobs as non-root `cirunner` with the host executor;
  `general-ubuntu` uses three Docker-executor Ubuntu labels and exposes the
  Docker socket only to the runner, never its sibling job containers. Callers
  cannot provide names, labels, images, directories, executors, or posture.
  The one-time registration credential is accepted only through
  `registration_token_secret_ref`; caller-supplied SSH routing is rejected. Its
  reverse is non-destructive: disable only, never delete. Keep it gated until
  the paired backend handler is deployed. Contract:
  [`docs/gitea-org-ci-runner-provision.md`](docs/gitea-org-ci-runner-provision.md).
- Samba file-server **read** procedures (`service.samba.1.*`) are seeded by
  migration `0049` (command rows in `0050`). Samba config write/lifecycle
  procedures are seeded by migration `0051` (command rows in `0052`). The twelve
  read procedures are `effect="read"`, `approval_required=False`, and target
  `["netbox_fileserver.sambadomain", "virtualization.virtualmachine", "dcim.device"]`.
  They are the observability half of the Samba catalog and drive the
  `netbox-fileserver` observed-state sync. Handler IDs are the procedure name with `samba.1` →
  `samba_1` (e.g. `service.samba_1.config_read`); the handlers live in
  nms-backend.
  - `config_read` (30s) — `/etc/samba/smb.conf` content + sha256.
  - `config_test` (30s) — `testparm -s` validation of the running config.
  - `config_list_files` (60s) — enumerates `/etc/samba/**/*.conf` with size,
    mtime, and per-file sha256. **Exempt** (backend-owned recursive walk + stat
    + hash loop).
  - `include_file_read` (30s) — reads ONE include file. Required `include_path`.
  - `service_status` (30s) — active/sub/unit-file state for `smbd`, `nmbd`,
    `winbind`, `samba-ad-dc`.
  - `version` (30s) — `smbd -V`.
  - `list_shares` (30s) — effective share definitions.
  - `status_report` (30s) — `smbstatus --json`; `output_parser="json"`. Its
    `output_schema` describes the **raw** Samba document: per
    `source3/utils/status.c`, sections are emitted via `add_section_to_json()` →
    `json_new_object()`, so `sessions`/`tcons`/`open_files`/`byte_range_locks`/
    `notifies` are **objects keyed by id, not arrays**, and there is **no
    top-level `locks` key** (`--locks` is a CLI flag). Sections are
    flag-dependent, so none are required. The `result_schema` is the handler's
    own envelope and flattens each section into an array.
  - `domain_info` (60s) — `samba-tool domain info` + `domain level show`.
  - `user_list` (60s) — directory usernames/SIDs/enabled state only.
  - `group_list` (90s) — groups + members. **Exempt** (per-group member
    expansion depends on prior command output).
  - `share_acl_read` (30s) — `sharesec --view`. Required `share_name`.
  - `config_deploy` (120s, write) — writes `config_content` via stdin to a
    temp candidate, runs `testparm` against the candidate, snapshots the
    previous config, then activates + reloads. On any failure after the snapshot
    is taken (activation, reload, timeout, or lost response), the backend must
    restore the snapshot, re-validate and reload the restored config, and report
    `stage`, `snapshot_id`, `activated`, `reloaded`, `rolled_back`, and
    nullable `rollback_error`. **Never write smb.conf directly and validate
    afterwards. Exempt** (stdin + validate/snapshot/activate/rollback
    orchestration).
  - `config_rollback` (60s, destructive, **approval required**) — restores a
    backend-issued config snapshot and reloads, reporting lifecycle and
    rollback-outcome fields where applicable. **Exempt**.
  - `include_file_write` (60s, write) — writes one confined include file via
    stdin, validates the full config, and activates atomically. Required
    `include_path`, `content`. **Exempt**.
  - `include_file_delete` (60s, destructive, **approval required**) — deletes
    one confined include file with validation/rollback guardrails. **Exempt**.
  - `share_upsert` (60s, write) — creates/updates one share from structured
    fields only (`share_name`, `path`, booleans, principal lists, masks,
    comment); no arbitrary Samba option map. **Exempt**.
  - `share_delete` (60s, destructive, **approval required**) — deletes one safe
    share definition with validation/rollback guardrails. **Exempt**.
  - `service_control` (30s, write) — fixed argv `systemctl` action. `unit` enum
    is `smbd`/`nmbd`/`winbind`/`samba-ad-dc`; `action` enum is
    `start`/`stop`/`restart`/`reload`. No `RPCLinuxServiceAllowlist` rows.

  **Security invariants.** Every procedure accepts the shared optional
  `rpc_ssh_*` connection overrides; beyond those, caller-supplied values are
  confined in *both* the `params_schema` and the normalizer, so pure-domain paths
  fail closed before nms-backend repeats the checks. Reuse
  `_normalize_samba_include_path` for write/delete include paths; it confines
  `.conf` paths under `/etc/samba` and returns the **resolved absolute path**.
  Reuse `_normalize_samba_share_name` for share names; it starts with a safe
  alphanumeric/underscore character so it can never be read as an option. Config
  bodies (`config_content`, include `content`) must never become argv; the
  normalizer forwards content for backend stdin use and fingerprints sha256 +
  byte count metadata. Before persistence/dispatch it scans every assignment's
  smb.conf parameter name case-insensitively and whitespace-insensitively,
  rejecting any name ending in `script`, `command`, or `action`, plus the
  `preexec`/`postexec` family (`root preexec` runs as root). `include`
  directives inside caller-supplied bodies must resolve under `/etc/samba`;
  `include = registry` and unconfined paths such as `/tmp/evil.conf` are
  rejected. The scan first joins smb.conf line-continuations (a physical line ending in `\\`, per Samba's `lib/util/tini.c`) into one logical line before splitting the parameter name, so a directive cannot be smuggled past the denylist by splitting its name across a backslash continuation (`root pree\\` / `xec = ...`). The seed patterns anchor with `(?![\s\S])` rather than `$` because
  `jsonschema` enforces `pattern` via `re.search`, and Python's `$` matches
  before a single trailing newline. The `user_list` and `domain_info`
  `result_schema`s contain no password/hash fields (asserted in
  `tests/test_jobs_samba_normalization.py`).
- Samba/AD **identity management** procedures (#160) are seeded by migration
  `0055` (command rows in `0056`). Nine procedures complete the Samba catalog
  with user/group create/delete/enable/disable/password/membership actions,
  all targeting `["netbox_fileserver.sambadomain", "virtualization.virtualmachine", "dcim.device"]`
  like the rest of the Samba catalog. Handler IDs follow the same
  `samba.1` → `samba_1` mapping (e.g. `service.samba_1.user_create`).
  - `user_create` (write, 60s, no approval) — creates a Samba/AD user.
    Required `username`, `password`; optional `full_name`, `disabled`.
  - `user_delete` (**destructive, 60s, approval required**) — deletes a user
    by `username`.
  - `user_set_password` (write, 60s, no approval) — resets a user's password.
    Required `username`, `password`.
  - `user_enable` / `user_disable` (write, 30s, no approval) — enable/disable
    a user account by `username`.
  - `group_create` (write, 60s, no approval) — creates a group. Required
    `group_name`.
  - `group_delete` (**destructive, 60s, approval required**) — deletes a
    group by `group_name`.
  - `group_add_members` / `group_remove_members` (write, 60s, no approval) —
    add/remove one or more users from a group. Required `group_name`,
    `members` (1–128 unique identifiers).

  **Password handling (hard security invariant).** `user_create` and
  `user_set_password` are the only two procedures in the whole netbox-rpc
  catalog whose `params_schema` declares a `password` property. The raw
  password is **never** represented as an argv token and **never** persisted
  anywhere in netbox-rpc:
  1. It travels to `samba-tool` over **stdin only** — both handlers are
     backend-orchestrated `EXEMPT_HANDLER_RATIONALE` entries in
     `netbox_rpc.command_contract` (seeded with one representative
     `backend-orchestrated` command row each in migration `0056`), because a
     stdin-secret delivery has no faithful fixed-argv representation.
  2. At execution-**creation** time (`command_handlers.create_execution()`),
     immediately after `params_schema` validation and before
     `serializer.save()`, `_scrub_password_param()` pops `password` from the
     in-place `params` dict and replaces it with `password_sha256`
     (`hashlib.sha256`) and `password_bytes` (byte length) — so the
     `RPCExecution` row is never written to the database with the plaintext
     value, not even transiently. `_PASSWORD_BEARING_HANDLER_IDS` in
     `command_handlers.py` is the single source of truth for which two
     handler IDs this applies to.
  3. The async normalizer (`_extract_samba_password_fingerprint()` in
     `netbox_rpc.domain.normalization`) never receives, reads, or forwards a
     raw password — it only reads and forwards the pre-computed
     `password_sha256`/`password_bytes` fingerprint fields, and defensively
     rejects a malformed or missing fingerprint (`RPC_PARAM_INVALID`) rather
     than falling back to any raw value.
  4. `tests/test_jobs_samba_normalization.py` proves the normalizer never
     leaks a password even if one is still present in `params` (belt and
     suspenders), and `netbox_rpc/tests/test_samba_identity_password_redaction.py`
     proves the same end to end against a real DB row: the persisted `params`,
     the post-run `normalized_params`, and every `RPCExecutionEvent.data`
     contain only the fingerprint, never the plaintext.

  **Backend implementation is a deliberately separate, not-yet-shipped step
  (catalog-first convention).** Like every prior Samba procedure (migrations
  `0049`–`0052`) and every `EXEMPT_HANDLER_RATIONALE` entry, `netbox-rpc` seeds
  the audited catalog first; the matching `service.samba_1.*` `@rpc_handler`
  lands separately in the execution backend and is **not part of this change**
  (no `samba` handler exists in `netbox-rpc-backend`/`nms-backend` yet). A direct
  consequence of the invariant above: because the scrub replaces the plaintext
  with an **irreversible** `password_sha256`, the fingerprint that reaches the
  backend (via the pull-side execution fetch) can confirm *which* password was
  requested but can never reconstruct it. Secure plaintext delivery to
  `samba-tool` stdin for `user_create`/`user_set_password` therefore requires a
  **separate operator-driven secure channel in the backend handler** (never
  netbox-rpc's stored params/events) — designing that channel is the paired
  backend follow-up, tracked outside #160. Until it ships, these two procedures
  are catalog/audit-only.

  Usernames, group names, and member-list entries are validated in *both* the
  `params_schema` (migration `0055`) and the normalizer
  (`_normalize_samba_username` / `_normalize_samba_group_name` /
  `_normalize_samba_member_list`) with a charset-confined, safe-first-character
  pattern, so a value can never be read as a `samba-tool` option or shell
  metacharacter.

  **`fileserver.samba.collect_state` / `fileserver.samba.deploy_config`
  (#160, migration `0057`)** are two `RPCIntent` rows grouping the pre-existing
  Samba read/write catalog above — `collect_state` (`execution_mode="parallel"`)
  groups the nine read procedures (`version`, `service_status`, `config_read`,
  `config_test`, `list_shares`, `status_report`, `user_list`, `group_list`,
  `domain_info`); `deploy_config` (`execution_mode="sequential"`) chains
  `config_test` → `config_deploy` → `service_control` → `service_status`. Both
  are declarative reference data only — no executor was added; running one goes
  through the existing `execute_intent()` (#130) fan-out, which re-applies
  every gate per child. See [`docs/intents.md`](docs/intents.md) → "Seeded
  intents" for the full contract. The nine identity procedures above are
  deliberately not grouped into either intent.
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
- Ubuntu 24.04 to 26.04 LTS upgrade lifecycle procedures are seeded by
  migrations `0063` (procedures) and `0064` (commands), with the ordered
  `Update Ubuntu OS from 24 LTS to 26 LTS` intent seeded by migration `0065`.
  Migration `0066` (issue #215) patches `run_upgrade`'s `result_schema` in
  place to give `upgrade_log_tail` an explicit `maxLength` of 65536 —
  without it, `event_store.py`'s 4096-char default silently clamped the log
  tail with no validation error. Round 2 of #215's adversarial review found
  that adding the bound alone would have created a worse failure mode: a
  backend returning even a few bytes more than 65536 chars would fail
  `_backend_result_schema_mismatch()` against the *raw* result and land the
  execution in `FAILED`/`RPC_RESULT_SCHEMA_MISMATCH` instead of clamping —
  turning an otherwise successful, possibly destructive, already-completed
  upgrade into a reported failure that could prompt an operator to re-run it
  unnecessarily. Round 2 first closed that gap by validating a length-clamped
  *copy* of the result, but round 3 of #215's adversarial review found that
  clamping-before-validating could itself hide a genuine schema violation that
  only appeared in the truncated tail, and could persist a value
  (`content[:max_length] + marker`) longer than the schema's own `maxLength`.
  `event_store.record_backend_response()` now instead validates the complete,
  untouched raw result against a deep-copied schema with `maxLength` stripped
  only at the specific paths `_collect_schema_string_limits()` already
  registers as deliberately-widened above the 4096-char default
  (`_relax_schema_string_lengths()` / `_strip_max_length_at_paths()`) — every
  other validator (`pattern`/`enum`/`type`/`required`/...) still runs at full
  fidelity everywhere else in the schema. The persisted/redacted result is
  separately clamped to fit the schema bound by `_result_schema_string_limits()`,
  which now reserves `len("...[truncated]")` bytes of headroom out of each
  schema-declared `maxLength` so a truncated value can never itself exceed the
  bound it was validated against. An oversized `upgrade_log_tail` is safely
  truncated — with the standard `"...[truncated]"` marker on the persisted
  result, same as any other wide-override result string — and the execution
  still succeeds; validated-vs-persisted can never disagree about whether a
  wide field is oversized. The `run_upgrade` backend handler (issue
  nms-backend#623) SHOULD still cap the tail it returns well below that bound
  (e.g. ~32KB) as a matter of efficiency, not correctness — netbox-rpc no
  longer relies on the schema ceiling as the actual truncation point.
  **Round 3's own adversarial review (a further, final follow-up round on
  the same branch) found one more gap in this mechanism**: validating the
  raw, untouched result against the relaxed schema only proves the *raw*
  value is schema-valid — it says nothing about the *persisted* (redacted +
  truncated) value that `redact_event_data()` actually produces and that
  gets stored on `ExecutionSucceeded`. A field can carry both a wide
  `maxLength` override *and* a `pattern` (or other non-length constraint);
  a raw value can satisfy `pattern` while oversized, yet the persisted
  `content[:limit] + "...[truncated]"` copy can violate that same `pattern`
  because the marker's characters aren't necessarily in the pattern's
  allowed set — recording `ExecutionSucceeded` in that case would store a
  value that fails the schema it claims to satisfy. `record_backend_response()`
  now runs a **second** validation pass, after the first (relaxed-schema,
  raw-value) pass succeeds: it validates the already-redacted/truncated
  `result` object against the real, unrelaxed schema
  (`_backend_result_schema_mismatch(execution, result)`, no `string_limits`
  override). Because `_result_schema_string_limits()` already reserves
  marker headroom, this second pass never fails purely on length — it only
  re-checks `pattern`/`enum`/`type`/`required`/... against what will
  actually be written to the database. Not currently reachable in
  production (no seeded `result_schema` combines a wide-override
  `maxLength` with a `pattern` on the same field — `upgrade_log_tail` itself
  has no `pattern`), but this is shared, general-purpose infrastructure any
  future wide-override field could hit, so the fix is unconditional rather
  than scoped to `run_upgrade`. Regression coverage:
  `tests/test_event_store_result_validation.py::test_truncation_introduced_pattern_violation_fails_closed`.
  All four target `dcim.device` and `virtualization.virtualmachine`; handler IDs
  equal procedure names:
  - `os.linux.ubuntu.24.upgrade_26.analyze_preupgrade` is read-only and not
    approval-gated. Its ten fixed `shell_argv` rows inspect release/kernel,
    root disk, held packages, third-party APT source filenames, upgrader
    presence, pending reboot state, crontab, and active sessions.
  - `os.linux.ubuntu.24.upgrade_26.save_preupgrade_state` is an additive write
    and not approval-gated. It is command-contract exempt because timestamped
    directory creation and manifest assembly across APT sources, package
    selections, holds, and analysis state are backend-orchestrated; its sole
    command row is representative. An optional `backup_dir` is confined to the
    absolute-path safe charset.
  - `os.linux.ubuntu.24.upgrade_26.run_upgrade` is destructive and
    `approval_required=True`. It is exempt because long-running
    `do-release-upgrade`, conditional rebooting, and safety gates cannot be
    faithfully represented by one fixed argv. The normalizer, not JSON Schema
    defaults alone, makes omitted `dry_run` effectively `true` and omitted
    `reboot_after_upgrade` effectively `false`. Its `timeout_seconds=7200` is
    the motivating case for issue #215's job-timeout fix: `create_execution()`
    now derives the RQ `job_timeout` from `procedure.timeout_seconds` (plus
    headroom, floored at the historical 600s) via
    `command_handlers._execution_job_timeout()`, instead of the flat
    `RPC_JOB_TIMEOUT = 600` constant `RPCExecutionJob.enqueue()` used to fall
    back to unconditionally. A real (non-dry-run) `run_upgrade` can now hold
    an RQ worker for up to ~2 hours instead of being killed at 10 minutes —
    size `netbox-rq` worker concurrency on the NetBox host accordingly if
    Ubuntu upgrades run alongside other long procedures
    (`qemu_vm_lifecycle`, Passbolt import/rotate). Round 2 of #215's
    adversarial review found that `jobs._call_backend()` re-read the
    procedure's *current* `timeout_seconds` for its own HTTP read timeout,
    so an operator editing `timeout_seconds` while an execution sat queued
    could desync the already-committed RQ deadline from the later HTTP
    timeout. `create_execution()` stamps the frozen value into
    `execution.params[RPCExecution.TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY]`
    strictly *after* `params_schema` validation (a `params_schema` may declare
    `additionalProperties: false`, so the key can't be present before
    validation) but, as of round 3, *before* `serializer.save()` — folded into
    the same local `params` dict the password scrub already mutates in place,
    so the stamp and the execution row commit together in the single
    `transaction.atomic()` block, rather than via a second, unguarded
    `execution.save(update_fields=["params"])` call outside both that
    transaction and the RQ-enqueue `try`/`except` (round 2's approach), which
    risked leaving an orphaned `queued` execution with no job and no failure
    event if that second write failed. Both `_execution_job_timeout()` (takes
    a raw seconds value, not a procedure object) and `jobs._call_backend()`
    read that same frozen snapshot, falling back to the live
    `procedure.timeout_seconds` only for executions created before this fix
    shipped. **Round 3's own adversarial review** found the prior
    `test_timeout_snapshot_keeps_rq_and_http_timeouts_consistent_after_edit`
    coverage only asserted the final stored snapshot value — a value the
    round-2 broken implementation (a second, unguarded post-commit
    `execution.save(update_fields=["params"])`) would also have produced, so
    it didn't actually distinguish the atomic fix from the shape it
    replaced. Two follow-up tests in
    `netbox_rpc/tests/test_ubuntu_upgrade_26_execution.py` close that gap:
    `test_timeout_snapshot_is_visible_in_validated_data_before_serializer_save`
    spies on `RPCExecutionSerializer.save` and asserts the snapshot is
    already present in `self.validated_data["params"]` at the moment
    `save()` is called (not written afterward), including with a falsy
    (`{}`) caller-supplied `params` — the exact case the
    `.get("params") or {}` aliasing bug affected; and
    `test_no_standalone_params_only_save_follows_execution_creation` spies
    on every `RPCExecution.save()` call made during `create_execution()` and
    asserts none of them is isolated to `update_fields=["params"]` — the
    literal signature of the round-2 second write. Both tests fail against
    the round-2 implementation and pass only under the round-3 atomic fix.
  - `os.linux.ubuntu.24.upgrade_26.verify_postupgrade` is read-only and not
    approval-gated. Its six fixed argv rows inspect release/kernel, APT and
    dpkg health, held packages, and pending reboot state; optional
    `expected_version_id` is a bounded free-form comparison value.

  The fixed analyze/verify rows contain only `SAFE_TOKEN_RE` tokens and never
  shell strings. The v1 intent action does not serialize RQ execution; operators
  must run and gate each procedure individually using
  `docs/ubuntu-24-to-26-upgrade-runbook.md`.
- `nmap-scan` is seeded by migration `0045` as a **read-only**
  (`effect="read"`, `approval_required=False`, 120s) SSH-backed diagnostic
  procedure. Handler ID: `os.linux.nmap.scan`. It targets
  `ipam.ipaddress`, `dcim.device`, and `virtualization.virtualmachine`, accepts
  a required scan `target` plus optional `ports`, `scan_type`
  (`connect`/`syn`/`os-detect`), and the shared `rpc_ssh_*` overrides. Its
  normalizer (`_normalize_nmap_execution`) rejects every target that is not an
  IPv4 address, strict IPv4 CIDR, or strict DNS hostname, and canonicalizes
  bounded port selectors before nms-backend constructs fixed argv
  (`nmap -oX - ...`). It must never accept arbitrary shell command text.
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

> **The pure-domain tier is blind to every database constraint.** Seed-migration tests
> here drive fake managers (plain dicts), so they enforce no column width, no NOT NULL,
> no uniqueness, and no FK integrity. A seeded value that violates one passes locally
> and fails only when a real database applies the migration — which means CI at best,
> and the production deploy at worst, since the plugin auto-deploys on merge to `main`
> and runs migrations via `ExecStartPre`. This is not theoretical: a 291-character
> seeded `description` shipped through a green pure-domain suite and failed the
> DB-backed compatibility job with
> `DataError: value too long for type character varying(255)`. When adding a seed,
> assert field lengths against the model explicitly (see
> `tests/test_influxdb3_debian13_procedures.py::test_seeded_descriptions_fit_the_model_column`,
> which reads `max_length` out of `models.py`).
>
> **Never delete through a historical model in a data migration.** `Model.delete()` and
> `QuerySet.delete()` both run Django's deletion collector, which walks related models —
> and a related model whose app has no migrations is rendered from the *real* app
> registry rather than from the migration state. The collector then filters that real
> model by a historical instance and Django raises
> `ValueError: Cannot query "<Model> object (N)": Must be "<Model>" instance`. This
> failed the NetBox 4.5.8 compatibility job, which migrates backwards past a seed with
> its rows present. Prefer `queryset.update(enabled=False)` in a reverse: it touches one
> table, never invokes the collector, and never destroys audited history.

Two tiers (see `docs/architecture.md` → Testing):

1. **Pure-domain unit tests** (`tests/`, `pytest`) — stub Django/NetBox, no
   database. `.gitea/workflows/ci.yml` runs `py_compile` + `pytest tests/ -q` on
   the sole scalar runner label `ci-untrusted-python312`; it must queue rather
   than fall back to a mirror, production-deploy, generic self-hosted, or hosted
   runner when that label is unavailable. Checkout is pinned by full action SHA,
   uses the triggering commit SHA, and does not persist credentials. The runner
   must pre-provision exact CPython 3.12.14 at `/usr/local/bin/python3.12` and
   uv 0.12.5 at `/usr/local/bin/uv`; the workflow verifies those fixed
   executables and never selects them through ambient `PATH`, downloads, or
   bootstraps a toolchain. Dependencies, including the exact build backend used
   by the wheel regression, come only
   from `.gitea/ci-requirements.lock`, the canonical CPython 3.12 / x86_64 glibc
   2.34 wheel closure, installed with hashes, wheel-only resolution, an empty
   inherited environment, no uv config/project sources/cache, and
   `UV_PYTHON_DOWNLOADS=never`. Syntax and tests likewise run through `env -i`
   with Python isolated mode (`-I`) and user-site disabled. Pytest runs with a
   reviewed, hashed `.gitea/pytest-ci.ini`, empty `PYTEST_ADDOPTS`, disabled
   plugin autoload, and only the explicitly loaded locked `pytest-asyncio`
   plugin, so ambient/candidate Python paths, plugins, or project options cannot
   turn execution into a collect-only or deselected false green.
   `tests/test_ci_workflow_security.py`
   parses YAML with duplicate/alias/flow constructs rejected and mutation-tests
   the complete fail-closed contract. `tests/test_deploy_manifest_contract.py`
   checks the canonical generated files, builds the wheel with that locked
   backend, and requires the manifest's migration/static paths and SHA-256
   digests to equal the exact archive; its hostile stale-manifest mutation must
   fail. Renew this gate whenever a migration or static file changes.
   Provisioning the dedicated runner is an
   external workspace prerequisite; an offline runner means ordinary CI remains
   queued, not rerouted. These candidate-side files are defense in depth, not
   runner authority: the Gitea repository/organization runner policy must make
   mirror and production-capable runners ineligible for pull-request jobs and
   allow this workflow to match only the isolated label. Ordinary CI remains
   blocked/queued until that trusted platform policy is proven. The portable
   `.github/workflows/test.yml` `unit` job mirrors the test scope. Cover the
   domain logic (projection fold/rebuild, typed events, aggregate invariants,
   value objects, queries, normalization). Add new domain/CQRS logic here. Use
   `monkeypatch`/`SimpleNamespace` stubs as in
   `tests/test_jobs_systemd_normalization.py`.

2. **DB-backed integration tests** (`netbox_rpc/tests/`, `manage.py test
   netbox_rpc`) — a real NetBox + PostgreSQL test database. Cover `event_store`,
   the rebuild oracle, the append-only ledger, the command handlers, and the
   command-only REST API. The required canonical Gitea pull-request gate needs
   an externally provisioned isolated untrusted runner, disposable digest-pinned
   PostgreSQL/Redis, and an exact hash-locked NetBox 4.5.8/4.6.5 dependency
   closure; it remains blocked until that trusted platform contract exists.
   The GitHub `.github/workflows/test.yml` matrix is supplementary post-mirror
   evidence, not canonical pre-merge evidence. The privileged
   `.gitea/workflows/integration.yml` is an operator-requested,
   canonical-`main`-only, manual non-gating diagnostic: it must never gain a
   PR/push trigger or count as branch-protection evidence. Its candidate-visible
   ref guard is defense in depth; trusted Gitea runner/ref eligibility remains
   authoritative.
   Config: `tests/ci/netbox_configuration.py`.

   **The Gitea integration workflow must stay serialised on a repo-wide
   concurrency group, and must not double-trigger.** Its compatibility matrix
   provisions **fixed-name** databases (`test_netbox_compat_458` / `_465`) and
   **fixed** Redis DB indexes on the runner host, so the contended resource is
   the *host*, not the ref. Two mistakes to avoid, both of which were live
   defects:
   - Keying `concurrency.group` on `github.ref`. A branch push
     (`refs/heads/<branch>`) and its pull request (`refs/pull/<n>/head`) are
     different refs, so they landed in different groups, never cancelled each
     other, and raced — `database "test_netbox_compat_458" is being accessed by
     other users`, then `already exists`. Pull-ref runs passed **1 time in 8**
     while `main` stayed green, because a `main` push has no paired PR ref.
   - Leaving `on: push` unscoped, which triggered that second run in the first
     place. `push` is restricted to `main`; `pull_request` already covers every
     branch, on the ref a reviewer actually gates on.

   `cancel-in-progress` is deliberately **false**: this is a gate, not a
   preview, so a newer run waits its turn instead of killing a `main` gate that
   is mid-flight. If the matrix is ever given run-scoped database names and
   Redis indexes, the serialisation can be relaxed — not before.

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

## OpenBao Procedure Catalogue (`service.openbao.1.*`)

Twenty-two OpenBao procedures are seeded (migrations `0077` allowlist, `0078`
procedures + command rows), targeting **`dcim.device` only**. The paired
backend's strict OpenBao credential lookup currently rejects VM identities;
`virtualization.virtualmachine` must not be advertised until the backend has an
equivalent identity-checked VM credential resolver. Their handlers live in `netbox-rpc-backend`
(`rpc/openbao_handlers.py`), registered as `service.openbao_1.<op>` — the usual
dotted-catalogue-name / underscored-handler-id convention.

The seeded subset is ten reads (`inspect`, `seal_status`, `health`,
`policies_list`, `auth_list`, `secrets_list`, `audit_list`, `raft_list_peers`,
`raft_autopilot_state`, `snapshots_list`), five writes (`auth_enable`,
`secrets_enable`, `audit_enable`, `snapshot_create`, `service_action`), and
seven destructive procedures (`seal`, `step_down`, `raft_remove_peer`,
`policy_delete`, `auth_disable`, `secrets_disable`, `audit_disable`).

Migration `0077` also adds an `RPCLinuxServiceAllowlist` row
(`openbao` → `openbao.service`), which makes the **existing** generic
`os.linux.ubuntu.24.*_service` and `journal_tail` procedures work against an
OpenBao host with no new procedure, normalizer, or handler — the same mechanism
as the `netbox` / `netbox-rq` rows in `0058`. The OpenBao-specific
`service_action` mixes restart with the generic catalogue's approval-gated
start/stop/reload/enable/disable actions, so the whole procedure is
`approval_required=True`; an execute-only caller cannot use it to stop or
disable `openbao.service`.

Both seed migrations fail forward on a pre-existing canonical procedure name or
allowlist slug instead of adopting operator-owned state. Both are explicitly
irreversible: after use, `RPCExecution.procedure` protects catalogue history,
and neither migration has a durable ownership ledger that could safely restore
or delete an operator-edited row. Removal or repair requires a reviewed forward
migration.

### Eight procedures are deliberately NOT seeded

`config_deploy`, `rekey`, `config_read`, `policy_read`, `initialize`, `unseal`,
and `snapshot_restore` each carry an unresolved defect in the execution backend:
ownership loss on activation,
commit-before-durable-capture, a digest that verifies a low-entropy credential
offline, a truncated share retained below its pattern's length floor, a writable
parent allowing the initialisation output to be replaced, and missing
accept-once dispatch respectively. `policy_write` is the eighth withheld
procedure. It was the only seeded procedure accepting free-form text, where
shape detection cannot guarantee that encoded, split, or homoglyph-obscured
secrets will never be persisted without also rejecting legitimate content.
Withholding it means no seeded procedure accepts free-form text, making the
no-secret-persistence guarantee structural rather than signature-dependent.
The replacement free-form content design and the other backend defects are
tracked in `netbox-rpc-backend` **#80**.

**Withholding the row is the control.** `RPCExecution` has a foreign key to
`RPCProcedure`, and the backend executes only what this plugin dispatches, so a
handler with no row cannot be invoked through the sanctioned path.
`tests/test_openbao_catalog.py` asserts all eight stay absent, so a later
migration cannot reintroduce one before #80 closes.

State the limit honestly: this is an operational hold, not a code-level lock. An
operator holding `add_rpcprocedure` could hand-create a row pointing at one of
them. That is an explicit, audited act rather than ambient exposure — but it is
not impossible.

### This plugin is the primary control for connection overrides

OpenBao `params_schema` rows declare **no** `rpc_ssh_*` property and set
`"additionalProperties": false`, and the normalizer emits none. **This
deliberately differs from the InfluxDB precedent**, which merges shared
`_SSH_PROPERTIES` into every schema — do not "restore consistency" by copying
that here.

The reason is ordering: caller-supplied host-key entries were the vector for two
separate key-material bypasses in the backend, and the backend refuses them now
— but this plugin persists `RPCExecution.params` **before** the backend ever
validates them. So the backend's refusal is layer two; declining to declare the
fields here is the layer that actually prevents persistence. Estate-wide
enforcement for every other procedure family is tracked in **#253**.

`openbao_validation.validate_openbao_params_for_persistence()` is the primary
secret-ingress control. `create_execution()` runs it after schema validation and
all platform-owned parameter stamps, immediately before `serializer.save()`, for
every `service.openbao.1.*` procedure. `RPCExecution.save()` repeats it over the
final ORM payload for direct script/job creation and params-save paths. All nested
dictionary keys and values are
classified by field name and by secret shape (OpenBao token prefixes, long
base64, long hex, private keys, authorization material, and credential-bearing
URLs). Accepted JSON documents are parsed and their decoded keys/values are
walked; HCL-style quoted strings are lexically decoded before assignment
classification, and escaped assignment identifiers are refused. This closes
escaped-name routes such as a JSON `pass\u0077ord` key before any raw value can
enter `RPCExecution.params`. The scanner returns immediately for non-OpenBao
procedures. For top-level schema-declared identifier fields (`policy_name`,
`mount_path`, `peer_id`, `snapshot_name`), length plus the base64 alphabet is not
sufficient evidence: low-entropy operational identifiers up to the advertised
128-character limit are accepted, while provider tokens, high-entropy
base64/base64url, and long hex remain refused. Every scanned string is capped
at 1 MiB of **UTF-8 bytes** before the more expensive classifiers run. The
seeded schemas impose much narrower typed and enum-constrained limits; none
accepts free-form text.

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

- `transport_driver` — the procedure's own driver: `ansible` (**default**),
  `asyncssh`, `paramiko`, `subprocess`, `fabric` (Linux/server SSH) or
  `ansible-network`, `scrapli`, `netmiko`, `napalm`, `nornir` (network CLI).
  AsyncSSH reproduces the legacy single-/multi-command SSH behaviour. The
  vocabulary and the driver → backend-capability map live in
  **`netbox_rpc/transport.py`**, not on the model, so the chain resolver shares
  one source of truth with the model's choices and stays importable (and
  testable) without Django. They mirror the capability each driver declares in
  netbox-rpc-backend's `drivers/` registry — a **cross-repo contract**, since
  the backend only falls back to a capability-matching driver.
- `transport_driver_chain` — an ordered **priority + fallback chain** of the
  same driver names (index 0 tried first), configured on the `RPCProcedure`
  page. The `netbox-rpc-backend` executor tries the drivers in order, skips
  capability-mismatched entries, advances on an unavailable/connection error,
  and stops on a command-level result.
- `transport_pinned` — excludes a procedure from the estate-wide policy below.
- **Estate-wide Ansible-first policy (`RpcPluginSettings`).**
  `default_transport_driver_chain` / `default_network_driver_chain` (seeded
  `["ansible"]` / `["ansible-network"]` by migration `0075`) make Ansible the
  default *way* to reach devices and VMs without rewriting a single procedure
  row. `domain.normalization.resolve_driver_chain()` resolves the effective
  chain at dispatch time, most specific first:

  1. the procedure's own `transport_driver_chain` — operator intent, verbatim;
  2. the settings default for the driver's capability, with the procedure's own
     `transport_driver` **appended** as its fallback;
  3. nothing — the backend uses the single `transport_driver`, then its own
     built-in capability default.

  Because it is a setting rather than a migration rewrite, **rollback is one
  edit**: clearing the two chains restores raw-driver behaviour estate-wide with
  no migration to undo and no per-procedure values lost.

  **A chain of only Ansible drivers automatically gains the capability's raw
  driver** (`asyncssh` / `scrapli`). Without that, making Ansible the default
  would turn an optional dependency into a hard one — a host without
  `ansible-core` would fail outright instead of degrading.

  **`transport_pinned` procedures never reach step 2.** Two are pinned by
  migration `0075`, and both must stay that way:

  - `service.netbox.staging.rotate_backend_token` — dispatches with
    `allow_fallback=False`, `capture_output=False`, `strict_auth=True`. The
    backend defines its boundary as *successful AsyncSSH process creation*, and
    `strict_auth` maps to AsyncSSH options (including trivial-auth rejection)
    that OpenSSH has no equivalent of. The backend's Ansible driver **refuses**
    `strict_auth` for exactly this reason, so an unpinned row would fail loudly
    rather than weaken silently — but a refused driver is still a broken
    procedure, and `allow_fallback=False` leaves no second chance.
  - `os.linux.ubuntu.24.upgrade_26.run_upgrade` (live) —
    `allow_fallback=params.dry_run`, so a live upgrade must never be
    redispatched onto a second driver, and it streams the upgrade's terminal
    output live, which the Ansible driver cannot provide incrementally.

  The pin is a **declared property**, not a name list consulted at dispatch, so
  a future procedure with the same requirement opts out by setting the flag.
  Neither pinned procedure's normalized payload changes, so their approval
  snapshots and policy hashes are unaffected.
- **`normalized_params["_ansible"]` — NetBox Platform → Ansible connection.**
  The execution backend has no view of what a target *is* (its SSH credential
  carries no platform), so when the resolved chain contains an Ansible driver,
  `_apply_ansible_context()` resolves the target device's NetBox Platform
  through `RpcPluginSettings.ansible_platform_map` and injects
  `{connection, network_os, become, become_method}`. The map follows the
  official `netbox.netbox` collection's conventions and is operator-editable, so
  the extractor drops unrecognised keys and **never raises** — an unmapped
  platform, a malformed map, or a malformed entry all inject nothing, and the
  backend then reports its network driver unavailable and falls back to a raw
  driver rather than guessing a vendor CLI dialect.

  Injection is **gated on the resolved chain containing an Ansible driver**, so
  every non-Ansible procedure keeps a byte-for-byte identical
  `normalized_params` payload — the same discipline the other pipeline overrides
  follow.

  Note: `_DEFAULT_TRANSPORT_DRIVER` in `domain/normalization.py` is still
  `"asyncssh"` even though the *model* default is now `"ansible"`. It means "the
  driver the backend assumes when the key is absent from the payload", which is
  a property of netbox-rpc-backend, not of this model. Changing it to match the
  model default would make every asyncssh procedure stop pinning its driver.
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
- A reverse data migration must not pass a historical model instance into a
  deletion collector that can see current-plugin reverse relations. Migration
  `0073` is deliberately irreversible because it has no durable row-ownership
  ledger: its reverse raises before inspection or mutation, preventing an
  operator replacement, rename, or reference from being deleted or left while
  the migration is recorded unapplied. Use a reviewed forward repair migration
  when catalog ownership cannot be proven durably.
- To test the reverse callable of an older migration below an irreversible
  migration, obtain that migration's historical project state and invoke its
  actual `RunPython.reverse_code` directly inside an isolated database test.
  Do not downgrade the complete graph through the later irreversible boundary;
  that tests the boundary instead of the older reverse behavior.

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
