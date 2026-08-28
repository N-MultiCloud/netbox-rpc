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

## Compatibility

`netbox-rpc` supports NetBox **4.5.8 through 4.6.x**. The plugin declares
`min_version = "4.5.8"` and `max_version = "4.6.99"`, covering the Django 5.2
runtime shipped by NetBox 4.5.x and the Django 6.0 runtime shipped by NetBox
4.6.x. Its external `extras` migration dependencies are anchored to
`0134_owner`, the final `extras` migration in NetBox 4.5.8 and an ancestor of
the 4.6.x migration graph.

`netbox-nms` remains optional: fresh installs have no `netbox_nms` migration
dependency, while deployments that install it retain the guarded runtime
adapter. The `nms` extra installs `netbox-nms>=0.1.8,<0.2.0`; NMS integration
on NetBox 4.5.x requires netbox-nms 0.1.8 or newer because that release
retargeted its migration dependencies to the NetBox 4.5.8-safe migration graph.

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
- `os.linux.ubuntu.24.upgrade_26.{analyze_preupgrade,save_preupgrade_state,run_upgrade,verify_postupgrade}`
- `os.linux.ubuntu.24.{restart,status,start,stop,reload,enable,disable}_service`
  and `os.linux.ubuntu.24.journal_tail` for the allowlisted `influxdb`
  (`influxdb.service`, OSS 2), `influxdb3-core` (`influxdb3-core.service`,
  Core 3), `netbox` (`netbox.service`), and `netbox-rq` (`netbox-rq.service`)
  services.
  Restarting `netbox-rq` is the audited way to sweep a NetBox RQ job stuck in
  `running` after its worker died.
- `netbox.plugin.install` — installs an **allowlisted** NetBox plugin at an
  **exact** version on a managed NetBox host, registers it in `PLUGINS`,
  migrates, collects static, restarts the allowlisted services, health checks,
  and **restores the previous settings file if NetBox does not come back**.
  `approval_required=True`.

  Params are only `plugin_slug`, `version`, and optional `dry_run`. Everything
  that decides what runs — distribution, module, interpreter, settings file,
  services — comes from an operator-managed `RPCNetBoxPluginAllowlist` row. A
  caller-supplied distribution would be remote code execution with an audit
  trail attached: it reaches `pip install`, which accepts URLs, paths and VCS
  references, and whatever it fetches is then imported by a NetBox restart.

  The rollback is the reason this is a procedure at all. A plugin outside the
  running NetBox's version window does not degrade — NetBox refuses to start —
  so a bad install is an outage on a host whose NetBox is already down.
  `dry_run=true` runs the version pre-flight and stops.

  Restart targets resolve through `RPCLinuxServiceAllowlist`, so this procedure
  can only bounce units that catalog already permits. Seeded `enabled=False`
  **and** hard-gated in code; do not open either until the paired nms-backend
  handler is deployed.

- `os.linux_env_file.upsert_var` — writes a single `KEY=VALUE` line (backend
  resolves the value from a `credential_pk` reference and delivers it over
  stdin; no raw secret is ever accepted as a param) into the allowlisted
  service's `environment_file`, then restarts its `systemd_unit`.
  `approval_required=True`. The `netbox`/`netbox-rq` allowlist rows do not
  ship a seeded `environment_file` — an operator must confirm the real path
  against the production systemd unit and set it via the
  `RPCLinuxServiceAllowlist` admin UI/API before dispatching against them.
  `environment_file` is validated as an absolute path (no traversal/control
  characters) at the model and normalizer layers. Seeded `enabled=False`,
  **and** the normalizer additionally carries a hard-coded code-level gate
  (`RPC_PROCEDURE_NOT_AVAILABLE`) that refuses to run regardless of the
  `enabled` flag: do not enable/open either gate until the paired
  nms-backend execution handler is deployed, issue #203 (object-scoped
  authorization for caller-supplied `*credential_pk` params, a pre-existing
  codebase-wide gap) or an equivalent scoped fix has landed, **and** issue
  #163 (the still-open two-person-approval parent) routes `approval_required`
  executions through an approval-time snapshot of the resolved allowlist
  policy — today `create_execution()` enforces `approval_required` only as a
  permission check and calls `queue()` directly, so an approver's decision is
  never bound to the `environment_file`/`systemd_unit` values the worker
  resolves later at claim time. That TOCTOU window is currently unreachable
  (the code-level gate above blocks the allowlist lookup outright) but must
  stay closed until #163 lands, independent of #203. Seed migration `0060`
  originally shipped `enabled=True` and was later edited in place to
  `enabled=False`; because Django tracks an applied migration by name only,
  a database that already ran the original `0060` keeps the stale
  `enabled=True` value unless it also runs additive migration `0061`, which
  re-asserts `enabled=False` on the existing row. `0060`'s reverse migration
  relies on `RPCProcedureCommand.procedure` being `on_delete=CASCADE` (so
  deleting the procedure also removes its command row in the same
  transaction) and catches `ProtectedError` from `RPCExecution.procedure`
  being `on_delete=PROTECT`, so a rollback with existing executions leaves
  both the procedure and its commands intact rather than partially deleted.
  The code-level gate is checked at three points through one shared
  function (`normalization.code_gate_unavailable_reason()`) so they can
  never diverge: admission time (`create_execution()`, before an
  `RPCExecution` row can be created), advertisement time
  (`/procedures/available/`, so the procedure never appears as
  dispatchable), and worker-claim time (the normalizer, retained as
  defense in depth for a row created by an older process before this gate
  existed). An operator flipping `RPCProcedure.enabled=True` — the only
  scenario the flag alone cannot protect against — is refused at all three.
- `os.linux.proxmox.convert_mellanox_nic_to_ethernet`
- `os.linux.proxmox.pvesh_json`
- `os.linux.proxmox.qemu_vm_lifecycle`
- `os.linux.proxmox.show_systemctl_services`
- `services.pterodactyl.bootstrap_api_key`
- `services.pterodactyl.artisan`
- `services.pterodactyl.container_logs`
- `services.passbolt.export_secrets`
- `services.passbolt.transfer_secrets`
- `services.passbolt.import_secrets`
- `services.passbolt.cleanup`
- `service.netbox.staging.rotate_backend_token` — destructive,
  approval-required rotation of the staging backend's NetBox service token.
  It targets only the existing `nms-front-door` `dcim.device` and accepts no
  caller parameters. The backend resolves that device's enabled SSH service,
  credential reference, port, and strict pinned known-host policy, then invokes
  the fixed root-owned provisioner. Callers cannot supply routing, a token,
  path, command, or arbitrary payload. Results are closed to
  `ok`, the constant `procedure` ID, constant `target="nms-front-door"`,
  nullable `rotated`, and the `execute`/`complete`/`indeterminate` stage. The
  exact tuples distinguish success, pre-commit failure, committed-but-failed
  recovery, and post-dispatch transport/timeout uncertainty
  (`false/null/indeterminate`), so automation cannot mistake uncertainty for a
  safe-to-retry `rotated=false`. A schema-valid closed failure or indeterminate
  tuple remains in the failed execution's `result`; malformed nested results
  fail as `RPC_RESULT_SCHEMA_MISMATCH` and are not persisted. The outer and
  nested `ok` values must be strict booleans and agree, and this procedure
  accepts no backend progress events. Token material
  and upstream command output cannot enter the audit record. Creation accepts
  only `procedure_id`, the exact assigned object, and empty `params`; backend,
  request/trace IDs, comments, tags, custom fields, and every other metadata
  field are rejected even when empty. Approval/rejection bodies accept no
  operator note and audit a fixed bounded reason. Creation returns `pending_approval`
  without enqueueing; execute and approve permissions must each be scoped to
  this exact procedure. A distinct approver records immutable requester/approver
  identities, queues the run, and those identities are bound into its one-time
  signed dispatch lease. This procedure has no ID-only compatibility fallback:
  absent signing keys fail with `RPC_DISPATCH_LEASE_REQUIRED` before any
  backend request. Admission, approval, worker claim, and pre-lease checks pin
  the exact enabled name/handler/version/target/effect/1800-second timeout,
  approval bit, transport driver/chain, output parser/schema, representative
  command contract, and params/result schemas. The concrete backend ID plus a
  non-secret URL/TLS identity fingerprint and canonical policy/schema hashes
  are part of the immutable approval snapshot. Migration reversal deletes the seed
  when it has no executions; if execution history protects it, reversal keeps
  the row and command history but forces `enabled=False`.
- `service.netbox.staging.deploy_dns_pair` — destructive, two-person deployment
  of one reviewed lowercase 40-hex commit to the staging NetBox DNS plugin and
  dns-api sidecar pair. It is fixed to the existing, requester-viewable
  `nms-front-door` device and accepts only `commit_sha`; provider names, PATs,
  record payloads, SSH routing, paths, commands, refs, and abbreviated SHAs are
  rejected. Approval and the lease freeze the exact local `nms-proxy` SSH
  service/credential revisions, host, port, authentication method, and
  known-host digest; point-of-use drift is rejected. Admission and worker claim
  both require an exact compatible backend capability whose golden semantic
  digest includes the reviewed wrapper, sudoers, and runtime generation held
  under the shared publication lock through execution. Approval and worker
  claim recompare the selected backend's URL/TLS fingerprint with the immutable
  request snapshot before sending its authentication header to a capability
  endpoint, so post-request backend-row drift cannot receive that credential. The
  result contains only `ok`, constant `procedure`, constant
  `target`, the approved `commit_sha`, nullable `deployed`, and `stage`: proven
  success is `true/true/complete`, proven pre-process failure is
  `false/false/execute`, and every post-process timeout, transport loss, signal,
  malformed response, or nonzero exit is `false/null/indeterminate`. Reconcile
  staging state before retrying an indeterminate run.
- `service.gitea.production.upgrade_1_27_1` — disabled-by-default,
  destructive, approval-required upgrade of the exact production `Gitea`
  `virtualization.virtualmachine` PK 170 from 1.26.2 to 1.27.1. It accepts an
  exact empty params object and server-normalizes VMID 222, cluster 6
  (`PVE-CLUSTER-02`), node `pve03`, IPv4 `10.0.30.96`, the target-owned SSH
  policy plus one enabled `DeviceService` public identity snapshot, and
  official artifact SHA-256
  `86a7ac26e7f9c9cca0f56c4fac07fff205d5fc3bca0e54af23a204f07b833bc9`.
  The service/identity IDs and UTC revisions, principal/method, locked host/port,
  pinned-known-host digest, policy reference, complete target/fingerprint, and
  exact backend `1` at `http://127.0.0.1:16005` with TLS verification disabled
  are captured in the immutable approval snapshot and signed lease. The public
  Nginx vhost is not a supported dispatch path. Its Gitea-only capability
  extension also binds that backend topology, the target,
  upgrade and guest constants, SSH pin parser, runtime budgets, closed schemas,
  result tuples, and versioned length/SHA-256 identities for the backend's exact
  59,952-byte upgrade script and complete 63,492-byte canonical fixed argv;
  other handler hashes remain
  byte-for-byte unchanged. The semantic-extension digest is also part of this
  procedure's approval-policy hash, so executable- or backend-only drift
  invalidates requested, pending, approved, and queued work before enqueue or
  lease issuance without adding a redundant lease field. Before any
  authenticated capability request at admission, approval, or worker claim,
  the catalog validates the exact loopback URL/TLS binding and reuses that same
  resolved target through snapshot, lease, and dispatch. Approval also requires
  a fresh uncached `COMPATIBLE` capability while the execution row is locked;
  drift leaves the request pending with no approval/queue event or job.
  Results expose only the
  closed `ok/procedure/target/changed/healthy/stage` state; valid failure and
  indeterminate results are preserved, while events and secret-prone output
  are forbidden. Capability and dispatch HTTP redirects are never followed.
  The exact five-key backend wrapper is reduced to `ok/result`; catalog-owned
  static diagnostics are selected only from the validated six-state tuple, so
  backend diagnostic strings never enter persistence. Migration `0073` is
  intentionally irreversible and its reverse raises before inspecting or
  mutating catalog data. This prevents an operator replacement, rename, or
  referenced seed from being deleted or left behind while Django records the
  migration unapplied. Forward migration also aborts before mutation if the
  canonical name already exists. Removal or repair requires a reviewed forward
  migration with explicit ownership evidence. See
  [`docs/gitea-production-upgrade-1.27.1.md`](docs/gitea-production-upgrade-1.27.1.md)
  for activation order, exact states, security, and rollback invariants.
- `service.gitea.runner.register` — disabled-by-default, destructive,
  two-person registration or reconciliation of one of eight exact
  isolated-runner scopes on `nmultifibra-ci-untrusted-01`, VM PK 399. It
  accepts only `operation` (`register` or `reconcile`) plus the allowlisted
  `scope`; callers cannot supply the token, label, host, credential, command,
  path, or backend. Aliases share a canonical, migration-seeded durable scope
  fence, so no second registration or reconciliation can race an unresolved
  token lifecycle. Reconciliation requires a terminal blocked execution or a
  stale `pending` worker reservation plus the shared 1800-second
  remote-quiescence window required by the longest `N-MultiCloud` fence
  participant.
  Under the fence lock, stale-`pending` takeover first terminalizes the lost
  execution, moves the fence to `blocked`, and records the reconciliation owner;
  that ownership advances a positive JS-safe generation and rejects every late
  original transition, even after reconciliation fails. The org provisioner
  uses the same generation protocol on the same canonical fence. The server freezes separate target-owned SSH
  service/credential identity snapshots for runner VM 399 and Gitea VM 170,
  and the backend revalidates both at point of use. It verifies the reviewed
  native runner and Gitea reset-helper digests, obtains the reusable scope token
  with fixed argv, forwards it only over bounded stdin, and always attempts an
  expected-token rotation before returning. Tokens and remote output never
  enter params, argv, environment, events, logs, or results. Closed results
  bind the non-secret reset proof to the fence; uncertainty blocks later
  registration until a separately approved, quiescence-gated `reconcile`
  succeeds. Migrations
  `0080`/`0081`/`0087`, a false code gate, and a false backend gate keep it inert until
  the exact host generation,
  `netbox-network` credential-identity API, signed lease, and scheduling-domain
  isolation are deployed together. See
  [`docs/gitea-runner-registration.md`](docs/gitea-runner-registration.md).
- `service.gitea.actions_runner.provision_org_ci_runner` — disabled-by-default,
  approval-required `provision|reconcile` contract for exactly the
  `root-python312` organization CI lane on `Gitea-Runner` VM PK 416
  (`10.0.30.241`). Forward migration `0087` binds that trust domain: container root maps to an
  unprivileged host account, each job gets a fresh capacity-one rootless
  container. Its five minimal job capabilities exist only inside that user
  namespace; host-effective and host-ambient capabilities remain empty. The job
  receives no host PID/IPC/UTS namespace, device, socket, host network, worktree,
  or cross-scope state. Build jobs have no network. The separately bounded
  publisher phase has only TLS-verified HTTPS to `git.nmulti.cloud:443`, using a
  static `10.0.30.96` host binding with DNS and redirects disabled; every other
  management and production destination is denied. Cgroup v2 fixes the job at
  two CPUs, 4 GiB memory with no swap, 512 PIDs, a read-only root filesystem,
  an 8 GiB ephemeral workspace, bounded `/tmp` and `/run` tmpfs mounts, exact
  ulimits, a 1800-second wall clock, and a 10-second kill grace. The two
  earlier non-root lane sketches remain future design data outside every
  caller-admissible schema/capability because the v1 backend is root-only. It is
  explicitly `activation_eligible=false`: the tracked source prerequisite must
  publish the content-addressed VM416 provision-and-prove helper and final job
  image before another forward migration can bind them. The existing
  registration/reset helpers are not a host-generation boundary.

  `provision` alone accepts an exact `nms-secret:<uuid>` reference;
  `reconcile` forbids credentials and derives its proof from the durable
  canonical `N-MultiCloud` fence. Normalization binds separate VM416 and VM170
  target-owned SSH service/credential revisions into approval and lease
  evidence. Backend responses are redirect-free, streamed, capped at 8192
  bytes, and governed by a 1740-second absolute deadline. Only the closed
  five-key envelope is projected; backend events and diagnostics are discarded.
  A distinct approver, exact capability, signed lease, exclusive scope fence,
  and full 1800-second reconciliation quiescence window are mandatory. Each
  reservation advances a monotonic, approval/lease/result-bound
  `fence_generation`; the legacy registration procedure uses that same
  generation and safety interval, and failed reconciliation never makes an
  older response current again. Schema-valid activation-ineligible work fails before backend,
  inventory, SSH, fence, capability, or authenticated network access. Migrations
  `0084` and `0087` both leave the row disabled, and the catalog/backend gates
  remain closed. See
  [`docs/gitea-org-ci-runner-provision.md`](docs/gitea-org-ci-runner-provision.md).
- `network.device.huawei.router.ne8000.f1a.show_bgp_peer` (handler
  `network.huawei_ne8000_f1a.show_bgp_peer`) — read-only BGP peer status fetch
  from a Huawei NE8000-F1A `dcim.device`. `effect="read"`,
  `approval_required=False`, 45s timeout. The normalizer derives `target` from
  the assigned device and rejects caller-supplied target overrides or other
  unknown params. Optional `vrf` is validated without normalization (default
  `""`; surrounding whitespace and control characters are rejected). The
  immutable assigned-object identity, not its display name, selects the target;
  credentials resolve only through that device's configured `DeviceService`,
  and callers cannot supply a credential override. The specialized handler is
  planned for `netbox-rpc-backend`. nms-backend's BGP work is the distinct NETCONF/fallback
  and netbox-bgp synchronization integration; its retained `automation/rpc`
  code is not the live procedure executor. Migration `0066` remains
  `enabled=False` and a three-layer code gate blocks admission, advertisement,
  and worker claim until the matching netbox-rpc-backend handler is deployed,
  its capability contract is approved, and the coordinated rollout is authorized.

Operators call named procedures, not arbitrary SSH commands.

## Compatibility

This release supports NetBox 4.5.8 through 4.6.x, including NetBox 4.6.5.
The plugin pins `max_version = "4.6.99"` and its migration dependencies target
NetBox migration anchors that exist in both 4.5.8 and 4.6.x.

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
`Intent: <name>` through the read-only `source_intent` relation; intent names are
never copied into `params`, see **Intents** below), status, target, backend, and
timing, and links to the execution detail. The execution detail additionally renders a **Command Output**
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
audited, and not event-sourced. An intent *declares* work; *executing* one
(fanning out one child `RPCExecution` per grouped procedure) is a separate
application-layer capability, `command_handlers.execute_intent()` (issue
#130), triggered via `POST /api/plugins/rpc/intents/{id}/run/`. It creates
every child through the exact same command path a direct `RPCExecution` POST
uses (`create_execution()`), so each child independently re-runs every
existing gate — permission, the authoritative opt-in + selected-backend
enforcement, the procedure's `enabled` check, `approval_required`, params
validation, and the backend capability check. An intent grouping an
`approval_required` or destructive procedure does **not** auto-run that
child; it is never a way to bypass approval or destructive gating — see the
LLM Agent Safety Guardrails in `AGENTS.md`.

### Intent API

- `GET`/`POST /api/plugins/rpc/intents/` — list/create intents.
- `GET`/`PATCH`/`PUT`/`DELETE /api/plugins/rpc/intents/{id}/` — retrieve, update,
  delete.
- On write, send an ordered `procedure_ids` list; the list order becomes the
  through `sequence`. The read representation returns `procedures` as an ordered
  list of `{id, name, handler_id, effect, approval_required, sequence}`.
- Filter with `?execution_mode=`, `?enabled=`, and `?procedure_id=`.
- `POST /api/plugins/rpc/intents/{id}/run/` — execute the intent, fanning out
  one child `RPCExecution` per grouped procedure in `sequence` order. Requires
  `netbox_rpc.execute_rpcintent` on the intent, in addition to each grouped
  procedure's own per-child gates. Returns `201` with the created children, or
  the first gated child's normal failure status (`403`/`400`) with no further
  children created.

See [`docs/intents.md`](docs/intents.md) for the full model, ordering
semantics, the executor's fail-fast/no-rollback and origin-marker contract,
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
Every present backend `result` is validated against the procedure's
`result_schema`, including false outer envelopes. A truthy envelope can append
`ExecutionSucceeded` only after validation. A false envelope remains failed but
projects its valid closed nested tuple so committed/indeterminate outcomes are
not discarded. A mismatch emits `ExecutionFailed` with
`RPC_RESULT_SCHEMA_MISMATCH`, no malformed result, and a bounded, value-free
diagnostic. Event messages are independently redacted and hard-capped at 4096
characters.

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

### Passbolt CE migration procedures

Migration `0048` adds four approval-gated, destructive procedures for a
one-time operator-run Passbolt CE migration from a source Docker deployment to
an already-provisioned native VM. Target models are empty because each run uses
explicit, audited `rpc_ssh_*` host/credential override params supplied at
runtime. Handler IDs equal procedure IDs:

| Procedure / handler | Purpose |
|---|---|
| `services.passbolt.export_secrets` | On the source Docker host, create `db.sql`, `gpg.tar`, and `jwt.tar` in a dedicated staging directory |
| `services.passbolt.transfer_secrets` | From the source host, rsync staged artifacts directly to the target host and verify target-side checksums |
| `services.passbolt.import_secrets` | On the target VM, import MariaDB data, extract GPG/JWT files, set `www-data` ownership and locked-down permissions, then run Passbolt migrate and healthcheck |
| `services.passbolt.cleanup` | Remove dedicated source and target staging directories after operator-confirmed success |

The normalizer validates every caller-supplied container name, DB name, env var
name, host, user, port, and absolute path with strict allowlists, rejects broad
or traversal paths, and records only metadata in the command fingerprint.
Neither `netbox-rpc` nor `nms-backend` stores or returns database dump contents,
GPG/JWT material, or DB passwords. The export procedure accepts DB credential
environment variable names only; the backend reads those variables inside the DB
container at execution time.

Operator instructions live in
[`docs/passbolt-migration-runbook.md`](docs/passbolt-migration-runbook.md).

### `service.influxdb.1.*` — InfluxDB OSS 2 / Core 3 guest management

Migrations `0055` and `0056` seed fifteen typed procedures for managed VMs and devices.
The `family` enum selects either OSS 2 (`influxdb.service`,
`/etc/influxdb/config.toml`, `/health`) or Core 3
(`influxdb3-core.service`, `/etc/influxdb3/influxdb3-core.conf`, `/ready`).

| Procedure | Effect | Purpose |
|---|---|---|
| `inspect` | read | Detect both installed package families and versions |
| `config_read` | read | Read bounded active config with secret redaction |
| `files_list` / `file_read` | read | Inventory/read confined managed and Core plugin files plus snapshots |
| `service_status` / `health` / `journal` | read | Observe systemd, loopback readiness, and bounded redacted logs |
| `config_deploy` | write | Validate TOML, snapshot, atomically activate, restart, health-check, and restore on failure |
| `config_rollback` | destructive | Restore a backend-issued snapshot with restart and health evidence |
| `file_write` | write | Snapshot any existing file, then atomically write confined non-secret content via stdin |
| `file_delete` | destructive | Snapshot then delete one confined file |
| `service_control` | write | Run a closed start/stop/restart/enable/disable action |
| `bootstrap` | write | Initialize a fresh OSS 2/Core 3 server and store generated credentials as `nms-secret:` references |
| `database_create` | write | Create an OSS bucket or Core database with an administrative secret reference |
| `token_create` | write | Create OSS query/writer or Core named-admin credentials and vault the one-time token |

All mutations set `approval_required=True`. File paths are relative to fixed
backend-owned roots, reject traversal/symlinks and credential-like filenames,
and allow plugin scope only for Core 3. Config/file bodies never enter argv;
normalization stores body content for authorized dispatch but records only its
sha256 and byte length in the command fingerprint. Literal passwords, tokens,
secrets, authorization headers, credential URLs, and private keys are rejected;
use `netbox-nms` secret references for credentials. Onboarding accepts no
caller-supplied plaintext. The execution backend generates or resolves secrets
only in memory, uses fixed loopback product APIs, and returns only references
and non-secret resource identifiers.

### `os.linux.debian.13.*_influxdb3_core` — Debian 13 InfluxDB 3 Core installation

The family above manages an InfluxDB instance that already exists. Migrations
`0071` (allowlist row `influxdb3-core` -> `influxdb3-core.service`) and `0072`
(procedures) add the audited contract for *standing one up* on a Debian 13 guest,
so installing a fresh Core 3 host will not require an interactive SSH session.
Both procedures target `dcim.device` and `virtualization.virtualmachine`, and both
are **seeded disabled** until the paired execution handler ships (see the end of
this section).

| Procedure | Effect | Approval | Timeout | Purpose |
|---|---|---|---|---|
| `preflight_influxdb3_core` | read | no | 60s | Report release/architecture/systemd, package + hold state, managed-config marker, unit state, configured bind/node-id/data-dir, TLS readability, and a derived `ready` verdict with bounded `blockers[]` |
| `install_influxdb3_core` | write | **yes** | 900s | Fingerprint-verified repository key, pinned package install, managed configuration, systemd drop-in, restart, readiness probe, and package hold |

`preflight` is deliberately both the pre-install gate and the post-install
verification read — the operator installer's precondition block and its
completion report inspect the same facts — so there is no separate `verify_*`
procedure. The installer's own completion report is its `result_schema`
(package/binary version, unit state, bind, node id, data dir, config path,
plugins enabled, package held, `stage`).

Optional install parameters mirror the operator script's environment variables:
`node_id`, `data_dir`, `http_bind`, `tls_cert`/`tls_key`, `enable_plugins`,
`disable_telemetry`, `wal_flush_interval`, `log_filter`, `package_version`,
`hold_package`, `upgrade_package`, `force_reconfigure`, and
`allow_plaintext_remote`. Every one is re-validated in the normalizer as well as
in `params_schema`, so a schema edit alone cannot widen what reaches the
execution backend.

**Neither procedure accepts the shared `rpc_ssh_*` connection overrides.** The
execution backend resolves host, port, credential, and known-host policy from the
execution's assigned NetBox object alone, as with the Huawei NE8000 BGP read; a
caller-supplied override is rejected with `RPC_PARAM_INVALID`. A caller-selected
`rpc_ssh_credential_pk` is not object-scoped against the requester, and a
caller-selected `rpc_ssh_host` would move an approved installation off the
audited target.

Path parameters must be **canonical**: `.` and `..` segments are rejected and the
value must equal its own `normpath`, so `data_dir` cannot resolve into one of the
forbidden roots `/home`, `/root`, `/run`, `/tmp`, `/var/tmp` (the packaged systemd
unit sandboxes those trees) via a non-canonical spelling such as
`/var/./tmp/influxdb3`. A dot inside a segment — `/etc/influxdb3/tls/server.crt` —
remains legal. `tls_cert`/`tls_key` are both-or-neither absolute paths, and
unknown parameters are rejected in both layers. **A remote `http_bind` with no TLS
is refused** unless the caller explicitly sets `allow_plaintext_remote=true`,
reproducing the installer's refusal to expose bearer-token authentication over
plaintext HTTP.

The installer's `result_schema` is a closed envelope: a nested `ok=true` must also
report `installed=true`, `ready=true`, and `stage="complete"`. Because the event
store derives success from the **outer** response `ok`, `record_backend_response()`
additionally requires the outer and nested `ok` to agree — and both to be strict
booleans — for this family, so a response wrapping a failed or partial install
cannot be recorded as a success. Every result string is explicitly bounded, since
unbounded strings are silently clamped at 4096 characters when the result is
persisted.

Because the SSH target is derived exclusively from the assigned NetBox object, that
object must exist **and** be viewable by the requester: execution creation resolves
it through `objects.restrict(user, "view")`, and the normalizer re-validates the
identity at worker claim and forwards the content type + object ID rather than the
display name, so an approved installation is pinned to the object that was approved.

**Both procedures are seeded `enabled=False`** and are additionally refused by a
fail-closed code gate at admission, advertisement, and worker claim, because no
`os.linux_debian_13.*` handler is deployed yet — an enabled row would only produce
executions that fail on an unknown handler. Enabling them is a coordinated rollout
step performed by an additive migration alongside the handler deployment.

**Neither procedure accepts or returns a credential.** The first administrative
token is created and vaulted only by `service.influxdb.1.bootstrap`
(`family="core3"`), which returns an `nms-secret:` reference. The sanctioned
sequence is `preflight` -> `install` -> `service.influxdb.1.bootstrap`. Both
handler IDs are `EXEMPT_HANDLER_RATIONALE` entries seeded with one
`backend-orchestrated` representative command row each. The paired
`netbox-packer` profile `influxdb-core-3.11.0-debian-13` bakes the same
production posture into a first-boot cloud-init template for *new* guests.

### `os.linux.debian.13.*_akvorado` — fresh-host Akvorado bootstrap

Migration `0086` adds the backend-first rollout for one assigned `dcim.device`
target but deliberately leaves both procedures disabled and the code gate
closed. A later catalog release may enable them only after the seed release is
fully deployed, so rolling workers and package rollback never expose the new
rows to older generic claim code. The seed refuses to overwrite a same-name row
or accept extra/drifted command rows; later enablement remains unusable until the
selected backend explicitly advertises a matching capability at admission,
availability, and uncached worker claim. Reversing the seed disables durable
rows instead of deleting their audit history:

| Procedure | Effect | Approval | Timeout | Purpose |
|---|---|---|---|---|
| `preflight_akvorado` | read | no | 90s | Report Debian/resource/sudo/host-key/Docker/Compose/file/port/stack posture and return the observed SSH host key. |
| `install_akvorado` | write | **yes** | 1200s | Install Debian Docker/Compose, converge pinned Akvorado 2.4.0 assets, start the stack, and verify console and ingestion listeners. |

Neither accepts `rpc_ssh_*`, credential, host, command, config-content, or image
parameters. The normalizer pins the exact assigned object ID and content type;
execution creation also requires the object to exist and be viewable. Preflight
can observe an unpinned target-owned DeviceService key, but installation is
admitted by the backend only after that same service stores the `known_hosts`
line and enables strict checking. The sole install parameter is
`allow_resource_shortfall` (default `false`), covering an explicit approved
exception to the 8-vCPU/16-GiB/50-GiB minimum.
The installer also uses the protected two-person approval path: concrete
procedure-scoped execute/approve restrictions, distinct requester and approver,
an immutable target/backend/params snapshot, approval-time capability
revalidation, and a required signed one-time dispatch lease. That public
snapshot and command fingerprint bind the exact target hash, SSH service and
credential IDs/revisions, local storage policy, primary IPv4/port, principal,
authentication method, explicit strict-key state, known-host digest, and
target-owned policy reference. The backend compares the same fields to the
point-of-use DeviceService response before using secret material; any drift
fails before SSH.

The runtime contract pins Akvorado, Kafka, Valkey, and ClickHouse with immutable
`tag@sha256` references, owns `.env` and `docker-compose.yml` through the
adjacent `.netbox-rpc-bootstrap-owner` sidecar, and keeps console HTTP on
loopback TCP 8080. Required packages come only from isolated, signed official
Debian 13 `trixie`, `trixie-updates`, and `trixie-security` sources; candidate
versions are installed exactly and dpkg-verified. Observation-only preflight never sends authentication
material; operators pin the returned public server identity and rerun before
any authenticated posture probe or install.

The install result uses a closed success envelope: `ok=true` requires
`installed`, `stack_healthy`, `console_ready`, `ingress_ports_ready`, and
`ready` all true with `stage="complete"`, exact expected/running/healthy
seven-service arrays, and an empty `error`; the event store also requires outer
and nested `ok` to agree. A timeout, redirect, server error, or malformed
install response—including a compressed, oversized, truncated, slow, or 2xx
document that is not the exact five-key envelope or fails the nested result
schema—returns `outcome_unknown` with nullable `installed`, `changed`, and
`config_created`. The client streams under an absolute deadline and 64-KiB body
cap, closes every response, and requires preflight reconciliation before retry. Both
handlers are transport-pinned to AsyncSSH and have one `backend-orchestrated`
command-contract row. Its capability hash also binds catalog policy/schema
fingerprints to exact asset hashes, image digests, ownership, result states,
paths, ports, locks, and the 90/1200-second end-to-end route deadlines.
Bootstrap preserves any existing
`/opt/nmulticloud/deploy/compose/akvorado/akvorado.yaml`; customize the initial
placeholder ASN, networks, classifiers, and SNMP community afterward with the
existing approval-gated `service.akvorado.1.config_deploy` procedure.

### `service.akvorado.1.*` — Akvorado flow-collector config and stack lifecycle

Migration `0057` seeds four typed procedures targeting `dcim.device` and
`virtualization.virtualmachine`.

| Procedure | Effect | Timeout | Purpose |
|---|---|---|---|
| `config_read` | read | 30s | Read the current `akvorado.yaml` content |
| `status_stack` | read | 150s | Read the current Compose stack status |
| `config_deploy` | write | 450s | Validate and deploy `akvorado.yaml` from structured `input_data` |
| `restart_stack` | write | 420s | Restart the Compose stack and report status |

Both write procedures set `approval_required=True`. `config_content` is a
structured `input_data` string payload — never argv-interpolated — and only its
sha256 digest and byte count enter the command fingerprint. NUL/unsafe control
characters, plaintext secret assignments, credential URLs, and private keys are
rejected before persistence/dispatch. All four handler IDs are
listed in `command_contract.EXEMPT_HANDLER_RATIONALE` and seeded with one
`backend-orchestrated` representative command row each, since Akvorado
config deployment is backend-orchestrated content handling, not fixed argv.
This catalog is the only sanctioned way to read or change Akvorado config or
stack lifecycle state; `netbox-observability`'s
`AkvoradoIntegration`/`AkvoradoExporterProfile` models store non-secret
metadata only.

The API accepts no caller-controlled Akvorado host/`target` parameter. Every
execution must reference an existing assigned `dcim.device` or
`virtualization.virtualmachine`; normalization derives the backend target name
only from that NetBox object so request params cannot pivot SSH dispatch.
Each lifecycle digest binds approval, targets, timeout, transport,
normalized/fingerprint schemas, result schema, and exact runtime assets. During
the coordinated one-release rollout, a backend may expose the legacy
command-only digest as primary plus the single reviewed semantic digest as
compatible; the catalog accepts that exact matrix only when its own current
digest matches the reviewed constant, so policy drift still fails closed.

### `service.samba.1.*` — Samba file-server observability and config lifecycle

Migration `0049` seeds twelve **read-only** procedures (`effect="read"`,
`approval_required=False`) that observe a managed Samba file server; migration
`0050` seeds their command rows. Migration `0051` adds seven config
write/lifecycle procedures and migration `0052` adds their command rows. Target models are
`netbox_fileserver.sambadomain`, `virtualization.virtualmachine`, and
`dcim.device` — `target_models` is a plain content-type label list, so this
creates no import or FK dependency on `netbox-fileserver`. Handler IDs are the
procedure name with `samba.1` → `samba_1`; the handlers live in nms-backend.

| Procedure | Timeout | Purpose |
|---|---|---|
| `service.samba.1.config_read` | 30s | `/etc/samba/smb.conf` content + sha256 |
| `service.samba.1.config_test` | 30s | `testparm -s` validation of the running config |
| `service.samba.1.config_list_files` | 60s | Enumerate `/etc/samba/**/*.conf` with size, mtime, sha256 |
| `service.samba.1.include_file_read` | 30s | Read one include file (`include_path`) |
| `service.samba.1.service_status` | 30s | active/sub/unit-file state for `smbd`, `nmbd`, `winbind`, `samba-ad-dc` |
| `service.samba.1.version` | 30s | `smbd -V` |
| `service.samba.1.list_shares` | 30s | Effective share definitions |
| `service.samba.1.status_report` | 30s | `smbstatus --json` → sessions, tcons, open files |
| `service.samba.1.domain_info` | 60s | `samba-tool domain info` + `domain level show` |
| `service.samba.1.user_list` | 60s | Directory usernames, SIDs, enabled state |
| `service.samba.1.group_list` | 90s | Groups and their members |
| `service.samba.1.share_acl_read` | 30s | `sharesec --view` for one share (`share_name`) |
| `service.samba.1.config_deploy` | 120s | Write smb.conf via temp file, `testparm`, snapshot, activate, reload, and post-snapshot rollback |
| `service.samba.1.config_rollback` | 60s | Restore a backend-issued config snapshot with lifecycle/rollback evidence; destructive, approval required |
| `service.samba.1.include_file_write` | 60s | Write one confined include file via stdin and validate |
| `service.samba.1.include_file_delete` | 60s | Delete one confined include file; destructive, approval required |
| `service.samba.1.share_upsert` | 60s | Create or update one share from structured fields |
| `service.samba.1.share_delete` | 60s | Delete one share definition; destructive, approval required |
| `service.samba.1.service_control` | 30s | Enum-constrained systemctl action for one Samba unit |

`status_report` pins `output_parser="json"` with an `output_schema` describing
the **raw** `smbstatus --json` document. Per Samba's `source3/utils/status.c`,
each section is emitted by `add_section_to_json()` → `json_new_object()`, so
`sessions`, `tcons`, `open_files`, `byte_range_locks`, and `notifies` are
**objects keyed by id, not arrays** — and there is no top-level `locks` key
(`--locks` is a CLI flag, not a JSON section). Which sections appear depends on
the flags smbstatus was invoked with, so none are required. The handler's own
`result_schema` flattens each section into an array, giving downstream consumers
(the `netbox-fileserver` observed state) stable lists instead of id-keyed maps.

`config_list_files`, `group_list`, and the config-editing write procedures are
exempt handlers. Their recursive reads, per-group expansion, stdin content,
temp-file validation, snapshots, atomic activation, reloads, and rollback
semantics are backend-orchestrated and cannot be reduced to fixed argv.
For `config_deploy`, any failure after the active config snapshot is taken
(activation, reload, timeout, or lost response) must make the backend restore
the snapshot, re-validate and reload the restored config, and report the
`stage`, `snapshot_id`, `activated`, `reloaded`, `rolled_back`, and nullable
`rollback_error` fields. `config_rollback` reports the same rollback-outcome
fields where applicable.
`service_control` is fixed argv because `unit` is one of `smbd`, `nmbd`,
`winbind`, or `samba-ad-dc`, and `action` is one of `start`, `stop`, `restart`,
or `reload` in both schema and normalizer.

Every procedure in this family also accepts the shared, optional `rpc_ssh_*`
connection overrides (`rpc_ssh_host`, `rpc_ssh_port`, `rpc_ssh_credential_pk`,
`rpc_ssh_known_hosts_entry`, `rpc_ssh_strict_host_key_checking`), forwarded by
`_copy_optional_ssh_overrides()` like the other SSH-backed families.
Procedure-specific params are confined in the `params_schema` and again in the
normalizer, so pure-domain execution paths fail closed before nms-backend
repeats the checks:

- `include_path` must be a `.conf` file under `/etc/samba`, rejected on traversal
  or shell metacharacters by regex **and** a `PurePosixPath.is_relative_to`
  confinement check. The normalizer forwards the **resolved absolute path**, not
  the caller's raw value — the command rows run `cat {include_path}`, so a
  relative value would otherwise read relative to the backend process cwd.
- `share_name` must match a safe charset whose first character is
  alphanumeric/underscore, so a value can never be read as a command option.
- `config_content` and include-file `content` are never argv. They are passed to
  backend handlers for stdin use, while the command fingerprint stores sha256 and
  byte-count metadata. Before persistence/dispatch the normalizer scans every
  assignment's parameter name case-insensitively and whitespace-insensitively,
  rejecting command-executing Samba directives: any name ending in `script`,
  `command`, or `action`, plus the `preexec`/`postexec` family. `include`
  directives inside these bodies must resolve under `/etc/samba`;
  `include = registry` and unconfined paths such as `/tmp/evil.conf` are
  rejected. The scan first joins smb.conf line-continuations (a physical line ending in `\\`, per Samba's `lib/util/tini.c`) into one logical line before splitting the parameter name, so a directive cannot be smuggled past the denylist by splitting its name across a backslash continuation (`root pree\\` / `xec = ...`).
- `share_upsert` accepts allowlisted fields only (`path`, booleans, principal
  lists, masks, and comment), not arbitrary Samba option names or command text.
- `config_rollback`, `include_file_delete`, and `share_delete` are
  `effect="destructive"` and `approval_required=True`.

Both normalizers `.strip()` before validating, so surrounding whitespace is
sanitized rather than propagated downstream. The seed patterns deliberately
anchor with `(?![\s\S])` instead of `$`: `jsonschema` enforces `pattern` with
`re.search`, and Python's `$` matches *before* a single trailing newline, so a
`$`-anchored pattern would accept `"smb.conf\n"`.

These procedures never return credential material — the `user_list` and
`domain_info` result schemas contain no password or hash fields, so the observed
state persisted by `netbox-fileserver` satisfies its no-secrets-at-rest
invariant.

### `service.samba.1.*` — Samba/AD identity management (#160)

Migration `0055` seeds nine procedures completing the Samba catalog with
user/group lifecycle actions; migration `0056` seeds their command rows.
Target models and handler-ID mapping are the same as the observability/config
family above.

| Procedure | Effect | Approval | Timeout | Purpose |
|---|---|---|---|---|
| `service.samba.1.user_create` | write | no | 60s | Create a Samba/AD user (`username`, `password`, optional `full_name`, `disabled`) |
| `service.samba.1.user_delete` | **destructive** | **yes** | 60s | Delete a user by `username` |
| `service.samba.1.user_set_password` | write | no | 60s | Reset a user's password (`username`, `password`) |
| `service.samba.1.user_enable` | write | no | 30s | Enable a user account by `username` |
| `service.samba.1.user_disable` | write | no | 30s | Disable a user account by `username` |
| `service.samba.1.group_create` | write | no | 60s | Create a group (`group_name`) |
| `service.samba.1.group_delete` | **destructive** | **yes** | 60s | Delete a group by `group_name` |
| `service.samba.1.group_add_members` | write | no | 60s | Add 1–128 members to a group |
| `service.samba.1.group_remove_members` | write | no | 60s | Remove 1–128 members from a group |

`user_create` and `user_set_password` are the only two procedures in the
catalog whose `params_schema` declares a `password` field, and it is handled
as a secret end to end:

- The password is delivered to `samba-tool` over **stdin only** — it is never
  an argv token. Both handlers are `EXEMPT_HANDLER_RATIONALE` entries in
  `netbox_rpc.command_contract`, seeded with one representative
  `backend-orchestrated` command row each.
- At execution-creation time, `command_handlers._scrub_password_param()` pops
  the raw `password` out of `params` and replaces it with a `password_sha256`
  (sha256 hex digest) + `password_bytes` (byte length) fingerprint **before**
  the `RPCExecution` row is saved — the plaintext is never written to the
  database, not even transiently.
- The normalizer's `_extract_samba_password_fingerprint()` never receives a
  raw password; it only forwards the pre-computed fingerprint fields and
  rejects (`RPC_PARAM_INVALID`) a missing or malformed fingerprint.
- No password or hash of it is ever present in `params`, `normalized_params`,
  `result`, or any `RPCExecutionEvent` — proven by
  `tests/test_jobs_samba_normalization.py` (pure-domain) and
  `netbox_rpc/tests/test_samba_identity_password_redaction.py` (DB-backed, a
  real created + run `RPCExecution` row and its events).

`username`, `group_name`, and each `members` entry are validated in both the
`params_schema` and the normalizer with the same charset-confined,
safe-first-character pattern used elsewhere in this family, so a value can
never be read as a `samba-tool` option.

### `fileserver.samba.*` — seeded RPCIntents (#160)

Migration `0057` seeds two `RPCIntent` rows grouping the Samba procedures
above — declarative reference data only, adding no executor and no new
mutation surface (see [Intents](#intents)):

| Intent | Mode | Grouped procedures |
|---|---|---|
| `fileserver.samba.collect_state` | `parallel` | `version`, `service_status`, `config_read`, `config_test`, `list_shares`, `status_report`, `user_list`, `group_list`, `domain_info` |
| `fileserver.samba.deploy_config` | `sequential` | `config_test` → `config_deploy` → `service_control` → `service_status` |

The nine identity procedures above are deliberately not grouped into either
intent — they are standalone actions. See
[`docs/intents.md`](docs/intents.md) → "Seeded intents" for the full contract.

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
  -> configured backend target /rpc/executions/{execution_id}/run
  -> transport driver (AsyncSSH / Scrapli / Netmiko / Paramiko / NAPALM)
  -> network device or Linux host
```

`netbox-rpc` is deliberately the source of truth, not the SSH runtime. It
owns:

- procedure names, handler IDs, categories, and enabled/approval policy;
- JSON request and response schemas used to validate procedure parameters;
- execution records, normalized parameters, status, results, errors, and audit
  events;
- NetBox job orchestration that delegates execution to the configured backend.

Deployments may retain the `netbox-nms` adapter that routes established
handlers to `nms-backend`, or configure the first-class `RPCBackend` row for
`netbox-rpc-backend`; selection is deployment configuration, never a
caller-supplied route. When an executor publishes a capability manifest, its
handler IDs and command-contract hashes are enforced; a missing legacy manifest
is reported as unknown and currently follows the documented compatibility path.
Existing `nms-backend` handlers include
`network.huawei_olt_ma5800_r024.start_ont` and
`network.dell_os10_s5232f_on.bootstrap_restconf` and
`os.linux_ubuntu_24.restart_service` and
`os.linux.dns_host.deploy_dns_stack` and
`os.linux_proxmox.qemu_vm_lifecycle`. The gated Huawei NE8000 handler is not
dispatchable until the `netbox-rpc-backend` capability and rollout gates open.

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

- `transport_driver`: the procedure's own driver — `ansible` (**default**),
  `asyncssh`, `paramiko`, `subprocess`, `fabric` (Linux/server SSH) or
  `ansible-network`, `scrapli`, `netmiko`, `napalm`, `nornir` (network CLI).
  `asyncssh` preserves the historical SSH behaviour.
- `transport_driver_chain`: an ordered priority + fallback chain of the same
  driver names (index 0 tried first). The netbox-rpc-backend executor tries them
  in order, advancing on an unavailable/connection error and stopping on a
  command-level result.
- `transport_pinned`: excludes this procedure from the estate-wide policy below.
  Set it when the backend handler depends on one specific driver.

**Ansible is the estate-wide default.** Rather than rewriting every procedure's
driver, the plugin settings carry a default chain per capability (seeded
`["ansible"]` / `["ansible-network"]`). A procedure that defines no chain of its
own resolves at dispatch time to *Ansible first, then the driver it already
used*, so the raw drivers remain the fallback tier and nothing loses its
existing behaviour. Rollback is a single settings edit — clearing the chains
restores raw-driver behaviour estate-wide, with no migration to undo.

A resolved chain containing only Ansible drivers automatically gains the
capability's raw driver, so making Ansible the default can never turn an
optional dependency into a required one.

Procedures marked `transport_pinned` are excluded: two ship pinned because they
disable transport fallback entirely, and one of them additionally needs
credential isolation Ansible cannot reproduce.

For network procedures the target device's NetBox **Platform** is resolved
through an operator-editable map (following the official `netbox.netbox`
collection's conventions) and passed to the executor as the Ansible network OS
and connection plugin. An unmapped platform passes nothing, and the executor
falls back to a raw driver instead of guessing a vendor's CLI dialect.
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
procedures. Top-level schema-declared identifiers (`policy_name`, `mount_path`,
`peer_id`, `snapshot_name`) distinguish low-entropy operational names from
high-entropy base64/base64url material, so realistic names up to 128 characters
remain usable while provider tokens, high-entropy base64, and long hex are still
refused. Every scanned string is capped at 1 MiB of **UTF-8 bytes** before the
more expensive classifiers run. The seeded schemas impose much narrower typed
and enum-constrained limits; none accepts free-form text.

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
2. **Approval** — legacy procedures with `approval_required=True` require the
   caller to hold `netbox_rpc.approve_rpcprocedure`. Protected staging-token
   rotation, exact-SHA staging DNS deployment, production Gitea upgrade, and
   isolated-runner registration
   procedures instead record
   `requested → pending_approval` without enqueueing; only a distinct actor
   with that permission may record
   `approved → queued` and enqueue it.
3. **Params schema** — when a procedure defines `params_schema`, submitted
   `params` are validated against the JSON Schema before proceeding.

These guards run at the API layer, not the model layer, because the serializer
receives the procedure as a foreign-key ID and the schema/enabled/approval
checks require the resolved object.

Ordinary commands emit `ExecutionQueued` before enqueueing. Protected procedures
emit `ExecutionRequested` and `ApprovalRequested` at creation, then
`ExecutionApproved` and `ExecutionQueued` only after a distinct decision. If
RQ/Redis enqueue fails, either flow emits `ExecutionEnqueueFailed` and projects
`error_code="RPC_ENQUEUE_FAILED"` instead of leaving a permanent queued record
with no job. Successful enqueue emits `JobEnqueued` and projects `job_id`.
Backend-supplied audit events for ordinary procedures are capped at 50 and
stored under the `Backend::` namespace, preventing a remote event name from
colliding with an internal domain transition during replay.

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
the `ci.yml` workflow. Ordinary Gitea CI is fail-closed on the dedicated scalar
runner label `ci-untrusted-python312`: if that runner is unavailable, the job
queues and never falls back to a mirror or production-capable runner. The
workflow checks out the triggering commit with a full-SHA-pinned checkout
action and no persisted credentials, requires preprovisioned CPython 3.12.14
at `/usr/local/bin/python3.12` plus uv 0.12.5 at `/usr/local/bin/uv`, and forbids
ambient-`PATH` tool selection or toolchain download/bootstrap. Its exact runtime,
build-backend, and test closure is `.gitea/ci-requirements.lock`, containing one compatible
hashed wheel per package for CPython 3.12 on x86_64 glibc 2.34. Installation
uses hash checking, wheel-only resolution, an empty inherited environment, the
explicit PyPI simple index, no uv configuration/project sources/cache, and
`UV_PYTHON_DOWNLOADS=never`. Syntax checks and Pytest also run through
`env -i` with isolated Python (`-I`), user-site disabled, and no ambient
Python/Pytest configuration. Pytest uses the reviewed, hashed
`.gitea/pytest-ci.ini`, an empty `PYTEST_ADDOPTS`, disabled plugin autoload, and
only the explicitly loaded locked `pytest-asyncio` plugin; candidate or runner
configuration cannot alter collection, imports, or plugin execution. Update the
dependency lock deliberately with every direct or transitive
dependency change and rerun its isolated install plus
`tests/test_ci_workflow_security.py`; the latter structurally parses the YAML,
rejects duplicate/alias/flow constructs, and mutation-tests runner, permissions,
job count, checkout, toolchain, installer, source, pin, hash, and pytest-bypass
regressions.

`tests/test_deploy_manifest_contract.py` also runs the canonical manifest check,
builds a wheel with the locked build backend, and compares the embedded
migration/static path-and-digest maps to the exact archive. A migration added
without renewing both the reviewed migration policy and generated manifest now
fails ordinary CI before the production deploy gateway sees it.

The workflow and its repository tests are defense in depth; they are not the
runner authorization boundary because a candidate branch can modify its own
workflow. Gitea's trusted repository/organization runner policy must make
mirror and production-capable runners ineligible for pull-request jobs and
permit ordinary CI to match only the isolated runner label. Until that external
policy is provisioned and proven, this CI contract must remain blocked/queued
rather than activated on a broader runner.

Migration `0084` added the disabled
`service.gitea.actions_runner.provision_org_ci_runner` skeleton on exact
`Gitea-Runner` VM PK 416 (`10.0.30.241`). Forward migration `0087` adds the
fixed `root-python312` candidate but keeps it activation-ineligible until the
tracked source prerequisite supplies the reviewed host-generation boundary and
final content-addressed job image. See
[`docs/gitea-org-ci-runner-provision.md`](docs/gitea-org-ci-runner-provision.md)
for the exact default-dark contract and activation order.

Tier 2 (`netbox_rpc/tests/`) covers the ORM-bound behavior — `event_store`, the
rebuild oracle, the append-only ledger, the command handlers, and the
command-only REST API. The required canonical Gitea pull-request gate needs an
externally provisioned isolated untrusted runner, disposable digest-pinned
PostgreSQL/Redis, and an exact hash-locked NetBox 4.5.8/4.6.5 dependency closure;
it remains blocked until that trusted platform contract exists. The GitHub
`.github/workflows/test.yml` matrix is supplementary post-mirror evidence, not
canonical pre-merge evidence. The privileged Gitea
`.gitea/workflows/integration.yml` is manual, canonical-`main`-only diagnostic
evidence and is never a PR/push trigger, branch-protection requirement, or
substitute for the isolated runner policy. Candidate-side ref checks remain
defense in depth; trusted Gitea runner/ref eligibility is authoritative.

Do not test this plugin against a real Linux host, Linux container/VM over SSH,
or a real Huawei OLT unless a separate explicit live-device test plan is
approved.
