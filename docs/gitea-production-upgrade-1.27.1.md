# Production Gitea 1.27.1 upgrade

`service.gitea.production.upgrade_1_27_1` is the only audited RPC contract for
upgrading the production Gitea VM from 1.26.2 to 1.27.1. Migration `0073`
deliberately seeds it disabled. Do not enable or dispatch it until the paired
backend gate and capability, VM-owned SSH service, pinned host key, signed
dispatch-lease verifier, backup location, and health-check topology are proven
and an operator has authorized the maintenance window.

## Immutable contract

- Target: `virtualization.virtualmachine` PK `170`, name `Gitea`, active and
  production-tagged; Proxmox VMID `222`; cluster PK `6` / `PVE-CLUSTER-02`;
  node device PK `27` / `pve03`; primary IPv4 `10.0.30.96`.
- Versions: exact source `1.26.2`, exact target `1.27.1`.
- Artifact: official binary SHA-256
  `86a7ac26e7f9c9cca0f56c4fac07fff205d5fc3bca0e54af23a204f07b833bc9`.
- Policy: `effect="destructive"`, approval required, 1800-second timeout,
  1725-second handler budget, 1690-second guest process timeout, and exact
  empty closed params object.
- Backend: the execution serializer carries scalar `RPCBackend` PK `1`; the
  backend re-fetches that authoritative row at dispatch and requires exact
  loopback base URL `http://127.0.0.1:16005` with `verify_ssl=false`. Dispatch
  through the public Nginx vhost is unsupported.
- Guest: `/usr/local/bin/gitea`, `gitea.service`, unit path
  `/etc/systemd/system/gitea.service` with SHA-256
  `557ad3478e463075b1f6dd3a459207631ca6114371a9db670458e76515d4b7f6`,
  user/group `git:git`, config `/etc/gitea/app.ini`, work/data roots
  `/var/lib/gitea` and `/var/lib/gitea/data`, backup root
  `/var/lib/netbox-rpc-gitea-upgrade-1.27.1-backups`, and transaction state
  below that root as `transaction-state.json`.
- Probes: local health `/api/healthz` and version `/api/v1/version` on
  `127.0.0.1:3000`, plus external
  `https://git.nmulti.cloud/api/v1/version`.
- SSH policy: non-secret reference
  `target-owned-ssh:virtualization.virtualmachine:170`. The caller cannot
  provide or override routing, credentials, versions, artifact data, commands,
  paths, or metadata.
- SSH identity: exactly one enabled `netbox_network.DeviceService` for the VM,
  resolved in one query. It must explicitly select `10.0.30.96:22`, strict
  host checking, one bounded known-hosts line, and a supported stored identity.
  Normalized params and the command fingerprint freeze `ssh_service_id`,
  `ssh_service_revision`, `ssh_identity_id`, `ssh_identity_revision`,
  `ssh_principal`, `ssh_method`, `ssh_host`, `ssh_port`,
  `ssh_known_hosts_sha256`, and `ssh_policy_ref`. Revisions use canonical UTC
  `Z`; only the exact known-hosts line digest is stored, never the line or any
  secret material.
- Host identity: the raw inventory record must contain exactly three
  space-separated fields: host `10.0.30.96`, algorithm `ssh-ed25519`, and a
  strict standard-Base64 token of at most 256 characters. Markers, comments,
  wildcards, lists, hashed hosts, bracket/port aliases, legacy algorithms, and
  malformed padding are rejected. The decoded SSH wire blob must repeat the
  exact `ssh-ed25519` algorithm and contain exactly one 32-byte Ed25519 key.

Admission, distinct-actor approval, worker claim, and pre-lease validation bind
the complete procedure/command/schema policy, target and command fingerprint,
authoritative backend ID plus URL/TLS fingerprint, and SSH-policy
reference. A signed one-time dispatch lease is mandatory; missing issuer keys
fail with `RPC_DISPATCH_LEASE_REQUIRED` before the backend is contacted.
The exact loopback backend binding is validated before every authenticated
capability request and the same resolved target is reused through approval,
lease creation, and dispatch. Approval performs an uncached compatibility check
under its row lock; mismatch or manifest loss leaves the execution pending and
appends no approval/queue event or job.
The backend must compare the signed requester and approver with the fetched
execution and independently re-derive the target, params, and SSH snapshot.
For this procedure only, the procedure-policy approval hash contains the exact
canonical semantic-extension digest, including the backend and executable
identity. Executable-, rollback-, backend-, schema-, or result-contract drift
therefore invalidates requested, pending, approved, and queued work before
enqueue or lease issuance. The signed lease's existing `contract_hash` binds
the same semantics; no redundant caller-controlled or lease field is added.

## Result states

The result is closed to `ok`, constant `procedure`, constant `target="Gitea"`,
`changed`, `healthy`, and `stage`:

| Meaning | `ok` | `changed` | `healthy` | `stage` |
|---|---:|---:|---:|---|
| Upgrade completed | true | true | true | `complete` |
| Already at 1.27.1 | true | false | true | `complete` |
| Known pre-mutation failure | false | false | false | `execute` |
| Upgrade failed and prior version is healthy | false | false | true | `rolled_back` |
| Mutation committed but health failed | false | true | false | `complete` |
| Post-dispatch outcome unknown | false | null | null | `indeterminate` |

Schema-valid false and indeterminate tuples remain on the failed execution so
operators do not mistake uncertainty for a safe retry. Outer and nested `ok`
must be strict matching booleans. The transport accepts only the backend's
exact five-key `ok/result/events/error_code/error_message` wire envelope,
requires `events=[]`, validates the closed nested result, and then discards all
backend diagnostics. The catalog projects only `ok/result` and derives fixed,
bounded failure code/message text solely from the validated six-state tuple;
opaque remote text can never enter execution or event persistence. Backend
progress events, extra envelope/result fields, and non-empty success diagnostics
are forbidden; malformed data fails closed and is not projected.
Read timeout, ambiguous HTTP failure, or non-JSON after the request is sent is
persisted as the exact `false/null/null/indeterminate` tuple. A connect timeout
known to occur before send is persisted as the exact `false/false/false/execute`
tuple. Schema-valid closed failure bodies returned with an HTTP error are
preserved rather than discarded. Capability and dispatch requests never follow
redirects. Every 3xx dispatch response becomes the exact indeterminate tuple;
a 3xx capability response is incompatible because no manifest from a different
origin can satisfy the approved backend binding.

## Activation and rollback invariants

Activation order is mandatory: deploy the backend handler with its runtime gate
closed; provision and verify lease keys, target-owned SSH, pinned host identity,
backup/restore, and capability contract; open the backend gate and advertise
the exact capability; only then may an operator enable the catalog row. Rollback
reverses the order: disable the catalog row first so no new approvals can enter,
drain/reconcile any in-flight execution, then close the backend gate.
Admission, approval, and an uncached worker pre-dispatch check require the
Gitea capability to be explicitly `COMPATIBLE`; absent, unreachable, malformed,
or oversized manifests fail closed.
The capability hash is derived from the representative command plus a
Gitea-only semantic extension binding static target/topology, versions,
artifact URL/digest, guest paths/unit/health URLs, 1725-second handler and
1690-second process budgets, the SSH pin parser, closed
caller/normalized/fingerprint schemas, all result tuples, and executable
contract version 1. The executable identity binds the backend's exact upgrade
script (68,394 bytes, SHA-256
`7e6fdacd945f038e06eb0c4f12752b72c702bfde984ff47a89cce2d68fffad41`)
and complete fixed argv (72,240 canonical bytes, SHA-256
`cc41baaa641673a191a4163595cacecb9df5d2233edbdb385cfec741b6ffb2d0`)
under the shared `json-sort-keys-compact-utf8` canonicalization; changing
mutation, rollback, or invocation bytes therefore changes capability
compatibility. Its compact
canonical JSON and digest fixture must match the paired backend byte-for-byte;
legacy handler hashes do not gain this extension.
Migration `0073` takes ownership only by creating an absent canonical name; if
an operator-owned procedure already uses that name, forward migration aborts
before modifying the procedure or any command. Migration `0073` is intentionally
irreversible because it has no durable row-ownership ledger. Its reverse always
raises before inspecting or mutating catalog data, so an operator replacement,
rename, execution history, approval state, or generic NetBox metadata cannot be
deleted or left behind while Django records the migration unapplied. Operators
must keep `0073` applied; removal or repair requires a reviewed forward migration
with explicit ownership evidence.

The backend must verify the official digest before stopping Gitea, run every
embedded root Python program in isolated mode from a root-owned working
directory, create and verify a restorable backup before mutation, and include
repositories, LFS, attachments, packages, repository archives, custom data,
avatars, Actions logs, and Actions artifacts in stopped source/archive byte
parity. Gitea 1.26.2 intentionally excludes repository-archive storage from its
dump command, so the root transaction must append that stopped tree to the
descriptor-sealed archive before parity verification. Curl configuration,
proxy, and TLS environment are discarded for artifact and health requests.
Exact SQLite verification scratch files are removed on every normal or
trapped failure exit. It then atomically installs the new binary and confirms
both the exact version and service/application health. A failure after mutation
must attempt rollback and re-check health. `indeterminate` or
`changed=true, healthy=false` is never automatically retried: reconcile the
installed binary, service, database state, and backup before a new request.
Never expose binary contents, credentials, configuration, backup paths, command
output, or logs through RPC params, results, events, approval notes, or leases.

Operators and agents must never create, approve, enable, or dispatch this
destructive production procedure autonomously.
