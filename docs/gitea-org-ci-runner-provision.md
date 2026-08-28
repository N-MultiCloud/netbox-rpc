# Gitea Organization CI Runner Provision Contract

`service.gitea.actions_runner.provision_org_ci_runner` is the default-dark
catalog contract for the Gitea Actions isolated root organization-runner lane on exact
`Gitea-Runner` VM PK 416 (`10.0.30.241`). Migration `0084` created the disabled
two-lane skeleton. Forward migration `0087` extends that same disabled row with
the isolated `root-python312` candidate, operation-discriminated schemas,
dual-target SSH approval evidence, durable token-scope reconciliation, and the
secret-protected backend response path.

The catalog row remains `enabled=False`,
`_GITEA_ORG_CI_RUNNER_AVAILABLE` remains false, and the matching backend gate
must also remain false. In addition, `root-python312` carries
`activation_eligible=false`: `N-MultiCloud/nmulticloud-context#411` must first
publish the reviewed content-addressed VM416 provision-and-prove helper, final
job-image digest, and a trusted server-owned publisher dispatcher whose phase
authorization cannot be selected by an untrusted workflow and that keeps publisher
credentials outside the untrusted job container. The helper must also
prove exact inode quota, cgroup-v2 block-I/O BPS/IOPS, and stdout/stderr/log byte
and rate ceilings. The current reviewed registration and token-reset helpers
cannot mutate or prove the host generation and must never be presented as
though they can.

## Frozen lane

Version 1 admits exactly one closed `lane`; every runtime identity and trust
value is server owned.

| Lane | Execution boundary | Scope | Activation |
| --- | --- | --- | --- |
| `root-python312` | root inside a fresh rootless user-namespace container | `nmulticloud-org-root` | ineligible until `nmulticloud-context#411` |

The earlier `general-ubuntu` and `untrusted-python312` sketches remain inert
future design data only. They are absent from the request, normalized,
fingerprint, result, migration, and capability lane enums because the paired v1
backend implements only `root-python312`. A future lane needs a separately
named and reviewed procedure rather than widening this handler implicitly.

The root lane is fixed to:

- sole label `ci-untrusted-root-python312`;
- non-login host service identity `gitea-runner-nmulticloud-org-root`;
- state `/var/lib/gitea-runner-nmulticloud-org-root` and config
  `/etc/gitea-runner/nmulticloud-org-root.yaml`;
- capacity one and a fresh container for every job;
- container UID 0 mapped to an unprivileged host UID, never host root;
- `privileged=false`, no host PID, IPC, or UTS namespace, host networking, host
  worktree bind, host volume, host device, daemon socket in the job, or
  cross-scope state;
- capability drop-all on the runner and job, followed only inside the rootless
  job user namespace by `CHOWN`, `SETUID`, `SETGID`, `FOWNER`, and
  `DAC_OVERRIDE`, with no-new-privileges; the host-effective and host-ambient
  capability sets remain empty;
- a default-deny job network namespace: the build phase has `network_mode=none`
  and no DNS or egress; the publisher phase alone may use TLS-verified HTTPS to
  `https://git.nmulti.cloud:443`, resolved without DNS by the exact static
  `git.nmulti.cloud -> 10.0.30.96` binding, with redirects disabled and all
  other destinations and ports denied;
- cgroup v2 CPU fixed at a 100000 µs period, 200000 µs quota, and weight 100;
- 4,294,967,296-byte memory maximum, zero swap, and 512-PID maximum;
- read-only root filesystem with only `/workspace`, `/tmp`, and `/run`
  writable: an 8,589,934,592-byte non-host-bound ephemeral workspace,
  1,073,741,824-byte `/tmp` tmpfs, and 67,108,864-byte `/run` tmpfs, both
  `nodev,nosuid,noexec`;
- exact core `0/0`, file-size `8589934592/8589934592`, open-file `1024/1024`,
  and process `512/512` soft/hard ulimits;
- a hard 1800-second job wall clock followed by a 10-second kill grace; and
- pinned public base input
  `ghcr.io/astral-sh/uv:0.12.5-python3.12-trixie-slim@sha256:0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f`,
  Python 3.12.14 source digest, and uv 0.12.5 archive digest.

The public Astral image is only a pinned build input. It is not the final NMC
job image and does not contain the required checkout/isolation helpers or
wheelhouse. Until issue #411 supplies that final content-addressed artifact and
host boundary, `runner_image`, provision-helper path/digest, and prove-helper
path/digest are deliberately null.

## Caller and approval contract

Every request requires `operation` (`provision` or `reconcile`) and exact lane
`root-python312`. `provision` additionally requires one exact
`registration_token_secret_ref` matching `nms-secret:<uuid>`; leading/trailing
whitespace is rejected rather than trimmed. `reconcile` forbids that field and
uses only the durable fence owner and expected token digest. Optional booleans
retain their existing defaults; build and prebuilt-image modes remain mutually
exclusive. Caller-supplied runner identity, labels, image, paths, origin,
organization, or any `rpc_ssh_*` routing is rejected.

Normalization binds two independent target-owned SSH snapshots:

- VM416, policy
  `target-owned-ssh:virtualization.virtualmachine:416`, principal
  `nms-runner-bootstrap`; and
- Gitea VM170 (`10.0.30.96`), policy
  `target-owned-ssh:virtualization.virtualmachine:170`, principal
  `nms-gitea-runner-control`.

Each snapshot carries the exact service and credential IDs/revisions, local
storage backend, principal, method, host, port 22, known-host digest, and policy
reference. The command fingerprint const-binds both target-object digests, the
lane-specific scope and lane-contract digest, the two snapshot digests, and the
fixed Gitea origin/organization. A distinct approver, current compatible
backend capability, and signed one-time dispatch lease are mandatory; there is
no ID-only fallback.

Because the only advertised lane is currently activation-ineligible, admission
and worker claim validate the closed request schema and then fail as
`RPC_HOST_GENERATION_UNAVAILABLE` before backend settings, capability,
inventory, SSH, fence, or authenticated network access.

## Secret transport and durable fence

The backend HTTP call is redirect-free and streamed. The route has a 1740-second
absolute deadline inside the procedure's 1800-second budget, and the response
body is capped at 8192 bytes with compressed, truncated, oversized, or trickled
responses rejected. Only the exact five-key wire envelope is accepted; backend
events and diagnostic strings are discarded. The durable projection receives
only `ok` plus a result validated against the closed schema. An opaque token in
an event, diagnostic, added field, log, or result cannot pass that projection.

`nmulticloud-org-root` maps to canonical Gitea scope `N-MultiCloud`, so token
mutation is serialized with legacy `service.gitea.runner.register` and every
existing operation on that organization. Both procedures use the same positive
JS-safe takeover-generation protocol and the same 1800-second safety interval. A provision
reservation moves the fence from clear to pending before backend I/O. Any
ambiguous failure blocks the scope. A separately approved `reconcile` may own
the blocked scope only after the original execution is terminal and the
full 1800-second maximum participant budget has elapsed; pending/running work is never
declared quiescent sooner. The fence's monotonic `takeover_generation` starts at
zero. Each register, provision, or reconcile approval binds the next positive JS-safe
`fence_generation`; reservation atomically advances the durable generation,
and every result, including transport or reconciliation failure, must echo it.
Reconciliation failure releases only its retry owner and never rolls the
generation back, so late original responses remain permanently invalid.

The pinned helper proof uses reset states `rotated` or `already_inactive` and a
positive replacement-token ID. Reconcile success uses one of the
`reconciled_*` states and also carries the positive replacement-token ID. The
closed schema deliberately rejects the older `deleted`/`already_absent` model,
missing replacement identity, mismatched operation/lane/scope/fence owner, and
unbounded diagnostics. A reset proof clears the fence; uncertain reset state
keeps it blocked.

## Activation and rollback

Activation remains a later reviewed source/deploy action. It requires, in
order:

1. merge and verify the content-addressed host-generation boundary from
   `N-MultiCloud/nmulticloud-context#411`, including the trusted publisher
   dispatcher and credential-phase binding plus inode, block-I/O, and log
   ceilings described above;
2. replace the null helper/image fields through another reviewed forward
   catalog migration and capability digest;
3. deploy a backend whose canonical capability bytes match the catalog fixture;
4. deploy the catalog while its row and code gate remain dark;
5. verify both VM SSH snapshots, signed leases, fence recovery, and closed
   transport; then
6. explicitly open backend/code/catalog gates in coordinated order.

Rollback closes backend/code/catalog gates before handler removal. Migration
`0087` is intentionally irreversible: its reverse raises before Django can
remove the durable takeover-generation column or mutate catalog state. A
reviewed forward migration must perform any later repair while retaining
audited procedure, execution, approval, and fence history.
