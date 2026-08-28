# Gitea runner registration

`service.gitea.runner.register` is the only audited RPC path for registering
the isolated runner identities declared by `nmulticloud-context/ci/runners`.
It is destructive, requires a distinct approver, is seeded disabled by
migration `0080`, upgraded onto the shared generation protocol by migration
`0087`, and is additionally blocked by a code availability gate. It
must not be enabled or dispatched until the coordinated catalog, backend,
runner-host, and credential-identity generations described here are deployed.

## Closed request and targets

The caller supplies exactly one `operation` (`register` or `reconcile`) and one
`scope` from this allowlist:

- `netbox-proxbox`
- `nmulticloud-org`
- `nmulticloud-org-root`
- `proxbox-api`
- `release-netbox-proxbox-validation`
- `release-netbox-proxbox-build`
- `release-proxbox-api-validation`
- `release-proxbox-api-build`

No host, port, username, credential, token, command, path, label, runner name,
or backend destination is caller-controlled. The assigned object must be the
requester-viewable `virtualization.virtualmachine` PK `399`,
`nmultifibra-ci-untrusted-01`, with cluster PK `8` / `CLUSTER01-DC01`, node PK
`34` / `node01`, tenant PK `14` / `N-MultiFibra`, role PK `5`, 8 vCPU, 16384
MiB RAM, 122880 MiB disk, active NetBox status, and one explicit primary IPv4
address. Token generation is pinned independently to production Gitea VM PK
`170`, name `Gitea`, IPv4 `10.0.30.96`.

The normalizer resolves exactly one enabled, target-owned SSH `DeviceService`
for each VM. The immutable approval snapshot and signed dispatch lease bind
both service and credential IDs and UTC revisions, principal, authentication
method, canonical IPv4 host, port 22, exact Ed25519 known-host digest, policy
reference, both target-object hashes, and the complete semantic capability
digest. The backend repeats those checks against the public service record and
the separately authorized credential response immediately before use. This
requires the deployed `netbox-network` credential-identity contract from issue
`#23`; missing identity or revision fields fail closed.

## Secret flow

For `register`, the worker first locks the canonical scope's migration-seeded
durable fence and changes it from `clear` to `pending`. Aliases such as
`nmulticloud-org` and `nmulticloud-org-root` share the same `N-MultiCloud`
fence, so they cannot race for the same reusable token. The backend verifies
the exact native runner helper at
`/usr/local/libexec/gitea-runner/register-runner` with SHA-256
`15b72776c546ff433dc585bb8bab0645524adada7151aa9038d7b7e2711a49ed`.
It then runs the fixed Gitea CLI prefix as the `git` account for the mapped
owner or repository scope. The returned 40-character reusable registration
token is accepted only as bounded command output and is forwarded over a pipe
to the fixed `nmc-register --scope <scope>` helper command running as the exact
per-scope service account.

The token must never enter RPC params, the command fingerprint, argv,
environment variables, event streams, logs, result data, or tracked/runtime
configuration. The helper accepts only a non-interactive pipe or socket, keeps
the token in best-effort-wiped process memory, disables process dumps, and
refuses to overwrite an existing `.runner` identity. Backend capture is capped at 512
combined stdout/stderr bytes and token-bearing commands emit no RPC events.
The route, handler, preflight, token, registration, reset, response-header, and
body deadlines are fixed in the cross-repository semantic contract. The
catalog gives connection establishment 10 seconds and response headers the
remaining 290 seconds of the 300-second route budget, then keeps the 4,096-byte
body and monotonic total-deadline checks. Once the token command process exists,
a route timeout is conservatively `indeterminate`.

Gitea 1.26 registration tokens are reusable. The CLI returns the current active
scope token and does not rotate it. Therefore the backend always invokes the
fixed Gitea-side helper
`/usr/local/libexec/nms/gitea-runner-token-reset` (SHA-256
`67562056a5c00c1f667383b98d83ff43a136ea10079ab041079680a511614c78`)
after token acquisition, even when registration fails or is cancelled. The
helper first refuses any runtime other than root-owned Gitea 1.26.2 with schema
version 331. It then locks and hard-deletes the exact expected credential row
transactionally, so Gitea's stale ID-only registration write cannot reactivate
the old secret or create a second active row. It verifies one different active
replacement and emits only bounded non-secret IDs and digests. A successful
proof clears the fence atomically with the terminal RPC event. A missing,
malformed, mismatched, or indeterminate proof leaves the scope `blocked`; no
later `register` request is admitted.

`reconcile` is the only way to clear an interrupted attempt. It is itself a
fresh destructive, distinctly approved RPC. The worker binds it to the blocked
execution and persisted expected-token digest. If interruption happened before
the digest was recorded, the all-zero sentinel tells the helper to classify
and rotate the currently active scope token conservatively. Only one
reconciliation may own a scope. Ordinary takeover requires a terminal blocked
execution and the full shared 1800-second interval since the last fence update.
A hard worker death can
leave the fence `pending` and the execution `running`; after the same full
1800-second remote-operation window, reconciliation reservation locks both rows,
terminalizes that stale execution with the fixed worker-loss code, changes the
fence to `blocked`, and records its owner atomically. A newer `pending` fence or
a nonterminal `blocked` owner remains ineligible. The window is deliberately
conservative: a client-side transport failure cannot authorize reset while the
backend may still be running. The interval and monotonic positive JS-safe
generation are shared with
`service.gitea.actions_runner.provision_org_ci_runner`, which also mutates the
canonical `N-MultiCloud` fence. Every reservation advances the generation and
every result must echo it. Once reconciliation owns the fence, every late
original transition is rejected, including after reconciliation fails; only
the owner's exact successful proof clears it. Do not copy an old or replacement
token into a comment, execution, shell, or evidence artifact.

## Closed results

The result contains the constant procedure and target, `operation`, allowlisted
`scope`, exact fence owner and generation, nullable `registered`/`reconciled`
state, whether invalidation was
proved, whether reconciliation remains required, the expected-token digest,
the bounded reset classification/IDs, and `stage`:

| Meaning | `ok` | invalidated | reset required | terminal fence |
|---|---:|---:|---:|---|
| Registration and expected-token rotation completed | `true` | `true` | `false` | `clear` |
| Failed definitively before token acquisition | `false` | `false` | `false` | `clear` |
| Registration failed but expected-token rotation was proved | `false` | `true` | `false` | `clear` |
| Token/reset/transport outcome is uncertain | `false` | `false` | `true` | `blocked` |
| Approved reconciliation proved conservative rotation | `true` | `true` | `false` | `clear` |

An `indeterminate` registration additionally requires checking whether the
exact runner identity was created before deciding whether another registration
is appropriate. Backend diagnostic strings and progress events are never
durable evidence.

## Activation and rollback

Activation order is fail-closed:

1. Merge and deploy the `netbox-network` issue `#23` credential-identity API.
2. Land and review the exact `nmulticloud-context/ci/runners` host generation,
   install both independent copies of the hash-pinned native runner helper on
   VM `399`, and keep every runner service stopped and unregistered.
3. Install the hash-pinned expected-token reset helper and exact
   `nms-gitea-runner-control` sudo policy on Gitea VM `170`.
4. Deploy the backend handler with
   `gitea_runner_registration_enabled=false`; verify its capability digest.
5. Apply catalog migrations `0080`, `0081`, and `0087` with the procedure disabled and
   its code gate false. Verify catalog/backend semantic digests are byte-identical
   and all three canonical scope fences are `clear`.
6. Record VM `399`'s explicit primary IPv4 and configure exactly one enabled,
   strict-known-host SSH service and usable credential on each of VM `399` and
   VM `170`.
7. In one reviewed coordinated release, open the catalog code gate, enable the
   backend gate, then explicitly enable the canonical procedure row. Confirm
   signed dispatch-lease enforcement and distinct execute/approve permissions.
8. After explicit operator confirmation, create one `register` request and have
   a different authorized actor approve it. Require the automatic token-reset
   proof and clear fence, then prove the exact runner name, ID, scope, labels,
   stopped/online state, isolation canaries, and required-check behavior through
   `nms git`.

Do not activate while privileged `prod-deploy`, `mirror-host`, or equivalent
labels remain schedulable from application repositories. Static merge is not
activation authority. Agents must never enable, create, approve, or dispatch
this procedure autonomously.

Rollback disables the catalog row first, completes an approved `reconcile` for
every pending/blocked fence, then closes the backend gate. Prove the scope token
was rotated before deleting or replacing any partially registered identity.
Runner disable/delete remains a Gitea control-plane operation through
`nms git`; this procedure intentionally does not generalize deregistration or
runner configuration deployment.
