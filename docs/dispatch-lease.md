# One-time signed RPC dispatch leases (#168)

`netbox-rpc` (the **issuer**) mints a short-lived, ed25519-signed *dispatch
lease* after a queued execution is atomically claimed, and hands it to the
paired `netbox-rpc-backend` (the **verifier**, N-MultiCloud/nms-backend#583) in
the `/rpc/executions/{id}/run` body. The lease lets the backend prove — before
it touches a managed host — that the dispatch it received is exactly the one
`netbox-rpc` authorized, and that it has not been replayed, tampered with,
downgraded, or misdirected.

Consumer/issuer code: [`netbox_rpc/dispatch_lease.py`](../netbox_rpc/dispatch_lease.py).
Cross-repo contract fixture: [`netbox_rpc/tests/fixtures/dispatch_lease/`](../netbox_rpc/tests/fixtures/dispatch_lease/).

## Envelope

`SignedDispatchLease = { algorithm, claims, signature }`. `claims` (`LeaseClaims`,
Pydantic v2, `extra="forbid"`, every field length-bounded) carries **references
and hashes only** — never a secret, private-key byte, credential value, or raw
exception chain:

| field | binds |
|---|---|
| `envelope_version` | protocol version (downgrade guard) |
| `execution_id` | the exact aggregate |
| `stream_version` | event-stream position at claim (TOCTOU / replay guard) |
| `nonce` | one-time use (accept-once) |
| `audience` | intended verifier (confused-deputy guard) |
| `handler_id` / `handler_version` / `effect` | the authorized handler contract |
| `contract_hash` | `derive_command_contract_hash()` — the **same** value the capability handshake (#167) verifies; both sides agree on *what will run* |
| `target_snapshot_hash` / `params_fingerprint` | the target + normalized params that were authorized |
| `credential_policy` | a non-secret policy reference (e.g. `device_credential:<pk>`) |
| `requested_by_id` / `approved_by_id` | the two-person-approval actors |
| `issued_at` / `expires_at` | short TTL (default 120 s, ≤ 900 s) |
| `key_id` / `key_version` | signing-key lineage (rotation) |
| `trace_id` | correlation |

The signature covers `claims.canonical_bytes()` — sorted-key, compact-separator
JSON — so both repositories compute an identical message. ed25519 is
deterministic (RFC 8032), which is what makes the checked-in fixture a hard
cross-repo contract.

## Threat model

- **Replay.** A captured lease is bound to `nonce` + `stream_version` + a short
  `expires_at`. The verifier owns the consumed-nonce store and rejects a second
  use; a replay against an advanced stream fails the `stream_version` check; a
  stale capture fails expiry.
- **TOCTOU (claim vs dispatch).** Issuance sits *behind* the atomic `start()`
  (queued → running) transition, so only the single winning claimer mints a
  lease, and it is bound to the stream version at that instant.
- **Confused deputy.** `audience` pins the intended verifier; a lease minted for
  one service is rejected by another.
- **Downgrade.** `envelope_version` must be in `SUPPORTED_ENVELOPE_VERSIONS` and
  `algorithm` is pinned to `ed25519`; an "alg=none" or weaker-primitive
  substitution is rejected before any signature work.
- **Key compromise / rotation.** Keys are `(key_id, key_version)`. The verifier
  resolves the signer by lineage and rejects **unknown lineage** — a retired or
  unrecognised key id/version is not trusted just because bytes verify against
  some key. Rotating in a new active key and retiring the old one invalidates
  leases signed by the retired lineage as soon as it leaves the verifier map.

## ADR

- **Signing = ed25519 (asymmetric).** The issuer holds the private key; the
  verifier needs only the public key, so a backend compromise cannot forge
  leases. Deterministic signatures give reproducible cross-repo fixtures.
- **Nonce ownership.** The **issuer** generates the nonce and records it on the
  append-only ledger (`DispatchLeaseIssued`); the **verifier** owns the
  consumed-nonce store (accept-once). Split ownership keeps the audit trail on
  the issuer and the single-use decision on the executor.
- **Event ownership.** Lease issuance is audited as `DispatchLeaseIssued` — an
  **audit-only** domain event that does not advance execution status (the stream
  already sits at `running` via `start()`); claimed/backend-result reuse the
  existing `ExecutionStarted` / backend-response events; a rejected lease is the
  verifier's `ExecutionFailed` on the backend result.
- **Rotation & coordinated rollout.** Multiple keys may be configured for
  overlap; exactly one is `active` and signs. Rollout mirrors #167: leases are
  **inert until a signing key is configured *and* the paired backend advertises
  verification**. With no key configured, `issue_dispatch_lease` returns `None`
  and ordinary dispatch stays ID-only, byte-for-byte as before (prod-safe).
  `service.netbox.staging.rotate_backend_token` is deliberately stricter: it
  fails with `RPC_DISPATCH_LEASE_REQUIRED` before contacting the backend unless
  a lease is signed. Its immutable approval snapshot additionally binds
  canonical hashes of the exact procedure policy (including transport/output
  pipeline and representative command), params/result schemas, and the
  concrete backend ID plus non-secret URL/TLS identity;
  any mutable catalog drift fails before approval, worker claim, or lease
  issuance. Coordinated issuer/verifier key provisioning is therefore a
  deployment prerequisite for that procedure.
  `service.gitea.production.upgrade_1_27_1` uses the same mandatory-lease
  boundary. Its lease and approval snapshot additionally bind the exact VM
  identity/topology, source/target versions, official artifact SHA-256, and
  `target-owned-ssh:virtualization.virtualmachine:170` SSH-policy reference.
  Its params fingerprint also freezes the public SSH service/identity IDs and
  UTC revisions, principal/method, host/port, and pinned-known-host digest.
  The verifier accepts expected target/params/policy and requester/approver
  values so the backend can re-derive and reject each mismatch. It is seeded
  disabled; activate the backend gate/capability first,
  then enable the catalog row. Disable the catalog row before closing the
  backend gate during rollback.
  The capability hash includes the Gitea semantic extension in addition to the
  representative command; all other handler hash payloads remain compatible
  with the generic command contract. Its semantic extension and approval
  policy both bind backend ID 1, loopback URL `http://127.0.0.1:16005`,
  `verify_ssl=false`, and the canonical executable/rollback/schema digest.
  The public Nginx vhost is unsupported. Requested, pending, approved, or queued
  work is invalidated before enqueue or lease issuance if those semantics
  drift. The existing lease `contract_hash` provides the signed binding; no new
  caller or wire field is added. Capability and dispatch requests do not
  follow redirects, so the signed lease cannot leave its approved backend
  destination. The exact backend URL/TLS binding is validated before any
  authenticated capability request and the same resolved target is reused
  through snapshot, lease, and dispatch. Approval performs an uncached
  compatibility check inside its locked transaction; drift leaves the request
  pending without approval/queue events or a job. A 3xx dispatch result is
  persisted as indeterminate. The raw
  backend diagnostic fields are discarded before event persistence; catalog
  failure diagnostics are fixed by the validated closed result tuple.

  `service.gitea.runner.register` also requires the mandatory lease. Its
  approval snapshot and lease bind runner VM 399, Gitea VM 170, both exact
  target-owned SSH service/credential identity snapshots, the allowlisted
  operation/scope, canonical durable fence snapshot, reviewed runner/reset
  helper digests, fixed token/helper argv, runtime ceilings, and the closed
  semantic capability hash. It is seeded and code-gated disabled; deploy the
  matching backend capability and host generation before opening either gate.
  Any result that cannot prove expected-token invalidation leaves the fence
  blocked until a separately approved reconciliation succeeds.

## Operations

Configure signing keys in `PLUGINS_CONFIG["netbox_rpc"]`:

```python
PLUGINS_CONFIG["netbox_rpc"] = {
    # ...
    "dispatch_lease_signing_keys": [
        {"key_id": "rpc-sign", "key_version": 2, "private_key_pem": "<PEM>", "active": True},
        # keep the previous version present (active=False) during overlap so the
        # verifier still recognises its lineage until fully drained:
        {"key_id": "rpc-sign", "key_version": 1, "public_key_pem": "<PEM>", "active": False},
    ],
    "dispatch_lease_audience": "netbox-rpc-backend",   # optional, default shown
    "dispatch_lease_ttl_seconds": 120,                 # optional, ≤ 900
}
```

For deployments whose generated NetBox plugin template cannot carry secret
material, omit the `dispatch_lease_signing_keys` key entirely and set all three
service environment variables for both NetBox and its RQ worker:

```text
NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_FILE=/absolute/path/to/issuer-private.pem
NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_ID=rpc-sign
NETBOX_RPC_DISPATCH_LEASE_SIGNING_KEY_VERSION=2
```

The environment contains only a path and bounded lineage, never PEM bytes.
Explicit `PLUGINS_CONFIG` is primary: an existing empty or malformed
`dispatch_lease_signing_keys` value fails closed and does not fall through. The
file loader uses descriptor-relative, no-follow path walking and a nonblocking
final open; it accepts only a ≤16 KiB regular, single-link,
root/current-euid-owned file with permissions no broader than `0640`, under
trusted non-writable ancestors (root-owned sticky directories are allowed).
Unsafe ownership/mode, symlinks, races, partial configuration, special files,
short/oversized reads, malformed PEM, or unavailable OS primitives yield no
lease and never log or return key contents. For staging token rotation and the
production Gitea upgrade that means `RPC_DISPATCH_LEASE_REQUIRED` before backend
dispatch.

- **Key rotation.** Add the new key with `active: True` and a higher
  `key_version`; set the previous key `active: False` (keep it listed so the
  verifier map still recognises its lineage while in-flight leases drain). Once
  drained, remove the old entry from **both** repos.
- **Rollback.** Remove all `dispatch_lease_signing_keys` (or set every entry
  `active: False`) → `issue_dispatch_lease` returns `None` → dispatch reverts to
  ID-only for ordinary procedures with no code change. Malformed key config
  also degrades ordinary procedures to ID-only rather than failing the worker.
  Staging token rotation instead fails closed and cannot be used during this
  rollback state.
- **Retiring ID-only dispatch.** Once every environment is issuing leases and the
  backend (#583) is enforcing, flip the backend to **require** a valid lease
  (reject ID-only). That switch lives on the verifier; this issuer is
  additive until then.
- **Metrics.** Count `DispatchLeaseIssued` events and the verifier's
  lease-rejected results to watch issuance/verification health across a rollout.
