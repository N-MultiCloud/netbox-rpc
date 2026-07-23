# Dispatch-lease cross-repo contract fixture (#168 ↔ nms-backend#583)

`contract.json` is the shared, checked-in proof that the **issuer**
(`netbox-rpc`, this repo) and the **verifier**
(`netbox-rpc-backend` / `nms-backend#583`) agree byte-for-byte on the signed
one-time dispatch lease.

## Why this works

ed25519 signatures are deterministic (RFC 8032): re-signing
`canonical_message_b64` with the key derived from `test_private_seed_hex` MUST
reproduce `signature_b64` exactly, in any language or library, in either repo.
So both sides can assert the same fixture and know their canonical serialization
+ verification match.

**The key material here is TEST-ONLY**, derived from a fixed public seed. It is
never used in production and grants no access to anything.

## What each side asserts

- **Accept-once:** `verify_dispatch_lease` accepts `claims`/`signature` at
  `verify_now_iso` with `audience`, and the public key resolved from
  `key_lineage`.
- **Reject replay:** the same lease is rejected once its `nonce` is in the
  consumed-nonce set (`negatives.replay.seen_nonce`).
- **Reject tamper:** applying `negatives.tamper.claims_override` and keeping the
  original signature fails signature verification.
- **Reject wrong audience:** verifying with `negatives.wrong_audience.verify_audience`
  fails.
- **Reject unknown lineage:** `negatives.unknown_lineage.claims_override`
  (`key_version` not in the verifier map) fails before signature check.
- **Reject expired:** verifying at `expired_now_iso` fails.

The verifier (nms-backend#583) owns the consumed-nonce store (accept-once); the
issuer owns nonce generation and records `DispatchLeaseIssued` on the ledger.
