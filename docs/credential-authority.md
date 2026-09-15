# Execution-bound credential references

## Scope and rollout

RPC execution records can carry named, metadata-only credential references. The
control plane freezes their actor, target, procedure policy and backend executor
identity at admission. An optional credential provider uses the signed dispatch
lease and immutable execution ledger to authorize a just-in-time reveal.

This is an authority contract, not a secret cache or an endpoint transport. The
standalone executor must implement and explicitly advertise reference schema 1,
the `netbox-openbao` provider version 1 and dispatch lease version 1 before a
reference-bearing execution can be dispatched. Missing capabilities, signing
keys, identity bindings or approval evidence fail closed. Existing executions
without references retain their prior behavior. No procedure is enabled by this
change, and existing permission-only approval procedures are not silently
converted into a complete approval workflow.

## Named reference format

The `credential_references` API field is a mapping containing at most 16 stable
names. Names and field names follow `[a-z][a-z0-9_]{0,63}`. Each reference has a
closed schema; unknown fields and malformed metadata are rejected without
including input values in validation errors.

```json
{
  "ssh": {
    "schema_version": 1,
    "provider": "netbox-openbao",
    "assignment_id": 42,
    "target": {"object_type": "dcim.device", "object_id": 17},
    "purpose": "login",
    "fields": ["private_key", "passphrase"],
    "version": {"policy": "live"}
  }
}
```

Exactly one of `assignment_id` or canonical `credential_uuid` is required. A UUID
does not grant direct access: the provider must still establish an active
assignment for the exact target and purpose. Valid purposes are `login`,
`enable`, `console`, `oob`, `api`, `agent` and `backup`. IDs and pinned version
numbers are positive JSON integers no larger than 9007199254740991; booleans,
numeric strings and integral floating-point values are rejected.

`version` is either `{"policy":"live"}` or
`{"policy":"pinned","number":3}`. The provider enforces version lifecycle and
approval policy; knowing a historical version number is not authorization to
read it. The requested field bundle contains 1–16 unique names. The provider's
credential schema determines which fields exist and which are required.
Username and other credential metadata are not automatically secret payload
fields; their approved metadata identity is frozen separately from the material.

The canonical dependency-light Python types live in
`netbox_rpc.credential_contract`. `CredentialReferenceV1.from_mapping(value)`
validates the wire shape, and `to_mapping()` returns its normalized JSON form.
Instances and nested target/version objects are frozen dataclasses; requested
fields are immutable tuples. Optional providers import this contract lazily.

## Immutable authority

Set `RPCBackend.executor_identity` to the dedicated authenticated NetBox service
user used by the execution backend. A missing or inactive identity never falls
back to a broad service account, superuser or caller-supplied user ID. The
initiating actor and executor must be distinct identities.

Admission writes `credential_references` and read-only `credential_authority`
in the original execution insert. The authority snapshot binds the initiating
actor, backend ID and executor, backend URL/TLS/revision, exact target identity
and revision, procedure policy and schemas, original parameters and the named
references. A generated correlation ID is separate from caller metadata.
Before approval, the optional provider's metadata-only
`netbox_openbao.automation.capture_reference_identity` helper captures the exact
credential UUID, assignment, target, purpose, username, fingerprint, credential
type, policy and engine IDs, engine-selector digest and schema digest. Its closed
metadata shape is validated before persistence. Missing provider code or failed
metadata authorization rejects reference-bearing admission without revealing
provider details. The provider performs no vault read during this capture.
PostgreSQL and ORM guards reject later changes to either credential field.
The additive migration leaves historical executions with empty references and
does not require either OpenBao or the optional inventory adapter to be installed.
Persistent database defaults allow a rolled-back plugin binary to continue
inserting ordinary executions without naming the new JSON columns. Application
rollback leaves the expanded schema and immutable-field trigger in place;
reversing the migration itself removes the new fields and is not the production
rollback procedure. A human-reviewed migration compatibility declaration is
required independently of hosted CI.

Normalization binds the complete authority digest into the command fingerprint
and derives a credential-policy reference from the same digest. Applicable
approval snapshots therefore include the declared references. Event redaction
preserves only strictly validated reference shapes and exact digest forms; a
secret stored under a reference-looking key remains redacted.
Protected public creation accepts the schema-validated reference field alongside
the existing closed request shape. Other caller metadata remains forbidden.
The worker reuses its already validated backend target during reference approval
checks; independently required resolver failures use fixed, value-free errors.

## Provider authorization interface

The provider receives an execution ID, reference name, optional step ID and
signed lease. It must obtain the authenticated executor from the request's
trusted authentication context, not its JSON body. Call:

```python
from netbox_rpc.credential_authority import validate_secret_resolution_dispatch

authorization = validate_secret_resolution_dispatch(
    execution=execution,
    dispatch_lease=lease_mapping,
    authenticated_executor=request.user,
    reference_name="ssh",
    step_id=None,
)
```

The helper reloads the execution by primary key. It checks current initiating
actor and executor activity, object-scoped target/procedure/backend access,
execution permission, integration settings and the frozen snapshot. When called
inside a transaction, authority objects are row-locked until that transaction
ends. Only actor rows use PostgreSQL `FOR NO KEY UPDATE`: actor updates and
deletions remain blocked, while provider audit foreign keys can take `KEY SHARE`
without reversing the provider material-write lock order. Procedure, backend,
target and command locks retain their full strength, including protection
against new child command inserts. Approval-required and destructive procedures additionally need immutable
current approval from an active, authorized distinct approver. The helper also
requires that approver's current `approve` scope to include this exact procedure;
approval permission for another procedure is insufficient. Classes still
using only the legacy approval permission gate cannot reveal credentials.
Low-risk procedures without an approval requirement do not gain an artificial
second-person approval requirement.

The signed lease must match its immutable `DispatchLeaseIssued` event and every
applicable execution, requester, nullable approver, procedure, target, parameter,
credential-policy and correlation binding. The issuance event follows the
normalized event at the lease's claimed stream version; it is not compared to
the latest stream version as though issuance had not advanced the stream. Any
subsequent execution event prevents reveal. Future-issued, naive, expired or
longer-than-300-second leases are rejected. Reference-bearing issuance clamps
the configured lifetime to 300 seconds while preserving shorter lifetimes and
the 120-second default. Non-reference issuance retains its existing lifetime
configuration. No ID-only fallback is accepted for reference-bearing executions.

The frozen `SecretResolutionAuthorization` result contains `initiating_actor`,
`executor_id`, `execution_id`, `stream_version`, `target_object`, `reference`,
`reference_name`, `step_id`, `dispatch_nonce`, `correlation_id`,
`approval_snapshot_hash`, `reason`, `provider_identity`, verified `expires_at`,
`procedure_id`, `backend_id`, nullable `approved_by_id` and `intent_run_id`.
The reason identifies the
audited procedure and assigned credential purpose, not caller-supplied reveal
text. The current standalone step ID is the empty string; nonempty step IDs are
rejected until durable named intent-run instances are implemented. `intent_run_id`
is currently `None`.

## Reveal lifetime and recovery

The helper does not consume the backend dispatch nonce and does not implement a
secret read. The provider owns a separate durable receipt keyed by execution,
dispatch nonce, step ID and reference name. Before reading material, the provider
must commit a reservation that records one selected concrete KV version. It must
then recheck execution authority and assignment/version policy in its reveal
transaction, read all requested fields from that one version, and return only
the permitted bundle. Material must never enter a database, queue, event or
application log on the RPC side.
After waiting for provider graph/schema locks, immediately before reading, and
after a blocking material read before delivery, call both
`check_authorization_permissions(authorization)` and
`check_authorization_lifetime(authorization)` from the same module. The permission
helper reloads users with uncached permission state and rechecks the requester's
exact procedure execution scope, the required approver's exact approval scope,
their procedure/target visibility, requester backend visibility and executor
activity. It performs ordinary queries only, without acquiring authority locks,
resolving a backend or calling a provider. Pass only the verified in-process
authorization result, never a caller-created mapping. The query-free lifetime
helper checks the verified signed expiry without acquiring a new
authority lock or parsing a replacement caller value. Providers must also
refresh their own permissions and restrictions after those waits. Expiry at
the current instant is denied; a reservation never extends lease lifetime.
These checks establish current permissions at each check; they do not lock future
ObjectPermission or group membership changes across an external material read.
The post-read check prevents delivery after revocation committed during that read.
Denied or ambiguous reads still consume the provider's reserved receipt and must
never silently retry against a newer version.

The provider compares its freshly locked metadata against `provider_identity`
both when reserving and immediately before revealing. Assignment retargeting,
username or key-fingerprint changes, schema drift and backend-selector changes
require a new execution authorization. Live password/token material may rotate
without a new authorization only while this metadata identity remains unchanged.

Every repeat after receipt reservation is refused, including a lost response or
unknown read outcome. An operator must reconcile the original execution; a retry
must never silently reselect the newest version. Provider receipts are not
substitutes for current actor, target or approval authorization. Runtime transport
integration, provider version policy, persistent cross-procedure chaining and
the complete endpoint procedure catalog are coordinated follow-on contracts.

The current execution serializer still exposes live procedure command rows.
This authority unit therefore freezes their contract digest and refuses any
definition drift; it does not treat those live rows as an approved execution
snapshot. A coordinated renderer unit must introduce a public immutable command
snapshot with a digest bound to approval, dispatch and the backend's capability
contract. Until that boundary exists, an unknown handler must not become
executable merely because its procedure contains command rows.

## Verification

Pure tests in `tests/test_credential_contract.py` cover hostile shape/type inputs,
immutable bundles, fingerprint drift and shape-checked event metadata. Real
NetBox tests in `netbox_rpc/tests/test_credential_authority.py` cover the original
ORM insert, PostgreSQL immutability, signed lease/ledger bindings, current actor
and executor revocation, object restrictions and denied legacy approval.
`netbox_rpc/tests/test_credential_dispatch.py` additionally verifies the real
serializer, admission, normalizer, worker, signed issuance ledger and resolution
path; default, shorter and capped lifetimes; exact non-superuser approval-scope
revocation; missing capabilities or signing keys; and a concurrent command-row
update blocked until the reveal transaction ends. Run
these against isolated NetBox 4.5.8, 4.6.5, and 4.7.0 PostgreSQL environments;
no test may connect to a managed endpoint.
