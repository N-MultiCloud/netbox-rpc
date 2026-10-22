# Fixed IAM UI control procedures

## Requirements and architecture

The procedure family `service.keycloak.iam_ui.*` controls only the dedicated NMS IAM UI on NetBox `dcim.device` 44, named `nmc-prod-207`. The fixed host helper is `/opt/nmulticloud/deploy/keycloak/bin/iam-ui-control`. The helper accepts exactly one literal mode: `inspect`, `configure`, `certificate`, or `activate`.

The public parameter schema is an empty object. Callers cannot supply a host, port, SSH identity, credential, command, path, realm, client, DNS name, callback, configuration file, or timeout. Normalization admits only the platform-owned timeout snapshot metadata. The normalized contract binds the target model, ID, name, handler ID, procedure name, and canonical SHA-256 of the exact fixed argv. A mismatch fails before credential resolution or host execution.

| Operation | Effect | Approval required | Host timeout |
|---|---|---|---|
| `inspect` | read | no | 60 seconds |
| `configure` | write | yes | 180 seconds |
| `certificate` | write | yes | 240 seconds |
| `activate` | write | yes | 60 seconds |

The selected transport is pinned AsyncSSH with strict authentication and no fallback. The runtime resolves current target-owned SSH credentials for device 44 at dispatch. It rejects `rpc_ssh_*` overrides. The production service uses its inventory-owned port 2222 and pinned host key; the handler never substitutes port 22. The production SSH principal is root, so the fixed sudo command needs no new sudoers grant. The separate deployment-runner application grant does not grant helper access.

## Design alternatives

The selected design follows the existing fixed-target NetBox RQ worker procedure path. It reuses the current strict target-owned resolver and the signed approval lease for write operations. A separate queued SSH revision snapshot would additionally bind approval to an exact credential version. The existing locked snapshot builder fixes port 22, so that alternative needs a separate generic snapshot contract before it can safely support production port 2222.

The residual difference is explicit: a target-owned credential can change while an approved execution is queued. Dispatch still reloads and validates the current credential, endpoint ownership, target identity, and strict host-key policy. No caller chooses that credential. This change does not widen the snapshot builder, ambient SSH authentication, or transport fallback policy.

A generic host-command procedure would expose unnecessary command and configuration selectors. The fixed helper design removes that caller-controlled surface and keeps the helper's root filesystem authority separate from the browser and RPC request.

## Capability and policy boundary

The plugin and dedicated runtime maintain the same `iam_ui_contract.py` definitions. Their semantic capability extension includes the actual catalog policy, all public and normalized schema hashes, command fingerprint schema hash, helper path, exact transport rules, bounded output, fixed timeouts, and indeterminate outcome rules. The catalog registers all four procedures in the explicit backend capability set. A missing or mismatched backend contract refuses execution.

The additive seed migration creates four procedures and one fixed representative command for each. Reapplication checks immutable fields and refuses drift. An operator-disabled procedure stays disabled on reapplication. The reverse migration disables the procedure rows and retains their command rows and execution history. It never deletes the audit catalog.

The existing `nms rpc procedures` and `nms rpc executions` commands expose the procedures and their audited runs. No direct managed-host command is an alternative when an approval or capability check refuses the operation.

## Closed results and uncertain outcomes

The helper reports only `ok`, `operation`, `admin_ready`, `bootstrap_available`, `certificate_present`, and `tls_active`. The runtime checks exact keys, strict boolean types, operation identity, success, and a 2048-byte response ceiling before a successful event or result is recorded. Raw stdout, stderr, client secrets, bootstrap tokens, backend environment content, and upstream errors never enter RPC results or events.

The runtime returns a closed result with the fixed procedure, target, operation, status, an optional readiness object, and `retry_requires_inspect`. A lost transport after channel or process creation, unknown exit status, capture failure, malformed response, or route deadline after creation is indeterminate. The operator must run `inspect` before any retry. There is no automatic replay. A nonzero write exit can follow partial host effects and therefore also requires inspection. Failure to publish the handler event or completion event preserves the closed uncertain result and suppresses tentative success events. A failure before channel or process creation reports a static failed result. A confirmed nonzero inspect exit reports a failed read without a write reconciliation requirement.

The route deadline encloses the host budget with 10 additional seconds. Process creation is tracked independently of response observation. The host helper serializes against deploy-control publication and concurrent IAM operations. The host helper owns private file validation, Keycloak client provisioning, certificate issuance and verification, and transactional nginx activation.

## Verification and deployment status

Tests cover fixed argv, production port preservation, all caller parameter refusal, target and fingerprint mutation, exact policy and approval, current strict credential resolution, unknown and oversized responses, secret output suppression, timeout and transport ambiguity, no replay, migration reapplication and reverse behavior, and plugin/runtime semantic alignment. The local cross-repository test also compares the frozen migration policy with the runtime policy. That cross-repository check is explicitly skipped when the companion catalog checkout is unavailable.

Source completion does not publish a package or activate this capability. The runtime must deploy before the plugin capability is used. The plugin migration must pass the repository's migration and release gates. The dedicated host helper and infrastructure must be reviewed and installed before an approved write can succeed. A root-owned bootstrap master administrator token is an external prerequisite for the first client setup when no dedicated credential exists. The helper does not reuse a restricted reconciler or registration credential.
