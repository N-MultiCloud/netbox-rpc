# Gitea user CI runner diagnosis and recovery

Migration `0091` seeds two disabled procedures for the existing user-scoped
Docker runner lane on exact `virtualization.virtualmachine` PK 604,
`Gitea-Runner`:

- `service.gitea.actions_runner.diagnose_user_ci_runner` v1 is read-only and
  does not require approval.
- `service.gitea.actions_runner.recover_user_ci_runner` v1 is a write and
  requires the protected two-person approval and signed-dispatch-lease path.

Both procedures accept exactly `{}`. The caller cannot select a host, SSH
credential, command, service, container, lane, resolver, path, or network.
Admission validates the exact active VM and view permission. Normalization
resolves the sole enabled target-owned SSH service and records only its
non-secret service/credential IDs and revisions, principal, method, canonical
primary IPv4 host, port, known-host digest, storage backend, and policy
reference. That snapshot and its digest are included in normalized params, the
command fingerprint, the approval snapshot, and the signed dispatch lease. The
backend resolves secrets only through `get_approved_target_ssh_credentials`
and rejects service, credential, host, port, principal, method, or host-key
drift before SSH. Inventory comments and descriptions are never read,
normalized, logged, or included in approval evidence.

The backend owns all executable policy. It inspects only the fixed
`user-ubuntu` lane, Compose project `/opt/nmc-ci-ubuntu-user-241`, runner
identity `ci-ubuntu-emersonfelipesp-241`, and unit
`gitea-runner-ubuntu-user-241.service`. Results are closed schemas with bounded
lists and strings. Plugin transport is redirect-free and capped at 65,536
bytes; backend events and free-form backend errors are discarded.

Recovery additionally requires a fixed authenticated Gitea runner-control-plane
current-held-task check to agree with Docker evidence before every mutation.
The paired backend repository currently has no approved user-scoped Gitea API
credential provider/client for this check. Its production seam therefore
returns unknown, recovery returns a closed `indeterminate` result before any
mutation, and the catalog row must remain disabled. The backend advertises the
diagnosis capability but omits recovery; the plugin therefore rejects recovery
at advertisement, admission, and worker claim. Recovery may be advertised only
after both the fixed authenticated client and one host-side lock spanning the
complete mutation transaction exist. Activation requires a
fixed client for the held-task state of
`ci-ubuntu-emersonfelipesp-241`; it must accept no caller URL, token, runner, or
scope. A held task refuses recovery even without a job container. Unknown or
disagreeing control-plane/Docker evidence is indeterminate.

After that dependency is implemented, recovery fails closed when a job is
active before or after the runner pause.
It may remove only `GITEA-ACTIONS-TASK-` networks proven to have zero attached
containers. It may reconcile Docker daemon DNS only to the ordered pair
`168.0.96.26`, `168.0.96.27`, and restart only the fixed runner unit. Existing
Docker `default-address-pools` are diagnostic evidence and are never rewritten.
The backend preserves per-job container isolation and accepts no caller data in
its fixed argv. Cancellation cleanup is bounded and awaited to a terminal
outcome; a route deadline after pause or mutation produces a schema-valid
`indeterminate` result.

Both catalog rows are capability-gated at advertisement, admission, and worker
claim. Their required v1 capability hashes are:

- diagnose: `8e9a33d189f2850e95a77965505cb7e2625ba20c642fc22c7326812bdadb9e7f`
- recover: `4597aaf1d59c1fc554a3993316ea85444e4673801ea133ebc04c33fcd375da20`

An operator may enable diagnosis only after the selected backend advertises its
exact hash. Recovery additionally requires the authenticated held-task client
and whole-transaction host-lock dependencies above; capability hash agreement
alone is insufficient. Reversing migration `0091` disables both rows without deleting
procedures, commands, executions, approvals, leases, or event history.
