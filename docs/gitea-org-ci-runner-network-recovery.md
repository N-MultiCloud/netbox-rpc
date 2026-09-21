# Gitea organization CI runner Docker-network recovery

Migration `0092` seeds two disabled procedures for the existing organization
Docker runner lane on exact `virtualization.virtualmachine` PK 604,
`Gitea-Runner`:

- `service.gitea.actions_runner.diagnose_org_ci_runner` v1 is read-only and
  does not require approval.
- `service.gitea.actions_runner.recover_org_ci_runner` v1 is a write and
  requires the protected two-person approval and signed-dispatch-lease path.

Both procedures accept exactly `{}`. The caller cannot select a host,
credential, command, runner, service, path, container, or network. Admission
validates the exact active VM and view permission. Normalization resolves the
sole enabled target-owned SSH service and binds its complete non-secret
service, credential, host, port, principal, method, revision, and host-key
snapshot into the command fingerprint, approval snapshot, and signed lease.
The backend must reject point-of-use drift.

The executable policy is fixed to lane `general-ubuntu`, runner
`ci-ubuntu-nmulticloud-org-241`, Compose directory
`/opt/nmc-ci-ubuntu-241`, service `runner`, systemd unit
`gitea-runner-ubuntu-241.service`, and image
`nmulti/gitea-act-ubuntu:22.04-actions`. Diagnosis reports bounded Docker,
runner, default-address-pool, matching-network, active-job, exhaustion, and
last-activity evidence through a closed response schema.

Recovery addresses only the Docker error `all predefined address pools have
been fully subnetted`. Before every removal, authenticated Gitea
current-held-task evidence and Docker evidence must independently prove the
fixed runner idle. The backend may then remove only networks whose names start
with `GITEA-ACTIONS-TASK-` and whose attachment count is zero. Unknown,
disagreeing, truncated, or active-job evidence fails closed without removal.
Recovery never changes Docker address pools or DNS, pauses or restarts the
runner, mutates containers, or touches any other network.

Both rows require exact backend capabilities at advertisement, admission, and
worker claim. Their v1 capability hashes are:

- diagnose: `2d98c0b205623df33114a623de8ec24a328c9ae1f86add08cfd9876395ce2abc`
- recover: `e7ff9405ed45f0eff23260fc111af93afddd06a11c852ed03ccab729fce3dd7b`

Keep both rows disabled until the selected backend advertises the exact hash
and its fixed authenticated Gitea client and whole-transaction host lock are
deployed. Enable and run diagnosis first. Enable recovery only when that
diagnosis identifies idle matching networks and the address-pool exhaustion
condition, then create and separately approve a recovery execution through the
normal `nms rpc` procedure and execution-history surfaces. Reversing migration
`0092` disables both rows without deleting procedures, commands, executions,
approvals, leases, or event history.
