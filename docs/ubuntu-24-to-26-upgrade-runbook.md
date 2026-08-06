# Ubuntu 24.04 to 26.04 LTS Upgrade RPC Runbook

This runbook is for an operator-controlled, in-place Ubuntu LTS upgrade through
the audited `netbox-rpc` catalog. It does not authorize an upgrade, grant the
approval permission, or replace a tested recovery plan.

A kernel or network-stack failure can remove the SSH transport used by
netbox-rpc. Before any non-dry-run execution, confirm working out-of-band access
to the exact target through a console, IPMI, iDRAC, iLO, or the hypervisor
console. Do not proceed based only on SSH reachability.

## Procedure IDs

Resolve procedure primary keys immediately before the maintenance window:

```bash
ANALYZE_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=os.linux.ubuntu.24.upgrade_26.analyze_preupgrade | jq -r '.results[0].id')"
SAVE_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=os.linux.ubuntu.24.upgrade_26.save_preupgrade_state | jq -r '.results[0].id')"
UPGRADE_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=os.linux.ubuntu.24.upgrade_26.run_upgrade | jq -r '.results[0].id')"
VERIFY_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=os.linux.ubuntu.24.upgrade_26.verify_postupgrade | jq -r '.results[0].id')"
```

Handler IDs equal the procedure names. Analyze and verify are read-only;
save-state is an additive write; the upgrade is `effect="destructive"` and
`approval_required=True`.

## Do Not Run The Intent As An Ordered Workflow

The seeded **Update Ubuntu OS from 24 LTS to 26 LTS** intent declares the four
steps, but the v1 intent runner only creates child executions in sequence. RQ
workers can execute them concurrently. Do not use the intent `run/` action for
this maintenance operation. Dispatch each procedure below individually only
after reviewing and accepting the prior result.

## Operator Inputs

Set the target type and ID for the exact managed object. Use either
`dcim.device` or `virtualization.virtualmachine`.

```bash
TARGET_TYPE="dcim.device"
TARGET_ID="<target-object-id>"
```

Optional audited SSH overrides are available when the registered target does
not provide the intended connection: `rpc_ssh_credential_pk`, `rpc_ssh_host`,
`rpc_ssh_port`, `rpc_ssh_known_hosts_entry`, and
`rpc_ssh_strict_host_key_checking`. Do not place passwords, private keys, or
shell commands in parameters.

## Preconditions

- Confirm the target is Ubuntu 24.04 LTS and is the intended device or VM.
- Confirm tested backups or snapshots exist outside the guest and that the
  restore procedure is understood.
- Confirm working out-of-band console/IPMI access to the target.
- Reserve enough maintenance time for package downloads, upgrade work, service
  interruption, validation, and recovery.
- Confirm package repositories needed during the window are reachable.
- Identify applications, active users, scheduled jobs, and network paths that
  could be interrupted.
- Ensure the operator who will authorize the destructive step has the bounded
  `approve_rpcprocedure` permission for this task.

## 1. Analyze Pre-Upgrade State

```bash
nms rpc executions create \
  --procedure "$ANALYZE_PROCEDURE_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json '{}' \
  --wait
```

Do not continue unless the result is successful, `ready` is true, and every
reported blocker has been resolved. Review at least the current release and
kernel, root disk free space, held packages, third-party APT sources, pending
reboot state, active sessions, and cron jobs. If the host already requires a
reboot, perform and validate that reboot before starting the upgrade lifecycle.

## 2. Save Pre-Upgrade State

Use the backend default directory or choose a dedicated absolute path containing
only the catalog's safe path characters:

```bash
nms rpc executions create \
  --procedure "$SAVE_PROCEDURE_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json '{"backup_dir":"/var/backups/ubuntu-upgrade-26"}' \
  --wait
```

Record the returned `backup_dir`, `manifest_sha256`, and `files_backed_up` in
the maintenance record. Do not continue if the backup is incomplete, the
manifest is missing, or its location is not available from the recovery path.
This catalog backup supplements platform backups; it is not a full system
backup.

## 3. Run The Upgrade Dry-Run

The semantic default is `dry_run=true` and `reboot_after_upgrade=false`, but set
both explicitly for an auditable maintenance record:

```bash
nms rpc executions create \
  --procedure "$UPGRADE_PROCEDURE_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --yes-when-destructive \
  --params-json '{"dry_run":true,"reboot_after_upgrade":false}' \
  --wait \
  --timeout 7200
```

Use the normal NetBox approval flow. Review the dry-run result and upgrade log
tail, then resolve every new blocker. A successful dry-run is required but does
not itself authorize the live upgrade.

## 4. Run The Live Upgrade

Immediately before approval, reconfirm the exact target, platform backup,
pre-upgrade state backup, maintenance impact, and out-of-band console. Then
create a new execution with `dry_run=false`:

```bash
nms rpc executions create \
  --procedure "$UPGRADE_PROCEDURE_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --yes-when-destructive \
  --params-json '{"dry_run":false,"reboot_after_upgrade":false}' \
  --wait \
  --timeout 7200
```

Approve only after a human has reviewed that exact params object. Keeping
`reboot_after_upgrade=false` preserves the default safety boundary. Set it to
`true` only after a separate, explicit confirmation that the target may reboot
now and that guest/service downtime is accepted. If no automatic reboot is
requested, perform any required reboot through the approved operational path
and wait for SSH and critical services to return before verification.

## 5. Verify Post-Upgrade State

After the live upgrade and any required reboot have completed, run verification
with the expected release value selected by the operator:

```bash
nms rpc executions create \
  --procedure "$VERIFY_PROCEDURE_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json '{"expected_version_id":"26.04"}' \
  --wait
```

Confirm the parsed release matches the intended version, `apt_check_ok` and
`dpkg_audit_ok` are true, held packages are understood, and the reboot-pending
state matches the maintenance plan. Validate application health, monitoring,
networking, storage, and any workload-specific checks outside this generic OS
catalog before closing the window.

## Partial Failure Or Lost SSH

- Do not blindly rerun `run_upgrade`; an interrupted release upgrade may have a
  mixed package and repository state.
- Preserve the pre-upgrade backup directory, manifest, execution events, and
  bounded upgrade log output.
- If SSH is unavailable, use the pre-confirmed out-of-band console. Check boot,
  network interface naming/configuration, resolver state, routes, and package
  manager status before changing anything.
- If SSH remains available, inspect and repair the package state only through
  approved, audited operational procedures. Do not introduce ad-hoc shell text
  into RPC parameters.
- Use the platform backup/snapshot recovery plan if the host cannot be repaired
  safely. Restoring APT source files from `backup_dir` is an operator recovery
  decision; this v1 catalog does not provide an automatic rollback procedure.
- Run `verify_postupgrade` only after repair or restore has reached a stable
  state, and keep the maintenance incident open until application and network
  health are confirmed.
