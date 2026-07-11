# Passbolt CE Docker To Native VM Migration RPC Runbook

This runbook is for the one-time operator-driven migration of an existing
Passbolt CE Docker deployment into an already-provisioned native VM. It creates
approval-gated `netbox-rpc` executions only. It does not grant approval and it
does not make any migration decision automatically.

Never place real secret contents in `params`, shell history, PRs, issues, logs,
or comments. These procedures return only paths, byte sizes, sha256 checksums,
and status booleans. They never return database dump contents, GPG key material,
JWT key material, or caller-supplied passwords.

## Procedure IDs

The CLI accepts the NetBox procedure primary key, not the dotted procedure name.
Resolve the IDs immediately before running the migration:

```bash
EXPORT_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=services.passbolt.export_secrets | jq -r '.results[0].id')"
TRANSFER_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=services.passbolt.transfer_secrets | jq -r '.results[0].id')"
IMPORT_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=services.passbolt.import_secrets | jq -r '.results[0].id')"
CLEANUP_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=services.passbolt.cleanup | jq -r '.results[0].id')"
```

Expected procedure and handler IDs:

| Procedure | Handler |
| --- | --- |
| `services.passbolt.export_secrets` | `services.passbolt.export_secrets` |
| `services.passbolt.transfer_secrets` | `services.passbolt.transfer_secrets` |
| `services.passbolt.import_secrets` | `services.passbolt.import_secrets` |
| `services.passbolt.cleanup` | `services.passbolt.cleanup` |

All four procedures are `effect="destructive"` and `approval_required=True`.
After each `nms rpc executions create` command, approve the execution through
the NetBox RPC approval flow before it will run.

## Operator Inputs

Fill these values at runtime. Do not hardcode them in docs, code, or wrapper
scripts.

| Placeholder | Meaning |
| --- | --- |
| `<source-docker-host>` | SSH hostname or IP of the Passbolt Docker host |
| `<source-credential-pk>` | `netbox-nms.DeviceCredential` PK for source host SSH |
| `<source-app-container>` | Passbolt application container name |
| `<source-db-container>` | Database container name used for `mysqldump` |
| `<source-db-name>` | Passbolt database name |
| `<source-db-host>` | DB host as seen from the DB container |
| `<source-db-port>` | DB port as seen from the DB container |
| `<source-db-user-env>` | Environment variable name inside the DB container holding the DB user |
| `<source-db-password-env>` | Environment variable name inside the DB container holding the DB password |
| `<source-staging-dir>` | Absolute staging directory on the source host |
| `<target-host>` | Target VM SSH host, for example `10.0.30.121` |
| `<target-ssh-user>` | SSH user the source host uses for rsync/cleanup to the target |
| `<target-ssh-port>` | SSH port for the target host |
| `<target-staging-dir>` | Absolute staging directory on the target VM |
| `<target-credential-pk>` | `netbox-nms.DeviceCredential` PK for target VM SSH |
| `<target-db-name>` | Native MariaDB Passbolt database name |

Optional path params have documented defaults:

| Param | Default |
| --- | --- |
| `gpg_dir` | `/etc/passbolt/gpg` inside the source app container or volume |
| `jwt_dir` | `/etc/passbolt/jwt` inside the source app container or volume |
| `gpg_dest_dir` | `/etc/passbolt/gpg` on the target VM |
| `jwt_dest_dir` | `/etc/passbolt/jwt` on the target VM |
| `cake_bin_path` | `/usr/share/php/passbolt/bin/cake` on the target VM |

## Preconditions

- The target VM is already provisioned with native Passbolt CE, MariaDB, and the
  expected Passbolt filesystem layout.
- The source host can SSH to the target host as `<target-ssh-user>` for rsync
  and cleanup. Migration file bytes travel source-host to target-host over
  rsync/ssh; they are not routed through nms-backend or stored by netbox-rpc.
- The DB container exposes the DB user/password in environment variables named
  by `db_user_env` and `db_password_env`.
- Staging directories are dedicated migration directories, not broad system
  directories such as `/`, `/tmp`, `/var/tmp`, or `/etc`.
- The operator has reviewed and is ready to approve each destructive execution.

## 1. Export On Source Docker Host

Creates `<source-staging-dir>/db.sql`, `<source-staging-dir>/gpg.tar`, and
`<source-staging-dir>/jwt.tar` on the source Docker host.

```bash
nms rpc executions create \
  --procedure "$EXPORT_PROCEDURE_ID" \
  --yes-when-destructive \
  --params-json '{"rpc_ssh_host":"<source-docker-host>","rpc_ssh_credential_pk":<source-credential-pk>,"app_container_name":"<source-app-container>","db_container_name":"<source-db-container>","db_name":"<source-db-name>","db_host":"<source-db-host>","db_port":<source-db-port>,"db_user_env":"<source-db-user-env>","db_password_env":"<source-db-password-env>","gpg_dir":"/etc/passbolt/gpg","jwt_dir":"/etc/passbolt/jwt","staging_dir":"<source-staging-dir>"}'
```

Approve this execution in NetBox. After completion, confirm the returned paths,
byte sizes, and sha256 checksums look sane. Do not expect or request file
contents.

## 2. Transfer Source Staging Files To Target VM

Runs rsync from the source host to the target host. The backend connects only to
the source host; the source host performs the target SSH connection.

```bash
nms rpc executions create \
  --procedure "$TRANSFER_PROCEDURE_ID" \
  --yes-when-destructive \
  --params-json '{"rpc_ssh_host":"<source-docker-host>","rpc_ssh_credential_pk":<source-credential-pk>,"source_staging_dir":"<source-staging-dir>","target_host":"<target-host>","target_ssh_user":"<target-ssh-user>","target_ssh_port":<target-ssh-port>,"target_staging_dir":"<target-staging-dir>"}'
```

Approve this execution in NetBox. After completion, compare source and target
sha256 values in the result; all three checksums must match before import.

## 3. Import On Target Native VM

Imports `db.sql` into local MariaDB, extracts GPG/JWT archives, applies
`www-data:www-data` ownership and locked-down permissions, then runs Passbolt CE
migrate and healthcheck as `www-data`.

```bash
nms rpc executions create \
  --procedure "$IMPORT_PROCEDURE_ID" \
  --yes-when-destructive \
  --params-json '{"rpc_ssh_host":"<target-host>","rpc_ssh_credential_pk":<target-credential-pk>,"staging_dir":"<target-staging-dir>","db_name":"<target-db-name>","gpg_dest_dir":"/etc/passbolt/gpg","jwt_dest_dir":"/etc/passbolt/jwt","cake_bin_path":"/usr/share/php/passbolt/bin/cake"}'
```

Approve this execution in NetBox. The result reports only migrate and
healthcheck status. If healthcheck fails, inspect the target VM manually through
the approved operations path; do not rerun cleanup until the operator decides
the staged artifacts are no longer needed.

## 4. Cleanup Staging Directories

Run cleanup only after a successful migration and operator confirmation that the
staged files can be removed from both hosts.

```bash
nms rpc executions create \
  --procedure "$CLEANUP_PROCEDURE_ID" \
  --yes-when-destructive \
  --params-json '{"rpc_ssh_host":"<source-docker-host>","rpc_ssh_credential_pk":<source-credential-pk>,"source_staging_dir":"<source-staging-dir>","target_host":"<target-host>","target_ssh_user":"<target-ssh-user>","target_ssh_port":<target-ssh-port>,"target_staging_dir":"<target-staging-dir>"}'
```

Approve this execution in NetBox. The result reports only whether the source and
target cleanup commands completed.
