# Ubuntu 26.04 Samba AD DC Bootstrap RPC Runbook

This runbook is for an operator-controlled bootstrap of the **first domain
controller of a new Active Directory domain** on a fresh Ubuntu Server 26.04 LTS
VM, through the audited `netbox-rpc` catalog. It does not authorize a run, grant
the approval permission, or replace a tested recovery plan.

The bootstrap is **not** a migration, repair, additional-DC join, or rerunnable
installer. There is no domain rollback. If a run fails, the recovery path is to
restore the VM snapshot taken before the run (see
[Failure handling](#failure-handling)).

## Procedures

| Procedure | Effect | Approval | Timeout | Purpose |
|---|---|---|---|---|
| `os.linux.ubuntu.26.samba_ad_dc.preflight` | read | no | 120s | Report whether the VM is a clean, supported candidate and return the values needed to fill in `provision`. |
| `os.linux.ubuntu.26.samba_ad_dc.provision` | **destructive** | **yes** | 3600s | Create the new domain, a private encrypted SMB3 share, the host firewall and Fail2ban. |
| `os.linux.ubuntu.26.samba_ad_dc.verify` | read | no | 180s | Credential-free post-install and post-reboot health report. |

Handler IDs equal the procedure names. All three target `dcim.device` or
`virtualization.virtualmachine`. The SSH destination is always derived from the
assigned NetBox object and its SSH `DeviceService`; `provision` accepts **no**
`rpc_ssh_*` override, so the execution always runs against the object named in
the request, and the normalized payload and command fingerprint bind that
object's content type and ID. `preflight` and `verify` accept the shared
optional overrides.

## Rollout status

Migration `0103` seeds the three rows **enabled** and transport-pinned to
AsyncSSH, with no separate code gate (the same as the Proxmox OCI pull). All three
names are in the explicit backend-capability registry, so until the selected
`netbox-rpc-backend` advertises a compatible capability for a handler, creation,
the `procedures/available` listing, approval and worker claim all fail closed.
The feature therefore starts working as soon as the paired backend release
advertises the handlers.

`provision` uses the catalog's **single-operator gate**: it is
`effect=destructive` with `approval_required=true`, so creating any execution
(dry runs included) requires the `approve_rpcprocedure` permission, but there is no
second approver, no `pending_approval` state and no mandatory dispatch lease. The
requester who holds the permission may approve their own run, and the run is
queued and enqueued immediately. The procedure is not on the protected two-person
path.

## What changes on the host

The bootstrap replaces or adds the following. Review this list before approving.

- **Packages:** Ubuntu `universe` is enabled and the Samba AD DC, Kerberos,
  chrony, nftables, Fail2ban and supporting packages are installed from Ubuntu
  repositories only. No PPA, `pip install` or source build is used. A backup of
  `/etc/apt` is taken first.
- **`/etc/hosts`:** replaced with the DC's FQDN and short name mapped to its IP.
- **`/etc/resolv.conf`:** replaced. During provisioning it points at the DNS
  forwarder; afterwards it points at the local Samba DNS (`127.0.0.1`).
  `systemd-resolved` is disabled and masked.
- **`/etc/nsswitch.conf`:** the `hosts:` line becomes `files dns`.
- **`/etc/krb5.conf`:** replaced with the file Samba generates for the domain.
- **chrony:** `/etc/chrony/chrony.conf` is replaced with the selected upstream
  plain-NTP sources (NTP.br by default, not NTS) and the Samba signed-NTP
  socket. `systemd-timesyncd` is disabled and masked.
- **Host firewall (nftables):** a restricted `inet samba_host` table with
  `input`/`forward` policy `drop` and `output` policy `accept`. AD, SMB and NTP
  are allowed only from the client networks; SSH is allowed only from the SSH
  allowlist. `/etc/nftables.conf` is replaced and `samba-ad-dc` is made to
  require `nftables.service`.
- **Fail2ban:** an anchored Samba SMB authentication-failure filter, a Samba
  JSON audit log with log rotation, an SMB jail, and an SSH jail only when SSH
  ports are configured. The filter is proven against a real failed login before
  the jails are activated.
- **AppArmor:** stays enabled. Scoped local rules are appended only to profiles
  that are actually installed (`usr.sbin.chronyd`, `usr.sbin.smbd`,
  `usr.sbin.samba`); no profile is created or disabled.
- **Samba:** a new domain is provisioned with mandatory SMB signing, a private
  share that requires SMB3 encryption, `follow symlinks = no`, guest access
  denied and `hosts allow`/`hosts deny` restrictions. The share ACL is set with
  native NT ACL handling for the domain Administrator only.
- **Cloud-init:** future cloud-init runs are disabled when `freeze_cloud_init`
  is true and cloud-init is present and ready. Existing users, keys and Netplan
  files are kept.
- **Timezone:** set to the requested `timezone`.

**Netplan, IP addresses, routes, gateways and disks are never modified and
`netplan apply` is never run.** Proxmox, router and other network firewalls are
not modified. UFW, if installed, must be inactive and unconfigured and remains
inactive.

## Prerequisites

- A **fresh, dedicated** Ubuntu Server 26.04 LTS VM with a booted systemd, one
  persistent **static** IPv4 address managed by Netplan/networkd (not DHCP, not
  NetworkManager, not a bridge or bond), and working Internet and DNS.
- **A VM snapshot taken immediately before the live run**, and working console
  access to the VM (for example the Proxmox console). Firewall rules are applied
  on a host you may be connected to over SSH.
- No existing Samba data or configuration, no `resolvconf`/`openresolv`, no
  active or configured UFW, `firewalld`, Fail2ban or nftables policy, and no
  existing `/etc/fail2ban` directory.
- The target registered in NetBox as a `dcim.device` or
  `virtualization.virtualmachine` with an enabled SSH `DeviceService` whose
  credential and pinned host key work.
- A `netbox-nms` **`DeviceCredential`** holding the NEW domain Administrator
  password, created through the NetBox UI. The password is referenced only by the
  credential's primary key (`admin_credential_pk`); it must never appear in RPC
  parameters, operator notes, shell history, chat, tickets or logs. Choose a
  password of at least 12 characters (at most 512 UTF-8 bytes) with at least
  three of upper case, lower case, digits and symbols that does not contain the
  word `Administrator`; the installer also enforces Samba's own complexity check.
- An operator holding the `execute_rpcprocedure` and `approve_rpcprocedure`
  permissions (the single-operator gate). Do not request or use the approval
  permission autonomously.

## Operator inputs

```bash
TARGET_TYPE="virtualization.virtualmachine"   # or dcim.device
TARGET_ID="<target-object-id>"
PREFLIGHT_ID="$(nms rpc procedures list --json --filter name=os.linux.ubuntu.26.samba_ad_dc.preflight | jq -r '.results[0].id')"
PROVISION_ID="$(nms rpc procedures list --json --filter name=os.linux.ubuntu.26.samba_ad_dc.provision | jq -r '.results[0].id')"
VERIFY_ID="$(nms rpc procedures list --json --filter name=os.linux.ubuntu.26.samba_ad_dc.verify | jq -r '.results[0].id')"
```

Resolve the identifiers immediately before the maintenance window. Never place
passwords, private keys or shell commands in parameters.

## Workflow

### 1. Preflight

```bash
nms rpc executions create \
  --procedure "$PREFLIGHT_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json '{}' \
  --wait
```

Do not continue unless `ok` is true and every verdict is resolved. Use the
`detected` block to fill in the plan: `ipv4` becomes `ip`,
`suggested_forwarder` becomes `forwarder`, `suggested_client_subnet` is the
default `client_networks`, and `ssh_ports` lists the ports that must stay open.
`cloud_init.freeze_required` tells you whether `freeze_cloud_init` applies.

### 2. Provision with `dry_run` (the default)

`dry_run` defaults to **true**. A dry run validates every setting, repeats the
preflight verdicts, and returns the full plan and rendered configuration
(`rendered_configs`) with no change to the host. Required parameters are
`domain`, `netbios`, `hostname`, `ip`, `forwarder` and `client_networks`.

```bash
PARAMS='{
  "domain": "ad.example.com",
  "netbios": "EXAMPLE",
  "hostname": "ad01",
  "ip": "10.0.30.10",
  "forwarder": "10.0.30.1",
  "client_networks": ["10.0.30.0/24"],
  "ssh_ports": [22],
  "ssh_networks": ["10.0.50.0/24"]
}'
nms rpc executions create \
  --procedure "$PROVISION_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json "$PARAMS" \
  --wait
```

Review the plan and every rendered file with the operator. Confirm the SSH source
allowlist covers the address the netbox-rpc backend connects from, as seen by
the VM.

`provision` is `approval_required`, and that flag applies to the whole
procedure, so **even the dry run needs the `approve_rpcprocedure` permission**.
Review the dry-run result before requesting the live run.

### 3. Operator confirmation

Take the pre-run VM snapshot now. Then request the live run by adding
`"dry_run": false` and `"admin_credential_pk": <id>` to the same parameters.

There is no second approver: the requester holding `approve_rpcprocedure` creates
the execution and it is queued and enqueued immediately. The confirmation is
therefore an operational step before submitting the request: review the exact
parameters and the dry-run plan with the system owner, confirm the snapshot and
console access, and submit only with their explicit in-session approval. An LLM
agent must not create or dispatch this execution autonomously.

A live run requires all of the following, and the request is refused otherwise:

- `admin_credential_pk`, referencing the Administrator password credential;
- a non-empty `ssh_ports` that includes the port the executing SSH session uses,
  and a non-empty `ssh_networks` that covers that session's source address. The
  installer proves this from the executing SSH session before it changes the
  firewall and fails closed if the proof is not possible.

### 4. Live provision

Approved, the run takes up to an hour. The stages are: prerequisite checks and
package installation, an immediate Administrator password quality check, host
firewall application with a 300-second rollback timer, confirmation of the
firewall over a **new** SSH connection, time synchronization, domain
provisioning, share and Fail2ban configuration, and end-to-end verification.

The firewall is confirmed only after the backend opens a fresh SSH connection
and proves it can log in through the new rules; an already-established session
survives the firewall through connection tracking and proves nothing. If the
proof fails, only the firewall is rolled back and the run stops before any
Samba service listens on the network.

Success reports `ok=true`, `stage="complete"`, `firewall.confirmed=true`, at least
one entry in `checks[]`, the `installer_sha256` and a bounded `log_tail`; the
result schema rejects a live success without all of these. A dry-run success
needs `stage` and `plan`; any failure needs `stage` and `rerunnable=false`. No password or hash appears anywhere in
parameters, events, results or logs.

### 5. Verify, and again after a reboot

```bash
nms rpc executions create \
  --procedure "$VERIFY_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json '{}' \
  --wait
```

`verify` is credential-free. It reports the state of `samba-ad-dc`, `chrony`,
`nftables` and `fail2ban`, `testparm -s`, `samba-tool dbcheck --cross-ncs`,
`ntacl sysvolcheck`, the domain DNS SRV records on `127.0.0.1`, chrony
tracking, the `inet samba_host` table and the Fail2ban jails. Run it once right
after the install and again after the first reboot.

## Failure handling

The bootstrap is not rerunnable and there is no domain rollback. A failed
`provision` result reports `ok=false`, the last `stage` reached, an `error_code`,
a bounded `error`, and `rerunnable=false`: the run cannot be retried.

1. **Do not rerun `provision` and do not delete Samba data.**
2. Read the result and the events; if the firewall was not confirmed, it was
   rolled back by the installer and the 300-second timer is only a fallback.
3. **Restore the VM snapshot taken before the run** (or repair the reported
   cause manually from the VM console), then start again from `preflight`.
4. A confirmed firewall is kept even when a later step fails. If the firewall
   must be removed in an emergency, use the **VM console** — the run leaves a
   root-only rollback script and the location of its backup directory in the
   result (`backup_dir`). That restores the initially unfiltered state; repair or
   reapply the firewall afterwards.
5. If `preflight` reports an existing Samba installation, an active firewall or
   any other non-clean condition, stop. The bootstrap refuses to run against an
   existing domain.

Configuration backups under `backup_dir` protect the host files only; they are
**not** an Active Directory or data backup.

## Parameter reference (`provision`)

| Parameter | Default | Rule |
|---|---|---|
| `dry_run` | `true` | Boolean. `false` requires `admin_credential_pk`, `ssh_ports` and `ssh_networks`. |
| `domain` | required | At least two DNS labels, at most 237 characters, not `.local`, last label not all digits. Lower-cased. |
| `netbios` | required | 1-15 characters, letter first, letter or digit last. Upper-cased. |
| `hostname` | required | Same pattern as `netbios`; lower-cased; must differ from `netbios` ignoring case. |
| `ip` | required | Routable unicast IPv4 (private allowed); must equal the VM's current address. |
| `forwarder` | required | Upstream DNS IPv4 with the same rules; must not equal `ip`. |
| `client_networks` | required | 1-16 unique strict IPv4 CIDRs with an explicit prefix; not `/0`, loopback, multicast or link-local. |
| `ntp_servers` | `a.ntp.br`, `b.ntp.br`, `c.ntp.br` | 1-8 unique DNS names or unicast IPs. |
| `timezone` | `America/Sao_Paulo` | Relative identifier; verified against the host's zoneinfo. |
| `share_name` | `shared` | Letter first, at most 64 characters; `global`, `homes`, `printers`, `sysvol`, `netlogon`, `ipc`, `admin` are reserved (any case). |
| `share_path` | `/srv/samba/<share_name>` | Below `/srv`, no `.` or `..` components; must be absent or empty on the host. |
| `ssh_ports` | `[]` | 0-16 unique ports; never a Samba AD service port. `[]` opens no SSH port and disables the SSH jail (dry run only). |
| `ssh_networks` | `[]` | 0-32 strict IPv4/IPv6 hosts or CIDRs, no scope ids; non-empty if and only if `ssh_ports` is non-empty. |
| `ban_exempt_networks` | `[]` | 0-32 additional Fail2ban never-ban hosts/CIDRs. Do not exempt the whole client LAN. |
| `fail2ban_findtime` | 600 | 60-86400 seconds. |
| `smb_max_retry` / `smb_bantime` | 10 / 900 | 3-100 failures / 60-86400 seconds. |
| `ssh_max_retry` / `ssh_bantime` | 5 / 3600 | 3-100 failures / 60-86400 seconds. |
| `legacy_netbios` | `false` | Also allow UDP 137/138 and TCP 139. |
| `freeze_cloud_init` | `true` | Disable future cloud-init runs. `false` with a ready cloud-init fails closed on the host. |
| `admin_credential_pk` | none | `DeviceCredential` id of the new Administrator password; the only credential-shaped input. |

Unknown parameters are rejected. There is no `password`, hash, command or shell
parameter, and a value that looks like one is refused before anything is stored.

## Security properties

- The Administrator password never enters params, events, results, logs or
  argv. The execution backend resolves it from the credential reference at run
  time and delivers it to the installer over stdin, never on disk.
- The installer program is uploaded to a root-only path, its SHA-256 is verified
  against a pinned constant, and it runs with fixed argv. No caller text reaches
  a shell.
- Core dumps are disabled, the process umask is `077`, and inherited password
  environment variables are stripped.
- The normalized payload and command fingerprint carry every concrete resolved
  setting and the exact assigned object (content type and ID), and differ between
  a dry run and a live run.
- The result contains no secret and every free-form string is length-bounded.

## Frozen bindings and credential authorization

Creation and worker claim each normalize the request, and the backend re-checks
the same values at run time. For `provision` the normalized payload and command
fingerprint additionally freeze:

- `ssh_snapshot`: the resolved SSH destination (host, port), the SHA-256 of the
  pinned host-key entry, the SSH service id and revision, the SSH login identity id
  and revision and its principal and method (non-secret), plus
  `ssh_strict_host_key_checking=true` and `ssh_policy_ref`
  (`target-owned-ssh:<content type>:<object id>`). A changed host, port, host key,
  service or login credential between request and dispatch is refused.
- `admin_credential_snapshot`: the Administrator credential id and its revision
  (`last_updated`). A rotated credential is refused.

Because creation runs the normalizer inside the creation transaction, an unusable
SSH destination, host key or credential fails the request with a clear error
before anything is queued.

`admin_credential_pk` is authorized, without reading or decrypting any secret, for
the requester at creation and again at worker claim: the
`netbox-nms` `DeviceCredential` must exist and be viewable by that actor through
NetBox object permissions, be a locally stored password credential with stored
material, and differ from the target's SSH login identity. `DeviceCredential` has
no per-target binding, so view permission is the strongest expressible rule. An actor who cannot view it, a missing
`netbox-nms`, or any other violation is refused with a clear error.

## Capability attestation and updating the installer

The capability hash of all three handlers includes a semantic contract that pins
the installer program digest, the stdin protocol version and modes, the firewall
proof and result protocols, and the catalog policy with the params and result
schema hashes (`netbox_rpc/samba_ad_dc_capability_contract.py`). The backend
reproduces it byte for byte; `tests/fixtures/samba_ad_dc_capability_contract.json`
holds the expected hashes that both repositories assert.

To ship a new installer: change `INSTALLER_SHA256` (and the protocol constants if
they changed) in `samba_ad_dc_capability_contract.py`, regenerate the fixture with
`python tests/test_samba_ad_dc_capability_contract.py --write-fixture`, and pin the
same digest in `netbox_rpc_backend/rpc/samba_ad_dc.py`. No migration is needed
because the digest is not stored in the database. Until both sides agree, the
advertised hash differs and dispatch fails closed with a capability mismatch.

## Migration compatibility attestation

The compatibility policy row for `0103_seed_ubuntu_26_samba_ad_dc_procedures` is
`true` because the migration is a single data-only `RunPython`: it creates three
catalog rows and one command row each (refusing to overwrite drifted existing rows)
and its reverse only sets `enabled=False`. It alters no schema, removes no field,
renames nothing and deletes no audited history, so an older plugin version that
does not know the rows continues to run unchanged.

## Limitations

- The DC and the data share are on the same VM; separate these roles for
  production use.
- **Concurrency fence:** creating a `provision` is refused (400) while another
  `requested`, `pending_approval`, `approved`, `queued` or `running` provision
  exists for the same target object, because the bootstrap is not rerunnable.
- **SSH prerequisites of the frozen binding:** the target must have exactly one
  enabled SSH `DeviceService` on port 22 with strict host-key checking and one
  pinned `ssh-ed25519` known-hosts entry for its management address, and its
  primary IPv4 must equal the `ip` parameter. These are the same rules as the
  Akvorado and Gitea protected procedures.
- **No result after a transport failure:** a failure or timeout after dispatch
  surfaces as a generic failed execution without a result. Because the bootstrap is
  not rerunnable, inspect the host state and restore the VM snapshot before any
  further attempt.
- Only a single Netplan/networkd Ethernet configuration is supported.
- AD service access over IPv6 is not enabled; SSH IPv6 sources may be allowed.
- The share is administrator-only. Create least-privilege users and groups and
  revise the share's `valid users` list and ACLs before everyday use.
- Do not clone or template a provisioned DC.
