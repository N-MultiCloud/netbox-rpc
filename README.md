# netbox-rpc

`netbox-rpc` is the NetBox source of truth for N-MultiCloud RPC procedures.
It stores procedure policy, JSON schemas, execution records, and audit events.
The plugin does not open SSH sessions directly; execution is delegated to
`nms-backend`, which runs hard-coded handler IDs against credentials owned by
`netbox-nms`.

The procedure catalog is intentionally narrow:

- `network.device.huawei.olt.ma5800.r024.start_ont`
- `network.device.dell_os10.s5232f_on.bootstrap_restconf`
- `network.device.dell_os10.s5232f_on.show_version`
- `network.device.dell_os10.s5232f_on.set_interface_description`
- `network.device.dell_os10.s5232f_on.set_vlan_description`
- `network.device.dell_os10.s5232f_on.write_memory`
- `os.linux.ubuntu.24.restart_service`
- `os.linux.proxmox.convert_mellanox_nic_to_ethernet`
- `services.pterodactyl.bootstrap_api_key`
- `services.pterodactyl.artisan`
- `services.pterodactyl.container_logs`

Operators call named procedures, not arbitrary SSH commands.

### `os.linux.proxmox.convert_mellanox_nic_to_ethernet`

Converts Mellanox ConnectX-3 (`mlx4`) NIC ports from InfiniBand to Ethernet on a
Proxmox host. Unlike the Ubuntu procedures, this one targets a **netbox-proxbox
`ProxmoxEndpoint`** (`target_models = ["netbox_proxbox.proxmoxendpoint"]`). SSH
connection details are resolved at execution time through the **netbox-nms
`ProxmoxEndpointSSHBinding`** via `netbox_nms.proxmox_ssh.resolve_proxmox_endpoint_ssh()`
(a function-local import — `netbox-rpc` never imports `netbox-proxbox`). The
normalizer emits the `rpc_ssh_host` / `rpc_ssh_port` / `rpc_ssh_credential_pk` /
`rpc_ssh_known_hosts_entry` / `rpc_ssh_strict_host_key_checking` host-override
keys that `nms-backend` consumes, plus the behaviour flags `reboot`,
`apply_network`, `interfaces_content`, and `dry_run`, and the operator bond
parameters `bond_name` (default `bond1`), `bond_vlans` (optional comma-separated
VLAN IDs/ranges 1-4094, emitted as `bridge-vids`; empty default declares no VLAN
filtering), and `bond_mtu` (default jumbo `9216`, allowed 576-9216) — accepted by
the `params_schema` since migration `0010` and re-validated strictly by
`nms-backend` before any shell embedding. `effect="destructive"` and
`approval_required=True`. Seeded by migration `0008`; handler
`os.linux_proxmox.convert_mellanox_nic_to_ethernet` lives in `nms-backend`.

### Pterodactyl Panel procedures

Three procedures for managing a Pterodactyl Panel Docker deployment via SSH to
the container host. Seeded by migration `0016`. Target models: `dcim.device`
and `virtualization.virtualmachine`.

**`services.pterodactyl.bootstrap_api_key`** — runs `php artisan about
--no-interaction` (falling back to `php artisan --version`) inside the
container. Verifies that the Panel application is operational. Optional
`container_name` (default `pterodactyl-panel-1`). `approval_required=True`.
Handler ID: `services.pterodactyl.bootstrap_api_key` (in `nms-backend`).

**`services.pterodactyl.artisan`** — runs one allowlisted Laravel Artisan
command inside the container. Required `command` param; accepted values:
`queue:status`, `schedule:run`, `cache:clear`, `config:clear`,
`queue:restart`, `migrate`. The allowlist is enforced by the normalizer
(`_PTERODACTYL_ARTISAN_ALLOWLIST` in `jobs.py`) and again by the Pydantic
schema in `nms-backend`. Disallowed commands raise
`RPCExecutionError(code="RPC_PARAM_INVALID")`. Optional `container_name`
(default `pterodactyl-panel-1`). `approval_required=False`. Handler ID:
`services.pterodactyl.artisan` (in `nms-backend`).

**`services.pterodactyl.container_logs`** — runs `docker logs --tail <N>
<container>` on the SSH host to retrieve recent log output. Optional
`container_name` (default `pterodactyl-panel-1`); optional `lines`
(1–500, default 100; values outside that range are clamped, not rejected).
`approval_required=False`. Handler ID: `services.pterodactyl.container_logs`
(in `nms-backend`).

## Architecture

```text
Client / nms UI
  -> netbox-rpc API
  -> NetBox RQ job
  -> nms-backend /rpc/executions/{execution_id}/run
  -> AsyncSSH or Scrapli executor
  -> network device or Linux host
```

`netbox-rpc` is deliberately the source of truth, not the SSH runtime. It
owns:

- procedure names, handler IDs, categories, and enabled/approval policy;
- JSON request and response schemas used to validate procedure parameters;
- execution records, normalized parameters, status, results, errors, and audit
  events;
- NetBox job orchestration that delegates execution to `nms-backend`.

`nms-backend` owns the hard-coded handler implementations and transport
libraries. It must execute only known handler IDs such as
`network.huawei_olt_ma5800_r024.start_ont` and
`network.dell_os10_s5232f_on.bootstrap_restconf` and
`os.linux_ubuntu_24.restart_service`.

`netbox-nms` owns SSH connection material through `DeviceService` rows with
`service_type="ssh"`. Those rows provide the management host, port, linked
`DeviceCredential`, `ssh_known_hosts_entry`, and
`ssh_strict_host_key_checking` values consumed by `nms-backend`.
Per-service Linux allowlist entries may set `ssh_credential_override` to a
`netbox-nms.DeviceCredential`; when present, the normalized execution params
include `rpc_ssh_credential_pk` so `nms-backend` fetches that credential by PK
instead of resolving SSH credentials by device name.

## Procedure Naming

Procedure names are canonical dotted strings:

| Domain | Shape | Example |
| --- | --- | --- |
| Operating system | `os.<family>.<distro>.<version>.<action>` | `os.linux.ubuntu.24.restart_service` |
| Network hardware | `network.device.<manufacturer>.<device-family>.<model>.<version>.<action>` | `network.device.huawei.olt.ma5800.r024.start_ont` |

The public contract is the procedure name plus validated parameters. API
clients must not submit arbitrary SSH command text.

## Security Rules

- Never add a procedure that stores user-provided shell commands.
- Dell OS10 procedures are fixed command templates used only as RESTCONF
  fallback/bootstrap paths. The RESTCONF automation user password is resolved
  in `nms-backend` from `restconf_credential_pk`; it must not be stored in
  `normalized_params` or `command_fingerprint`.
- Prefer enum or allowlist parameters for command fragments such as service
  names, board/slot identifiers, or ONT IDs.
- Keep SSH credentials in `netbox-nms`; this plugin stores execution metadata,
  not private keys or passwords.
- Keep strict host-key checking enabled unless an operator explicitly disables
  it for a lab or migration case.
- Treat stdout and stderr as audit data. Store full output only where policy
  allows; otherwise store redacted summaries or hashes in future extensions.

## API Validation

`RPCExecutionViewSet.create()` enforces three guards before an execution
record is created and the RQ job is enqueued:

1. **Enabled** — disabled procedures are rejected (HTTP 400).
2. **Approval** — procedures with `approval_required=True` require the caller
   to hold `netbox_rpc.approve_rpcprocedure`.
3. **Params schema** — when a procedure defines `params_schema`, submitted
   `params` are validated against the JSON Schema before proceeding.

These guards run at the API layer, not the model layer, because the serializer
receives the procedure as a foreign-key ID and the schema/enabled/approval
checks require the resolved object.

RPC execution jobs are queued without using NetBox's attached-object job fields.
NetBox 4.6 validates attached job object types against the `jobs` feature, and
`RPCExecution` is audit metadata rather than a job-capable operational object.
The worker receives the execution primary key through `execution_pk` and
persists it in the job `data` JSON for retry/debug recovery.

## Admin Form Security

NetBox edit views attach the active request to RPC form instances so form-level
security policy can evaluate the requesting user. `RPCProcedureForm` blocks
changing an existing procedure from `approval_required=True` to `False` unless
the user has `netbox_rpc.approve_rpcprocedure`. `RPCLinuxServiceAllowlistForm`
scopes `ssh_credential_override` choices with
`DeviceCredential.objects.restrict(user, "view")` and falls back to an empty
queryset if no request context is available.

## Testing

Default tests are static or mocked:

```bash
python -m pytest tests
```

Do not test this plugin against a real Linux host, Linux container/VM over SSH,
or a real Huawei OLT unless a separate explicit live-device test plan is
approved.
