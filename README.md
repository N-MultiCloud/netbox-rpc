# netbox-rpc

`netbox-rpc` is the NetBox source of truth for N-MultiCloud RPC procedures.
It stores procedure policy, JSON schemas, execution records, and audit events.
The plugin does not open SSH sessions directly; execution is delegated to
`nms-backend`, which runs hard-coded handler IDs against credentials owned by
`netbox-nms`.

The initial procedure catalog is intentionally narrow:

- `network.device.huawei.olt.ma5800.r024.start_ont`
- `os.linux.ubuntu.24.restart_service`

Operators call named procedures, not arbitrary SSH commands.

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
`os.linux_ubuntu_24.restart_service`.

`netbox-nms` owns SSH connection material through `DeviceService` rows with
`service_type="ssh"`. Those rows provide the management host, port, linked
`DeviceCredential`, `ssh_known_hosts_entry`, and
`ssh_strict_host_key_checking` values consumed by `nms-backend`.

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
- Prefer enum or allowlist parameters for command fragments such as service
  names, board/slot identifiers, or ONT IDs.
- Keep SSH credentials in `netbox-nms`; this plugin stores execution metadata,
  not private keys or passwords.
- Keep strict host-key checking enabled unless an operator explicitly disables
  it for a lab or migration case.
- Treat stdout and stderr as audit data. Store full output only where policy
  allows; otherwise store redacted summaries or hashes in future extensions.

## Testing

Default tests are static or mocked:

```bash
python -m pytest tests
```

Do not test this plugin against a real Linux host, Linux container/VM over SSH,
or a real Huawei OLT unless a separate explicit live-device test plan is
approved.
