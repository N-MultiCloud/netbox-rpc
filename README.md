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
