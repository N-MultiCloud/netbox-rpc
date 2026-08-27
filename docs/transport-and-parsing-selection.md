# Transport-driver and output-parser selection

This guide defines how `netbox-rpc` authors choose `RPCProcedure.transport_driver`,
`output_parser`, and `output_schema` for the NMS execution pipeline. `netbox-rpc`
stores policy and validated procedure schemas; `nms-backend` owns the handler
implementation, transport runtime, and parser runtime.

## Transport-driver decision matrix

| Driver | Default availability | Use for | NMS device classes | Avoid when |
| --- | --- | --- | --- | --- |
| `ansible` | **Estate default** (optional `ansible` extra on the backend) | Linux/VM targets routed through an Ansible control node; brings vendor-neutral connection handling and the module ecosystem | Linux `dcim.device` rows, VMs, Proxmox hosts | `strict_auth` procedures, fingerprint-pinned credentials, passphrase-protected keys, and anything that streams a long-running command's output live — all AsyncSSH-only |
| `ansible-network` | **Estate default** for network CLI (optional extra) | Vendor-aware CLI over Ansible's persistent `network_cli` connection, with per-platform cliconf/terminal plugins | Network `dcim.device` rows whose NetBox Platform is mapped | A device whose Platform is not mapped to an Ansible network OS — the driver reports itself unavailable and the chain falls back |
| `asyncssh` | Raw fallback (built in) | Linux and Proxmox read-only shell handlers with a single semantic action | Linux `dcim.device` rows, Proxmox host devices, VM-like Linux targets with DeviceService SSH | Network CLI workflows that need privilege modes, prompts, or structured multi-command sessions |
| `scrapli` | Built into production runtime when declared in nms-backend requirements | Network CLI sessions with prompt handling and multi-command show/display flows | Dell OS10 S5232F-ON, Huawei VRP switches, Huawei MA5800 OLTs, other network `dcim.device` rows | Generic Linux host automation where plain SSH is enough |
| `paramiko` | Fallback | Raw SSH compatibility fallback when AsyncSSH cannot support a target environment | Legacy appliances, older network devices, constrained SSH servers | New procedures where AsyncSSH or Scrapli fits the device class |
| `netmiko` | Opt-in extra | Vendor CLI workflows that benefit from Netmiko platform drivers and built-in TextFSM/Genie/TTP helpers | Mixed vendor network devices when a Netmiko platform driver is required | Default production use; install the extra only when a procedure needs it |
| `napalm` | Opt-in heavy extra | Vendor-neutral getters and structured network state APIs | Network devices where NAPALM supports the OS and the desired getter | Fixed command procedures or Linux host workflows |

Start with the smallest driver that matches the device class. For the current
pipeline exemplars:

| Procedure | Driver | Why |
| --- | --- | --- |
| `os.linux.proxmox.pvesh_json` | `asyncssh` | nms-backend builds a fixed `pvesh` invocation from a validated API path |
| `os.linux.collect_facts` | `asyncssh` | Linux fact collection uses a fixed backend handler and a Linux parser |
| `network.device.dell_os10.s5232f_on.show_version_structured` | `scrapli` | Dell OS10 is a network CLI target with structured prompt/session handling |

### `transport_driver_chain` (ordered fallback)

`RPCProcedure.transport_driver_chain` is an ordered **priority + fallback
chain** of the same driver names as `transport_driver` (index 0 tried first).
Populate it only when a procedure should try more than one driver at runtime —
for example a network device reachable over `scrapli` but with `netmiko` as a
fallback platform driver. Leave it empty (the default) to use the single
`transport_driver` value; this is the right choice for the great majority of
procedures, including all current pipeline exemplars above.

**You rarely need to populate it now.** The estate-wide policy in
`RpcPluginSettings` (`default_transport_driver_chain` /
`default_network_driver_chain`, seeded `["ansible"]` / `["ansible-network"]`)
already resolves every procedure without its own chain to *Ansible first, then
the procedure's own `transport_driver` as fallback*. Populate
`transport_driver_chain` explicitly only to express a preference that differs
from that — for example a network device that should try `scrapli` before
`netmiko` and skip Ansible entirely. An explicit chain wins **verbatim** and is
never reordered.

Set `transport_pinned` instead when a procedure's backend handler depends on one
specific driver — it disables transport fallback, relies on AsyncSSH credential
isolation, or streams output live. Pinned procedures are excluded from the
estate-wide policy entirely and keep a byte-for-byte identical payload.

`resolve_driver_chain()` injects the resolved chain into
`normalized_params["transport_driver_chain"]` (and `command_fingerprint`) only
when it is non-empty, so a procedure with no chain and no applicable policy
keeps a byte-for-byte identical normalized payload. The `netbox-rpc-backend` executor
tries the listed drivers in order, skips capability-mismatched entries,
advances to the next driver on an unavailable/connection error, and stops the
chain on a command-level result (a command failure is not a transport failure
and must not trigger fallback to the next driver).

## Output-parser decision ladder

1. Prefer native `json` or `xml` when the device can return structured output.
2. Use `jc` for Linux command output that has a stable `jc` parser.
3. Use `textfsm` or `ttp` for network CLI `show`/`display` output, with inline templates stored in `output_schema` so the procedure is self-contained and reviewable.
4. Use `regex` only for small, stable extraction from bounded output.
5. Use `none` when callers need raw output and no downstream structured state is expected.
6. Use `auto` only when the handler deliberately supports the parser chain and the operator accepts the extra dependency/runtime variability.

For inline templates, keep the whole template in `output_schema`, for example
`{"textfsm_template": "..."}`. Do not rely on an unpinned local template path
unless the nms-backend runtime image owns and versions that path.

## Production availability

| Parser or library | Production availability | Authoring rule |
| --- | --- | --- |
| `json` | Always available | Use first when a handler can request JSON output |
| `xml` | Always available | Use first for XML-capable network APIs |
| `regex` | Always available | Keep patterns narrow and field-specific |
| `jc` | Available in production through `nms-backend` requirements.txt | Declare `output_schema["jc_parser"]` |
| `textfsm` | Available in production through `nms-backend` requirements.txt | Prefer inline `output_schema["textfsm_template"]` |
| `ntc-templates` | Opt-in | Install in the nms-backend runtime image before seeding a dependent procedure |
| `ttp` | Opt-in | Install in the nms-backend runtime image before selecting `ttp` |
| `genie` | Opt-in | Install in the nms-backend runtime image before selecting `genie` |
| `netmiko` | Opt-in transport extra | Install in the nms-backend runtime image before selecting `netmiko` |
| `napalm` | Opt-in heavy transport extra | Install in the nms-backend runtime image before selecting `napalm` |

## Security invariant

Procedures and normalizers MUST NOT assemble, store, or accept free-text shell
or CLI commands. They emit validated semantic parameters only: enum values,
bounded strings, integer ranges, credential references, target identifiers, and
parser hints. The matching nms-backend `@rpc_handler` builds every device
command server-side from allowlists, constants, and validated params.

This keeps API callers from turning `RPCExecution.params` into arbitrary remote
execution. It also keeps audit fingerprints stable: fingerprints record handler
IDs, validated semantic params, parser selections, and hashes of large schemas
or templates rather than raw executable text.

## Adding a new pipeline exemplar

1. Add a data-only seed migration row for `RPCProcedure` with `name`,
   `handler_id`, `target_models`, `effect`, approval policy, timeout,
   `params_schema`, `result_schema`, `transport_driver` (plus
   `transport_driver_chain` only if the procedure needs an ordered
   priority/fallback chain of drivers), `output_parser`, and `output_schema`.
2. Add a normalizer branch in `_dispatch_normalize_execution_params()` in
   `netbox_rpc.domain.normalization`, keyed by the procedure name constant
   (`jobs.py` only re-exports this function for compatibility).
3. Make the normalizer emit validated semantic params only. Do not emit
   `commands`, shell snippets, CLI text, script text, or unbounded strings.
4. Add the matching nms-backend `@rpc_handler(handler_id=...)` that builds the
   runtime action server-side.
5. Deploy nms-backend first, then apply the netbox-rpc seed migration. This
   ordering prevents NetBox from exposing a procedure whose handler ID is not
   yet available in the execution runtime.
6. Add stub-based normalizer tests plus static migration/docs contract tests.

Seed migrations must inline strings and dicts. They must not import
`netbox_rpc.constants` or any other live `netbox_rpc` module.
