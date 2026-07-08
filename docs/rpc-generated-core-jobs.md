# Reading a netbox-rpc-generated NetBox core job

When an RPC procedure runs, `netbox-rpc` enqueues a NetBox **core RQ job**
(visible at `/core/jobs/<N>/`) and links it to the `RPCExecution` audit
aggregate. The core job page itself is deliberately thin — it does **not** show
the command(s) that ran on the target, their output, or how long each one took.
All of that lives on the linked `RPCExecution`: its `result.steps[]` payload and
its append-only event ledger.

This page explains, for any netbox-rpc-generated core job, exactly where to read:

1. the command or commands issued,
2. each command's output (stdout / stderr / exit code), if any, and
3. the time each command took to run, plus the overall execution timing.

A fully worked example (core job **555**) is at the bottom.

## Field map (quick reference)

| You want… | Read it from | Notes |
|---|---|---|
| Which `RPCExecution` a `core/jobs/<N>` belongs to | `RPCExecution.job_id == N` | Projected by the `JobEnqueued` event. The core job's own `data.execution_pk` points back the other way. |
| The command(s) issued | `RPCExecution.result.steps[].command` | One entry per command actually run on the target, in order. |
| A command's stdout | `result.steps[].stdout` | Raw target output for that command (empty string if none). |
| A command's stderr | `result.steps[].stderr` | Empty string when the command produced no error output. |
| A command's exit code | `result.steps[].exit_code` | `0` = success. `result.steps[].ok` mirrors this as a bool. |
| Overall success | `RPCExecution.result.ok` and `RPCExecution.status` | `status` is `succeeded` / `failed` / `cancelled` / `queued` / `running`. |
| Overall timing | `RPCExecution.created`, `started_at`, `finished_at` | Queue → start → finish, projected by the lifecycle events. |
| Per-command timing | The `*.step` → `*.step.result` event pair in the event ledger | E.g. `proxmox.qemu.step` → `proxmox.qemu.step.result`. The gap between the two stamps is that command's run time. |

## Core job ↔ RPCExecution link

`netbox-rpc` intentionally enqueues its RQ job **without** using NetBox's
attached-object job fields (NetBox 4.6 validates attached job object types
against the `jobs` feature, and `RPCExecution` is audit metadata, not a
job-capable operational object). The two sides are linked by IDs instead:

- **Core job → execution:** the worker receives the execution primary key and
  persists it in the core job's `data` JSON as `execution_pk` (for retry/debug
  recovery).
- **Execution → core job:** on successful enqueue, `create_execution()` emits a
  `JobEnqueued` event, which projects `job_id` onto the `RPCExecution`. So
  `RPCExecution.job_id` equals the number in the `/core/jobs/<N>/` URL.

To go from a core job number `N` to the audit data, find the execution whose
`job_id == N` (see the `nms rpc` recipe below).

## Where the command(s) live

The concrete commands that ran on the target are recorded as an ordered list in
`RPCExecution.result.steps`. Each step is one command:

```json
{
  "command": "<exact command line issued on the target>",
  "operation": "<logical operation this command implements>",
  "exit_code": 0,
  "ok": true,
  "stdout": "<raw output>",
  "stderr": ""
}
```

`steps` is authoritative for "what was issued": procedures only ever run
structured, fixed-argv commands (caller input never becomes arbitrary SSH text),
and every command that actually executed appears here in order. A procedure that
performs several operations (e.g. `status`, then `agent_ping`) produces one step
per command.

## Where the output lives

For each command:

- **`stdout`** — the raw standard output the target returned. For the Proxmox
  procedures this is typically a JSON document (`pvesh ... --output-format json`).
- **`stderr`** — standard error; empty string when the command emitted none.
- **`exit_code`** / **`ok`** — the process exit status and its boolean mirror.

The top-level `result.ok` is the AND of the steps plus procedure-level checks,
and `RPCExecution.status` is the projected terminal state. If a command failed,
its non-zero `exit_code` and any `stderr` are preserved on the step, and the
execution's `error_code` / `error_message` fields (projected by
`ExecutionFailed`) summarize the failure.

## Where the timing lives

Two granularities are available:

**Overall (execution-level), from projection timestamps:**

| Interval | Fields | Meaning |
|---|---|---|
| Queue latency | `started_at − created` | Time the job waited in RQ before the worker picked it up. |
| Run time | `finished_at − started_at` | Wall-clock from worker start to terminal state. |
| End-to-end | `finished_at − created` | Total time from enqueue to completion. |

**Per-command, from the append-only event ledger:** each command emits a paired
progress event — a `*.step` event ("Running …") immediately before it runs and a
`*.step.result` event ("… succeeded", carrying `exit_code`) immediately after.
The delta between the two stamps is that single command's run time on the target.
For the Proxmox QEMU procedure the pair is `proxmox.qemu.step` →
`proxmox.qemu.step.result`; other procedures follow the same `*.step` /
`*.step.result` convention. These are `BackendEventRecorded` audit events and do
not change the projection — they exist precisely for progress and timing.

> **Timestamp ordering nuance.** `finished_at` is written when the
> `ExecutionSucceeded` projection is applied, while the backend's audit events
> (`ssh.connect`, `*.step`, `*.step.result`, `completed`) are appended by the
> dispatch stream with their own wall-clock stamps. Those audit stamps can trail
> the `finished_at` write by a few milliseconds, so an event's timestamp may be
> slightly *after* `finished_at`. Use the projection timestamps for the overall
> numbers and the `*.step` → `*.step.result` delta for per-command run time;
> don't subtract across the two clocks expecting exact agreement.

## Retrieving it with `nms rpc` (sanctioned reads)

All of this is read through `nms rpc` — never by hitting the NetBox or Proxmox
API directly. Given a core job number `N`:

```bash
# 1. Find the execution whose job_id == N (N = the /core/jobs/<N>/ number).
nms --json rpc executions list | \
  python3 -c "import sys,json; \
    print(next(r['id'] for r in json.load(sys.stdin)['results'] if r.get('job_id')==N))"

# 2. Full execution record — includes result.steps[] (commands, stdout, exit_code)
#    and the created/started_at/finished_at timestamps.
nms --json rpc executions get <exec-id>

# 3. The event ledger — the ordered progress events used for per-command timing.
nms rpc events <exec-id>
```

## Worked example — core job 555

- **Core job:** `/core/jobs/555/`
- **Linked execution:** `RPCExecution #413` (`job_id = 555`)
- **Procedure:** `os.linux.proxmox.qemu_vm_lifecycle` (procedure #33), operation
  `status`
- **Target:** Proxmox endpoint `cluster01.dc01.cotia.sp.nmulti.cloud`
  (10.0.30.71), node `node01`, VM `10023` (`dns.nmulti.cloud`)
- **Status:** `succeeded` (`result.ok == true`)

### Command(s) issued

Exactly **one** command ran (`result.steps` has a single entry):

| # | Operation | Command |
|---|---|---|
| 1 | `status` | `pvesh get /nodes/node01/qemu/10023/status/current --output-format json` |

### Output

| Field | Value |
|---|---|
| `exit_code` | `0` |
| `ok` | `true` |
| `stderr` | *(empty)* |
| `stdout` | VM status JSON for `dns.nmulti.cloud` |

The `stdout` JSON reports the live VM state — abridged:

```json
{
  "name": "dns.nmulti.cloud",
  "vmid": 10023,
  "status": "running",
  "qmpstatus": "running",
  "uptime": 30,
  "cpus": 2,
  "cpu": 0,
  "mem": 458035200,
  "maxmem": 2147483648,
  "maxdisk": 107374182400,
  "netin": 26833,
  "netout": 7276,
  "running-qemu": "11.0.0",
  "running-machine": "pc-i440fx-11.0+pve0",
  "ha": { "managed": 0 }
}
```

(The full payload also carries `ballooninfo`, per-disk `blockstat` for `ide2`
and `scsi0`, per-NIC counters under `nics.tap10023i0`, and `proxmox-support`
capability flags.)

### Timing

Overall (from the execution projection timestamps):

| Interval | Duration |
|---|---|
| Queue latency (`created` → `started_at`) | ≈ 0.106 s |
| Run time (`started_at` → `finished_at`) | ≈ 1.972 s |
| **End-to-end** (`created` → `finished_at`) | **≈ 2.078 s** |

Per-phase, from the event ledger (execution 413, sequences 1–6):

| Phase | Event pair | Duration |
|---|---|---|
| Normalize params | `started` → `normalized` | ≈ 0.026 s |
| Backend dispatch + SSH session setup | `normalized` → `ssh.connect` | ≈ 1.939 s |
| Connect → command start | `ssh.connect` → `proxmox.qemu.step` | ≈ 0.006 s |
| **Command run (`pvesh get … status/current`)** | `proxmox.qemu.step` → `proxmox.qemu.step.result` | **≈ 0.007 s** |
| Finalize | `proxmox.qemu.step.result` → `completed` | ≈ 0.006 s |

So the one command itself took only **≈ 7 ms** on the Proxmox host; the ≈ 2 s
end-to-end wall-clock is dominated by backend dispatch and establishing the SSH
session to the node (≈ 1.94 s), not by the command.

Raw timestamps for reference:

```
created     2026-06-24T20:25:12.861063Z
started_at  2026-06-24T20:25:12.966760Z
finished_at 2026-06-24T20:25:14.939136Z

seq 1  started                    20:25:12.988860Z  RPC execution started.
seq 2  normalized                 20:25:13.014963Z  Execution parameters normalized by NetBox.
seq 3  ssh.connect                20:25:14.953923Z  Connecting to 10.0.30.71:22
seq 4  proxmox.qemu.step          20:25:14.959805Z  Running Proxmox QEMU status
seq 5  proxmox.qemu.step.result   20:25:14.966867Z  Proxmox QEMU status succeeded (exit_code 0)
seq 6  completed                  20:25:14.973216Z  RPC execution completed.
```

## Multi-command procedures

The same layout scales to procedures that issue several commands. A
`qemu_vm_lifecycle` run with `operations: ["status", "agent_ping",
"agent_network_get_interfaces"]`, for instance, produces three `result.steps[]`
entries (one command each, in order) and three `proxmox.qemu.step` /
`proxmox.qemu.step.result` event pairs — so you get one command line, one
output, and one run-time delta per operation, read exactly as above.

## See also

- [`architecture.md`](./architecture.md) → **Event Catalog** and **Projection
  Fold** for the full event list and how `job_id` / `result` are projected.
- `README.md` → **API Validation** for how `JobEnqueued` / `job_id` are emitted.
