# RPC Intents

An **intent** is a declarative grouping of RPC procedures. It answers *what*
needs to be done; the grouped `RPCProcedure`s (with their commands) answer *how*.

## Model

| Model | Fields | Notes |
|---|---|---|
| `RPCIntent` | `name` (unique), `execution_mode` (`sequential` / `parallel`, default `sequential`), `enabled`, `description`, `comments`, `procedures` (M2M → `RPCProcedure` through `RPCIntentProcedure`), tags | Declarative reference-data: plain NetBox CRUD, `ObjectChange`-audited, **not** event-sourced. The custom permission `execute_rpcintent` gates the `run` action documented below. |
| `RPCIntentProcedure` | FK `intent` (CASCADE), FK `procedure` (PROTECT), `sequence` (PositiveInteger, **≥ 1** — `MinValueValidator` + DB `CheckConstraint`) | Ordered through model. `sequence` orders the procedures for sequential/nested execution; it is informational in parallel mode. Unique `(intent, procedure)`; ordering `(intent, sequence, id)`. |

Changes to the grouped procedures (add / remove / reorder) are captured in the
intent's changelog: `RPCIntent.serialize_object()` includes the ordered
`intent_procedures`, and the form / API reconcile the through rows *before* the
model save on the update path so the `ObjectChange` diff reflects the new order.

`execution_mode` is single-sourced from the `ExecutionMode` domain value object
(`netbox_rpc/domain/value_objects.py`), mirroring `Effect` / `ExecutionStatus`.

## Execution modes

- **`sequential`** — the grouped procedures are *nested* and triggered one after
  another, in ascending `sequence` order. Use this when a later procedure
  depends on an earlier one having completed.
- **`parallel`** — the grouped procedures are triggered *concurrently*, with no
  nesting at all. `sequence` is retained but informational. Use this when the
  grouped procedures are independent.

## Scope: declaration vs execution

The model layer **declares** intents (this page's Model/UI/REST-API sections
above). *Executing* one — fanning out one child `RPCExecution` per grouped
procedure — is a separate capability, `command_handlers.execute_intent()`
(issue #130), triggered via the `run` action documented below.

`execute_intent()` creates every child through the exact same command path a
direct `RPCExecution` POST uses
(`netbox_rpc.application.command_handlers.create_execution`) — never a side
channel. That means each child independently re-runs **every** existing gate:
the `execute_rpcprocedure` permission check, the #166 authoritative opt-in +
selected-backend enforcement, the procedure's `enabled` check, the
`approval_required` permission gate (`approve_rpcprocedure`), `params_schema`
validation, and the #167 backend capability check. An intent grouping an
`approval_required` or destructive procedure does **not** auto-run that
child — the same `PermissionDenied`/`ValidationError` a direct create would
raise propagates out of `execute_intent()` unmodified, aborting the run. There
is no code path here that bypasses approval or destructive gating; see the
[LLM Agent Safety Guardrails](../AGENTS.md#llm-agent-safety-guardrails).

**Ordering and fan-out (v1 semantics).** Children are always created in
ascending `RPCIntentProcedure.sequence` order — `sequential` and `parallel`
both fan out synchronously, in that order, within one call today; the mode
distinction (true concurrent dispatch for `parallel`, nested/chained dispatch
for `sequential`) is reserved for a future enhancement and is not required by
the safety contract this executor implements. Fan-out is **fail-fast**: the
first child that fails any gate raises immediately, aborting the rest of the
run. Children created before that failure are **not** rolled back — each
`create_execution()` call is its own independent commit (wrapping the whole
fan-out in one outer transaction would risk RQ jobs left dangling against rows
a later sibling's failure rolled back). Cancel an unwanted stray child
individually via the existing `cancel` command.

**Origin marker.** After a child is created — deliberately *after*
`params_schema` validation has already run against the caller's `params`
unmodified, since many seeded procedures set
`"additionalProperties": false` and would reject an unexpected key — the
underscore-prefixed `_intent` / `_intent_name` keys are patched into the
child's stored `params`. This is a plain-field update, not part of the
event-sourced projection (only `normalized_params` is), so it does not touch
the aggregate or its event stream. The [Procedure Runs
tab](../AGENTS.md#procedure-runs-tab-query-side) then attributes the run as
`Intent: <name>` instead of `Direct`.

## Running an intent

```
POST /api/plugins/rpc/intents/{id}/run/
{
  "assigned_object_type": "dcim.device",
  "assigned_object_id": 42,
  "params": {}
}
```

Requires `netbox_rpc.execute_rpcintent` (checked first, on the intent) in
addition to whatever each grouped procedure's own gates require per child (see
above). `params`, if given, is applied to every fanned-out child unmodified —
the origin marker is stamped onto stored params, never merged into this input.
On success, returns `201` with the list of created child `RPCExecution`
representations, in the same order they were created. On the first gated
child's refusal, the response reflects that gate's normal status code (`403`
for a missing/approval permission, `400` for a validation failure) and no
further children are created.

## UI

Create and manage intents at **RPC → Intents**. The edit form lets you select
multiple procedures and choose the execution mode; the through `sequence` follows
the submitted selection order. The detail page lists the grouped procedures in
execution order with their effect and approval flags.

## REST API

Base path: `/api/plugins/rpc/intents/`.

- `GET /api/plugins/rpc/intents/` — list. Filter with `?execution_mode=`,
  `?enabled=`, `?procedure_id=`.
- `POST /api/plugins/rpc/intents/` — create.
- `GET`/`PATCH`/`PUT`/`DELETE /api/plugins/rpc/intents/{id}/` — retrieve/update/delete.

### Write channel: `procedure_ids`

Send an **ordered** `procedure_ids` list. The list order becomes the through
`sequence` (renumbered from 1). Omitting `procedure_ids` on `PATCH` leaves the
existing grouping untouched; sending `[]` clears it. Duplicate IDs are rejected
with a `400` (each procedure may appear at most once per intent).

```jsonc
// POST /api/plugins/rpc/intents/
{
  "name": "provision-and-verify",
  "execution_mode": "sequential",
  "procedure_ids": [12, 7, 30]   // runs 12 → 7 → 30
}
```

### Read representation: `procedures`

The response returns `procedures` as an ordered list:

```jsonc
{
  "id": 3,
  "name": "provision-and-verify",
  "execution_mode": "sequential",
  "enabled": true,
  "procedures": [
    {"id": 12, "name": "os.linux.ubuntu.24.install_qemu_guest_agent", "handler_id": "...", "effect": "write", "approval_required": false, "sequence": 1},
    {"id": 7,  "name": "os.linux.ubuntu.24.restart_service",          "handler_id": "...", "effect": "write", "approval_required": false, "sequence": 2},
    {"id": 30, "name": "packer.vm.verify_services",                   "handler_id": "...", "effect": "read",  "approval_required": false, "sequence": 3}
  ]
}
```

## Migration

Seeded by `netbox_rpc/migrations/0039_rpcintent.py` — an additive migration
(two `CreateModel`s + the ordered M2M + a unique constraint) depending on the
`0038_merge_rpc_procedure_commands` leaf. It has no live imports and no
`netbox_nms` dependency, so standalone boot is preserved.
`0040_rpcintentprocedure_sequence_min.py` adds the `sequence >= 1` validator and
DB `CheckConstraint` (normalizing any existing sub-1 rows first, so it is safe on
populated databases).

Supports NetBox **4.5.8 through 4.6.x**. The migration depends on
`extras.0134_owner`, the final `extras` migration in NetBox 4.5.8 and an
ancestor of the 4.6.x migration graph.
Requires NetBox **4.5.8+** (`min_version = "4.5.8"`): the migration graph depends
only on NetBox migration anchors present in both NetBox 4.5.8 and 4.6.x.
