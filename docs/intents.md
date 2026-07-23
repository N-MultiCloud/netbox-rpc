# RPC Intents

An **intent** is a declarative grouping of RPC procedures. It answers *what*
needs to be done; the grouped `RPCProcedure`s (with their commands) answer *how*.

## Model

| Model | Fields | Notes |
|---|---|---|
| `RPCIntent` | `name` (unique), `execution_mode` (`sequential` / `parallel`, default `sequential`), `enabled`, `description`, `comments`, `procedures` (M2M → `RPCProcedure` through `RPCIntentProcedure`), tags | Declarative reference-data: plain NetBox CRUD, `ObjectChange`-audited, **not** event-sourced. Custom permission `execute_rpcintent` is reserved for the future executor. |
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

This model layer only **declares** intents. Actually *executing* an intent
(fanning out one child `RPCExecution` per grouped procedure, honouring the
sequential/parallel topology) is a separate, future capability. When that
executor is built it MUST:

- create one `RPCExecution` per grouped procedure through the normal command path
  (`netbox_rpc.application.command_handlers.create_execution`), so every child
  run is event-sourced and audited;
- continue to enforce each procedure's `approval_required` / `effect` gating and
  the [LLM Agent Safety Guardrails](../AGENTS.md#llm-agent-safety-guardrails).

An intent must never become a way to bypass approval on a destructive procedure.

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
