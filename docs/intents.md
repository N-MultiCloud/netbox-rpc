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
selected-backend enforcement, the procedure's `enabled` check, its approval
policy, `params_schema` validation, and the #167 backend capability check.
Legacy `approval_required` procedures retain the requester permission gate;
staging token rotation instead returns a pending child and requires a distinct
later approval. An intent grouping an
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

**Origin relation.** `create_execution()` writes the child execution's
read-only `source_intent` foreign key in the same insert as its caller params.
Attribution never enters or mutates `params`, so schemas with
`"additionalProperties": false` remain valid and family-specific final-payload
guards cannot be bypassed by a later update. The [Procedure Runs
tab](../AGENTS.md#procedure-runs-tab-query-side) resolves that relation and
attributes the run as `Intent: <name>` instead of `Direct`. Legacy `_intent` /
`_intent_name` params markers remain readable for historical rows only.

## Seeded intents

The first migration-seeded intents are `fileserver.samba.collect_state`
(`execution_mode="parallel"`, the read-only Samba observability family) and
`fileserver.samba.deploy_config` (`execution_mode="sequential"`, the
config-lifecycle write path), both seeded by
`netbox_rpc/migrations/0057_seed_fileserver_samba_intents.py` (#160), grouping
the pre-existing Samba read/write catalog (migrations `0049`–`0052`; see
`AGENTS.md` → "Samba file-server read/write procedures"):

- **`fileserver.samba.collect_state`** (`execution_mode="parallel"`) — the
  read-only observability sweep: `version`, `service_status`, `config_read`,
  `config_test`, `list_shares`, `status_report`, `user_list`, `group_list`,
  `domain_info`. All nine grouped procedures are `effect="read"`.
- **`fileserver.samba.deploy_config`** (`execution_mode="sequential"`) — the
  config-lifecycle write path, in order: `config_test` → `config_deploy` →
  `service_control` (reload) → `service_status`. Validates before writing,
  deploys, reloads, then re-checks status — never writes `smb.conf` and
  validates afterwards.

Both intents are pure reference-data groupings — they add **no executor** and
**no new mutation surface**; running either goes through the same
`execute_intent()` (#130) fan-out described above, and re-applies every gate
per child exactly as a direct create would. The nine `service.samba.1.*`
identity procedures added alongside these intents in #160 (user/group
create/delete/enable/disable/password/members — see `AGENTS.md`) are
deliberately **not** grouped into either intent; they are standalone actions,
not part of the read-sweep or the config-deploy lifecycle.

A second intent, **Update Ubuntu OS from 24 LTS to 26 LTS**, is seeded by
`netbox_rpc/migrations/0065_seed_ubuntu_upgrade_26_intent.py`. It groups these
procedures in declared sequence order:

1. `os.linux.ubuntu.24.upgrade_26.analyze_preupgrade`
2. `os.linux.ubuntu.24.upgrade_26.save_preupgrade_state`
3. `os.linux.ubuntu.24.upgrade_26.run_upgrade`
4. `os.linux.ubuntu.24.upgrade_26.verify_postupgrade`

This declaration is useful for discovery, but it is not a serialized upgrade
workflow under v1 semantics. Calling `POST /intents/{id}/run/` creates children
for all allowed steps in one synchronous loop, then RQ workers may run those
children concurrently. Consequently, `save_preupgrade_state` is not guaranteed
to finish before `run_upgrade` starts, and `verify_postupgrade` is not guaranteed
to wait for the upgrade. Operators must dispatch the four procedures
individually and gate each one on the prior result, following the
[Ubuntu 24.04 to 26.04 upgrade runbook](ubuntu-24-to-26-upgrade-runbook.md),
rather than relying on the intent's `run/` action for ordering.

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

Supports the NetBox **4.7.x GA** line only. The migration retains the
historical `extras.0134_owner` anchor so existing installations can upgrade
onto the 4.7-only support line.
