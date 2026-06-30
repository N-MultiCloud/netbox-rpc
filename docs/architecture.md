# netbox-rpc Architecture

`netbox-rpc` is the Remote Command Policy bounded context. It owns procedure
policy, execution audit state, normalization, and backend dispatch selection. It
does not own SSH drivers or device protocol implementations; those remain in
backend services such as `nms-backend`.

## Domain Model

`RPCExecution` is the command aggregate and the NetBox-compatible read
projection. Django models remain the persistence boundary because NetBox
requires `NetBoxModel` for permissions, API serialization, object views, tags,
custom fields, and object deletion. The domain code therefore wraps the model
instead of introducing repository abstractions over the ORM.

The aggregate wrapper lives in `netbox_rpc.domain.aggregate` and enforces these
lifecycle invariants:

- terminal executions (`succeeded`, `failed`, `cancelled`) do not transition;
- only a queued execution can start;
- only a queued execution can be cancelled;
- `ExecutionQueued` is the first event in a new stream;
- normalized params and backend responses are recorded only for running
  executions.

`RPCProcedure`, `RPCLinuxServiceAllowlist`, and `RPCBackend` are intentional
reference-data/configuration entities. They are ordinary NetBox CRUD models,
audited by NetBox `ObjectChange`, and are not event-sourced.

## Event Catalog

Typed domain events live in `netbox_rpc.domain.events`. `EVENT_TYPES` maps
persisted event names to dataclasses, and `from_record(name, data)` rebuilds
typed events from `RPCExecutionEvent` rows.

| Event | Projection effect |
|---|---|
| `ExecutionQueued` | status `queued` |
| `JobEnqueued` | `job_id` |
| `ExecutionStarted` | status `running`, `started_at` |
| `ParametersNormalized` | `normalized_params`, `resolved_command_hash` |
| `BackendEventRecorded` | no projection change; audit/progress only |
| `ExecutionSucceeded` | status `succeeded`, `result`, `finished_at`, clear errors |
| `ExecutionFailed` | status `failed`, `error_code`, `error_message`, `finished_at` |
| `ExecutionEnqueueFailed` | status `failed`, enqueue error fields, `finished_at` |
| `ExecutionCancelled` | status `cancelled`, `finished_at`, clear errors |

`RPCExecutionEvent` is append-only: ORM updates/deletes are rejected and the
database trigger layer protects the ledger below Django. Event append failures
fail closed through `RPCEventStoreError`.

## Projection Fold

`netbox_rpc.domain.projection.apply(state, event)` is the canonical projection
definition. `rebuild(events)` folds from the initial queued state to prove that
the event stream can recreate the current projection.

`netbox_rpc.event_store` is the only gateway for execution state changes. Each
transition follows one path:

1. build a typed domain event;
2. append an `RPCExecutionEvent` with redaction, bounding, sequence collision
   retry, and `payload_hash`;
3. apply the pure reducer to compute the new `ProjectionState`;
4. write only changed projection fields back to `RPCExecution`.

`rebuild_projection(execution)` loads ordered events and folds them.
`reproject(execution)` writes the rebuilt state back to the model.

## CQRS

Command-side behavior lives in `netbox_rpc.application.command_handlers`:

- `create_execution(...)` checks execute permission, enabled state, approval
  permission, JSON schema, creates the row, emits `ExecutionQueued`, enqueues
  the RQ job, and emits `JobEnqueued` or `ExecutionEnqueueFailed`;
- `run_execution(execution)` starts the aggregate, resolves the backend,
  normalizes params, records normalization, calls the backend, and records the
  backend response;
- `cancel_execution(execution, user)` is a queued-only command that emits
  `ExecutionCancelled`.

Query-side helpers live in `netbox_rpc.application.queries`. Execution list,
detail, and event endpoints read projections. The execution API is
command-only for writes: create and cancel are explicit commands. PUT/PATCH are
disabled (state is derived from the event log, never edited), and DELETE is
disabled too — an execution and its append-only event ledger are immutable
history once created (a cascading delete would be rejected by the ledger's
append-only trigger). Execution records are retained, not deleted, by design.

## Normalization Boundary

Normalization lives in `netbox_rpc.domain.normalization`. `netbox_rpc.jobs`
re-exports the historical imports (`normalize_execution_params`,
`RPCExecutionError`, `_dispatch_normalize_execution_params`, and
`_apply_driver_pipeline_overrides`) for compatibility, but RQ job orchestration
delegates to application command handlers.

Procedure normalizers accept structured parameters only. They must not accept or
store arbitrary SSH command text. Driver/parser selection is injected centrally
from `RPCProcedure.transport_driver`, `output_parser`, and `output_schema`.


## Testing

The suite is two tiers:

1. **Fast pure-domain unit tests** (`tests/`, run by `pytest`): they stub Django
   and NetBox and need no database. They cover the domain logic — the projection
   `apply`/`rebuild` fold, typed domain events and their round-trips, the
   aggregate invariants, the value objects, the query helpers, and the
   normalization service — plus source-level contract checks. This is the
   `ci.yml` workflow.

2. **DB-backed integration tests** (`netbox_rpc/tests/`, run by
   `python netbox/manage.py test netbox_rpc` against a real Postgres test
   database): they cover the parts that only exist against the ORM — the
   `event_store` append+project path, the rebuild oracle (`rebuild_projection`
   reproduces the live projection for every lifecycle path), the append-only
   ledger (model guards + the database trigger; an execution with events cannot
   be deleted), the command handlers (create/run/cancel and the cancel-vs-start
   row-locked race), and the REST API (command-only write model: PUT/PATCH/DELETE
   return 405; cancel is an action; the event log is read-only). This is the
   `integration.yml` (self-hosted) and `.github/workflows/test.yml` (portable,
   with a Postgres service) workflows, using the minimal NetBox config at
   `tests/ci/netbox_configuration.py`.

Run them locally with:

```bash
# Tier 1 — fast, no database
pytest tests/

# Tier 2 — against a NetBox checkout + Postgres
python netbox/manage.py test netbox_rpc
```
