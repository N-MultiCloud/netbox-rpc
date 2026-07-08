# Command templating & output-variable chaining

`RPCProcedureCommand` steps can opt into **Jinja2 templating** and **output
capture**, so a procedure's commands can use:

1. **NetBox object variables** — fields of the run's target object
   (`{{ target.name }}`, `{{ target.serial }}`);
2. **Declared parameter variables** — the procedure's `params_schema` values
   (`{{ params.vlan_id }}`);
3. **Output-based variables** — a value captured from an **earlier** command's
   output and referenced by a **later** command (`{{ vars.vmid }}`), the
   "nesting chain".

This is opt-in per command. The default `render_mode="literal"` keeps the
historical fixed-token `{param}` substitution behaviour byte-for-byte; nothing
about existing procedures changes.

> **Where execution happens.** netbox-rpc is the *authoring, validation and
> contract* authority. The runtime that renders the templates, captures each
> command's output, and threads it into later commands lives in the nms-backend
> RPC executor. This document defines the data contract that executor consumes.

## Fields

| Field | Meaning |
|---|---|
| `render_mode` | `literal` (default) or `jinja`. In `jinja` mode each `argv` token is a Jinja2 expression template. |
| `produces_var` | Optional snake_case name to capture this command's output into, so a later command can use `{{ vars.<name> }}`. Unique within the procedure. |
| `capture_kind` | How to extract the value: `stdout`, `stdout_stripped`, `json`, `regex`, `line`. |
| `capture_expression` | For `json` (dotted path), `regex` (exactly one capturing group), or `line` (integer index). Empty for `stdout`/`stdout_stripped`. |

## Render context (`render_mode="jinja"`)

Each token is rendered against a fixed context:

| Root | Source | Example |
|---|---|---|
| `params.<name>` | the procedure's declared `params_schema.properties` | `{{ params.vlan_id }}` |
| `target.<field>` | the run's NetBox target object (see snapshot below) | `{{ target.name }}` |
| `vars.<name>` | a value captured from an **earlier** command | `{{ vars.vmid }}` |
| `runtime.<key>` | the SSH connection keys (`rpc_ssh_host`, `rpc_ssh_port`, `rpc_ssh_credential_pk`, `rpc_ssh_known_hosts_entry`, `rpc_ssh_strict_host_key_checking`) | `{{ runtime.rpc_ssh_host }}` |
| `item` | the current `for_each` element (only when `for_each_param` is set) | `{{ item }}` |

Tokens are **expressions only**. Statement/comment blocks (`{% %}`, `{# #}`) and
function/method calls are rejected — use the structured `for_each_param` /
`condition_param` fields for iteration and conditionals, not inline logic.

## Validation (author time)

`RPCProcedureCommand.clean()` (via `netbox_rpc.command_templating`) enforces:

- **Template syntax** parses under a sandboxed Jinja2 environment.
- **No statements / no calls / no dunder access at any depth** — `{% %}`/`{# #}`
  blocks, function/method calls (`x()`), and private/dunder attribute or key
  access (`target.name.__class__`, `target['_x']`) are all rejected.
- **Filter allowlist**: only scalar-safe filters are permitted (`int`, `float`,
  `string`, `default`, `upper`, `lower`, `trim`, `capitalize`, `title`,
  `replace`, `truncate`, `length`, `abs`, `round`, `join`). Attribute-reaching
  filters (`attr`, `map`, `selectattr`, …) are rejected.
- **Safe literals**: text outside `{{ }}` **and string constants inside `{{ }}`**
  must use the conservative argv charset (no whitespace, braces, or shell
  metacharacters), so shell text can't be smuggled through a Jinja string
  literal (`{{ '; rm -rf /' }}` is rejected).
- **Reference resolution**: `params.*` must be a declared param; `runtime.*` a
  known runtime key; `target.*` any non-dunder field; and `vars.*` a variable
  produced by a command with a **strictly smaller `sequence`**. Referencing an
  output variable before it is produced is an error — this is what makes the
  chain safe and legible. Saving a command also re-checks the **whole
  procedure**, so editing a producer (renaming its `produces_var` or moving it to
  a later `sequence`) that would orphan a downstream consumer is rejected.
- **Capture spec**: `produces_var` is a unique snake_case name (not a reserved
  context root); `regex` compiles with exactly one group; `line` is an integer;
  `json`/`regex`/`line` require an expression while `stdout`/`stdout_stripped`
  forbid one.

> Validation is enforced by `clean()` (the form/API path). As with the existing
> fixed-token contract, a direct ORM/`bulk_create` write bypasses `clean()`, and
> a producer *deleted* outright is not re-checked against its consumers; the
> executor's `StrictUndefined` render surfaces any residual dangling reference as
> a clean run failure.

## NetBox-object snapshot

netbox-rpc owns the NetBox object; the executor only sees the serialized
execution payload. So when a procedure has **any** jinja command, the normalizer
serializes a bounded, redacted, JSON-safe snapshot of the target object into
`normalized_params["_target_object"]` (the `{{ target.* }}` context) and records
`command_fingerprint["target_object_sha256"]`. The snapshot:

- includes the object's concrete public fields plus `id`, `display`, `name`, and
  `custom_fields`;
- redacts any field whose name matches `pass|secret|token|private_key|api_key|credential`;
- caps field count and value length.

Because this is gated on the presence of a jinja command, **legacy / literal
procedures keep a byte-for-byte identical normalized payload** and the cross-repo
POST body stays `{}`.

## Executor security requirements (nms-backend)

The eventual executor runs a single shell string over SSH (`$SHELL -c`); there
is no execve/no-shell path. Therefore the executor **must**:

1. Render each token with a **sandboxed** Jinja2 environment and `StrictUndefined`.
2. **Shell-quote every rendered token** (`shlex.quote`) before joining.
3. Extract `produces_var` per `capture_kind`, **bound and redact** the captured
   value, and **re-validate** it (safe charset / expected shape) before it enters
   any later command's render context.
4. Never store or accept arbitrary shell text — the argv token list plus this
   contract is the only command surface.

## Worked example — the nesting chain

A procedure that, for a target `dcim.device`, resolves a VMID from a lookup
command's output (derived from the NetBox object) and then acts on it:

| # | render_mode | argv | produces / captures |
|---|---|---|---|
| 1 | `jinja` | `["/usr/bin/lookup-vmid", "--host", "{{ target.name }}"]` | `vmid` ← `regex`: `VMID=(\d+)` |
| 2 | `jinja` | `["/usr/sbin/qm", "start", "{{ vars.vmid }}"]` | — |

Command 1's input comes from the NetBox object (`{{ target.name }}`); its output
yields `vmid`; command 2 consumes `{{ vars.vmid }}`. `clean()` accepts command 2
only because `vmid` is produced by the earlier command 1.

## Authoring on the NetBox UI

Add/edit commands on the procedure's **Commands** card or at
`/plugins/rpc/procedure-commands/`. Set `render_mode` to `Jinja2 template`,
write templated tokens in `argv`, and (for producers) fill `produces_var` +
`capture_kind` (+ `capture_expression`). The procedure detail Commands card
shows each step's mode, the produced variable and its capture rule, and the
templated argv, so the chain reads top-to-bottom.
