# Minecraft Stack RPC Guardrails

`netbox-rpc` is the policy, catalog, validation, and audit owner for Minecraft
stack procedures. It does not execute SSH commands. The execution boundary is
`nms-backend automation.rpc`; browser callers reach these procedures only
through the NMS `/minecraft/servers/{id}/...` bridge.

This document is intentionally prescriptive. If an implementation change
weakens any item here, update the tests in the same change and record why the
new boundary is still safe.

## Ownership Boundary

| Concern | Owner | Guardrail |
|---|---|---|
| Procedure name, handler ID, effect, timeout, approval flag | `netbox-rpc` constants and migration `0029` | Handler IDs must match procedure names exactly. No procedure stores shell text. |
| Input policy | `params_schema` plus NetBox normalizers | Every Minecraft schema has `additionalProperties: False`; unexpected fields are rejected before enqueue. |
| Execution record and audit fields | `RPCExecution` and `normalize_execution_params()` | Normalized params are structured data. URL values are fingerprinted with SHA-256 in `command_fingerprint`. |
| SSH target and credential | `DeviceService` SSH rows or explicit `rpc_ssh_*` overrides | SSH overrides are connection metadata only. They are not command text. |
| Shell command construction | `nms-backend automation.rpc.handlers` | Backend handlers build fixed command templates from normalized fields only. |
| Browser route | the NMS browser console through NMS | Browser never receives SSH credentials, NetBox service tokens, backend URLs, or raw RPC internals. |

## Procedures

All six procedures target `dcim.device` and `virtualization.virtualmachine`.
They are seeded by `netbox_rpc/migrations/0029_seed_minecraft_stack_procedures.py`.

| Procedure | Effect | Approval | Required params | Purpose |
|---|---:|---:|---|---|
| `services.minecraft.plugin.install_url` | write | no | `server_uuid`, `source_url`, `filename` | Install one public `.jar` URL into a server `plugins/` directory. |
| `services.minecraft.viaversion.install` | write | no | `server_uuid` | Install ViaVersion-family plugins by preset or explicit enum list. |
| `services.minecraft.papermc.install` | write | no | `server_uuid`, `project`, `version` | Install Paper, Folia, or Velocity server JAR from PaperMC Fill API metadata. |
| `services.pterodactyl.wings.status` | read | no | none | Read `wings.service` status on a node. |
| `services.pterodactyl.wings.logs` | read | no | none | Read bounded `wings.service` journal output. |
| `services.pterodactyl.wings.restart` | write | yes | none | Restart `wings.service`; approval is required because node management is disrupted. |

## Accepted Structured Params

### Common SSH override fields

These optional fields may be emitted into `normalized_params`:

- `rpc_ssh_credential_pk`
- `rpc_ssh_host`
- `rpc_ssh_port`
- `rpc_ssh_known_hosts_entry`
- `rpc_ssh_strict_host_key_checking`

They select the SSH endpoint consumed by `nms-backend`. They must not be used
to pass command fragments, remote paths, package names, service names, or shell
arguments.

### Plugin URL install

`services.minecraft.plugin.install_url` accepts:

- `server_uuid`: canonical UUID. The normalizer lowercases it.
- `source_url`: `http://` or `https://` only, max 2048 characters.
- `filename`: safe `.jar` filename, max 128 characters.
- `restart`: boolean, default `false`.
- optional `rpc_ssh_*` override fields.

URL guardrails:

- Rejects non-HTTP schemes such as `ftp:`, `file:`, `data:`, and `ssh:`.
- Rejects `localhost`, `localhost.localdomain`, and `.local` names.
- Rejects private, loopback, link-local, and multicast literal IP addresses.
- Rejects control characters.
- Stores `source_url_sha256` in `command_fingerprint` instead of the raw URL.

Filename guardrails:

- Must match `^[A-Za-z0-9._-]+\.jar$`.
- Must not include `..`, `/`, or `\`.
- Is never treated as a path; the backend places it under the fixed server
  volume directory.

### ViaVersion install

`services.minecraft.viaversion.install` accepts:

- `server_uuid`: canonical UUID.
- `preset`: `minimal`, `standard`, or `full`; default `standard`.
- `plugins`: optional explicit list of `viaversion`, `viabackwards`,
  `viarewind`; when present it overrides `preset`.
- `restart`: boolean, default `false`.
- optional `rpc_ssh_*` override fields.

Plugin guardrails:

- Unknown plugin names are rejected.
- Duplicate plugin names are rejected.
- The normalizer reorders custom plugin lists into deterministic install order:
  `viaversion`, `viabackwards`, `viarewind`.
- Download project names are fixed in `nms-backend`; callers never pass a repo
  owner, repository name, asset pattern, or download command.

### PaperMC install

`services.minecraft.papermc.install` accepts:

- `server_uuid`: canonical UUID.
- `project`: one of `paper`, `folia`, or `velocity`.
- `version`: safe PaperMC version identifier, max 64 characters.
- `build_id`: optional integer >= 1.
- `server_jarfile`: safe `.jar` filename, default `server.jar`.
- `restart`: boolean, default `false`.
- optional `rpc_ssh_*` override fields.

Project guardrails:

- The project enum is closed. Do not add a new project without matching
  backend handler tests and documentation.
- The backend resolves downloads from PaperMC Fill API v3. Callers do not pass
  a direct PaperMC URL for this procedure.
- The JAR destination is always under the fixed Pterodactyl server volume root.

### Wings service operations

The Wings procedures accept only optional SSH override fields plus `lines` for
logs. The service is always `wings.service`; callers cannot select another
systemd unit.

`services.pterodactyl.wings.logs` clamps `lines` to 1..500 at both schema and
normalizer boundaries.

## Explicitly Rejected Inputs

The Minecraft stack schemas and normalizers must never accept any of these
parameter names or equivalents:

- `command`
- `commands`
- `shell_command`
- `raw_command`
- `command_text`
- `script`
- `argv`
- `args`
- arbitrary destination paths
- arbitrary service names
- arbitrary package names
- arbitrary repository owner/name pairs

If an operation needs a new field, the field must be a narrow enum, bounded
integer, canonical identifier, or regex-constrained string with a test that
proves hostile examples fail.

## Audit Requirements

Every normalized Minecraft execution must include a `command_fingerprint` with:

- the backend `handler_id`,
- the canonical target identifier such as `server_uuid`,
- sorted or deterministic enum selections,
- bounded booleans and integer options,
- hashes for sensitive or lengthy URL-like values.

Do not add credentials, bearer tokens, SSH private keys, raw known-hosts data,
or raw download URLs to the command fingerprint unless there is a documented
audit requirement and a redaction/hash strategy.

## Extension Checklist

Before adding or changing a Minecraft stack procedure:

1. Add or update the constants entry and migration seed data.
2. Keep `name == handler_id` unless a documented compatibility constraint
   requires otherwise.
3. Keep `additionalProperties: False`.
4. Add a normalizer branch in `jobs.py`.
5. Add normalizer tests for valid input and rejected hostile input.
6. Add static tests that pin schema fields, migration seed data, and docs.
7. Update this guide, `README.md`, and `AGENTS.md`.
8. Coordinate the matching backend handler in `nms-backend`.
9. Keep browser-facing route docs in the NMS browser console aligned.

## Verification Map

| Requirement | Test location |
|---|---|
| Procedure names and migration seed data stay aligned | `tests/test_static_contract.py` |
| Schemas remain closed and command-free | `tests/test_static_contract.py` |
| URL, UUID, filename, enum, and project validation | `tests/test_jobs_pterodactyl_normalization.py` |
| Source URL is hashed in the fingerprint | `tests/test_jobs_pterodactyl_normalization.py` |
| Wings restart remains approval-gated | `tests/test_static_contract.py` |

