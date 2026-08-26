# netbox-rpc Agent Notes

`AGENTS.md` is the agent-facing source for this repository. Keep this file in
sync when architecture, commands, or workflows change.

Project-facing SSH RPC architecture, naming, security, and testing guidance
lives in `README.md`; keep it aligned with the agent notes below.
The DDD/CQRS/Event Sourcing architecture contract lives in
[`docs/architecture.md`](docs/architecture.md), which also carries the
**System Architecture** diagrams: the component view across netbox-rpc /
netbox-rpc-backend / managed targets, the execution lifecycle, and driver-chain
resolution with the Ansible-first policy and its raw-driver fallback.

## Standalone usage

`netbox-rpc` must boot and migrate without `netbox-nms`. Standalone installs use
the local `RPCBackend` model to reach the execution backend — point it at the
backend by IP address or domain (plus `port` / `use_https`, composed into the
URL, à la netbox-proxbox `FastAPIEndpoint`), or set an explicit `base_url`
override — with TLS verification and an optional static auth header. Deployments that should not store an auth token in NetBox
should configure `PLUGINS_CONFIG["netbox_rpc"]["backend_resolver"]` and return a
`netbox_rpc.backends.BackendTarget`.

When `netbox-nms` is installed and no custom resolver is configured,
`netbox-rpc` auto-detects `netbox_nms.backend.get_backend(pk)` and adapts it to
the same tiny runtime contract. Treat netbox-nms as one optional integration,
not as a required plugin dependency.

## Compatibility

Support NetBox 4.5.8 through 4.6.x (`min_version = "4.5.8"`,
`max_version = "4.6.99"`), including Django 5.2 and 6.0. Keep external
`extras` migration dependencies anchored to `extras.0134_owner`, the final
NetBox 4.5.8 migration and an ancestor in 4.6.x. Any adoption of NetBox
4.6-only APIs must have a 4.5.8 guard or fallback.

## Transport-driver & output-parser selection

Use [`docs/transport-and-parsing-selection.md`](docs/transport-and-parsing-selection.md)
for driver/parser authoring rules, production parser availability, inline
template guidance, security boundaries, and deploy ordering for new pipeline
exemplar procedures.

## RPC Procedure Commands

`AGENTS.md` is the source for the command source-of-truth contract. Keep its
`RPCProcedureCommand` model/API/object-view guidance, command payload shape, and
`EXEMPT_HANDLER_RATIONALE` notes synchronized with README whenever procedure
command behavior changes.

> **LLM Agent Safety:** Before creating any `RPCExecution` record, read the
> **LLM Agent Safety Guardrails** section in `AGENTS.md`. Destructive Proxmox
> procedures (`os.linux.proxmox.convert_mellanox_nic_to_ethernet`) MUST NOT be
> dispatched without explicit human confirmation of the target endpoint, params,
> and expected network impact. The destructive Passbolt migration procedures
> (`services.passbolt.export_secrets`, `services.passbolt.transfer_secrets`,
> `services.passbolt.import_secrets`, and `services.passbolt.cleanup`) also
> require explicit operator approval and must never expose DB dump contents,
> GPG/JWT material, or DB passwords in params, logs, events, or results.
> `service.gitea.production.upgrade_1_27_1` is likewise destructive and must
> never be enabled, created, approved, or dispatched autonomously. It is seeded
> disabled and accepts no caller parameters; see
> `docs/gitea-production-upgrade-1.27.1.md` for its exact target, artifact,
> signed-lease, activation, and rollback contract.
> `service.gitea.actions_runner.provision_org_ci_runner` is an approval-required
> runner-host provisioning procedure, seeded disabled and hard-gated until the
> paired backend handler exists. It accepts only an `nms-secret:<uuid>` runner
> token reference plus bounded metadata, fixes the label to
> `ci-untrusted-python312`, and rejects caller SSH routing. See
> `docs/gitea-org-ci-runner-provision.md`.

@AGENTS.md

## Package Publishing (Gitea Package Registry)

`.gitea/workflows/publish-pypi.yml` builds sdist+wheel and publishes to the
internal registry (`git.nmulti.cloud/api/packages/N-MultiCloud/pypi`) on
`v*` tag push, or via `workflow_dispatch` with a `version` input (used when a
tag predates the workflow). Registry-only: production deploys stay with
`deploy-production.yml`. Verify a published version with `nms git packages`
and confirm the wheel contains `templates/netbox_rpc/*.html` (package-data).

## Production Deployment (source-aware)

Pushes to `main` trigger `.gitea/workflows/deploy-production.yml`, which deploys
the merged commit to the production NetBox instance.

**This plugin is on the source-aware deploy contract — the generic plugin
helper is deliberately refused for it.** `deploy-netbox-plugin` rejects both
`rpc` and `netbox-rpc` up front ("so direct sudo cannot enter the generic plugin
helper"), so `deploy-plugin rpc <ref>` fails with:

```
error: rpc production accepts only fixed source-aware deploy actions
```

The two accepted host-side actions are:

| Action | Argument | Runs |
|---|---|---|
| `deploy-netbox-rpc-package` | exact canonical version | `python-package-deploy netbox-rpc package <version>` |
| `deploy-netbox-rpc-main` | **exact 40-hex commit SHA** | `python-package-deploy netbox-rpc git <sha>` |

`-main` takes a commit SHA, never a branch name.

**Invocation is local-first.** The `prod-deploy` runner runs on the target host
as root and invokes `/opt/nmulticloud/deploy/bin/python-package-deploy`
directly; the SSH branch is only a fallback for a runner placed on another host.
This mirrors `netbox-rpc-backend`'s workflows.

**Deploy source.** A `main` push deploys `main_branch` with `github.sha` — the
merged commit is by definition not yet published as a package. A manual
`workflow_dispatch` offers the estate-standard choice, defaulting to the
immutable `latest_package` (which requires an exact `package_version`).

**Source build lock (required for `main_branch`).** The `git <sha>` path builds
the wheel inside an isolated, pristine snapshot of the commit and installs the
build backend with `--require-hashes`. It therefore refuses to run unless the
commit carries `.gitea/deploy/python-build.lock.json`; without it the deploy
fails with:

```
error: source build lock or pyproject is unreadable
```

The file is canonical JSON (`sort_keys`, `,`/`:` separators, one trailing
newline) and must pin every applicable `[build-system] requires` entry to an
exact `==` version whose sha256 matches the artifact on PyPI:

```json
{"dependencies":[{"hashes":["<sha256>"],"requirement":"setuptools==83.0.0"}],"frontend":{"name":"uv","version":"0.12.5"},"python_version":"3.12.13","schema":1}
```

`python_version` and `frontend.version` must equal the gateway's pinned
`BUILD_PYTHON_VERSION` / `UV_BUILD_VERSION`. Bumping `[build-system] requires`
past the pinned version — or the gateway bumping its own pins — requires
regenerating this file, or every `main_branch` deploy fails closed.

The `latest_package` path does **not** read this lock; it is separately blocked
on the deploy attestation ("completion") package (issue #258).

**Embedded deployment manifest (required for every path).** The gateway then
reads `netbox_rpc/_nmulticloud_deploy.json` **out of the built wheel**. It
synthesises one only for a pre-contract legacy wheel captured during
first-activation recovery — "new package and main candidates must publish the
manifest themselves" — so a wheel without it fails with:

```
error: required deployment manifest is missing for netbox-rpc
```

The manifest declares package identity (name, version, repository, cp312 /
manylinux_2_17_x86_64 runtime target, a sha256 over the wheel's sorted
`Requires-Dist`), the fixed plugin strategy triple
(`dependency_mode="host-provided-no-install"`, empty `dependencies`,
`database_strategy="expand-only-rollback-compatible"`,
`static_strategy="append-only-hashed"`), and a path+sha256 row for **every**
migration and static file in the wheel. The gateway recomputes those digests
from the archive and refuses any mismatch, so the manifest cannot drift from
what is actually shipped.

Generate it — never hand-edit it:

```bash
.gitea/scripts/generate_deploy_manifest.py --write    # rewrites the lock + manifest
.gitea/scripts/generate_deploy_manifest.py            # --check; non-zero if stale
```

`pyproject.toml` must keep `_nmulticloud_deploy.json` in
`[tool.setuptools.package-data]`, or the file exists in the repository and is
silently absent from the wheel.

**The migration attestation is a review gate, not a generated value.** Every
migration row is declared `rollback_compatible: true`, and
`DeploymentContent.from_mapping()` rejects any other value — so the manifest can
only be built by attesting that the whole migration graph is expand-only.
`.gitea/deploy/migration-compatibility.json` pins the count and a canonical
digest of those rows; adding a migration makes the manifest generator fail
with "migration compatibility policy is stale" until a human reviews the new
migration and renews the file:

```bash
.gitea/scripts/generate_deploy_manifest.py --show-migration-attestation > \
  .gitea/deploy/migration-compatibility.json
```

Renew it only after confirming the new migration is additive: no `RemoveField`,
`DeleteModel`, `RenameField`/`RenameModel`, no narrowing `AlterField`, and no
data-destroying `RunPython`/`RunSQL`. Dropping a stale constraint (as `0034`
does) and adding a nullable column with a backfill (as `0031` does) are both
expand-only; removing a column an older plugin version still reads is not.

**Repository variables** (Settings → Actions → Variables), all optional:

| Variable | Default |
|---|---|
| `DEPLOY_PACKAGE_BIN` | `/opt/nmulticloud/deploy/bin/python-package-deploy` |
| `DEPLOY_STATUS_BIN` | `/opt/nmulticloud/deploy/bin/status-app` |
| `DEPLOY_SSH_HOST` | `nmc-prod-207` |

> The legacy `DEPLOY_PLUGIN_BIN` variable is **no longer used** by this
> workflow. It points at `deploy-netbox-plugin`, which refuses this plugin.

**Status reporting** queries the `netbox` app, not `netbox-rpc` — the host-side
validator accepts only its known app names and `netbox-rpc` is not one, and the
service whose health matters after a plugin deploy is NetBox itself.

**Manual dispatch:**

```bash
# Deploy the current main commit
nms git api POST /repos/N-MultiCloud/netbox-rpc/actions/workflows/deploy-production.yml/dispatches \
  --body-json '{"ref":"main","inputs":{"deploy_source":"main_branch","package_version":""}}'

# Deploy a published package version
nms git api POST /repos/N-MultiCloud/netbox-rpc/actions/workflows/deploy-production.yml/dispatches \
  --body-json '{"ref":"main","inputs":{"deploy_source":"latest_package","package_version":"0.1.6"}}'
```

**Monitoring:** watch the run in Gitea Actions; the final step prints the
deploy-target status.

For comprehensive deploy infrastructure documentation, see `/root/personal-context/nmulticloud-context/CLAUDE.md` section "Automatic Plugin Deployment to Production".
