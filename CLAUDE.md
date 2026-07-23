# netbox-rpc Agent Notes

`AGENTS.md` is the agent-facing source for this repository. Keep this file in
sync when architecture, commands, or workflows change.

Project-facing SSH RPC architecture, naming, security, and testing guidance
lives in `README.md`; keep it aligned with the agent notes below.
The DDD/CQRS/Event Sourcing architecture contract lives in
[`docs/architecture.md`](docs/architecture.md).

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

@AGENTS.md

## Package Publishing (Gitea Package Registry)

`.gitea/workflows/publish-pypi.yml` builds sdist+wheel and publishes to the
internal registry (`git.nmulti.cloud/api/packages/N-MultiCloud/pypi`) on
`v*` tag push, or via `workflow_dispatch` with a `version` input (used when a
tag predates the workflow). Registry-only: production deploys stay with
`deploy-production.yml`. Verify a published version with `nms git packages`
and confirm the wheel contains `templates/netbox_rpc/*.html` (package-data).

## Automatic Production Deployment

**Starting with the deploy-production workflow**, new commits to `main` automatically deploy to the production NetBox instance (deploy target configured per-environment via the `deploy-production` workflow's `DEPLOY_*` variables/secrets).

**Deploy job in `.gitea/workflows/deploy-production.yml`:**
- Triggers on `push: [main]` branch updates
- Also supports manual dispatch via `workflow_dispatch` with optional `ref` input
- Runs on `prod-deploy` runner with SSH access to production host
- Executes: `ssh <prod-deploy-host> -- deploy-plugin <plugin-name> "$REF"`

**Deploy parameters:**
- REF: can be a version tag (v0.1.0), branch name (main/develop), or 7+ character commit SHA
- Default: uses current commit SHA if not specified in manual dispatch

**Security hardening:**
- REF is passed via environment variable, not direct GitHub Actions context interpolation
- Bash case statement validates ref format before SSH (whitelist: version tags, branch names, commit SHAs)
- StrictHostKeyChecking=accept-new prevents MITM attacks
- Quoted variable interpolation prevents shell injection

**Deployment on production server (`<prod-deploy-host>`):**
1. Git fetch/checkout of the specified ref in the plugin submodule
2. pip install -e to refresh editable install and pick up new dependencies
3. manage.py migrate to apply any pending migrations
4. manage.py collectstatic to collect new/updated static files
5. systemctl reload netbox-production (graceful gunicorn reload)
6. systemctl restart netbox-rq (RQ worker restart for code changes)
7. Health check: curl -sf http://127.0.0.1:18001/api/ to verify service is responding

**Monitoring and verification:**
- Watch the `deploy-production.yml` workflow run in Gitea Actions
- Check the `deploy` job logs for SSH output and health check results
- Verify production is healthy: `ssh <prod-deploy-host> -- health netbox`
- Check service logs: `ssh <prod-deploy-host> -- logs netbox`

**Manual deployment trigger:**
```bash
# Deploy a specific tag or branch via workflow dispatch
nms git actions run <plugin> .gitea/workflows/deploy-production.yml \
  -r main -f ref=v0.1.0

# Or SSH directly to production
ssh <prod-deploy-host> -- deploy-plugin <plugin-name> v0.1.0
```

For comprehensive deploy infrastructure documentation, see `/root/personal-context/nmulticloud-context/CLAUDE.md` section "Automatic Plugin Deployment to Production".
