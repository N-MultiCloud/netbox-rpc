# Gitea Organization CI Runner Provision Contract

`service.gitea.actions_runner.provision_org_ci_runner` is the catalog contract
for making both Gitea Actions organization-runner lanes on the dedicated runner
host reproducible. Migration `0084_seed_gitea_org_ci_runner_provision` seeds the
row with `enabled=False`, and `_GITEA_ORG_CI_RUNNER_AVAILABLE` independently
keeps admission, advertisement, and worker claim closed.

There is no `netbox-rpc-backend` handler yet. Do not enable, advertise, approve,
or dispatch this procedure until the paired handler and exact capability
contract are deployed in a coordinated forward rollout.

## Frozen lanes

The caller must select one `lane` enum. That choice selects every installation
identity and trust-posture value as one server-owned unit; callers cannot supply
or override the runner name, labels, image, executor, Compose directory, or
socket/security posture.

| Contract field | `untrusted-python312` | `general-ubuntu` |
| --- | --- | --- |
| Compose directory | `/opt/nmc-ci-untrusted-org-241` | `/opt/nmc-ci-ubuntu-241` |
| Runner name | `ci-untrusted-nmulticloud-org-241` | `ci-ubuntu-nmulticloud-org-241` |
| Image | `nmc/ci-untrusted-runner:python312-241` | `nmulti/gitea-act-ubuntu:22.04-actions` |
| Executor | `host` | `docker` |
| Runner mounts `/var/run/docker.sock` | no | yes |
| Jobs mount `/var/run/docker.sock` | no | no |
| Runner `cap_drop: ALL` | yes | no |
| Runner `no-new-privileges` | yes | no |
| Pinned job user | non-root `cirunner` | none; job image policy applies |

The exact label arrays are:

```text
untrusted-python312:
  ci-untrusted-python312:host

general-ubuntu:
  ubuntu-latest:docker://nmulti/gitea-act-ubuntu:22.04-actions
  ubuntu-24.04:docker://nmulti/gitea-act-ubuntu:22.04-actions
  ubuntu-22.04:docker://nmulti/gitea-act-ubuntu:22.04-actions
```

These lanes intentionally do not share a flattened security profile:

- `untrusted-python312` executes jobs inside the runner container as non-root
  `cirunner`. The runner has no Docker socket, drops all capabilities, and uses
  `no-new-privileges`; its label therefore uses the host executor.
- `general-ubuntu` uses Docker-executor labels. The runner alone mounts the
  Docker socket so it can create sibling job containers. Those job containers
  never receive the socket.

The `prod-deploy` release lane remains on `10.0.30.96` and is deliberately out
of scope for this procedure.

## Caller contract

The assigned NetBox object identifies the prepared runner host. The backend must
resolve host, port, credential, and pinned-known-host policy only from that
object. Caller-provided `rpc_ssh_*` routing is rejected.

Required params:

| Param | Contract |
| --- | --- |
| `lane` | `untrusted-python312` or `general-ubuntu` |
| `registration_token_secret_ref` | exact `nms-secret:<uuid>` reference |

Optional params retain bounded operational controls without changing the
selected lane's frozen identities or security posture:

| Param | Default |
| --- | --- |
| `gitea_instance_url` | `http://10.0.30.96:3000` |
| `organization` | `N-MultiCloud` |
| `install_docker` | `true` |
| `build_runner_image` | `true` |
| `load_prebuilt_runner_image` | `false` |
| `force_recreate` | `false` |

`build_runner_image=true` and `load_prebuilt_runner_image=true` are mutually
exclusive. `additionalProperties` is false. In particular, `runner_name`,
`runner_labels`, `runner_image`, `compose_project_dir`, executor, and trust
posture are never caller params.

The registration credential remains a reference throughout the catalog,
normalization, approval snapshot, command fingerprint, event ledger, tests, and
documentation. Secret material must never enter RPC params, schema defaults,
command rows, results, logs, or durable diagnostics.

## Normalized and result contract

Normalization copies the selected lane's full frozen contract into normalized
params and binds scalar values plus a digest of the exact ordered label array
into `command_fingerprint`. This makes approval drift visible without allowing
the caller to shape the installation.

The closed result schema requires the selected `lane` and all corresponding
constants. It rejects a result that mixes lanes, changes label order, reports a
different image or directory, or flattens the socket/security posture. A
successful result additionally requires:

```text
ok=true
registered=true
online=true
stage=complete
docker_installed=true
image_ready=true
compose_ready=true
```

False results may report only the bounded fields admitted by the same closed
schema. They must never contain a registration credential, remote command
output, arbitrary filesystem content, or an exception chain.

## Future activation sequence

Activation is intentionally out of scope for issue `#277`. When a paired
backend implementation exists, a reviewed rollout must:

1. Implement both exact lane contracts without accepting caller-defined
   labels, images, directories, executors, or socket posture.
2. Resolve only `registration_token_secret_ref`; never accept or emit a raw
   registration credential.
3. Advertise the exact handler/version/effect/contract hash from the backend.
4. Add an audited forward migration that enables the catalog row while the code
   gate is opened in the same coordinated release.
5. Exercise each lane through the approval workflow and verify that the closed
   result matches its frozen contract.

Rollback closes the code/backend gates and disables the catalog row before any
handler removal. Migration `0084` itself reverses by disabling the row; it does
not delete audited procedure history.
