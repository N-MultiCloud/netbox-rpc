# Gitea Organization CI Runner Provision Runbook

This runbook documents the operator procedure behind
`service.gitea.actions_runner.provision_org_ci_runner`.

The procedure provisions one dedicated Gitea Actions organization runner for
ordinary N-MultiCloud CI. It is fixed to the scalar label
`ci-untrusted-python312`; it must not be generalized to `prod-deploy`,
`mirror-host`, `ubuntu-latest`, or `self-hosted`.

The catalog row is seeded by migration `0080` with `enabled=False` and a closed
code gate. It becomes runnable only after the matching
`service.gitea.actions_runner.*` handler and capability contract are deployed
in `netbox-rpc-backend`.

## Procedure IDs

Resolve the NetBox primary key immediately before use:

```bash
RUNNER_PROCEDURE_ID="$(nms rpc procedures list --json --filter name=service.gitea.actions_runner.provision_org_ci_runner | jq -r '.results[0].id')"
```

Expected procedure and handler:

| Procedure | Handler |
| --- | --- |
| `service.gitea.actions_runner.provision_org_ci_runner` | `service.gitea.actions_runner.provision_org_ci_runner` |

## Operator Inputs

Use the exact NetBox object for the runner host. For the current host, that is
the object whose management address is `10.0.30.241`.

```bash
TARGET_TYPE="virtualization.virtualmachine"
TARGET_ID="<runner-host-object-id>"
REGISTRATION_TOKEN_SECRET_REF="nms-secret:<uuid>"
```

Generate the one-time organization runner token from Gitea, store it in the
NMS secret bridge, and pass only the returned `nms-secret:<uuid>` reference.
Do not place the token or the SSH password in RPC params, shell history, PRs,
issues, docs, events, or command rows.

Optional params and defaults:

| Param | Default |
| --- | --- |
| `gitea_instance_url` | `http://10.0.30.96:3000` |
| `organization` | `N-MultiCloud` |
| `runner_name` | `ci-untrusted-nmulticloud-org-241` |
| `install_docker` | `true` |
| `build_runner_image` | `true` |
| `load_prebuilt_runner_image` | `false` |
| `force_recreate` | `false` |

The runner label and image are not caller input:

```text
ci-untrusted-python312:docker://nmulti/gitea-act-ubuntu:22.04-actions
```

## NMS Execution

After the backend handler rollout opens the gate and enables the procedure:

```bash
nms rpc executions create \
  --procedure "$RUNNER_PROCEDURE_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json "{\"registration_token_secret_ref\":\"$REGISTRATION_TOKEN_SECRET_REF\"}" \
  --wait \
  --timeout 2400
```

For a rebuild that intentionally replaces local runner state:

```bash
nms rpc executions create \
  --procedure "$RUNNER_PROCEDURE_ID" \
  --assigned-object-type "$TARGET_TYPE" \
  --assigned-object-id "$TARGET_ID" \
  --params-json "{\"registration_token_secret_ref\":\"$REGISTRATION_TOKEN_SECRET_REF\",\"force_recreate\":true}" \
  --wait \
  --timeout 2400
```

The result must report `ok=true`, `registered=true`, `online=true`,
`stage="complete"`, `docker_installed=true`, `image_ready=true`, and
`compose_ready=true`.

## Manual Command Record

These are the shell commands to translate into an Ansible role or to run during
backend-handler development. Replace placeholders with reviewed values. Keep
the registration token out of history by loading it from the vault or a
root-only temporary file.

Local operator shell:

```bash
export RUNNER_HOST="10.0.30.241"
export RUNNER_USER="runner"
export GITEA_INSTANCE_URL="http://10.0.30.96:3000"
export GITEA_ORGANIZATION="N-MultiCloud"
export RUNNER_NAME="ci-untrusted-nmulticloud-org-241"
export RUNNER_LABEL="ci-untrusted-python312:docker://nmulti/gitea-act-ubuntu:22.04-actions"
export RUNNER_IMAGE="nmulti/gitea-act-ubuntu:22.04-actions"
export ACT_RUNNER_IMAGE="docker.io/gitea/act_runner:latest"
export PYTHON_STANDALONE_RELEASE="<reviewed-python-build-standalone-release>"
export PYTHON_STANDALONE_SHA256="<reviewed-python-build-standalone-sha256>"
export UV_RELEASE="0.12.5"
export UV_SHA256="<reviewed-uv-linux-x86_64-sha256>"
export REGISTRATION_TOKEN_FILE="<root-only-file-containing-token>"
```

Create the runner image Dockerfile:

```bash
cat > /tmp/gitea-act-runner.Dockerfile <<'DOCKERFILE'
FROM ghcr.io/catthehacker/ubuntu:act-22.04

ARG PYTHON_312_VERSION=3.12.14
ARG PYTHON_STANDALONE_RELEASE
ARG PYTHON_STANDALONE_SHA256
ARG PYTHON_STANDALONE_URL=https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_STANDALONE_RELEASE}/cpython-${PYTHON_312_VERSION}+${PYTHON_STANDALONE_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz
ARG UV_RELEASE=0.12.5
ARG UV_SHA256
ARG UV_URL=https://github.com/astral-sh/uv/releases/download/${UV_RELEASE}/uv-x86_64-unknown-linux-gnu.tar.gz

USER root
SHELL ["/bin/bash", "--login", "-e", "-o", "pipefail", "-c"]

RUN test -n "${PYTHON_STANDALONE_RELEASE}" \
    && test -n "${PYTHON_STANDALONE_SHA256}" \
    && mkdir -p /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64 \
    && curl -fsSL "${PYTHON_STANDALONE_URL}" -o /tmp/python.tgz \
    && echo "${PYTHON_STANDALONE_SHA256}  /tmp/python.tgz" | sha256sum -c - \
    && tar -xz --strip-components=1 \
      -C /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64 \
      -f /tmp/python.tgz \
    && rm -f /tmp/python.tgz \
    && touch /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64.complete \
    && ln -sfn /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/bin/python3.12 /usr/local/bin/python3.12 \
    && ln -sfn /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/bin/python3.12 /usr/local/bin/python3 \
    && ln -sfn /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/bin/python3.12 /usr/local/bin/python \
    && ln -sfn /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/bin/pip3.12 /usr/local/bin/pip3.12 \
    && ln -sfn /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/bin/pip3.12 /usr/local/bin/pip3 \
    && ln -sfn /opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/bin/pip3.12 /usr/local/bin/pip

RUN test -n "${UV_SHA256}" \
    && curl -fsSL "${UV_URL}" -o /tmp/uv.tgz \
    && echo "${UV_SHA256}  /tmp/uv.tgz" | sha256sum -c - \
    && tar -xz -C /tmp -f /tmp/uv.tgz \
    && install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv \
    && rm -rf /tmp/uv.tgz /tmp/uv-x86_64-unknown-linux-gnu

RUN rm -rf /opt/cargo /opt/rustup /root/.cargo /root/.rustup \
    && mkdir -p /opt/cargo /opt/rustup \
    && RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
      curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
      | RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
        sh -s -- -y --default-toolchain stable --profile minimal --component clippy \
    && ln -sfn /opt/cargo /root/.cargo \
    && ln -sfn /opt/rustup /root/.rustup \
    && /opt/cargo/bin/rustup --version \
    && /opt/cargo/bin/rustc --version \
    && /opt/cargo/bin/cargo --version

ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    AGENT_TOOLSDIRECTORY=/opt/hostedtoolcache \
    RUNNER_TOOL_CACHE=/opt/hostedtoolcache \
    LD_LIBRARY_PATH=/opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/lib \
    LIBRARY_PATH=/opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/lib \
    C_INCLUDE_PATH=/opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/include/python3.12 \
    PKG_CONFIG_PATH=/opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/lib/pkgconfig \
    PATH=/root/.cargo/bin:/opt/hostedtoolcache/Python/${PYTHON_312_VERSION}/x64/bin:/opt/acttoolcache/node/24.15.0/x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN test "$(/usr/local/bin/python3.12 --version)" = "Python 3.12.14" \
    && test "$(/usr/local/bin/uv --version)" = "uv 0.12.5 (x86_64-unknown-linux-gnu)"
DOCKERFILE
```

Copy the Dockerfile and verify SSH reachability:

```bash
scp /tmp/gitea-act-runner.Dockerfile "${RUNNER_USER}@${RUNNER_HOST}:/tmp/gitea-act-runner.Dockerfile"
ssh "${RUNNER_USER}@${RUNNER_HOST}" 'id && uname -a && command -v docker || true'
```

Install Docker when absent:

```bash
ssh "${RUNNER_USER}@${RUNNER_HOST}" 'bash -se' <<'REMOTE'
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-plugin
  sudo systemctl enable --now docker
fi
sudo usermod -aG docker runner
sudo docker version
REMOTE
```

Build the CI job image on the runner host:

```bash
ssh "${RUNNER_USER}@${RUNNER_HOST}" \
  "sudo docker build \
    --build-arg PYTHON_STANDALONE_RELEASE='${PYTHON_STANDALONE_RELEASE}' \
    --build-arg PYTHON_STANDALONE_SHA256='${PYTHON_STANDALONE_SHA256}' \
    --build-arg UV_RELEASE='${UV_RELEASE}' \
    --build-arg UV_SHA256='${UV_SHA256}' \
    -t '${RUNNER_IMAGE}' \
    -f /tmp/gitea-act-runner.Dockerfile /tmp"
```

Create the runner project files. This reads the registration token from the
operator-side file and writes only the remote `.env`, which must be mode 0600.

```bash
REGISTRATION_TOKEN="$(tr -d '\r\n' < "$REGISTRATION_TOKEN_FILE")"
export REGISTRATION_TOKEN
ssh "${RUNNER_USER}@${RUNNER_HOST}" 'sudo install -d -m 0755 /opt/gitea-ci-runner/data'
ssh "${RUNNER_USER}@${RUNNER_HOST}" 'sudo tee /opt/gitea-ci-runner/config.yaml >/dev/null' <<'YAML'
log:
  level: info
runner:
  file: /data/.runner
  capacity: 1
  timeout: 3h
  shutdown_timeout: 10s
cache:
  enabled: true
  dir: /data/cache
container:
  network: host
  valid_volumes:
    - /tmp
host:
  workdir_parent: /data/work
YAML

ssh "${RUNNER_USER}@${RUNNER_HOST}" \
  "sudo install -m 0600 /dev/null /opt/gitea-ci-runner/.env && \
   sudo tee /opt/gitea-ci-runner/.env >/dev/null" <<EOF
GITEA_INSTANCE_URL=${GITEA_INSTANCE_URL}
GITEA_RUNNER_REGISTRATION_TOKEN=${REGISTRATION_TOKEN}
GITEA_RUNNER_NAME=${RUNNER_NAME}
GITEA_RUNNER_LABELS=${RUNNER_LABEL}
CONFIG_FILE=/config.yaml
EOF

ssh "${RUNNER_USER}@${RUNNER_HOST}" 'sudo tee /opt/gitea-ci-runner/docker-compose.yml >/dev/null' <<EOF
services:
  gitea-runner:
    image: ${ACT_RUNNER_IMAGE}
    container_name: gitea-ci-untrusted-nmulticloud-org-241
    restart: unless-stopped
    env_file:
      - /opt/gitea-ci-runner/.env
    volumes:
      - /opt/gitea-ci-runner/config.yaml:/config.yaml:ro
      - /opt/gitea-ci-runner/data:/data
      - /var/run/docker.sock:/var/run/docker.sock
EOF
unset REGISTRATION_TOKEN
```

Start and inspect the runner:

```bash
ssh "${RUNNER_USER}@${RUNNER_HOST}" \
  'sudo docker compose -f /opt/gitea-ci-runner/docker-compose.yml up -d'
ssh "${RUNNER_USER}@${RUNNER_HOST}" \
  'sudo docker compose -f /opt/gitea-ci-runner/docker-compose.yml ps'
ssh "${RUNNER_USER}@${RUNNER_HOST}" \
  'sudo docker compose -f /opt/gitea-ci-runner/docker-compose.yml logs --tail=80 gitea-runner'
```

Record the exact pulled image digest for later Ansible pinning:

```bash
ssh "${RUNNER_USER}@${RUNNER_HOST}" \
  "sudo docker image inspect '${ACT_RUNNER_IMAGE}' --format '{{index .RepoDigests 0}}'"
ssh "${RUNNER_USER}@${RUNNER_HOST}" \
  "sudo docker image inspect '${RUNNER_IMAGE}' --format '{{.Id}}'"
```

Verify from Gitea or its database that the organization runner named
`ci-untrusted-nmulticloud-org-241` is online and advertises exactly
`ci-untrusted-python312`.

## Ansible Mapping Notes

Map the commands to idempotent tasks in this order:

1. Install `docker.io` and `docker-compose-plugin`, then enable `docker`.
2. Render the audited runner-image Dockerfile with reviewed Python and uv hashes.
3. Build or load `nmulti/gitea-act-ubuntu:22.04-actions`.
4. Create `/opt/gitea-ci-runner`, `config.yaml`, `.env` mode `0600`, and
   `docker-compose.yml`.
5. Start the compose service and check container health/log tail.
6. Verify Gitea sees the runner online with only `ci-untrusted-python312`.

Sources for release metadata:

- python-build-standalone publishes release metadata at
  `https://raw.githubusercontent.com/astral-sh/python-build-standalone/latest-release/latest-release.json`.
- uv release artifacts are published under
  `https://github.com/astral-sh/uv/releases`.
