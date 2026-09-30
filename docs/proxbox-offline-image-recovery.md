# Proxbox API Offline Build-Image Recovery

This procedure pair restores the digest-pinned external images required by one
verified proxbox-api package release. It exists for the narrow case where a
deployment reached the safe pre-activation boundary but the deploy host did not
already contain every external build image.

## Safety contract

The catalog accepts one field: `manifest_sha256`, a lowercase 64-hex digest.
The caller cannot choose an image, registry, host, path, credential, tag, or
command. Both procedures target the `dcim.device` selected by the
`nmulticloud-deploy-host` `RPCTargetBinding`; normalization binds the target,
binding identity and revision, handler, and manifest digest into the immutable
command fingerprint.

| Procedure | Effect | Approval | Timeout |
|---|---|---:|---:|
| `service.nmulticloud.deploy.diagnose_proxbox_api_images` | `read` | No | 120 s |
| `service.nmulticloud.deploy.preload_proxbox_api_images` | `write` | Two-person | 2100 s |

The backend executes only these forced-command gateway vectors:

```text
diagnose-proxbox-api-images <manifest_sha256>
preload-proxbox-api-images <manifest_sha256>
```

The response is closed to `ok`, `procedure`, `target`, `manifest_sha256`,
`stage`, and a bounded `images` array. Each image row contains only `image`,
`present`, and the immutable local `image_id`. Raw transport output and secrets
must never enter results or events.

## Operator sequence

1. List the procedures through `nms rpc procedures` and select the deployment
   host device bound by `nmulticloud-deploy-host`.
2. Create and run diagnosis for the exact release `manifest_sha256`.
3. If images are missing, create the preload execution for the same target and
   digest. A distinct authorized operator must review and approve it.
4. Inspect the durable execution and event history through
   `nms rpc executions` and `nms rpc events`.
5. Run diagnosis again before retrying the package deployment.

Do not automatically retry preload after a timeout, connection loss, malformed
response, or any other post-start non-clean outcome. The write may have
completed. Such outcomes use `stage="indeterminate"`; reconcile current state
with diagnosis first.

## Rollout and retirement

Deploy the reviewed host gateway and standalone `netbox-rpc-backend` capability
before applying or enabling the catalog migration. Capability mismatch or an
unavailable capability fails closed at advertisement, admission, and worker
claim. Migration reversal disables the rows without deleting execution history.

Retire this recovery surface only after the normal package rollout guarantees
that every verified release's external images are pre-positioned. Disable the
catalog procedures before removing backend handlers or host gateway actions,
and retain historical executions and events.
