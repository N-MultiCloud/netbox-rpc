# Backend capability diagnostics

Staff operators can inspect a configured backend without dispatching a procedure:

```console
nms rpc raw GET backends/1/capabilities/ --json
```

The NetBox route is `GET /api/plugins/rpc/backends/{id}/capabilities/`.
Authentication, staff or superuser status, and the backend view permission are
required. Backend object restrictions apply before any upstream fetch. Procedure
object view restrictions independently limit the returned catalog. The endpoint
accepts no query parameters or caller-controlled backend destinations, headers,
paths, timeouts, or refresh options.

The backend row's authoritative `backend_url`, authentication headers, and TLS
verification setting select the server-side target. The existing manifest reader
performs a fresh fetch without cache reads, rejects redirects, and reads at most
512 KiB. An unavailable, oversized, or malformed manifest is reported as unknown.
This diagnostic does not change advertisement, admission, or worker-claim rules.

The response contains the backend ID, manifest availability, supported and
advertised envelope versions, and at most 200 visible catalog procedures ordered
by primary key. `catalog_truncated` identifies an incomplete catalog. Each entry
includes expected and advertised handler identity, version, effect, and contract
hashes, together with the authoritative compatibility status and one reason:

- `unknown_manifest`: no usable manifest was obtained.
- `envelope_mismatch`: the advertised envelope is unsupported.
- `missing_handler`: the procedure's handler is absent.
- `version_mismatch`: the handler version differs.
- `effect_mismatch`: the handler effect differs.
- `contract_mismatch`: no accepted contract hash matches.
- `compatible`: the existing verifier accepts the handler, including reviewed
  compatible-hash and legacy compatibility windows.

Only handlers matching visible procedures are projected. Advertised identities
must satisfy bounded identifier, integer, effect, and hexadecimal digest rules;
invalid identities are omitted with `advertised_projection_valid: false`.
Oversized envelope integers are similarly omitted. Projection failure returns a
fixed 503 response. Backend URLs, credentials, headers, command arguments, unknown
manifest fields, raw upstream errors, and runtime build versions are never
returned. The endpoint does not infer a backend build version from a manifest.

Use the expected and advertised fields to reconcile catalog drift before an
approved procedure execution. This read does not authorize recovery, deployment,
or any other mutation.
