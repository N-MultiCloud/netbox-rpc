"""Seed `service.openbao.1.provision_netbox_approle` (issue #296).

Extends the OpenBao catalogue seeded by `0078` rather than starting a parallel
family: same canonical/handler naming (`service.openbao.1.<op>` /
`service.openbao_1.<op>`), same `backend-orchestrated` command row, same
all-or-nothing ownership rule, same irreversibility.

## What it is for

`netbox-openbao` is installed on the NetBox estate and inert: it has no
`SecretEngine`, and no engine is useful until an AppRole exists for NetBox to
authenticate with. Creating one today means a human running `bao` at a shell
holding an admin token — unaudited, unrepeatable, and outside this catalogue.

## Why this is one procedure rather than a sequence of the existing ones

`secrets_enable` and `auth_enable` are already seeded and could each do a step,
but the operation as a whole is not decomposable into them. Provisioning is
**idempotent as a unit** — mount, policy, auth method, role, then a SecretID
delivered to the file NetBox reads — and a caller driving four separate
approval-gated procedures could stop half way, leaving a policy with no role or
a role with no credential. Neither existing procedure can write a policy at all.

## The policy problem, and why this does not reopen it

`policy_write` is deliberately withheld from this catalogue, and the reason
matters here: it was the only procedure accepting **free-form text**, where
shape detection cannot guarantee that encoded, split, or homoglyph-obscured
secrets are never persisted without also rejecting legitimate policy documents.
Withholding it makes "no seeded procedure accepts free-form text" a *structural*
property rather than a signature-dependent one.

This procedure writes a policy and **does not reopen that hole**. It accepts no
policy text. The document is generated inside the backend from a fixed template
whose only variable is `mount`, already constrained by the catalogue's mount
pattern. There is no parameter through which arbitrary text could reach the
policy, so the structural guarantee is preserved: still no seeded procedure
takes free-form text.

## The credential never comes back

A SecretID is a credential, and `RPCExecution.params` is persisted **before**
the backend validates anything, while `result` is persisted after. So neither
the RoleID nor the SecretID may appear in either. Returning a SecretID would put
a live OpenBao credential into the NetBox database, which is precisely what
`netbox-openbao` exists to prevent — its own `SecretEngine` model "deliberately
holds no authentication material".

The procedure therefore delivers the credential to where it is consumed, an
environment file the NetBox service reads, and reports only non-secret
metadata: the mount, the policy, the role, the AppRole **accessor** (an
identifier usable to revoke, never to authenticate), and the file path.
`additionalProperties: false` on the result schema is what makes that
enforceable rather than a convention.

Seeded `enabled=False`, unlike `0078`'s rows: the handler and a scoped
provisioning token in the backend's environment must both exist first, and
enabling before then yields a procedure that fails at execution rather than at
configuration.
"""

from django.db import migrations

_OPERATION = "provision_netbox_approle"
_NAME = f"service.openbao.1.{_OPERATION}"
_HANDLER_ID = f"service.openbao_1.{_OPERATION}"

# Same target restriction as 0078: the backend's OpenBao credential lookup
# rejects VM identities, so virtualization.virtualmachine must not be
# advertised here either.
_TARGET_MODELS = ["dcim.device"]

_MOUNT_PATH_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
    r"(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,63})*/?(?![\s\S])"
)
# Role and engine slug are single path segments and reach a remote command, so
# they are narrower than the mount pattern rather than equal to it.
_ROLE_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,62}(?![\s\S])"
_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}(?![\s\S])"

_TEXT = {"type": "string", "minLength": 1, "maxLength": 512}

_PARAMS = {
    "type": "object",
    "required": ["mount", "role_name", "engine_slug"],
    # No rpc_ssh_* overrides, matching the rest of this catalogue: params are
    # persisted before the backend can refuse them, so declining to declare the
    # fields here is the layer that actually prevents persistence.
    "additionalProperties": False,
    "properties": {
        "mount": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": _MOUNT_PATH_PATTERN,
        },
        "role_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 63,
            "pattern": _ROLE_PATTERN,
        },
        "engine_slug": {
            "type": "string",
            "minLength": 1,
            "maxLength": 63,
            "pattern": _SLUG_PATTERN,
        },
        # Declared because the normalizer accepts it and the backend scopes the
        # ACL to `<path_prefix>/credentials/*` with it. Omitting it from a
        # closed schema meant the API rejected every explicit value and
        # silently forced the default, so a deployment using another prefix got
        # a policy for the wrong subtree and could not authenticate.
        "path_prefix": {
            "type": "string",
            "minLength": 1,
            "maxLength": 63,
            "pattern": _ROLE_PATTERN,
        },
        # `ttl_seconds`, not `secret_id_ttl`: the event store redacts any
        # key containing "secret" by substring, which would turn this
        # integer into the string "[REDACTED]" and fail schema validation.
        "ttl_seconds": {
            "type": "integer",
            "minimum": 0,
            "maximum": 31536000,
        },
        "restart_netbox": {"type": "boolean"},
    },
}

_SUCCESS_METADATA = (
    "mount",
    "policy",
    "role_name",
    "engine_slug",
    "env_prefix",
    "env_file",
    # `approle_accessor`, not `secret_id_accessor`, and `ttl_seconds`, not
    # `secret_id_ttl`. The event store redacts any key CONTAINING "secret",
    # by substring, so the earlier names were destroyed on persistence: the
    # accessor became "[REDACTED]" and the integer TTL became a string, which
    # then failed post-redaction schema validation. That records
    # RPC_RESULT_SCHEMA_MISMATCH *after* the credential has been minted and
    # installed, and an operator retrying that apparent failure mints another.
    # The values are not secret; the names simply have to survive the filter.
    "approle_accessor",
    "ttl_seconds",
    "created_mount",
    "created_policy",
    "created_approle_method",
    "created_role",
    "netbox_restarted",
    "revocation_pending",
)

_RESULT = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _HANDLER_ID},
        "target": _TEXT,
        "mount": _TEXT,
        "policy": _TEXT,
        "role_name": _TEXT,
        "engine_slug": _TEXT,
        # Derived from engine_slug; the variable names NetBox reads.
        "env_prefix": _TEXT,
        "env_file": _TEXT,
        # Revokes a SecretID. Cannot authenticate with one.
        "approle_accessor": _TEXT,
        "ttl_seconds": {"type": "integer", "minimum": 0},
        "created_mount": {"type": "boolean"},
        "created_policy": {"type": "boolean"},
        "created_approle_method": {"type": "boolean"},
        "created_role": {"type": "boolean"},
        "netbox_restarted": {"type": "boolean"},
        # Superseded credentials whose revocation did not succeed. They are
        # still live, so this must be visible in the execution record rather
        # than only in a file on the target.
        "revocation_pending": {"type": "integer", "minimum": 0},
        # Deliberately not `_TEXT`: `_TEXT` has minLength 1, and an empty
        # detail is the normal shape of a success. Rejecting it would fail
        # validation *after* the credential was published and the previous
        # one revoked, and invite a retry that mints another.
        "detail": {"type": "string", "maxLength": 512},
    },
    # A success that omits the accessor or the file path is unrecoverable: the
    # operator cannot tell what changed and cannot revoke what was minted. So
    # success requires the whole metadata tuple, and only a failure may be
    # sparse.
    "allOf": [
        {
            "if": {"properties": {"ok": {"const": True}}, "required": ["ok"]},
            "then": {"required": list(_SUCCESS_METADATA)},
        }
    ],
}

_DESCRIPTION = (
    "Provision the NetBox AppRole on an OpenBao server: ensure the KV v2 "
    "mount, an ACL policy generated from a fixed template and scoped to that "
    "mount alone, the approle auth method, and the role; then issue a SecretID "
    "and write it with the RoleID to the environment file the NetBox service "
    "reads. Idempotent. Accepts no free-form text and returns no credential."
)

_PROCEDURE = {
    "name": _NAME,
    "handler_id": _HANDLER_ID,
    # Mints a credential and rewrites a service's environment. Never runs
    # without a human.
    "effect": "write",
    "approval_required": True,
    # End-to-end budget with headroom: provisioning is bounded at 180s and
    # each of the two service restarts at 60s, so the route can consume 300s
    # before this deadline is reached. A caller timeout after publication --
    # or between the two restarts -- leaves an ambiguous execution and
    # possibly one consumer on the old credential.
    "timeout_seconds": 420,
    "description": _DESCRIPTION,
    "params_schema": _PARAMS,
    "result_schema": _RESULT,
}


def _command():
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "openbao-provision-netbox-approle"],
        "description": _DESCRIPTION,
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
    }


def _seed(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    # Ownership is all-or-nothing, as in 0078: adopting an operator-created row
    # would overwrite it, and no reverse-time check could later tell that row
    # apart from migration-owned data.
    if RPCProcedure.objects.filter(name=_NAME).exists():
        raise RuntimeError(
            "Migration 0089 cannot seed the OpenBao AppRole procedure because "
            f"an RPC procedure named {_NAME} already exists; preserve and "
            "reconcile the operator-owned row before retrying."
        )
    procedure = RPCProcedure.objects.create(
        name=_NAME,
        handler_id=_PROCEDURE["handler_id"],
        effect=_PROCEDURE["effect"],
        approval_required=_PROCEDURE["approval_required"],
        timeout_seconds=_PROCEDURE["timeout_seconds"],
        description=_PROCEDURE["description"],
        params_schema=_PROCEDURE["params_schema"],
        result_schema=_PROCEDURE["result_schema"],
        version=1,
        # Enabled only once the handler is deployed and a scoped provisioning
        # token exists in the backend's environment.
        enabled=False,
        target_models=_TARGET_MODELS,
    )
    RPCProcedureCommand.objects.create(procedure=procedure, sequence=1, **_command())


def _remove(apps, schema_editor):
    """Abort rather than guess, matching 0078.

    Procedure rows are operator-mutable and executions protect their procedure
    through an on-delete PROTECT foreign key, so there is no reverse that can
    distinguish migration-owned state from an operator's edits. Removal or
    repair is a reviewed forward migration.
    """
    raise RuntimeError(
        "Migration 0089 is irreversible: the OpenBao AppRole procedure may "
        "carry executions that are the audit record of a credential having "
        "been minted. Remove or repair it with a reviewed forward migration."
    )


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0088_rpcprocedurecommand_tags_and_custom_fields"),
    ]

    operations = [migrations.RunPython(_seed, _remove)]
