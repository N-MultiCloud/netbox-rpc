"""Seed the approval-gated Linux environment-file variable upsert procedure.

The caller supplies only an allowlisted service slug, a confined variable name,
and a DeviceCredential primary key. The normalizer resolves the environment-file
path and systemd unit from RPCLinuxServiceAllowlist. The backend resolves the
credential and delivers its value over stdin; plaintext secret material is never
accepted by this schema or represented in the command row.

This migration intentionally does NOT seed ``environment_file`` on the
``netbox``/``netbox-rq`` RPCLinuxServiceAllowlist rows added by 0058. NetBox
runs as a native venv install (``ExecStartPre=/opt/netbox/venv/bin/python3
manage.py migrate``, ``systemctl restart netbox.service``), not a Docker
Compose deployment, so there is no locally-documented ``EnvironmentFile=``
path to seed with confidence -- guessing one here would be invisible to an
approver at dispatch time (it is normalizer-derived, not a caller param) and
could silently write to the wrong file. The normalizer already fails closed
with ``RPC_LINUX_SERVICE_ENVIRONMENT_FILE_MISSING`` while ``environment_file``
is unset. An operator must confirm the real path against the production
systemd unit and set it via the RPCLinuxServiceAllowlist admin UI/API before
this procedure can be dispatched against ``netbox``/``netbox-rq``.

The procedure is seeded ``enabled=False``: the paired nms-backend execution
handler does not exist yet, and the caller-supplied ``credential_pk`` param
is not yet object-scoped-authorization checked against the requesting user
(tracked separately as issue #203, a pre-existing gap shared by every
``*credential_pk`` param in this plugin, not specific to this procedure). Do
not enable this procedure until both the execution handler is deployed and
#203 (or an equivalent scoped fix) has landed.

``RPCProcedure.enabled`` is ordinary mutable catalog data, so it alone is not
a trust boundary -- an operator could flip it without knowing the
authorization gap above is still open. ``netbox_rpc.domain.normalization``
therefore also carries a hard-coded, code-level gate
(``_LINUX_ENV_FILE_UPSERT_AVAILABLE = False``) that unconditionally refuses
to normalize this procedure's executions before any allowlist or credential
lookup runs, regardless of the ``enabled`` flag.

A third precondition also gates the code-level flag: ``create_execution()``
enforces ``approval_required`` only as a single-actor permission check today
and calls ``RPCExecutionAggregate.queue()`` directly -- no procedure's
approval decision is bound to a snapshot of the state the worker later
resolves at claim time. For this procedure that means an approver could
approve against one ``RPCLinuxServiceAllowlist`` policy
(``environment_file``/``systemd_unit``/``target_models``/
``ssh_credential_override_id``) while the worker executes against a
different one edited in between. This TOCTOU window is real but currently
unreachable in practice because the code-level gate above prevents the
allowlist lookup from running at all (see
``test_upsert_var_gate_blocks_by_default``). Closing it for real requires
routing this procedure's ``approval_required`` executions through an
approval-time snapshot -- tracked by the still-open parent issue #163
(items 2 and 9), not the now-closed #165 (API/UI only).

All three preconditions -- execution handler deployed, #203 landed, #163's
approval-snapshot routing landed for this procedure -- must hold before
``_LINUX_ENV_FILE_UPSERT_AVAILABLE`` is flipped to ``True``.
"""

from django.db import migrations
from django.db.models import ProtectedError


_PROCEDURE_NAME = "os.linux_env_file.upsert_var"

# jsonschema evaluates ``pattern`` with re.search(), where ``$`` accepts a final
# newline. The negative lookahead is the strict end-of-string equivalent of the
# requested ^[A-Z][A-Z0-9_]*$ contract.
_VAR_NAME_PATTERN = r"^[A-Z][A-Z0-9_]*(?![\s\S])"

_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["service_slug", "var_name", "credential_pk"],
    "additionalProperties": False,
    "properties": {
        "service_slug": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
        },
        "var_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": _VAR_NAME_PATTERN,
        },
        "credential_pk": {
            "type": "integer",
            "minimum": 1,
            "description": (
                "netbox-nms DeviceCredential primary key; the execution backend "
                "resolves the value at run time. Raw secrets are not accepted."
            ),
        },
    },
}

_PROCEDURE_DEFAULTS = {
    "handler_id": _PROCEDURE_NAME,
    "version": 1,
    # Ship disabled until the matching nms-backend execution handler is
    # deployed and verified; a follow-up migration or operator UI/API toggle
    # of RPCProcedure.enabled can then enable it (see the "ship procedures
    # disabled by default" convention introduced for the Akvorado catalog).
    "enabled": False,
    "target_models": ["dcim.device"],
    "effect": "write",
    "timeout_seconds": 60,
    "approval_required": True,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": {},
    "description": (
        "Upsert a credential-backed variable in an allowlisted Linux service "
        "environment file, then restart the service."
    ),
}

_REPRESENTATIVE_COMMAND = {
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "linux-env-file-upsert-var"],
    "description": (
        "Backend resolves the DeviceCredential reference and delivers the secret "
        "over stdin to a fixed upsert script before restarting the allowlisted "
        "systemd unit; no secret value is represented as argv."
    ),
    "condition_param": "",
    "condition_negate": False,
    "for_each_param": "",
    "continue_on_error": False,
}


def seed_linux_env_file_upsert_var(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")

    procedure, _created = RPCProcedure.objects.update_or_create(
        name=_PROCEDURE_NAME,
        defaults=_PROCEDURE_DEFAULTS,
    )
    RPCProcedureCommand.objects.update_or_create(
        procedure=procedure,
        sequence=1,
        defaults=_REPRESENTATIVE_COMMAND,
    )


def unseed_linux_env_file_upsert_var(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")

    procedures = RPCProcedure.objects.filter(name=_PROCEDURE_NAME)
    try:
        # RPCProcedureCommand.procedure is on_delete=CASCADE, so deleting the
        # procedure also deletes its command rows -- no separate delete call
        # is needed. RPCExecution.procedure is on_delete=PROTECT: once any
        # execution has been created against this procedure,
        # Collector.collect() raises ProtectedError *before* any DELETE is
        # issued, and QuerySet.delete() runs inside its own atomic
        # transaction, so this exception leaves both the procedure row and
        # its cascade-linked commands untouched -- never a partial delete.
        # Reversing this migration is then a no-op rather than a crash -- the
        # audit trail an execution represents must survive a schema rollback.
        procedures.delete()
    except ProtectedError:
        pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0059_rpclinuxserviceallowlist_environment_file"),
    ]

    operations = [
        migrations.RunPython(
            seed_linux_env_file_upsert_var,
            reverse_code=unseed_linux_env_file_upsert_var,
        ),
    ]
