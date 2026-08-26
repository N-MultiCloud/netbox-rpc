"""Seed the approval-gated NetBox plugin installation procedure.

The caller supplies an allowlisted plugin slug and an exact version. Everything
that decides *what runs* -- distribution, module, interpreter, settings file,
services to restart -- comes from ``RPCNetBoxPluginAllowlist`` and is resolved
by the normalizer. A caller-supplied distribution would make this procedure
remote code execution with an audit trail attached.

## Why this needs to exist at all

There is no sanctioned way to install a *new* NetBox plugin on a managed host.
``deploy-plugin`` upgrades plugins already installed and already listed in
``PLUGINS``; ``os.linux.ubuntu.24.restart_service`` restarts one. Nothing
installs a distribution, edits ``PLUGINS``, or runs the plugin's migrations. So
the operation has only ever been reachable by SSH, which estate policy forbids.

## The step that matters most is the rollback

A plugin whose ``min_version``/``max_version`` window excludes the running
NetBox does not degrade -- **NetBox refuses to start**. Confirmed while testing
``netbox-openbao`` against 4.6: the container went from healthy to exited and
stayed down until the entry was removed from ``PLUGINS``. On production that is
an outage, and one whose fix requires editing the configuration of a host whose
NetBox is already down.

So the handler takes a copy of the settings file before editing, and restores
it if NetBox does not come back. That is the reason this is a procedure rather
than something done by hand.

The ``dry_run`` parameter exists for the same reason: it performs the
version-window pre-flight and stops, turning "install a plugin that cannot
load" from an outage into a rejected request.

## Deliberately no ``config`` parameter

An earlier sketch of this procedure accepted a ``PLUGINS_CONFIG`` entry. It
does not, for two reasons.

The settings file is *Python*, and JSON is not a subset of it --
``null``/``true``/``false`` are not ``None``/``True``/``False``. Writing
caller-supplied JSON into it either corrupts the file or requires a converter
whose bugs are settings-file corruption on a production host.

And it is not needed: a plugin with ``required_settings = []`` installs and
loads with no entry at all, and plugin *configuration* is a separate operation
from plugin *installation*, with a different blast radius. ``netbox-openbao``,
the plugin this was written for, is configured through NetBox models rather
than ``PLUGINS_CONFIG``.

## Ships disabled, behind two independent gates

``RPCProcedure.enabled=False`` here, and ``_NETBOX_PLUGIN_INSTALL_AVAILABLE =
False`` in ``netbox_rpc.domain.normalization``. The catalog flag alone is not a
trust boundary -- it is mutable data an operator could flip without knowing the
handler is not deployed. The code-level gate is checked at admission,
advertisement, and worker-claim time so the three cannot diverge.

Preconditions before either is flipped:

1. The ``nms-backend`` execution handler is deployed and verified.
2. The approval-snapshot gap (#163) is understood for this procedure: an
   approver could approve against one ``RPCNetBoxPluginAllowlist`` row while
   the worker resolves a different one edited in between. Unlike
   ``os.linux_env_file.upsert_var`` this procedure takes no ``credential_pk``,
   so #203 does not apply to it -- SSH is resolved from the target device's
   own ``DeviceService``, exactly as ``restart_service`` does.
"""

from django.db import migrations
from django.db.models import ProtectedError


_PROCEDURE_NAME = "netbox.plugin.install"

# jsonschema evaluates ``pattern`` with re.search(), where ``$`` accepts a
# trailing newline. The negative lookahead is the strict end-of-string form.
_SLUG_PATTERN = r"^[-a-zA-Z0-9_]+(?![\s\S])"

# An exact version, never a range or a bare name. `pip install pkg` with no pin
# resolves to whatever is newest at that moment, which makes the artifact a
# NetBox restart is about to execute unknowable from the audit record.
_VERSION_PATTERN = r"^[0-9][A-Za-z0-9.!+-]{0,63}(?![\s\S])"

_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["plugin_slug", "version"],
    "additionalProperties": False,
    "properties": {
        "plugin_slug": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": _SLUG_PATTERN,
            "description": (
                "RPCNetBoxPluginAllowlist slug. The only thing the caller may "
                "name; the row supplies the distribution and module."
            ),
        },
        "version": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": _VERSION_PATTERN,
            "description": (
                "Exact version to install. Ranges and unpinned installs are "
                "refused so the audit record names the precise artifact."
            ),
        },
        "dry_run": {
            "type": "boolean",
            "default": False,
            "description": (
                "Run the version-window pre-flight and stop. Nothing is "
                "installed, no file is edited, no service is restarted."
            ),
        },
    },
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "plugin", "dry_run"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "plugin": {"type": "string"},
        "distribution": {"type": "string"},
        "module": {"type": "string"},
        "version": {"type": "string"},
        "dry_run": {"type": "boolean"},
        # Pre-flight evidence. Recorded whether or not the install proceeds, so
        # a refusal says which two versions did not overlap rather than only
        # that something was incompatible.
        "netbox_version": {"type": "string"},
        "plugin_min_version": {"type": "string"},
        "plugin_max_version": {"type": "string"},
        "version_window_ok": {"type": "boolean"},
        # What actually happened, step by step, so a partial run is legible.
        "installed": {"type": "boolean"},
        "plugins_updated": {"type": "boolean"},
        "migrated": {"type": "boolean"},
        "collectstatic": {"type": "boolean"},
        "restarted": {"type": "boolean"},
        "healthy": {"type": "boolean"},
        "rolled_back": {"type": "boolean"},
        "detail": {"type": "string"},
    },
}

_PROCEDURE_DEFAULTS = {
    "handler_id": _PROCEDURE_NAME,
    "version": 1,
    # Disabled until the nms-backend handler is deployed; see the module
    # docstring for the full precondition list and the second, code-level gate.
    "enabled": False,
    "target_models": ["dcim.device", "virtualization.virtualmachine"],
    "effect": "write",
    # Generous: a pip install plus NetBox migrations plus two service restarts
    # plus a health poll. A timeout that fires mid-install is the worst
    # outcome available -- it leaves the host in the state the rollback exists
    # to prevent, with nothing left running to perform it.
    "timeout_seconds": 900,
    "approval_required": True,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
    "description": (
        "Install an allowlisted NetBox plugin at an exact version, register it "
        "in PLUGINS, migrate, and restart -- restoring the previous settings "
        "file if NetBox fails to come back."
    ),
}

_REPRESENTATIVE_COMMAND = {
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "netbox-plugin-install"],
    # Kept under RPCProcedureCommand.description's 255-char column; the full
    # rationale lives in command_contract.EXEMPT_HANDLER_RATIONALE.
    "description": (
        "Backend-orchestrated: version pre-flight, pinned install, in-place "
        "PLUGINS edit from a backup, migrate, collectstatic, allowlisted "
        "restarts, health check, and settings restore if NetBox stays down."
    ),
    "condition_param": "",
    "condition_negate": False,
    "for_each_param": "",
    "continue_on_error": False,
}


def seed_netbox_plugin_install(apps, schema_editor):
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


def unseed_netbox_plugin_install(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")

    procedures = RPCProcedure.objects.filter(name=_PROCEDURE_NAME)
    try:
        # RPCProcedureCommand.procedure is CASCADE, so the command row goes with
        # the procedure. RPCExecution.procedure is PROTECT: once an execution
        # exists, collect() raises before any DELETE is issued and the whole
        # queryset delete rolls back, so this is never a partial delete. The
        # audit trail an execution represents must survive a schema rollback,
        # so reversing becomes a no-op rather than a crash.
        procedures.delete()
    except ProtectedError:
        pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0068_rpcnetboxpluginallowlist"),
    ]

    operations = [
        migrations.RunPython(
            seed_netbox_plugin_install,
            reverse_code=unseed_netbox_plugin_install,
        ),
    ]
