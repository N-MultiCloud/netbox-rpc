"""Seed production NetBox Compose RQ worker procedures and retire the host unit.

The legacy ``netbox-rq.service`` allowlist row remains for audit history, but
is disabled. The replacement procedures are bound to NetBox device 44 and use
backend-owned fixed Compose arguments; callers cannot select a project,
service, file, environment file, or command.

Both procedures are seeded enabled. They are registered in the explicit
backend-capability set, so admission, listing, and worker claim fail closed
until the selected backend advertises the matching semantic contract.
"""

from django.db import migrations, transaction

_STATUS_NAME = "service.netbox.production.status_rq_worker"
_RESTART_NAME = "service.netbox.production.restart_rq_worker"
_TARGET_MODELS = ["dcim.device"]
_TARGET = "nmc-prod-207"
_PROJECT = "nmc-netbox"
_SERVICE = "netbox-rq"
_OUTPUT_MAX_LENGTH = 8192
_RETIREMENT_COMMENT = (
    "Retired legacy host unit. Use "
    "service.netbox.production.status_rq_worker for status and "
    "service.netbox.production.restart_rq_worker for approved restarts."
)

_PARAMS_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}


def _result_schema(name):
    return {
        "type": "object",
        "required": [
            "ok",
            "procedure",
            "target",
            "project",
            "service",
            "status",
            "phase",
            "retry_requires_status_check",
            "state",
            "health",
            "container",
            "exit_code",
            "output",
        ],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"const": name},
            "target": {"const": _TARGET},
            "project": {"const": _PROJECT},
            "service": {"const": _SERVICE},
            "status": {
                "enum": [
                    "running",
                    "stopped",
                    "degraded",
                    "missing",
                    "status_failed",
                    "restart_failed",
                    "timeout",
                    "indeterminate",
                ]
            },
            "phase": {"enum": ["status", "restart", "readiness"]},
            "retry_requires_status_check": {"type": "boolean"},
            "state": {"type": "string", "maxLength": 64},
            "health": {"type": "string", "maxLength": 64},
            "container": {"type": "string", "maxLength": 255},
            "exit_code": {"type": "integer"},
            "output": {"type": "string", "maxLength": _OUTPUT_MAX_LENGTH},
        },
    }


_STATUS_DESCRIPTION = (
    "Report the production NetBox Compose RQ worker status without changing it."
)
_RESTART_DESCRIPTION = (
    "Restart only the production NetBox Compose RQ worker and wait until it is running."
)


def _procedure_defaults(name, description, effect, timeout_seconds, approval_required):
    return {
        "handler_id": name,
        "version": 1,
        "description": description,
        "effect": effect,
        "timeout_seconds": timeout_seconds,
        "approval_required": approval_required,
        "enabled": True,
        "target_models": _TARGET_MODELS,
        "params_schema": _PARAMS_SCHEMA,
        "result_schema": _result_schema(name),
        "transport_driver": "asyncssh",
        "transport_pinned": True,
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
    }


_STATUS_DEFAULTS = _procedure_defaults(
    _STATUS_NAME,
    _STATUS_DESCRIPTION,
    "read",
    45,
    False,
)
_RESTART_DEFAULTS = _procedure_defaults(
    _RESTART_NAME,
    _RESTART_DESCRIPTION,
    "write",
    150,
    True,
)
_IMMUTABLE_PROCEDURE_FIELDS = tuple(
    field for field in _STATUS_DEFAULTS if field != "enabled"
)
_IMMUTABLE_COMMAND_FIELDS = (
    "step_type",
    "device_cli_mode",
    "argv",
    "description",
    "condition_param",
    "condition_negate",
    "for_each_param",
    "continue_on_error",
    "render_mode",
    "produces_var",
    "capture_kind",
    "capture_expression",
)


def _command(token, description):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", token],
        "description": description,
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
        "render_mode": "literal",
        "produces_var": "",
        "capture_kind": "",
        "capture_expression": "",
    }


def _matches(instance, expected, fields):
    return all(getattr(instance, field) == expected[field] for field in fields)


def _seed_procedure(Procedure, Command, name, defaults, token, description):
    procedure = Procedure.objects.filter(name=name).first()
    expected_command = _command(token, description)
    if procedure is None:
        procedure = Procedure.objects.create(name=name, **defaults)
        Command.objects.create(
            procedure=procedure,
            sequence=1,
            **expected_command,
        )
        return
    commands = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
    if (
        not _matches(procedure, defaults, _IMMUTABLE_PROCEDURE_FIELDS)
        or len(commands) != 1
        or not _matches(commands[0], expected_command, _IMMUTABLE_COMMAND_FIELDS)
    ):
        raise RuntimeError(
            f"Refusing to overwrite {name}; immutable procedure or command fields differ"
        )


def _disable_legacy_allowlist(ServiceAllowlist):
    row = ServiceAllowlist.objects.filter(slug="netbox-rq").first()
    if row is None:
        return
    comments = str(getattr(row, "comments", "") or "").strip()
    if _RETIREMENT_COMMENT not in comments:
        row.comments = f"{comments}\n\n{_RETIREMENT_COMMENT}".strip()
    row.enabled = False
    row.save(update_fields=["enabled", "comments"])


def seed(apps, schema_editor):
    """Seed exact contracts and disable, but never delete, the legacy row."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    ServiceAllowlist = apps.get_model("netbox_rpc", "RPCLinuxServiceAllowlist")
    rows = (
        (
            _STATUS_NAME,
            _STATUS_DEFAULTS,
            "netbox-production-status-rq-worker",
            _STATUS_DESCRIPTION,
        ),
        (
            _RESTART_NAME,
            _RESTART_DEFAULTS,
            "netbox-production-restart-rq-worker",
            _RESTART_DESCRIPTION,
        ),
    )
    with transaction.atomic():
        for row in rows:
            _seed_procedure(Procedure, Command, *row)
        _disable_legacy_allowlist(ServiceAllowlist)


def reverse(apps, schema_editor):
    """Disable replacement procedures without reviving the dead host unit."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    ServiceAllowlist = apps.get_model("netbox_rpc", "RPCLinuxServiceAllowlist")
    with transaction.atomic():
        Procedure.objects.filter(name__in=[_STATUS_NAME, _RESTART_NAME]).update(
            enabled=False
        )
        _disable_legacy_allowlist(ServiceAllowlist)


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0109_merge_enabled_publication_adoption"),
    ]
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
