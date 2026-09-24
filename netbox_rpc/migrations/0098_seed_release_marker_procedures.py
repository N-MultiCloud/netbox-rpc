"""Seed the audited release-marker check/reconcile procedures (issue #605).

Two fixed-argv procedures targeting the deploy host device (``dcim.device``,
bound via ``RPCTargetBinding`` slug ``nmulticloud-deploy-host``), handled in
netbox-rpc-backend:

- ``service.nmulticloud.deploy.release_marker_check`` (read, no approval):
  runs ``/opt/nmulticloud/deploy/bin/reconcile-release-marker <app> --check``
  and parses only its bounded key=value report.
- ``service.nmulticloud.deploy.release_marker_reconcile`` (destructive,
  approval required): same helper with ``--apply``. The helper itself only
  rewrites the active release marker when the marker's own image is missing
  and the running container's image exists with a full 40-hex tag; it never
  builds, pulls, or prunes an image.

Neither procedure accepts a caller-supplied path, flag, or command text --
only the closed ``app`` enum (``nms-backend-staging``, ``nms-backend``).
Migration data stays inline so applying it remains deterministic if runtime
constants or schemas change later.
"""

from django.db import migrations, transaction

_CHECK_NAME = "service.nmulticloud.deploy.release_marker_check"
_RECONCILE_NAME = "service.nmulticloud.deploy.release_marker_reconcile"
_TARGET_MODELS = ["dcim.device"]

_APP_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["app"],
    "properties": {
        "app": {
            "type": "string",
            "enum": ["nms-backend-staging", "nms-backend"],
        },
    },
}

_CHECK_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "app", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _CHECK_NAME},
        "target": {"type": "string", "maxLength": 255},
        "app": {"type": "string", "enum": ["nms-backend-staging", "nms-backend"]},
        "current_ref": {"type": ["string", "null"], "maxLength": 64},
        "current_image": {
            "type": ["string", "null"],
            "enum": ["present", "missing", None],
        },
        "running_ref": {"type": ["string", "null"], "maxLength": 64},
        "running_image": {
            "type": ["string", "null"],
            "enum": ["present", "missing", None],
        },
        "stage": {
            "type": "string",
            "enum": ["execute", "complete", "indeterminate"],
        },
    },
}

_RECONCILE_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "procedure", "target", "app", "stage"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _RECONCILE_NAME},
        "target": {"type": "string", "maxLength": 255},
        "app": {"type": "string", "enum": ["nms-backend-staging", "nms-backend"]},
        "before_ref": {
            "type": ["string", "null"],
            "pattern": "^([0-9a-f]{40}|none)$",
        },
        "after_ref": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
        "stage": {
            "type": "string",
            "enum": ["execute", "complete", "indeterminate"],
        },
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "stage": {"const": "complete"},
                "before_ref": {"type": "string"},
                "after_ref": {"type": "string"},
            },
            "required": ["before_ref", "after_ref"],
        },
        {
            "properties": {
                "ok": {"const": False},
                "stage": {"const": "execute"},
                "before_ref": {"const": None},
                "after_ref": {"const": None},
            },
        },
        {
            "properties": {
                "ok": {"const": False},
                "stage": {"const": "indeterminate"},
                "before_ref": {"const": None},
                "after_ref": {"const": None},
            },
        },
    ],
}

_CHECK_DEFAULTS = {
    "handler_id": _CHECK_NAME,
    "version": 1,
    "enabled": True,
    "target_models": _TARGET_MODELS,
    "effect": "read",
    "timeout_seconds": 60,
    "approval_required": False,
    "params_schema": _APP_PARAMS_SCHEMA,
    "result_schema": _CHECK_RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Report the active release marker's image state and the running "
        "container's image state for nms-backend or nms-backend-staging, "
        "without changing anything (issue #605)."
    ),
}

_RECONCILE_DEFAULTS = {
    "handler_id": _RECONCILE_NAME,
    "version": 1,
    "enabled": True,
    "target_models": _TARGET_MODELS,
    "effect": "destructive",
    "timeout_seconds": 300,
    "approval_required": True,
    "params_schema": _APP_PARAMS_SCHEMA,
    "result_schema": _RECONCILE_RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Rewrite the active nms-backend/nms-backend-staging release marker "
        "to the running container's image ref, but only when the marker's "
        "own image is missing and the running image exists with a full "
        "40-hex tag (issue #605). Never builds, pulls, or prunes an image."
    ),
}


def _representative_command(argv_last_token):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": [
            "/opt/nmulticloud/deploy/bin/reconcile-release-marker",
            "{app}",
            argv_last_token,
        ],
        "description": (
            "Run the release-marker helper on the RPCTargetBinding-bound "
            "deploy host and parse only its closed key=value report."
        ),
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
        "render_mode": "literal",
        "produces_var": "",
        "capture_kind": "",
        "capture_expression": "",
    }


# Fields compared to recognize "this row is exactly what this migration would
# seed" on re-apply. Deliberately excludes `enabled`: that is the one field
# `unseed_release_marker_procedures()` mutates, so a disabled-but-otherwise-
# identical row from a prior forward/reverse cycle must still be recognized
# as this migration's own row, not rejected as operator-owned drift.
_IMMUTABLE_PROCEDURE_FIELDS = (
    "handler_id",
    "version",
    "target_models",
    "effect",
    "timeout_seconds",
    "approval_required",
    "params_schema",
    "result_schema",
    "transport_driver",
    "transport_driver_chain",
    "output_parser",
    "output_schema",
    "description",
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


def _procedure_matches_seed(procedure, defaults):
    """True only when every immutable field equals this migration's seed.

    ``enabled`` is intentionally not compared -- see
    ``_IMMUTABLE_PROCEDURE_FIELDS``'s docstring above.
    """
    return all(
        getattr(procedure, field) == defaults[field]
        for field in _IMMUTABLE_PROCEDURE_FIELDS
    )


def _command_matches_seed(command, expected):
    return all(
        getattr(command, field) == expected[field]
        for field in _IMMUTABLE_COMMAND_FIELDS
    )


def seed_release_marker_procedures(apps, schema_editor):
    """Create each procedure, or -- on re-apply after a reverse -- recognize
    and re-enable this migration's own exact row instead of refusing it.

    A prior ``unseed_release_marker_procedures()`` only disables rows (see
    its docstring); it never deletes them, so a forward -> reverse -> forward
    cycle must not treat the still-present row as an operator-owned
    collision. Forward therefore requires an existing same-name row's
    immutable fields *and* its exact single command row to equal what this
    migration would seed before it re-enables it; any drift -- a different
    schema, timeout, argv, or more/fewer command rows -- still refuses with
    the original adoption error, so a genuinely operator-edited or
    differently-originated row is never silently taken over.
    """
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")

    with transaction.atomic():
        for name, defaults, argv_last_token in (
            (_CHECK_NAME, _CHECK_DEFAULTS, "--check"),
            (_RECONCILE_NAME, _RECONCILE_DEFAULTS, "--apply"),
        ):
            existing = RPCProcedure.objects.filter(name=name).first()
            if existing is None:
                procedure = RPCProcedure.objects.create(name=name, **defaults)
                RPCProcedureCommand.objects.create(
                    procedure=procedure,
                    sequence=1,
                    **_representative_command(argv_last_token),
                )
                continue

            expected_command = _representative_command(argv_last_token)
            commands = list(
                RPCProcedureCommand.objects.filter(procedure=existing).order_by(
                    "sequence"
                )
            )
            if not _procedure_matches_seed(existing, defaults) or (
                len(commands) != 1
                or not _command_matches_seed(commands[0], expected_command)
            ):
                raise RuntimeError(
                    f"release-marker migration refuses to overwrite an existing "
                    f"procedure row named {name!r} whose immutable fields or "
                    f"command contract differ from this migration's seed."
                )
            if existing.enabled is not True:
                existing.enabled = True
                existing.save(update_fields=["enabled"])


def unseed_release_marker_procedures(apps, schema_editor):
    """Disable the seeded rows instead of deleting them.

    Non-destructive for the same reasons documented on
    ``0096_seed_netbox_openbao_import_procedures``: ``RPCExecution.procedure``
    is ``on_delete=PROTECT`` so a procedure with execution history cannot be
    deleted, and an ``update()`` touches only this table. Rows disabled here
    are recognized and re-enabled, not rejected, by a later re-run of
    ``seed_release_marker_procedures()`` -- see its docstring.
    """

    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[_CHECK_NAME, _RECONCILE_NAME],
    ).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0097_rpctargetbinding"),
    ]

    operations = [  # noqa: RUF012
        migrations.RunPython(
            seed_release_marker_procedures,
            reverse_code=unseed_release_marker_procedures,
        ),
    ]
