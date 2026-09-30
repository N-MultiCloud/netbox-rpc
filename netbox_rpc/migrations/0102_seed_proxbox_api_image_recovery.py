"""Seed disabled, target-bound proxbox-api retained-image procedures."""

from django.db import migrations, transaction

_INSPECT_NAME = "service.proxbox_api.release_images.inspect"
_RECOVER_NAME = "service.proxbox_api.release_images.recover"
_TARGET_MODELS = ["dcim.device"]
_PARAMS_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
_IMAGE_ID = {"type": "string", "pattern": r"^sha256:[a-f0-9]{64}$"}
_IMAGE_REF = {
    "type": "string",
    "pattern": r"^[^\s]+@sha256:[a-f0-9]{64}$",
    "maxLength": 512,
}
_INSPECT_IMAGE_SCHEMA = {
    "type": "object",
    "required": ["image", "present", "image_id"],
    "additionalProperties": False,
    "properties": {
        "image": _IMAGE_REF,
        "present": {"type": "boolean"},
        "image_id": {"oneOf": [_IMAGE_ID, {"type": "null"}]},
    },
}
_RECOVER_IMAGE_SCHEMA = {
    "type": "object",
    "required": ["image", "present", "image_id"],
    "additionalProperties": False,
    "properties": {
        "image": _IMAGE_REF,
        "present": {"const": True},
        "image_id": _IMAGE_ID,
    },
}


def _result_schema(name, mode, image_schema, ready_schema):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", "mode", "images", "ready"],
        "additionalProperties": False,
        "properties": {
            "ok": {"const": True},
            "procedure": {"const": name},
            "target": {"const": "nmc-prod-207"},
            "mode": {"const": mode},
            "images": {
                "type": "array",
                "items": image_schema,
                "minItems": 1,
                "maxItems": 16,
            },
            "ready": ready_schema,
        },
    }


_DESCRIPTION = (
    "Inspect or recover only the immutable images bound to the retained "
    "proxbox-api pre-activation transaction."
)
_INSPECT_DEFAULTS = {
    "handler_id": _INSPECT_NAME,
    "version": 1,
    "description": _DESCRIPTION,
    "effect": "read",
    "timeout_seconds": 120,
    "approval_required": False,
    "enabled": False,
    "target_models": _TARGET_MODELS,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _result_schema(
        _INSPECT_NAME, "inspect", _INSPECT_IMAGE_SCHEMA, {"type": "boolean"}
    ),
    "transport_driver": "asyncssh",
    "transport_pinned": True,
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
}
_RECOVER_DEFAULTS = {
    "handler_id": _RECOVER_NAME,
    "version": 1,
    "description": _DESCRIPTION,
    "effect": "destructive",
    "timeout_seconds": 1200,
    "approval_required": True,
    "enabled": False,
    "target_models": _TARGET_MODELS,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _result_schema(
        _RECOVER_NAME, "recover", _RECOVER_IMAGE_SCHEMA, {"const": True}
    ),
    "transport_driver": "asyncssh",
    "transport_pinned": True,
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
}
_IMMUTABLE_PROCEDURE_FIELDS = tuple(
    field for field in _INSPECT_DEFAULTS if field != "enabled"
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


def _command(token):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": [token],
        "description": _DESCRIPTION,
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


def seed(apps, schema_editor):
    """Create disabled rows without changing a later operator activation."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    rows = (
        (_INSPECT_NAME, _INSPECT_DEFAULTS, "inspect-proxbox-api-release-images"),
        (_RECOVER_NAME, _RECOVER_DEFAULTS, "recover-proxbox-api-release-images"),
    )
    with transaction.atomic():
        for name, defaults, token in rows:
            procedure = Procedure.objects.filter(name=name).first()
            if procedure is None:
                procedure = Procedure.objects.create(name=name, **defaults)
                Command.objects.create(
                    procedure=procedure, sequence=1, **_command(token)
                )
                continue
            expected_command = _command(token)
            commands = list(
                Command.objects.filter(procedure=procedure).order_by("sequence")
            )
            if (
                not _matches(procedure, defaults, _IMMUTABLE_PROCEDURE_FIELDS)
                or len(commands) != 1
                or not _matches(
                    commands[0], expected_command, _IMMUTABLE_COMMAND_FIELDS
                )
            ):
                raise RuntimeError(
                    f"Refusing to overwrite {name}; immutable procedure or command fields differ"
                )


def reverse(apps, schema_editor):
    """Disable rows while retaining execution history and exact contracts."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Procedure.objects.filter(name__in=[_INSPECT_NAME, _RECOVER_NAME]).update(
        enabled=False
    )


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0101_widen_ubuntu_restart_service_targets"),
    ]
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
