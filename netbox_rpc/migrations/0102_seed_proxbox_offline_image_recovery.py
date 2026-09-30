"""Seed fixed proxbox-api offline-image diagnosis and preload procedures.

The caller supplies only one immutable release-manifest SHA-256. Both rows
target the operator-bound deployment host; the backend and host derive the
exact digest-pinned image inventory from that verified release. Migration data
is deliberately inline so historical application remains deterministic.
"""

from django.db import migrations, transaction

_DIAGNOSE_NAME = "service.nmulticloud.deploy.diagnose_proxbox_api_images"
_PRELOAD_NAME = "service.nmulticloud.deploy.preload_proxbox_api_images"
_PROCEDURE_NAMES = (_DIAGNOSE_NAME, _PRELOAD_NAME)
_MANIFEST_PATTERN = "^[a-f0-9]{64}$"
_IMAGE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,439}@sha256:[a-f0-9]{64}$"
_IMAGE_ID_PATTERN = "^sha256:[a-f0-9]{64}$"

_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["manifest_sha256"],
    "properties": {
        "manifest_sha256": {"type": "string", "pattern": _MANIFEST_PATTERN}
    },
}

_IMAGE_STATUS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["image", "present", "image_id"],
    "properties": {
        "image": {
            "type": "string",
            "minLength": 3,
            "maxLength": 512,
            "pattern": _IMAGE_PATTERN,
        },
        "present": {"type": "boolean"},
        "image_id": {"type": ["string", "null"], "pattern": _IMAGE_ID_PATTERN},
    },
    "oneOf": [
        {
            "properties": {
                "present": {"const": True},
                "image_id": {"type": "string", "pattern": _IMAGE_ID_PATTERN},
            }
        },
        {
            "properties": {
                "present": {"const": False},
                "image_id": {"const": None},
            }
        },
    ],
}


def _result_schema(procedure, stages):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "ok",
            "procedure",
            "target",
            "manifest_sha256",
            "stage",
            "images",
        ],
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"type": "string", "const": procedure},
            "target": {"type": "string", "minLength": 1, "maxLength": 255},
            "manifest_sha256": {
                "type": "string",
                "pattern": _MANIFEST_PATTERN,
            },
            "stage": {"type": "string", "enum": stages},
            "images": {
                "type": ["array", "null"],
                "items": _IMAGE_STATUS_SCHEMA,
                "minItems": 1,
                "maxItems": 8,
            },
        },
        "oneOf": [
            {
                "properties": {
                    "ok": {"const": True},
                    "stage": {"const": "complete"},
                    "images": {"type": "array"},
                }
            },
            {
                "properties": {
                    "ok": {"const": False},
                    "stage": {
                        "enum": [stage for stage in stages if stage != "complete"]
                    },
                    "images": {"const": None},
                }
            },
        ],
    }


_DIAGNOSE_RESULT_SCHEMA = _result_schema(_DIAGNOSE_NAME, ["complete", "execute"])
_PRELOAD_RESULT_SCHEMA = _result_schema(
    _PRELOAD_NAME,
    ["complete", "execute", "indeterminate"],
)


def _defaults(*, name, effect, timeout_seconds, approval_required, result_schema):
    return {
        "handler_id": name,
        "version": 1,
        "enabled": True,
        "target_models": ["dcim.device"],
        "effect": effect,
        "timeout_seconds": timeout_seconds,
        "approval_required": approval_required,
        "params_schema": _PARAMS_SCHEMA,
        "result_schema": result_schema,
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "transport_pinned": True,
        "output_parser": "none",
        "output_schema": {},
    }


_PROCEDURES = (
    (
        _DIAGNOSE_NAME,
        {
            **_defaults(
                name=_DIAGNOSE_NAME,
                effect="read",
                timeout_seconds=120,
                approval_required=False,
                result_schema=_DIAGNOSE_RESULT_SCHEMA,
            ),
            "description": (
                "Diagnose the exact digest-pinned external image inventory for "
                "one verified proxbox-api release without changing the deploy host."
            ),
        },
        "diagnose-proxbox-api-images",
    ),
    (
        _PRELOAD_NAME,
        {
            **_defaults(
                name=_PRELOAD_NAME,
                effect="write",
                timeout_seconds=2100,
                approval_required=True,
                result_schema=_PRELOAD_RESULT_SCHEMA,
            ),
            "description": (
                "Preload and verify only the digest-pinned external images bound "
                "to one approved proxbox-api release manifest."
            ),
        },
        "preload-proxbox-api-images",
    ),
)


def _command(action):
    return {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": [action, "{manifest_sha256}"],
        "description": (
            "Invoke the fixed deploy-host gateway action for the exact approved "
            "proxbox-api release manifest."
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


def seed_proxbox_offline_image_recovery(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    with transaction.atomic():
        for name, _defaults_value, _action in _PROCEDURES:
            if RPCProcedure.objects.filter(name=name).exists():
                raise RuntimeError(
                    "Migration 0102 refuses to adopt an existing proxbox offline-image "
                    f"procedure {name!r}; reconcile the operator-owned row first."
                )
        for name, defaults, action in _PROCEDURES:
            procedure = RPCProcedure.objects.create(name=name, **defaults)
            RPCProcedureCommand.objects.create(procedure=procedure, **_command(action))


def disable_proxbox_offline_image_recovery(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=_PROCEDURE_NAMES).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0101_widen_ubuntu_restart_service_targets"),
    ]

    operations = [
        migrations.RunPython(
            seed_proxbox_offline_image_recovery,
            reverse_code=disable_proxbox_offline_image_recovery,
        )
    ]
