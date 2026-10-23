"""Seed the frozen fixed-purpose IAM UI control procedures."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.db import migrations, transaction

PREFIX = "service.keycloak.iam_ui."
MODES = ("inspect", "configure", "certificate", "activate")
HANDLER_IDS = frozenset(PREFIX + mode for mode in MODES)
WRITE_HANDLER_IDS = HANDLER_IDS - {PREFIX + "inspect"}
TARGET_NAME = "nmc-prod-207"
TARGET_MODEL = "dcim.device"
TARGET_OBJECT_ID = 44
HELPER = "/opt/nmulticloud/deploy/keycloak/bin/iam-ui-control"
TIMEOUTS = dict(zip(MODES, (60, 180, 240, 60), strict=True))
MAX_OUTPUT_BYTES = 2048
TRANSPORT_PINNED = True
PARAMS_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
TARGET_OBJECT_SCHEMA = {
    "type": "object",
    "required": ["content_type", "object_id"],
    "additionalProperties": False,
    "properties": {
        "content_type": {"const": TARGET_MODEL},
        "object_id": {"const": TARGET_OBJECT_ID},
    },
}
RESPONSE_KEYS = (
    "ok",
    "operation",
    "admin_ready",
    "bootstrap_available",
    "certificate_present",
    "tls_active",
)
DESCRIPTIONS = {
    "inspect": "Report only fixed IAM UI readiness without changing the host.",
    "configure": "Configure only the dedicated IAM client and fixed NMS integration.",
    "certificate": "Issue only the dedicated IAM UI certificate through HTTP-01.",
    "activate": "Activate only the reviewed IAM UI TLS virtual host.",
}


def canonical_sha256(value: object) -> str:
    """Hash the shared compact canonical JSON representation."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def command(mode: str) -> dict[str, Any]:
    """Return the exact representative command row."""
    return {
        "sequence": 1,
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", "keycloak-iam-ui-" + mode],
        "description": DESCRIPTIONS[mode],
        "condition_param": "",
        "condition_negate": False,
        "for_each_param": "",
        "continue_on_error": False,
        "render_mode": "literal",
        "produces_var": "",
        "capture_kind": "",
        "capture_expression": "",
    }


def fingerprint_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["handler_id", "procedure", "target_object", "argv_sha256"],
        "additionalProperties": False,
        "properties": {
            "handler_id": {"const": handler_id},
            "procedure": {"const": handler_id},
            "target_object": TARGET_OBJECT_SCHEMA,
            "argv_sha256": {
                "const": canonical_sha256(
                    ["sudo", "-n", HELPER, handler_id.removeprefix(PREFIX)]
                )
            },
        },
    }


def normalized_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["target", "target_object", "command_fingerprint"],
        "additionalProperties": False,
        "properties": {
            "target": {"const": TARGET_NAME},
            "target_object": TARGET_OBJECT_SCHEMA,
            "command_fingerprint": fingerprint_schema(handler_id),
        },
    }


def result_schema(handler_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "ok",
            "procedure",
            "target",
            "operation",
            "status",
            "retry_requires_inspect",
            "readiness",
        ],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"const": handler_id},
            "target": {"const": TARGET_NAME},
            "operation": {"const": handler_id.removeprefix(PREFIX)},
            "status": {"enum": ["succeeded", "failed", "indeterminate"]},
            "retry_requires_inspect": {"type": "boolean"},
            "readiness": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "required": list(RESPONSE_KEYS),
                        "additionalProperties": False,
                        "properties": {
                            **{
                                key: {"type": "boolean"}
                                for key in RESPONSE_KEYS
                                if key != "operation"
                            },
                            "ok": {"const": True},
                            "operation": {"const": handler_id.removeprefix(PREFIX)},
                        },
                    },
                ],
            },
        },
    }


NORMALIZED_PARAMS_SCHEMAS = {name: normalized_schema(name) for name in HANDLER_IDS}
COMMAND_FINGERPRINT_SCHEMAS = {name: fingerprint_schema(name) for name in HANDLER_IDS}
RESULT_SCHEMAS = {name: result_schema(name) for name in HANDLER_IDS}
PROCEDURE_POLICIES = {
    PREFIX + mode: {
        "name": PREFIX + mode,
        "handler_id": PREFIX + mode,
        "version": 1,
        "enabled": True,
        "description": DESCRIPTIONS[mode],
        "effect": "read" if mode == "inspect" else "write",
        "timeout_seconds": TIMEOUTS[mode],
        "approval_required": mode != "inspect",
        "target_models": [TARGET_MODEL],
        "params_schema": PARAMS_SCHEMA,
        "result_schema": RESULT_SCHEMAS[PREFIX + mode],
        "transport_driver": "asyncssh",
        "transport_pinned": True,
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
    }
    for mode in MODES
}



def _seed_one(Procedure, Command, name, policy):
    defaults = {key: value for key, value in policy.items() if key != "name"}
    expected = command(name.removeprefix(PREFIX))
    row = Procedure.objects.filter(name=name).first()
    if row is None:
        row = Procedure.objects.create(name=name, **defaults)
        Command.objects.create(procedure=row, **expected)
        return
    immutable = {key: value for key, value in defaults.items() if key != "enabled"}
    commands = list(Command.objects.filter(procedure=row).order_by("sequence"))
    if (
        any(getattr(row, key) != value for key, value in immutable.items())
        or len(commands) != 1
        or any(getattr(commands[0], key) != value for key, value in expected.items())
    ):
        raise RuntimeError("Refusing to overwrite a changed IAM UI control contract")


def seed(apps, schema_editor):
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    with transaction.atomic():
        for name, policy in PROCEDURE_POLICIES.items():
            _seed_one(Procedure, Command, name, policy)


def reverse(apps, schema_editor):
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Procedure.objects.filter(name__in=HANDLER_IDS).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0111_seed_pbs_procedures")]  # noqa: RUF012
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
