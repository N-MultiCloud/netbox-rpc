"""Seed the disabled, approval-gated composite Gitea runner registration."""

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

_PROCEDURE_NAME = "service.gitea.runner.register"
_SCOPES = [
    "netbox-proxbox",
    "nmulticloud-org",
    "nmulticloud-org-root",
    "proxbox-api",
    "release-netbox-proxbox-build",
    "release-netbox-proxbox-validation",
    "release-proxbox-api-build",
    "release-proxbox-api-validation",
]
_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["operation", "scope"],
    "properties": {
        "operation": {"type": "string", "enum": ["reconcile", "register"]},
        "scope": {"type": "string", "enum": _SCOPES},
    },
}
_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "ok",
        "procedure",
        "target",
        "operation",
        "scope",
        "registered",
        "reconciled",
        "token_invalidated",
        "token_reset_required",
        "token_sha256",
        "reset_state",
        "prior_token_id",
        "prior_active_sha256",
        "replacement_token_id",
        "stage",
    ],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _PROCEDURE_NAME},
        "target": {"const": "nmultifibra-ci-untrusted-01"},
        "operation": {
            "type": "string",
            "enum": ["reconcile", "register"],
        },
        "scope": {"type": "string", "enum": _SCOPES},
        "registered": {"type": ["boolean", "null"]},
        "reconciled": {"type": ["boolean", "null"]},
        "token_invalidated": {"type": "boolean"},
        "token_reset_required": {"type": "boolean"},
        "token_sha256": {
            "type": ["string", "null"],
            "pattern": r"^[0-9a-f]{64}$",
        },
        "reset_state": {
            "type": "string",
            "enum": [
                "not_started",
                "rotated",
                "already_inactive",
                "reconciled_expected_active",
                "reconciled_expected_inactive",
                "reconciled_no_active",
                "failed",
                "indeterminate",
            ],
        },
        "prior_token_id": {"type": ["integer", "null"], "minimum": 1},
        "prior_active_sha256": {
            "type": ["string", "null"],
            "pattern": r"^[0-9a-f]{64}$",
        },
        "replacement_token_id": {
            "type": ["integer", "null"],
            "minimum": 1,
        },
        "stage": {
            "type": "string",
            "enum": [
                "generate_token",
                "register",
                "reset",
                "reconcile",
                "complete",
                "indeterminate",
            ],
        },
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "operation": {"const": "register"},
                "registered": {"const": True},
                "reconciled": {"const": None},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "reset_state": {"enum": ["rotated", "already_inactive"]},
                "prior_token_id": {"type": "integer", "minimum": 1},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {"type": "integer", "minimum": 1},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "register"},
                "registered": {"const": False},
                "reconciled": {"const": None},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": False},
                "token_sha256": {"const": None},
                "reset_state": {"const": "not_started"},
                "prior_token_id": {"const": None},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {"const": None},
                "stage": {"const": "generate_token"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "register"},
                "registered": {"type": ["boolean", "null"]},
                "reconciled": {"const": None},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "reset_state": {"enum": ["rotated", "already_inactive"]},
                "prior_token_id": {"type": "integer", "minimum": 1},
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {"type": "integer", "minimum": 1},
                "stage": {"enum": ["register", "indeterminate"]},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "register"},
                "registered": {"type": ["boolean", "null"]},
                "reconciled": {"const": None},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": True},
                "token_sha256": {
                    "type": ["string", "null"],
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "reset_state": {"enum": ["failed", "indeterminate"]},
                "prior_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "prior_active_sha256": {"const": None},
                "replacement_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "stage": {"enum": ["register", "reset", "indeterminate"]},
            }
        },
        {
            "properties": {
                "ok": {"const": True},
                "operation": {"const": "reconcile"},
                "registered": {"const": None},
                "reconciled": {"const": True},
                "token_invalidated": {"const": True},
                "token_reset_required": {"const": False},
                "token_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "reset_state": {
                    "enum": [
                        "reconciled_expected_active",
                        "reconciled_expected_inactive",
                        "reconciled_no_active",
                    ]
                },
                "prior_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "prior_active_sha256": {
                    "type": ["string", "null"],
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "replacement_token_id": {"type": "integer", "minimum": 1},
                "stage": {"const": "complete"},
            }
        },
        {
            "properties": {
                "ok": {"const": False},
                "operation": {"const": "reconcile"},
                "registered": {"const": None},
                "reconciled": {"type": ["boolean", "null"]},
                "token_invalidated": {"const": False},
                "token_reset_required": {"const": True},
                "token_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "reset_state": {"enum": ["failed", "indeterminate"]},
                "prior_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "prior_active_sha256": {
                    "type": ["string", "null"],
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "replacement_token_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
                "stage": {"enum": ["reconcile", "indeterminate"]},
            }
        },
    ],
}
_PROCEDURE_DEFAULTS = {
    "handler_id": _PROCEDURE_NAME,
    "version": 1,
    "enabled": False,
    "target_models": ["virtualization.virtualmachine"],
    "effect": "destructive",
    "timeout_seconds": 360,
    "approval_required": True,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Register or reconcile one fixed Gitea runner scope and invalidate the "
        "reusable token before completion without accepting, persisting, "
        "logging, or returning token material."
    ),
}
_REPRESENTATIVE_COMMAND = {
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "gitea-runner-lifecycle-composite"],
    "description": (
        "Backend registers or reconciles one fixed runner scope, always "
        "invalidating the reusable Gitea token before completion."
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


def seed_gitea_runner_register(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    if RPCProcedure.objects.filter(name=_PROCEDURE_NAME).exists():
        raise RuntimeError(
            "Migration 0080 cannot adopt an existing Gitea runner registration "
            "procedure; reconcile the operator-owned row before retrying."
        )
    procedure = RPCProcedure.objects.create(
        name=_PROCEDURE_NAME,
        **_PROCEDURE_DEFAULTS,
    )
    RPCProcedureCommand.objects.create(
        procedure=procedure,
        sequence=1,
        **_REPRESENTATIVE_COMMAND,
    )


def unseed_gitea_runner_register(apps, schema_editor):
    raise IrreversibleError(
        "Migration 0080 is intentionally irreversible because catalog row "
        "ownership cannot be proven after operator mutation."
    )


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0079_rpcexecution_source_intent")]

    operations = [
        migrations.RunPython(
            seed_gitea_runner_register,
            reverse_code=unseed_gitea_runner_register,
        )
    ]
