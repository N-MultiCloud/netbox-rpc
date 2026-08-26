"""Seed the gated Gitea Actions org CI runner provision procedure.

This procedure is the NetBox catalog contract for provisioning the dedicated
``ci-untrusted-python312`` organization runner on a prepared NMS runner host.
It intentionally does not accept caller-supplied SSH routing. The backend must
resolve host, port, credential, and known-host policy from the execution's
assigned NetBox object, then resolve the one-time Gitea registration token from
``registration_token_secret_ref`` through the netbox-nms secret bridge.

The row is seeded ``enabled=False`` because no
``service.gitea.actions_runner.*`` handler exists in ``netbox-rpc-backend`` yet.
A paired fail-closed code gate in ``netbox_rpc.domain.normalization`` refuses
admission, advertisement, and worker claim until the backend handler and its
capability contract are deployed in a coordinated rollout.
"""

from django.db import migrations


_PROCEDURE_NAME = "service.gitea.actions_runner.provision_org_ci_runner"
_HANDLER_ID = _PROCEDURE_NAME
_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]
_RUNNER_LABEL = "ci-untrusted-python312"
_RUNNER_IMAGE = "nmulti/gitea-act-ubuntu:22.04-actions"
_RUNNER_LABEL_SPEC = f"{_RUNNER_LABEL}:docker://{_RUNNER_IMAGE}"
_DEFAULT_GITEA_INSTANCE_URL = "http://10.0.30.96:3000"
_DEFAULT_ORGANIZATION = "N-MultiCloud"
_DEFAULT_RUNNER_NAME = "ci-untrusted-nmulticloud-org-241"
_COMPOSE_PROJECT_DIR = "/opt/gitea-ci-runner"

_NMS_SECRET_REF_PATTERN = (
    r"^nms-secret:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?![\s\S])"
)
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?![\s\S])"
_ORG_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?![\s\S])"
_HTTP_ORIGIN_PATTERN = (
    r"^https?://[A-Za-z0-9][A-Za-z0-9.-]{0,253}"
    r"(?::[0-9]{1,5})?/?(?![\s\S])"
)

_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["registration_token_secret_ref"],
    "additionalProperties": False,
    "properties": {
        "registration_token_secret_ref": {
            "type": "string",
            "minLength": 47,
            "maxLength": 47,
            "pattern": _NMS_SECRET_REF_PATTERN,
            "description": "Reference to the vaulted one-time Gitea runner token.",
        },
        "gitea_instance_url": {
            "type": "string",
            "minLength": 8,
            "maxLength": 255,
            "pattern": _HTTP_ORIGIN_PATTERN,
            "default": _DEFAULT_GITEA_INSTANCE_URL,
        },
        "organization": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": _ORG_PATTERN,
            "default": _DEFAULT_ORGANIZATION,
        },
        "runner_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": _IDENTIFIER_PATTERN,
            "default": _DEFAULT_RUNNER_NAME,
        },
        "install_docker": {"type": "boolean", "default": True},
        "build_runner_image": {"type": "boolean", "default": True},
        "load_prebuilt_runner_image": {"type": "boolean", "default": False},
        "force_recreate": {"type": "boolean", "default": False},
    },
    "not": {
        "required": ["build_runner_image", "load_prebuilt_runner_image"],
        "properties": {
            "build_runner_image": {"const": True},
            "load_prebuilt_runner_image": {"const": True},
        },
    },
}

_SHORT_TEXT = {"type": "string", "maxLength": 64}
_TEXT = {"type": "string", "maxLength": 255}
_URL_TEXT = {"type": "string", "maxLength": 255}
_ERROR = {"type": "string", "maxLength": 2048}

_RESULT_SCHEMA = {
    "type": "object",
    "required": [
        "ok",
        "procedure",
        "target",
        "changed",
        "registered",
        "online",
        "stage",
        "runner_name",
        "organization",
        "runner_label",
        "runner_image",
        "gitea_instance_url",
        "docker_installed",
        "image_ready",
        "compose_ready",
    ],
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"const": _HANDLER_ID},
        "target": _TEXT,
        "changed": {"type": ["boolean", "null"]},
        "registered": {"type": "boolean"},
        "online": {"type": "boolean"},
        "stage": {
            "type": "string",
            "enum": [
                "preconditions",
                "docker",
                "image",
                "config",
                "register",
                "start",
                "verify",
                "complete",
                "indeterminate",
            ],
        },
        "runner_name": _TEXT,
        "organization": _TEXT,
        "runner_label": {"const": _RUNNER_LABEL},
        "runner_image": {"const": _RUNNER_IMAGE},
        "runner_labels": {
            "type": "array",
            "items": {"const": _RUNNER_LABEL_SPEC},
            "maxItems": 1,
        },
        "gitea_instance_url": _URL_TEXT,
        "compose_project_dir": {"const": _COMPOSE_PROJECT_DIR},
        "docker_installed": {"type": "boolean"},
        "image_ready": {"type": "boolean"},
        "compose_ready": {"type": "boolean"},
        "container_state": _SHORT_TEXT,
        "service_state": _SHORT_TEXT,
        "warnings": {
            "type": "array",
            "items": {"type": "string", "maxLength": 512},
            "maxItems": 32,
        },
        "error": _ERROR,
    },
    "oneOf": [
        {
            "properties": {
                "ok": {"const": True},
                "registered": {"const": True},
                "online": {"const": True},
                "stage": {"const": "complete"},
                "docker_installed": {"const": True},
                "image_ready": {"const": True},
                "compose_ready": {"const": True},
            }
        },
        {"properties": {"ok": {"const": False}}},
    ],
}

_PROCEDURE_DEFAULTS = {
    "handler_id": _HANDLER_ID,
    "version": 1,
    "enabled": False,
    "target_models": _TARGET_MODELS,
    "effect": "write",
    "timeout_seconds": 1800,
    "approval_required": True,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_pinned": True,
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Provision the dedicated Gitea Actions organization CI runner with the "
        "fixed ci-untrusted-python312 label on the assigned runner host."
    ),
}

_REPRESENTATIVE_COMMAND = {
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "gitea-org-ci-runner-provision"],
    "description": (
        "Backend installs Docker as needed, prepares the fixed runner image and "
        "Compose project, resolves the vaulted token, registers the org runner, "
        "starts it, and verifies online state."
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


def seed_gitea_org_ci_runner_provision(apps, schema_editor):
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


def unseed_gitea_org_ci_runner_provision(apps, schema_editor):
    """Disable the seeded row without deleting audited procedure history."""

    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_PROCEDURE_NAME).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0079_rpcexecution_source_intent"),
    ]

    operations = [
        migrations.RunPython(
            seed_gitea_org_ci_runner_provision,
            reverse_code=unseed_gitea_org_ci_runner_provision,
        ),
    ]
