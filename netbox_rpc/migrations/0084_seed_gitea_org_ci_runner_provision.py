"""Seed the gated Gitea Actions org CI runner provision procedure.

This procedure is the NetBox catalog contract for provisioning either reviewed
organization-runner lane on the prepared NMS runner host. The caller chooses a
closed lane enum; the runner name, labels, image, executor, project directory,
and trust posture are server-owned constants. It intentionally does not accept
caller-supplied SSH routing. The backend must resolve host, port, credential,
and known-host policy from the execution's assigned NetBox object, then resolve
the one-time Gitea registration token from ``registration_token_secret_ref``
through the netbox-nms secret bridge.

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
_DEFAULT_GITEA_INSTANCE_URL = "http://10.0.30.96:3000"
_DEFAULT_ORGANIZATION = "N-MultiCloud"

# The dedicated runner VM 10.0.30.241 hosts two lanes with DIFFERENT trust
# postures. Every per-lane value below is a frozen server-side constant: the
# caller selects a lane and nothing else. Opening label, image, or directory to
# caller-supplied values would defeat the point of this contract, which is that
# an approver can read the lane name and know exactly what gets installed.
#
#   untrusted-python312 — runs UNTRUSTED pull-request code. No Docker socket,
#     cap_drop ALL, no-new-privileges, jobs run as the non-root "cirunner" user
#     inside the runner container, which is itself the isolation boundary. The
#     label therefore uses the ":host" executor: there is no daemon to drive.
#
#   general-ubuntu — the estate's general CI lane, migrated off the Gitea
#     server on 2026-08-27. Its labels use the "docker://" executor, so the
#     RUNNER (never the job) holds /var/run/docker.sock and act_runner spawns
#     sibling job containers. This is why it cannot share the untrusted lane's
#     posture, and why the two must stay separate stacks.
_LANE_UNTRUSTED = "untrusted-python312"
_LANE_GENERAL = "general-ubuntu"

_LANES = {
    _LANE_UNTRUSTED: {
        "compose_project_dir": "/opt/nmc-ci-untrusted-org-241",
        "runner_name": "ci-untrusted-nmulticloud-org-241",
        "runner_image": "nmc/ci-untrusted-runner:python312-241",
        "runner_labels": ["ci-untrusted-python312:host"],
        "executor": "host",
        "runner_mounts_docker_socket": False,
        "jobs_mount_docker_socket": False,
        "runner_cap_drop_all": True,
        "runner_no_new_privileges": True,
        "job_user": "cirunner",
    },
    _LANE_GENERAL: {
        "compose_project_dir": "/opt/nmc-ci-ubuntu-241",
        "runner_name": "ci-ubuntu-nmulticloud-org-241",
        "runner_image": "nmulti/gitea-act-ubuntu:22.04-actions",
        "runner_labels": [
            "ubuntu-latest:docker://nmulti/gitea-act-ubuntu:22.04-actions",
            "ubuntu-24.04:docker://nmulti/gitea-act-ubuntu:22.04-actions",
            "ubuntu-22.04:docker://nmulti/gitea-act-ubuntu:22.04-actions",
        ],
        "executor": "docker",
        "runner_mounts_docker_socket": True,
        "jobs_mount_docker_socket": False,
        "runner_cap_drop_all": False,
        "runner_no_new_privileges": False,
        "job_user": None,
    },
}

_LANE_NAMES = sorted(_LANES)
_ALL_RUNNER_NAMES = sorted(lane["runner_name"] for lane in _LANES.values())
_ALL_RUNNER_IMAGES = sorted(lane["runner_image"] for lane in _LANES.values())
_ALL_COMPOSE_DIRS = sorted(lane["compose_project_dir"] for lane in _LANES.values())


def _lane_result_binding(lane_name):
    """Bind every frozen per-lane value to the selected lane in the result."""

    lane = _LANES[lane_name]
    return {
        "if": {"properties": {"lane": {"const": lane_name}}, "required": ["lane"]},
        "then": {
            "properties": {
                **{key: {"const": value} for key, value in lane.items()},
            }
        },
    }


_NMS_SECRET_REF_PATTERN = (
    r"^nms-secret:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?![\s\S])"
)
_ORG_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?![\s\S])"
_HTTP_ORIGIN_PATTERN = (
    r"^https?://[A-Za-z0-9][A-Za-z0-9.-]{0,253}"
    r"(?::[0-9]{1,5})?/?(?![\s\S])"
)

_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["lane", "registration_token_secret_ref"],
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
        # The lane is the ONLY thing the caller chooses about what is installed.
        # runner_name/label/image/dir are all derived from it server-side.
        "lane": {
            "type": "string",
            "enum": _LANE_NAMES,
            "description": (
                "Which frozen runner lane to provision on the assigned host. "
                "Selects the compose directory, runner name, label set, image, "
                "and Docker-socket posture as one reviewed unit."
            ),
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
        "lane",
        "runner_labels",
        "runner_image",
        "compose_project_dir",
        "executor",
        "runner_mounts_docker_socket",
        "jobs_mount_docker_socket",
        "runner_cap_drop_all",
        "runner_no_new_privileges",
        "job_user",
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
        "runner_name": {"enum": _ALL_RUNNER_NAMES},
        "organization": _TEXT,
        "lane": {"enum": _LANE_NAMES},
        "runner_image": {"enum": _ALL_RUNNER_IMAGES},
        "executor": {"type": "string", "enum": ["host", "docker"]},
        "runner_mounts_docker_socket": {"type": "boolean"},
        "jobs_mount_docker_socket": {"type": "boolean"},
        "runner_cap_drop_all": {"type": "boolean"},
        "runner_no_new_privileges": {"type": "boolean"},
        "job_user": {"type": ["string", "null"], "maxLength": 64},
        "runner_labels": {
            "type": "array",
            "items": {"type": "string", "maxLength": 255},
            "minItems": 1,
            "maxItems": 8,
            "uniqueItems": True,
        },
        "gitea_instance_url": _URL_TEXT,
        "compose_project_dir": {"enum": _ALL_COMPOSE_DIRS},
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
    "allOf": [_lane_result_binding(_lane) for _lane in _LANE_NAMES],
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
        "Provision one frozen Gitea Actions organization-runner lane on the "
        "assigned host. The untrusted lane uses a no-socket host executor; the "
        "general lane uses a runner-socket-only Docker executor. Names, labels, "
        "images, directories, and posture are fixed."
    ),
}

_REPRESENTATIVE_COMMAND = {
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "gitea-org-ci-runner-provision"],
    "description": (
        "Backend installs Docker as needed, applies the selected frozen lane and "
        "trust posture, resolves the vaulted token reference, registers the org "
        "runner, starts it, and verifies online state."
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
        ("netbox_rpc", "0083_seed_netbox_plugin_install"),
    ]

    operations = [
        migrations.RunPython(
            seed_gitea_org_ci_runner_provision,
            reverse_code=unseed_gitea_org_ci_runner_provision,
        ),
    ]
