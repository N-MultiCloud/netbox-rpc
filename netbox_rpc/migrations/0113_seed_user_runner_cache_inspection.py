"""Seed the disabled fixed runner 44 source and image inspection procedure."""

from django.db import migrations

_PROCEDURE_NAME = "service.gitea.actions_runner.inspect_user_cache"
_PARAMS_SCHEMA = {
    "additionalProperties": False,
    "properties": {},
    "title": "EmptyParams",
    "type": "object",
}
_RESULT_SCHEMA = {
    "$defs": {
        "InspectionEvidence": {
            "additionalProperties": False,
            "description": "The result never contains raw "
            "configuration, tokens, or command "
            "output.",
            "properties": {
                "active_job": {"default": None, "title": "Active Job", "type": "null"},
                "bind_mount_count": {
                    "maximum": 64,
                    "minimum": 0,
                    "title": "Bind Mount Count",
                    "type": "integer",
                },
                "cap_add_count": {
                    "maximum": 64,
                    "minimum": 0,
                    "title": "Cap Add Count",
                    "type": "integer",
                },
                "cap_drop_all": {"title": "Cap Drop All", "type": "boolean"},
                "capacity": {
                    "maximum": 16,
                    "minimum": 0,
                    "title": "Capacity",
                    "type": "integer",
                },
                "compose_identity_matches": {
                    "title": "Compose Identity Matches",
                    "type": "boolean",
                },
                "compose_sha256": {
                    "pattern": "^[0-9a-f]{64}$",
                    "title": "Compose Sha256",
                    "type": "string",
                },
                "config_mount_read_only": {
                    "title": "Config Mount Read Only",
                    "type": "boolean",
                },
                "config_path": {
                    "const": "/opt/nmc-ci-untrusted-user-241/config.yaml",
                    "title": "Config Path",
                    "type": "string",
                },
                "config_paths_match": {
                    "title": "Config Paths Match",
                    "type": "boolean",
                },
                "config_sha256": {
                    "pattern": "^[0-9a-f]{64}$",
                    "title": "Config Sha256",
                    "type": "string",
                },
                "configured_image": {
                    "maxLength": 160,
                    "title": "Configured Image",
                    "type": "string",
                },
                "container_config_user": {
                    "maxLength": 64,
                    "title": "Container Config User",
                    "type": "string",
                },
                "container_id": {
                    "pattern": "^[0-9a-f]{64}$",
                    "title": "Container Id",
                    "type": "string",
                },
                "docker_socket_mounted": {
                    "title": "Docker Socket Mounted",
                    "type": "boolean",
                },
                "exec_process_uid": {
                    "maximum": 2147483647,
                    "minimum": 0,
                    "title": "Exec Process Uid",
                    "type": "integer",
                },
                "health": {
                    "anyOf": [
                        {
                            "enum": ["healthy", "unhealthy", "starting"],
                            "type": "string",
                        },
                        {"type": "null"},
                    ],
                    "title": "Health",
                },
                "host_label_matches": {
                    "title": "Host Label Matches",
                    "type": "boolean",
                },
                "installed_binary_version": {
                    "pattern": "^v[0-9]+\\.[0-9]+\\.[0-9]+$",
                    "title": "Installed Binary Version",
                    "type": "string",
                },
                "matches_source": {"title": "Matches Source", "type": "boolean"},
                "mount_count": {
                    "maximum": 64,
                    "minimum": 0,
                    "title": "Mount Count",
                    "type": "integer",
                },
                "no_new_privileges": {"title": "No New Privileges", "type": "boolean"},
                "observed_container_name": {
                    "maxLength": 128,
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
                    "title": "Observed Container Name",
                    "type": "string",
                },
                "privileged": {"title": "Privileged", "type": "boolean"},
                "read_only_rootfs": {"title": "Read Only Rootfs", "type": "boolean"},
                "registration_id": {
                    "default": None,
                    "title": "Registration Id",
                    "type": "null",
                },
                "runner_name": {
                    "const": "ci-untrusted-emersonfelipesp-241",
                    "title": "Runner Name",
                    "type": "string",
                },
                "running_image": {
                    "maxLength": 160,
                    "title": "Running Image",
                    "type": "string",
                },
                "running_image_id": {
                    "pattern": "^sha256:[0-9a-f]{64}$",
                    "title": "Running Image Id",
                    "type": "string",
                },
                "runtime_identity_matches": {
                    "title": "Runtime Identity Matches",
                    "type": "boolean",
                },
                "scheduling_drained": {
                    "const": False,
                    "default": False,
                    "title": "Scheduling Drained",
                    "type": "boolean",
                },
                "state": {
                    "enum": [
                        "running",
                        "created",
                        "restarting",
                        "exited",
                        "paused",
                        "dead",
                    ],
                    "title": "State",
                    "type": "string",
                },
                "target": {
                    "const": "Gitea-Runner",
                    "title": "Target",
                    "type": "string",
                },
                "target_object_id": {
                    "const": 604,
                    "title": "Target Object Id",
                    "type": "integer",
                },
                "trusted_fixed_paths": {
                    "title": "Trusted Fixed Paths",
                    "type": "boolean",
                },
                "user_scope_verified": {
                    "const": False,
                    "default": False,
                    "title": "User Scope Verified",
                    "type": "boolean",
                },
            },
            "required": [
                "target",
                "target_object_id",
                "runner_name",
                "config_path",
                "config_sha256",
                "compose_sha256",
                "trusted_fixed_paths",
                "capacity",
                "host_label_matches",
                "config_paths_match",
                "compose_identity_matches",
                "configured_image",
                "running_image",
                "running_image_id",
                "container_id",
                "observed_container_name",
                "matches_source",
                "installed_binary_version",
                "exec_process_uid",
                "container_config_user",
                "runtime_identity_matches",
                "state",
                "health",
                "cap_drop_all",
                "cap_add_count",
                "no_new_privileges",
                "privileged",
                "read_only_rootfs",
                "mount_count",
                "bind_mount_count",
                "docker_socket_mounted",
                "config_mount_read_only",
            ],
            "title": "InspectionEvidence",
            "type": "object",
        }
    },
    "additionalProperties": False,
    "properties": {
        "evidence": {
            "anyOf": [{"$ref": "#/$defs/InspectionEvidence"}, {"type": "null"}]
        },
        "ok": {"title": "Ok", "type": "boolean"},
        "procedure": {
            "const": "service.gitea.actions_runner.inspect_user_cache",
            "title": "Procedure",
            "type": "string",
        },
        "stage": {
            "enum": ["complete", "indeterminate"],
            "title": "Stage",
            "type": "string",
        },
    },
    "required": ["ok", "procedure", "stage", "evidence"],
    "title": "InspectResult",
    "type": "object",
}
_COMMAND = {
    "sequence": 1,
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "gitea-user-runner-cache-inspect"],
    "description": "Backend inspects fixed runner source, image, binary, and container fields.",
    "condition_param": "",
    "condition_negate": False,
    "for_each_param": "",
    "continue_on_error": False,
    "render_mode": "literal",
    "produces_var": "",
    "capture_kind": "",
    "capture_expression": "",
}


def seed_user_runner_cache_inspection(apps, schema_editor):
    """Add one closed, disabled read-only procedure without adopting foreign rows."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    if Procedure.objects.filter(name=_PROCEDURE_NAME).exists():
        raise RuntimeError(
            "Migration 0113 cannot adopt an existing user runner inspection procedure."
        )
    procedure = Procedure.objects.create(
        name=_PROCEDURE_NAME,
        handler_id=_PROCEDURE_NAME,
        version=2,
        enabled=False,
        target_models=["virtualization.virtualmachine"],
        effect="read",
        timeout_seconds=120,
        approval_required=False,
        params_schema=_PARAMS_SCHEMA,
        result_schema=_RESULT_SCHEMA,
        transport_driver="asyncssh",
        transport_driver_chain=[],
        transport_pinned=True,
        output_parser="none",
        output_schema={},
        description=(
            "Inspect fixed user-scoped runner 44 source and image evidence on "
            "Gitea-Runner without caller-selected inputs or host mutation."
        ),
    )
    Command.objects.create(procedure=procedure, **_COMMAND)


def disable_user_runner_cache_inspection(apps, schema_editor):
    """Keep the row and execution history while disabling reverse deployment."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Procedure.objects.filter(name=_PROCEDURE_NAME).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0112_seed_iam_ui_control")]  # noqa: RUF012
    operations = [  # noqa: RUF012
        migrations.RunPython(
            seed_user_runner_cache_inspection,
            disable_user_runner_cache_inspection,
        ),
    ]
