"""Seed the fixed protected publication-runner pair, disabled by default."""

import hashlib
import json

from django.db import migrations, transaction

_PROVE = "service.gitea.actions_runner.protected_pair.prove"
_PROVISION = "service.gitea.actions_runner.protected_pair.provision"
_TARGET_OBJECT = {
    "content_type": "virtualization.virtualmachine",
    "object_id": 416,
}
_TARGET_MODELS = ["virtualization.virtualmachine"]
_SCOPE_OWNER = "N-MultiCloud"
_SCOPE_TYPE = "organization"
_RUNNER_BINARY_SHA256 = (
    "7cc722a0de44af661d299c0b86eeee03231f993effa517718e48a45c2c188ef1"
)
_BUILD_SANDBOX = "/usr/local/bin/nmulticloud-release-build-sandbox"
_BUILD_SANDBOX_SHA256 = "2e644e715af33b73a91e517f6b5b59f76e0c0c2461576a9f87f522a3603f18ec"
_HOST_GENERATION_SHA256 = "11fc017aff23a9572db7b4a2d38cba895dcba50bfd600a2127dfad7bfcb778b5"
_RUNTIME_INVENTORY_SHA256 = "0398104f4485b623c10a9e236a53b4e950c9b03ba4101aa6cc5d33b7679ebd4e"
_PROVE_HELPER_SHA256 = "43e47fe535e4497624cc423097bf7a386aedbbd10fde2ae90c72c280005aa0a7"
_PROVISION_HELPER_SHA256 = "a977c99a33ab26ae4beb0b8c71848d3ed116daf821a4088caa29a31ea8979216"
_PUBLICATION_BROKER_SHA256 = "452b1a3b61413509e9f2de07a0d603961dfb06e3564f28eb7c9029b8d1fee153"
_PUBLICATION_POLICY_SHA256 = "75844eb1293ae8ebc06d2d2ef76c16604901a1b6825a8cea30ea664273ecac40"
_PARAMS_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
_SHA256_SCHEMA = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
_RUNNER_ID_SCHEMA = {
    "type": "integer",
    "minimum": 1,
    "maximum": 9_007_199_254_740_991,
}
_ROLES = {
    "builder": {
        "runner_name": "ci-release-builder-netbox-rpc-backend",
        "service_user": "nmc-rpc-release-builder",
        "service_name": "nmc-rpc-release-builder.service",
    },
    "publisher": {
        "runner_name": "ci-release-publisher-netbox-rpc-backend",
        "service_user": "nmc-rpc-release-publisher",
        "service_name": "nmc-rpc-release-publisher.service",
    },
    "validator": {
        "runner_name": "ci-release-validator-netbox-rpc-backend",
        "service_user": "nmc-rpc-release-validator",
        "service_name": "nmc-rpc-release-validator.service",
    },
}


def _role_schema(role):
    policy = _ROLES[role]
    service_user = policy["service_user"]
    return {
        "type": "object",
        "required": [
            "runner_id",
            "runner_name",
            "labels",
            "online",
            "busy",
            "service_active",
            "service_user",
            "service_name",
            "process_identity",
            "workspace_root",
            "state_root",
            "cache_root",
            "config_path",
            "launcher_sha256",
            "scope_owner",
            "scope_type",
            "scope_sha256",
            "runtime_inventory_sha256",
            "accepts_pull_requests",
            "control_plane_https",
            "candidate_build_network",
            "package_write_credential_present",
            "package_mutation",
        ],
        "additionalProperties": False,
        "properties": {
            "runner_id": _RUNNER_ID_SCHEMA,
            "runner_name": {"const": policy["runner_name"]},
            "labels": {"const": [f"release-{role}"]},
            "online": {"const": True},
            "busy": {"const": False},
            "service_active": {"const": True},
            "service_user": {"const": policy["service_user"]},
            "service_name": {"const": policy["service_name"]},
            "process_identity": {"type": "string", "minLength": 1, "maxLength": 128},
            "workspace_root": {"const": f"/var/lib/{service_user}/work"},
            "state_root": {"const": f"/var/lib/{service_user}"},
            "cache_root": {"const": f"/var/cache/{service_user}"},
            "config_path": {"const": f"/etc/nmc-protected-publication/{role}.yaml"},
            "scope_owner": {"const": _SCOPE_OWNER},
            "scope_type": {"const": _SCOPE_TYPE},
            "scope_sha256": _SHA256_SCHEMA,
            "launcher_sha256": {"const": _RUNNER_BINARY_SHA256},
            "runtime_inventory_sha256": {"const": _RUNTIME_INVENTORY_SHA256},
            "accepts_pull_requests": {"const": False},
            "control_plane_https": {"const": "same-origin-gitea-only"},
            "candidate_build_network": {"const": "none"},
            "package_write_credential_present": {"const": False},
            "package_mutation": {
                "const": "broker-socket-only" if role == "publisher" else "none"
            },
        },
    }


_PAIR_SCHEMA = {
    "type": "object",
    "required": [
        "distinct_runner_ids",
        "distinct_service_users",
        "distinct_processes",
        "distinct_workspaces",
        "distinct_state_roots",
        "distinct_cache_roots",
        "crossover_absent",
    ],
    "additionalProperties": False,
    "properties": {
        "distinct_runner_ids": {"const": True},
        "distinct_service_users": {"const": True},
        "distinct_processes": {"const": True},
        "distinct_workspaces": {"const": True},
        "distinct_state_roots": {"const": True},
        "distinct_cache_roots": {"const": True},
        "crossover_absent": {"const": True},
    },
}
_SET_FIELDS = (
    "all_cache_roots_distinct",
    "all_processes_distinct",
    "all_runner_ids_distinct",
    "all_service_users_distinct",
    "all_state_roots_distinct",
    "all_workspaces_distinct",
    "crossover_absent",
    "validator_build_authority_absent",
    "validator_publisher_socket_absent",
)
_SET_SCHEMA = {
    "type": "object",
    "required": list(_SET_FIELDS),
    "additionalProperties": False,
    "properties": {field: {"const": True} for field in _SET_FIELDS},
}
_ISOLATION_FIELDS = (
    "fresh_unprivileged_execution",
    "candidate_network_blocked",
    "candidate_credentials_hidden",
    "source_read_only",
    "output_scoped",
    "authority_paths_hidden",
    "sibling_paths_hidden",
    "runner_control_paths_hidden",
    "environment_cleared",
    "resources_bounded",
    "processes_reaped",
    "writable_layer_absent",
    "persistence_absent",
)
_ISOLATION_SCHEMA = {
    "type": "object",
    "required": list(_ISOLATION_FIELDS),
    "additionalProperties": False,
    "properties": {field: {"const": True} for field in _ISOLATION_FIELDS},
}
_PUBLICATION_BROKER_SCHEMA = {
    "type": "object",
    "required": [
        "socket_path",
        "service_template",
        "credential_scope",
        "broker_sha256",
        "policy_sha256",
        "credential_exposed_to_runner",
        "credential_exposed_to_candidate",
        "canonical_main_reauthorized",
        "active_run_reauthorized",
        "workflow_digest_reauthorized",
        "same_origin_https_only",
        "redirects_denied",
        "mutations_scoped",
    ],
    "additionalProperties": False,
    "properties": {
        "socket_path": {"const": "/run/nmc-release-control/publish.sock"},
        "service_template": {"const": "nmc-release-publish@.service"},
        "credential_scope": {"const": "netbox-rpc-backend-package-write-only"},
        "broker_sha256": {"const": _PUBLICATION_BROKER_SHA256},
        "policy_sha256": {"const": _PUBLICATION_POLICY_SHA256},
        "credential_exposed_to_runner": {"const": False},
        "credential_exposed_to_candidate": {"const": False},
        "canonical_main_reauthorized": {"const": True},
        "active_run_reauthorized": {"const": True},
        "workflow_digest_reauthorized": {"const": True},
        "same_origin_https_only": {"const": True},
        "redirects_denied": {"const": True},
        "mutations_scoped": {"const": True},
    },
}


def _result_schema(procedure, operation):
    return {
        "type": "object",
        "required": [
            "ok",
            "schema_version",
            "procedure",
            "operation",
            "stage",
            "target",
            "target_object",
            "scope",
            "host_generation_sha256",
            "runtime_inventory_sha256",
            "helper_sha256",
            "sandbox_path",
            "sandbox_owner",
            "sandbox_mode",
            "sandbox_sha256",
            "roles",
            "pair",
            "set",
            "isolation",
            "publication_broker",
        ],
        "additionalProperties": False,
        "properties": {
            "ok": {"const": True},
            "schema_version": {"const": 1},
            "procedure": {"const": procedure},
            "operation": {"const": operation},
            "stage": {"const": "complete"},
            "target": {"const": "Gitea-Runner"},
            "target_object": {"const": _TARGET_OBJECT},
            "scope": {"const": {"owner": _SCOPE_OWNER, "type": _SCOPE_TYPE}},
            "host_generation_sha256": {"const": _HOST_GENERATION_SHA256},
            "runtime_inventory_sha256": {"const": _RUNTIME_INVENTORY_SHA256},
            "helper_sha256": {
                "const": (
                    _PROVE_HELPER_SHA256
                    if operation == "prove"
                    else _PROVISION_HELPER_SHA256
                )
            },
            "sandbox_path": {"const": _BUILD_SANDBOX},
            "sandbox_owner": {"const": "root"},
            "sandbox_mode": {"const": "0755"},
            "sandbox_sha256": {"const": _BUILD_SANDBOX_SHA256},
            "roles": {
                "type": "object",
                "required": ["builder", "publisher", "validator"],
                "additionalProperties": False,
                "properties": {
                    "builder": _role_schema("builder"),
                    "publisher": _role_schema("publisher"),
                    "validator": _role_schema("validator"),
                },
            },
            "pair": _PAIR_SCHEMA,
            "set": _SET_SCHEMA,
            "isolation": _ISOLATION_SCHEMA,
            "publication_broker": _PUBLICATION_BROKER_SCHEMA,
        },
    }


_DESCRIPTION = (
    "Prove or provision the fixed, distinct release-validator, release-builder, "
    "and release-publisher set without accepting caller-selected host operations."
)


def _defaults(name, *, effect, timeout, approval):
    return {
        "handler_id": name,
        "version": 1,
        "description": _DESCRIPTION,
        "effect": effect,
        "timeout_seconds": timeout,
        "approval_required": approval,
        "enabled": False,
        "target_models": _TARGET_MODELS,
        "params_schema": _PARAMS_SCHEMA,
        "result_schema": _result_schema(name, "provision" if approval else "prove"),
        "transport_driver": "asyncssh",
        "transport_pinned": True,
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
    }


_PROVE_DEFAULTS = _defaults(_PROVE, effect="read", timeout=300, approval=False)
_PROVISION_DEFAULTS = _defaults(
    _PROVISION, effect="destructive", timeout=1800, approval=True
)
def _command(operation):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", operation],
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


def _canonical_sha256(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _provenance_marker(name, defaults, command):
    return {
        "migration": "0104_seed_protected_publication_pair",
        "procedure": name,
        "contract_sha256": _canonical_sha256(
            {"procedure": defaults, "command": command}
        ),
    }


def _predecessor_provenance_marker(name, defaults, command):
    """Identify the exact pre-rebase migration contract already deployed."""
    return {
        "migration": "0103_seed_protected_publication_pair",
        "procedure": name,
        "contract_sha256": _canonical_sha256(
            {"procedure": defaults, "command": command}
        ),
    }


def _matches(instance, expected):
    return all(getattr(instance, field) == value for field, value in expected.items())


def seed(apps, schema_editor):
    """Create immutable disabled rows without changing later activation."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    rows = (
        (_PROVE, _PROVE_DEFAULTS, "gitea-protected-publication-pair-prove"),
        (_PROVISION, _PROVISION_DEFAULTS, "gitea-protected-publication-pair-provision"),
    )
    with transaction.atomic():
        observed_mode = None
        for name, defaults, operation in rows:
            procedure = Procedure.objects.filter(name=name).first()
            expected_command = _command(operation)
            command_defaults = {
                **expected_command,
                "custom_field_data": _provenance_marker(
                    name, defaults, expected_command
                ),
            }
            if procedure is None:
                if observed_mode not in {None, "new"}:
                    raise RuntimeError(
                        "Refusing partial protected publication predecessor state"
                    )
                observed_mode = "new"
                procedure = Procedure.objects.create(name=name, **defaults)
                Command.objects.create(
                    procedure=procedure,
                    sequence=1,
                    **command_defaults,
                )
                continue
            commands = list(
                Command.objects.filter(procedure=procedure).order_by("sequence")
            )
            predecessor_command_defaults = {
                **expected_command,
                "custom_field_data": _predecessor_provenance_marker(
                    name, defaults, expected_command
                ),
            }
            current_matches = (
                _matches(procedure, defaults)
                and len(commands) == 1
                and getattr(commands[0], "sequence", None) == 1
                and _matches(commands[0], command_defaults)
            )
            predecessor_matches = (
                _matches(procedure, defaults)
                and len(commands) == 1
                and getattr(commands[0], "sequence", None) == 1
                and _matches(commands[0], predecessor_command_defaults)
            )
            unmarked_matches = (
                _matches(procedure, defaults)
                and len(commands) == 1
                and getattr(commands[0], "sequence", None) == 1
                and _matches(commands[0], expected_command)
                and getattr(commands[0], "custom_field_data", None) == {}
            )
            mode = (
                "current"
                if current_matches
                else (
                    "predecessor"
                    if predecessor_matches
                    else "unmarked" if unmarked_matches else "invalid"
                )
            )
            if observed_mode not in {None, mode}:
                raise RuntimeError(
                    "Refusing mixed protected publication predecessor state"
                )
            observed_mode = mode
            if predecessor_matches:
                commands[0].custom_field_data = command_defaults["custom_field_data"]
                commands[0].save(update_fields=["custom_field_data"])
                continue
            if unmarked_matches:
                Command.objects.filter(procedure=procedure).update(
                    custom_field_data=command_defaults["custom_field_data"]
                )
                continue
            if not current_matches:
                raise RuntimeError(
                    f"Refusing to adopt pre-existing protected publication row {name}"
                )


def reverse(apps, schema_editor):
    """Disable rows while retaining execution history and exact contracts."""
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Procedure.objects.filter(name__in=[_PROVE, _PROVISION]).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")]
    operations = [migrations.RunPython(seed, reverse)]
