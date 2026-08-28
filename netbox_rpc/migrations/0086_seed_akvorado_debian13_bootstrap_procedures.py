"""Seed the audited Debian 13 Akvorado bootstrap procedures.

The existing ``service.akvorado.1.*`` family manages an already-present
Compose stack. These rows close the fresh-host gap with a mutation-free posture
read and an approval-gated, rerunnable installer. Neither accepts SSH routing or
credential input: both are bound to one assigned ``dcim.device`` and resolve its
enabled SSH DeviceService in the execution backend.

Rows are seeded disabled and remain closed for this release so an old worker
cannot claim them during a rolling deployment or after package rollback. A
later release may enable them only after this code is fully deployed. Reverse
migration disables rather than deletes audited procedures.
"""

from django.db import migrations

_TARGET_MODELS = ["dcim.device"]
_PREFLIGHT_NAME = "os.linux.debian.13.preflight_akvorado"
_INSTALL_NAME = "os.linux.debian.13.install_akvorado"

_SHORT_TEXT = {"type": "string", "maxLength": 64}
_IDENTIFIER_TEXT = {"type": "string", "maxLength": 128}
_PATH_TEXT = {"type": "string", "maxLength": 255}
_SERVICE_LIST = {
    "type": "array",
    "items": _SHORT_TEXT,
    "maxItems": 16,
    "uniqueItems": True,
}
_MESSAGE_LIST = {
    "type": "array",
    "items": {"type": "string", "maxLength": 512},
    "maxItems": 32,
}
_EXPECTED_SERVICES = [
    "clickhouse",
    "console",
    "inlet",
    "kafka",
    "orchestrator",
    "outlet",
    "redis",
]
_NULLABLE_BOOLEAN = {"type": ["boolean", "null"]}


def _params(properties=None):
    return {
        "type": "object",
        "required": [],
        "additionalProperties": False,
        "properties": dict(properties or {}),
    }


def _result(procedure_name, required, properties):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", *required],
        "additionalProperties": False,
        "properties": {
            "ok": {"type": "boolean"},
            "procedure": {"const": procedure_name},
            "target": {"type": "string", "maxLength": 255},
            **properties,
        },
    }


_PREFLIGHT_RESULT = _result(
    _PREFLIGHT_NAME,
    (
        "supported",
        "install_ready",
        "os_id",
        "os_version_id",
        "architecture",
        "vcpus",
        "memory_bytes",
        "root_free_bytes",
        "resource_ready",
        "sudo_ready",
        "host_key_pinned",
        "known_hosts_entry",
        "host_key_fingerprint",
        "docker_installed",
        "docker_package_version",
        "docker_version",
        "docker_supported",
        "compose_installed",
        "compose_package_version",
        "compose_version",
        "docker_active",
        "docker_enabled",
        "docker_group_member",
        "compose_dir_present",
        "config_present",
        "env_managed",
        "compose_managed",
        "stack_present",
        "stack_healthy",
        "services_expected",
        "services_running",
        "services_healthy",
        "console_ready",
        "port_conflicts",
        "blockers",
    ),
    {
        "supported": {"type": "boolean"},
        "install_ready": {"type": "boolean"},
        "os_id": _SHORT_TEXT,
        "os_version_id": _SHORT_TEXT,
        "architecture": _SHORT_TEXT,
        "vcpus": {"type": "integer", "minimum": 0},
        "memory_bytes": {"type": "integer", "minimum": 0},
        "root_free_bytes": {"type": "integer", "minimum": 0},
        "resource_ready": {"type": "boolean"},
        "sudo_ready": {"type": "boolean"},
        "host_key_pinned": {"type": "boolean"},
        "known_hosts_entry": {"type": "string", "maxLength": 1024},
        "host_key_fingerprint": _IDENTIFIER_TEXT,
        "docker_installed": {"type": "boolean"},
        "docker_package_version": _IDENTIFIER_TEXT,
        "docker_version": _IDENTIFIER_TEXT,
        "docker_supported": {"type": "boolean"},
        "compose_installed": {"type": "boolean"},
        "compose_package_version": _IDENTIFIER_TEXT,
        "compose_version": _IDENTIFIER_TEXT,
        "docker_active": {"type": "boolean"},
        "docker_enabled": {"type": "boolean"},
        "docker_group_member": {"type": "boolean"},
        "compose_dir_present": {"type": "boolean"},
        "config_present": {"type": "boolean"},
        "env_managed": {"type": "boolean"},
        "compose_managed": {"type": "boolean"},
        "stack_present": {"type": "boolean"},
        "stack_healthy": {"type": "boolean"},
        "services_expected": _SERVICE_LIST,
        "services_running": _SERVICE_LIST,
        "services_healthy": _SERVICE_LIST,
        "console_ready": {"type": "boolean"},
        "port_conflicts": _SERVICE_LIST,
        "blockers": _MESSAGE_LIST,
    },
)

_INSTALL_RESULT = _result(
    _INSTALL_NAME,
    (
        "installed",
        "changed",
        "config_created",
        "docker_package_version",
        "compose_package_version",
        "docker_version",
        "compose_version",
        "compose_path",
        "config_path",
        "stack_healthy",
        "services_expected",
        "services_running",
        "services_healthy",
        "console_ready",
        "ingress_ports_ready",
        "ready",
        "stage",
        "warnings",
        "error",
    ),
    {
        "installed": _NULLABLE_BOOLEAN,
        "changed": _NULLABLE_BOOLEAN,
        "config_created": _NULLABLE_BOOLEAN,
        "docker_package_version": _IDENTIFIER_TEXT,
        "compose_package_version": _IDENTIFIER_TEXT,
        "docker_version": _IDENTIFIER_TEXT,
        "compose_version": _IDENTIFIER_TEXT,
        "compose_path": _PATH_TEXT,
        "config_path": _PATH_TEXT,
        "stack_healthy": {"type": "boolean"},
        "services_expected": _SERVICE_LIST,
        "services_running": _SERVICE_LIST,
        "services_healthy": _SERVICE_LIST,
        "console_ready": {"type": "boolean"},
        "ingress_ports_ready": {"type": "boolean"},
        "ready": {"type": "boolean"},
        "stage": {
            "type": "string",
            "enum": [
                "preconditions",
                "package",
                "filesystem",
                "configure",
                "activate",
                "verify",
                "complete",
                "outcome_unknown",
            ],
        },
        "warnings": _MESSAGE_LIST,
        "error": {"type": "string", "maxLength": 2048},
    },
)
_INSTALL_RESULT["oneOf"] = [
    {
        "properties": {
            "ok": {"const": True},
            "installed": {"const": True},
            "changed": {"type": "boolean"},
            "config_created": {"type": "boolean"},
            "stack_healthy": {"const": True},
            "console_ready": {"const": True},
            "ingress_ports_ready": {"const": True},
            "ready": {"const": True},
            "stage": {"const": "complete"},
            "services_expected": {"const": _EXPECTED_SERVICES},
            "services_running": {"const": _EXPECTED_SERVICES},
            "services_healthy": {"const": _EXPECTED_SERVICES},
            "error": {"const": ""},
        }
    },
    {
        "properties": {
            "ok": {"const": False},
            "installed": {"type": "boolean"},
            "changed": {"type": "boolean"},
            "config_created": {"type": "boolean"},
            "ready": {"const": False},
            "stage": {
                "enum": [
                    "preconditions",
                    "package",
                    "filesystem",
                    "configure",
                    "activate",
                ]
            },
            "stack_healthy": {"const": False},
            "services_expected": {"const": _EXPECTED_SERVICES},
            "services_running": {"const": []},
            "services_healthy": {"const": []},
            "console_ready": {"const": False},
            "ingress_ports_ready": {"const": False},
            "error": {"type": "string", "minLength": 1, "maxLength": 2048},
        },
    },
    {
        "properties": {
            "ok": {"const": False},
            "installed": {"type": "boolean"},
            "changed": {"type": "boolean"},
            "config_created": {"type": "boolean"},
            "ready": {"const": False},
            "stage": {"const": "verify"},
            "services_expected": {"const": _EXPECTED_SERVICES},
            "error": {"type": "string", "minLength": 1, "maxLength": 2048},
        },
        "not": {
            "properties": {
                "stack_healthy": {"const": True},
                "console_ready": {"const": True},
                "ingress_ports_ready": {"const": True},
                "services_running": {"const": _EXPECTED_SERVICES},
                "services_healthy": {"const": _EXPECTED_SERVICES},
            }
        },
    },
    {
        "properties": {
            "ok": {"const": False},
            "installed": {"const": None},
            "changed": {"const": None},
            "config_created": {"const": None},
            "stack_healthy": {"const": False},
            "services_expected": {"const": _EXPECTED_SERVICES},
            "services_running": {"const": []},
            "services_healthy": {"const": []},
            "console_ready": {"const": False},
            "ingress_ports_ready": {"const": False},
            "ready": {"const": False},
            "stage": {"const": "outcome_unknown"},
            "error": {"type": "string", "minLength": 1, "maxLength": 2048},
        }
    },
]

_PROCEDURES = (
    {
        "name": _PREFLIGHT_NAME,
        "handler_id": "os.linux_debian_13.preflight_akvorado",
        "effect": "read",
        "timeout_seconds": 90,
        "approval_required": False,
        "description": (
            "Report Debian 13 Akvorado bootstrap posture: resources, sudo, "
            "host-key pin, Docker/Compose, managed files, required ports, stack "
            "health, and console readiness."
        ),
        "params_schema": _params(),
        "result_schema": _PREFLIGHT_RESULT,
        "command_slug": "akvorado-bootstrap-preflight",
    },
    {
        "name": _INSTALL_NAME,
        "handler_id": "os.linux_debian_13.install_akvorado",
        "effect": "write",
        # Backend script deadline is 1140s; leave room for HTTP/RQ headroom.
        "timeout_seconds": 1200,
        "approval_required": True,
        "description": (
            "Install Debian Docker/Compose and converge the pinned Akvorado 2.4.0 "
            "stack: managed files, preserved application config, image validation, "
            "startup, ports, and console health."
        ),
        "params_schema": _params(
            {"allow_resource_shortfall": {"type": "boolean", "default": False}}
        ),
        "result_schema": _INSTALL_RESULT,
        "command_slug": "akvorado-bootstrap-install",
    },
)


def _command(slug, description):
    return {
        "step_type": "shell_argv",
        "device_cli_mode": "",
        "argv": ["backend-orchestrated", slug],
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


def _assert_fields_match(instance, expected, *, label):
    mismatched = [
        key for key, value in expected.items() if getattr(instance, key, None) != value
    ]
    if mismatched:
        raise RuntimeError(
            f"Refusing to overwrite existing {label}; mismatched fields: "
            + ", ".join(sorted(mismatched))
        )


def seed_akvorado_debian13_bootstrap_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    for row in _PROCEDURES:
        defaults = {
            key: value
            for key, value in row.items()
            if key not in {"name", "command_slug"}
        }
        defaults.update(
            {
                "version": 1,
                "enabled": False,
                "target_models": _TARGET_MODELS,
                "transport_driver": "asyncssh",
                "transport_pinned": True,
                "transport_driver_chain": [],
                "output_parser": "none",
                "output_schema": {},
            }
        )
        procedure = RPCProcedure.objects.filter(name=row["name"]).first()
        created = procedure is None
        if created:
            procedure = RPCProcedure.objects.create(name=row["name"], **defaults)
        else:
            _assert_fields_match(procedure, defaults, label=f"procedure {row['name']}")

        expected_command = _command(row["command_slug"], row["description"])
        commands = list(
            RPCProcedureCommand.objects.filter(procedure=procedure).order_by("sequence")
        )
        if created:
            if commands:
                raise RuntimeError(
                    f"Refusing to seed {row['name']}; orphan commands already exist."
                )
            RPCProcedureCommand.objects.create(
                procedure=procedure,
                sequence=1,
                **expected_command,
            )
            continue
        if len(commands) != 1 or getattr(commands[0], "sequence", None) != 1:
            raise RuntimeError(
                f"Refusing to overwrite existing procedure {row['name']}; "
                "expected exactly one command at sequence 1."
            )
        _assert_fields_match(
            commands[0],
            expected_command,
            label=f"command for {row['name']}",
        )


def unseed_akvorado_debian13_bootstrap_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name__in=[row["name"] for row in _PROCEDURES]).update(
        enabled=False
    )


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0085_seed_dns_staging_deploy")]

    operations = [
        migrations.RunPython(
            seed_akvorado_debian13_bootstrap_procedures,
            reverse_code=unseed_akvorado_debian13_bootstrap_procedures,
        )
    ]
