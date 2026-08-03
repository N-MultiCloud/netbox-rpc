"""Seed the Akvorado v1 service-management procedure catalog.

File bodies are structured executor input. The backend must consume config
content through ``input_data``; it may not be substituted into a shell command
line.
"""

from django.db import migrations


_TARGET_MODELS = ["dcim.device", "virtualization.virtualmachine"]
_MAX_FILE_CONTENT = 1024 * 1024
_MAX_OUTPUT = 64 * 1024
# Best-effort defense in depth, not a complete secret detector. Durable storage
# relies on unconditional event-store redaction; the future backend renderer
# must accept credential references rather than literal secrets.
_SECRET_CONTENT_PATTERNS = (
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    (
        r"(?im)(?:^[ \t]*|[,{]\s*|-\s+)[\"']?[A-Za-z0-9_.-]*"
        r"(?:token|password|passphrase|secret|authorization|api[-_]?key|access[-_]?key|"
        r"private[-_]?key|credential)"
        r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?[ \t]*[^\s\"']+"
    ),
    (
        r"(?m)^([ \t]*)[\"']?[A-Za-z0-9_.-]*"
        r"(?:token|password|passphrase|secret|authorization|api[-_]?key|access[-_]?key|"
        r"private[-_]?key|credential)"
        r"[A-Za-z0-9_.-]*[\"']?\s*:\s*[|>]"
        r"(?:[1-9][+-]?|[+-][1-9]?)?[ \t]*$(?:\n(?:\1[ \t].*|[ \t]*$))*"
    ),
    r"(?im)\b(?:authorization|bearer)\s*[:=]\s*[^\r\n]+$",
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]",
)
_INPUT_DATA_CONTENT = {
    "type": "string",
    "minLength": 1,
    "maxLength": _MAX_FILE_CONTENT,
    "pattern": r"\S",
    "allOf": [{"not": {"pattern": pattern}} for pattern in _SECRET_CONTENT_PATTERNS],
    "description": (
        "Non-secret file content transported to the SSH executor through structured "
        "input_data; never interpolated into shell argv."
    ),
}


def _params(required=(), properties=None):
    return {
        "type": "object",
        "required": list(required),
        "additionalProperties": False,
        "properties": {**(properties or {})},
    }


_COMMON_RESULT = {
    "ok": {"type": "boolean"},
    "procedure": {"type": "string"},
    "target": {"type": "string"},
}


def _result(required=(), properties=None):
    return {
        "type": "object",
        "required": ["ok", "procedure", "target", *required],
        "additionalProperties": False,
        "properties": {**_COMMON_RESULT, **(properties or {})},
    }


_STATUS = {
    "type": "string",
    "minLength": 1,
    "maxLength": 64,
}
_OUTPUT = {"type": "string", "maxLength": _MAX_OUTPUT}

AKVORADO_PROCEDURES = (
    {
        "name": "service.akvorado.1.config_read",
        "handler_id": "service.akvorado.1.config_read",
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "description": "Read the current Akvorado akvorado.yaml configuration.",
        "params_schema": _params(),
        "result_schema": _result(
            ("content",),
            {"content": {"type": "string", "maxLength": _MAX_FILE_CONTENT}},
        ),
    },
    {
        "name": "service.akvorado.1.config_deploy",
        "handler_id": "service.akvorado.1.config_deploy",
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 120,
        "approval_required": True,
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "description": (
            "Validate and deploy akvorado.yaml from structured input_data."
        ),
        "params_schema": _params(
            ("config_content",),
            {"config_content": _INPUT_DATA_CONTENT},
        ),
        "result_schema": _result(
            ("deploy_status", "validation_output"),
            {"deploy_status": _STATUS, "validation_output": _OUTPUT},
        ),
    },
    {
        "name": "service.akvorado.1.status_stack",
        "handler_id": "service.akvorado.1.status_stack",
        "target_models": _TARGET_MODELS,
        "effect": "read",
        "timeout_seconds": 60,
        "approval_required": False,
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "description": "Read the current Akvorado Compose stack status.",
        "params_schema": _params(),
        "result_schema": _result(
            ("status", "output"),
            {"status": _STATUS, "output": _OUTPUT},
        ),
    },
    {
        "name": "service.akvorado.1.restart_stack",
        "handler_id": "service.akvorado.1.restart_stack",
        "target_models": _TARGET_MODELS,
        "effect": "write",
        "timeout_seconds": 120,
        "approval_required": True,
        "transport_driver": "asyncssh",
        "transport_driver_chain": [],
        "output_parser": "none",
        "output_schema": {},
        "description": "Restart the Akvorado Compose stack and report its status.",
        "params_schema": _params(),
        "result_schema": _result(
            ("status", "output"),
            {"status": _STATUS, "output": _OUTPUT},
        ),
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
    }


def seed_akvorado_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    # Ship disabled until matching nms-backend service.akvorado.1.* execution
    # handlers are deployed and verified; a follow-up migration or operator UI/API
    # toggle of RPCProcedure.enabled can then enable them.
    for item in AKVORADO_PROCEDURES:
        defaults = {**item, "version": 1, "enabled": False}
        name = defaults.pop("name")
        procedure, _ = RPCProcedure.objects.update_or_create(
            name=name, defaults=defaults
        )
        slug = item["handler_id"].replace("service.akvorado.1.", "akvorado-").replace(
            "_", "-"
        )
        RPCProcedureCommand.objects.update_or_create(
            procedure=procedure,
            sequence=1,
            defaults=_command(slug, item["description"]),
        )


def unseed_akvorado_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[item["name"] for item in AKVORADO_PROCEDURES]
    ).update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0056_seed_influxdb_onboarding_procedures"),
    ]

    operations = [
        migrations.RunPython(
            seed_akvorado_procedures,
            reverse_code=unseed_akvorado_procedures,
        ),
    ]
