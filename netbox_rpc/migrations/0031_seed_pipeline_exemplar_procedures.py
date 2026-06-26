"""Seed read-only pipeline exemplar RPC procedures."""

from django.db import migrations

_TARGET_MODELS = ["dcim.device"]

_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts it at execution time.",
}

_TIMEOUT_REF = {
    "type": "integer",
    "minimum": 1,
    "maximum": 600,
    "description": "Optional per-handler timeout in seconds.",
}

_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean"},
        "data": {},
    },
}

_PVESH_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["pvesh_path"],
    "additionalProperties": False,
    "properties": {
        "pvesh_path": {
            "type": "string",
            "pattern": "^/[A-Za-z0-9/_.\\-]{1,128}$",
            "description": "Validated pvesh API path; nms-backend builds the invocation.",
        },
        "timeout": _TIMEOUT_REF,
        "rpc_ssh_credential_pk": _CREDENTIAL_REF,
    },
}

_COLLECT_FACTS_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "timeout": _TIMEOUT_REF,
        "rpc_ssh_credential_pk": _CREDENTIAL_REF,
    },
}

_SSH_CREDENTIAL_ONLY_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "rpc_ssh_credential_pk": _CREDENTIAL_REF,
    },
}

_DELL_OS10_SHOW_VERSION_TEXTFSM = """Value OS_VERSION (\\S+)
Value BUILD_VERSION (\\S+)
Value SYSTEM_TYPE (\\S+)
Value UPTIME (.+)

Start
  ^OS Version:\\s+${OS_VERSION}
  ^Build Version:\\s+${BUILD_VERSION}
  ^System Type:\\s+${SYSTEM_TYPE}
  ^Up Time:\\s+${UPTIME} -> Record
"""

_PROCEDURES = [
    {
        "name": "os.linux.proxmox.pvesh_json",
        "handler_id": "os.linux.proxmox.pvesh_json",
        "effect": "read",
        "approval_required": False,
        "enabled": True,
        "version": 1,
        "target_models": _TARGET_MODELS,
        "transport_driver": "asyncssh",
        "output_parser": "json",
        "output_schema": {},
        "timeout_seconds": 30,
        "description": "Read a validated Proxmox pvesh API path as JSON.",
        "params_schema": _PVESH_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "os.linux.collect_facts",
        "handler_id": "os.linux.collect_facts",
        "effect": "read",
        "approval_required": False,
        "enabled": True,
        "version": 1,
        "target_models": _TARGET_MODELS,
        "transport_driver": "asyncssh",
        "output_parser": "jc",
        "output_schema": {"jc_parser": "uname"},
        "timeout_seconds": 30,
        "description": "Collect basic Linux host facts through the fixed backend handler.",
        "params_schema": _COLLECT_FACTS_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.show_version_structured",
        "handler_id": "network.dell_os10_s5232f_on.show_version_structured",
        "effect": "read",
        "approval_required": False,
        "enabled": True,
        "version": 1,
        "target_models": _TARGET_MODELS,
        "transport_driver": "scrapli",
        "output_parser": "textfsm",
        "output_schema": {"textfsm_template": _DELL_OS10_SHOW_VERSION_TEXTFSM},
        "timeout_seconds": 30,
        "description": "Read Dell OS10 show version data with inline TextFSM parsing.",
        "params_schema": _SSH_CREDENTIAL_ONLY_PARAMS_SCHEMA,
        "result_schema": _RESULT_SCHEMA,
    },
]


def _seed_pipeline_exemplar_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in _PROCEDURES:
        RPCProcedure.objects.update_or_create(
            name=procedure["name"],
            defaults={
                "handler_id": procedure["handler_id"],
                "effect": procedure["effect"],
                "approval_required": procedure["approval_required"],
                "timeout_seconds": procedure["timeout_seconds"],
                "enabled": procedure["enabled"],
                "version": procedure["version"],
                "target_models": procedure["target_models"],
                "transport_driver": procedure["transport_driver"],
                "output_parser": procedure["output_parser"],
                "output_schema": procedure["output_schema"],
                "description": procedure["description"],
                "params_schema": procedure["params_schema"],
                "result_schema": procedure["result_schema"],
            },
        )


def _remove_pipeline_exemplar_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[procedure["name"] for procedure in _PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0030_rpcprocedure_driver_fields"),
    ]

    operations = [
        migrations.RunPython(
            _seed_pipeline_exemplar_procedures,
            reverse_code=_remove_pipeline_exemplar_procedures,
        ),
    ]
