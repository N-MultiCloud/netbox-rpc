from django.db import migrations


_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts it at execution time.",
}

_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
        "output": {"type": "string"},
        "fallback": {"type": "boolean"},
    },
}

DELL_OS10_S5232F_PROCEDURES = [
    {
        "name": "network.device.dell_os10.s5232f_on.bootstrap_restconf",
        "handler_id": "network.dell_os10_s5232f_on.bootstrap_restconf",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": True,
        "description": "Enable Dell SmartFabric OS10 RESTCONF over HTTPS with audited SSH CLI fallback.",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "configure_user": {"type": "boolean", "default": False},
                "restconf_credential_pk": _CREDENTIAL_REF,
                "certificate_name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                },
                "session_timeout": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1440,
                    "default": 60,
                },
                "cipher_suites": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 12,
                    "items": {"type": "string", "minLength": 1, "maxLength": 80},
                },
                "enable_ssh": {"type": "boolean", "default": True},
                "enable_restconf": {"type": "boolean", "default": True},
                "write_memory": {"type": "boolean", "default": True},
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.show_version",
        "handler_id": "network.dell_os10_s5232f_on.show_version",
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Run show version on Dell SmartFabric OS10.",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"rpc_ssh_credential_pk": _CREDENTIAL_REF},
        },
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.set_interface_description",
        "handler_id": "network.dell_os10_s5232f_on.set_interface_description",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": True,
        "description": "Set an OS10 interface description through an audited fixed SSH procedure.",
        "params_schema": {
            "type": "object",
            "required": ["interface_name", "description"],
            "additionalProperties": False,
            "properties": {
                "interface_name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                    "pattern": "^[A-Za-z][A-Za-z0-9/._:-]{0,63}$",
                },
                "description": {"type": "string", "minLength": 0, "maxLength": 240},
                "write_memory": {"type": "boolean", "default": False},
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.set_vlan_description",
        "handler_id": "network.dell_os10_s5232f_on.set_vlan_description",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": True,
        "description": "Set an OS10 VLAN interface description through an audited fixed SSH procedure.",
        "params_schema": {
            "type": "object",
            "required": ["vlan_id", "description"],
            "additionalProperties": False,
            "properties": {
                "vlan_id": {"type": "integer", "minimum": 1, "maximum": 4094},
                "description": {"type": "string", "minLength": 0, "maxLength": 240},
                "write_memory": {"type": "boolean", "default": False},
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
    {
        "name": "network.device.dell_os10.s5232f_on.write_memory",
        "handler_id": "network.dell_os10_s5232f_on.write_memory",
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": True,
        "description": "Persist the Dell SmartFabric OS10 running configuration.",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"rpc_ssh_credential_pk": _CREDENTIAL_REF},
        },
        "result_schema": _RESULT_SCHEMA,
    },
]


def seed_dell_os10_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for item in DELL_OS10_S5232F_PROCEDURES:
        name = item["name"]
        defaults = {key: value for key, value in item.items() if key != "name"}
        RPCProcedure.objects.update_or_create(name=name, defaults=defaults)


def unseed_dell_os10_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[item["name"] for item in DELL_OS10_S5232F_PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        (
            "netbox_rpc",
            "0008_seed_convert_mellanox_nic_to_ethernet_procedure",
        ),
    ]

    operations = [
        migrations.RunPython(seed_dell_os10_procedures, unseed_dell_os10_procedures),
    ]
