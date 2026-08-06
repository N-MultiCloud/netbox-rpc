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
        "output": {"type": "string"},
    },
}

HUAWEI_NE8000_BGP_PROCEDURES = [
    {
        "name": "Show BGP Peer (Huawei NE8000-F1A)",
        "handler_id": "network.huawei_ne8000_f1a.show_bgp_peer",
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 45,
        "approval_required": False,
        # Seeded disabled: neither the netbox-rpc-side normalizer branch (see
        # AGENTS.md "Adding New Procedures") nor the paired nms-backend
        # execution handler exist yet as of this migration. Without a
        # normalizer branch in _dispatch_normalize_execution_params(), any
        # dispatch of this procedure fails at runtime with
        # RPC_PROCEDURE_NOT_NORMALIZABLE (mirrors the os.linux_env_file.
        # upsert_var precedent, migration 0060). The credential-resolution
        # shape (explicit rpc_ssh_credential_pk override vs. implicit
        # resolution from the target device's own DeviceService binding, cf.
        # HUAWEI_MA5800_R024_START_ONT) is intentionally deferred to that
        # normalizer fast-follow rather than guessed here, so it can be
        # written against the nms-backend handler's actual, landed contract
        # (nms-backend#620) instead of an assumption. Flip to enabled=True in
        # the same commit that adds the normalizer branch.
        "enabled": False,
        "description": "Fetch BGP peer status from a Huawei NE8000-F1A device.",
        "params_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "vrf": {"type": "string", "default": ""},
                "rpc_ssh_credential_pk": _CREDENTIAL_REF,
            },
        },
        "result_schema": _RESULT_SCHEMA,
    },
]


def seed_huawei_ne8000_bgp_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for item in HUAWEI_NE8000_BGP_PROCEDURES:
        name = item["name"]
        defaults = {key: value for key, value in item.items() if key != "name"}
        RPCProcedure.objects.update_or_create(name=name, defaults=defaults)


def unseed_huawei_ne8000_bgp_procedures(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(
        name__in=[item["name"] for item in HUAWEI_NE8000_BGP_PROCEDURES]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0065_seed_ubuntu_upgrade_26_intent"),
    ]

    operations = [
        migrations.RunPython(
            seed_huawei_ne8000_bgp_procedures,
            unseed_huawei_ne8000_bgp_procedures,
        ),
    ]
