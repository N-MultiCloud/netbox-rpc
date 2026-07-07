"""Tighten rpc_ssh_host JSON Schema validation for shared SSH overrides."""

from django.db import migrations

_RPC_SSH_HOST_PATTERN = r"^[^\s\x00-\x1f]{1,255}$"
_RPC_SSH_HOST_DESCRIPTION = (
    "Optional SSH host override consumed by nms-backend. Must not contain "
    "whitespace or control characters."
)

_PROCEDURE_NAMES = (
    "os.linux.ubuntu.24.install_qemu_guest_agent",
    "os.linux.ubuntu.24.install_zabbix_agent2",
    "services.minecraft.plugin.install_url",
    "services.minecraft.viaversion.install",
    "services.minecraft.papermc.install",
    "services.pterodactyl.wings.status",
    "services.pterodactyl.wings.logs",
    "services.pterodactyl.wings.restart",
    "os.linux.ubuntu.24.ookla.diagnose",
    "os.linux.ubuntu.24.ookla.check_service",
    "os.linux.ubuntu.24.ookla.check_listeners",
    "os.linux.ubuntu.24.ookla.check_tls",
    "os.linux.ubuntu.24.ookla.check_firewall",
)


def _schema_with_hardened_ssh_host(schema):
    schema = dict(schema or {})
    properties = dict(schema.get("properties") or {})
    ssh_host = properties.get("rpc_ssh_host")
    if not isinstance(ssh_host, dict):
        return schema, False

    ssh_host = dict(ssh_host)
    changed = False
    if ssh_host.get("pattern") != _RPC_SSH_HOST_PATTERN:
        ssh_host["pattern"] = _RPC_SSH_HOST_PATTERN
        changed = True
    if ssh_host.get("description") != _RPC_SSH_HOST_DESCRIPTION:
        ssh_host["description"] = _RPC_SSH_HOST_DESCRIPTION
        changed = True
    if not changed:
        return schema, False

    properties["rpc_ssh_host"] = ssh_host
    schema["properties"] = properties
    return schema, True


def harden_rpc_ssh_host_schemas(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in RPCProcedure.objects.filter(name__in=_PROCEDURE_NAMES).iterator():
        schema, changed = _schema_with_hardened_ssh_host(procedure.params_schema)
        if changed:
            procedure.params_schema = schema
            procedure.save(update_fields=["params_schema"])


def relax_rpc_ssh_host_schemas(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in RPCProcedure.objects.filter(name__in=_PROCEDURE_NAMES).iterator():
        schema = dict(procedure.params_schema or {})
        properties = dict(schema.get("properties") or {})
        ssh_host = properties.get("rpc_ssh_host")
        if not isinstance(ssh_host, dict):
            continue
        ssh_host = dict(ssh_host)
        if "pattern" not in ssh_host:
            continue
        ssh_host.pop("pattern", None)
        properties["rpc_ssh_host"] = ssh_host
        schema["properties"] = properties
        procedure.params_schema = schema
        procedure.save(update_fields=["params_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0035_seed_ookla_diagnostic_procedures"),
    ]

    operations = [
        migrations.RunPython(
            harden_rpc_ssh_host_schemas,
            reverse_code=relax_rpc_ssh_host_schemas,
        ),
    ]
