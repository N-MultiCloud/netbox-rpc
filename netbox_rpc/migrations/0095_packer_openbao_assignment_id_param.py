"""Let the four ``packer.vm.*`` procedures accept a netbox-openbao
``CredentialAssignment`` reference as a mutually exclusive alternative to
``rpc_ssh_credential_pk``.

``RPCProcedure.params_schema`` is operator-editable reference data, and
NetBox runs migrations on every start, so this migration must never abort on
a customised schema. It transforms each schema structurally:

* adds the ``openbao_assignment_id`` property;
* drops ``rpc_ssh_credential_pk`` from ``required`` (every other required key
  and every unrelated property is preserved);
* adds a ``oneOf`` requiring exactly one of the two credential references.

A schema that already carries this migration's shape is left alone
(idempotent). A schema whose shape makes the change unsafe (not an object
schema, an existing conflicting ``openbao_assignment_id`` property, or an
existing ``oneOf``) is skipped with a warning and left untouched. The reverse
removes only what this migration added and restores ``rpc_ssh_credential_pk``
to ``required``.
"""

import logging

from django.db import migrations

_PACKER_PROCEDURE_NAMES = [
    "packer.vm.test_ssh_connectivity",
    "packer.vm.check_agent_running",
    "packer.vm.verify_services",
    "packer.vm.collect_info",
]

_OPENBAO_ASSIGNMENT_REF = {
    "type": "integer",
    "minimum": 1,
    "description": (
        "Optional netbox_openbao.CredentialAssignment PK, mutually exclusive "
        "with rpc_ssh_credential_pk. Bound to this exact PackerTemplate and "
        "verified at dispatch time; see domain/normalization.py. netbox-rpc "
        "never imports netbox-openbao."
    ),
}
_ONE_OF_CREDENTIAL = [
    {
        "required": ["rpc_ssh_credential_pk"],
        "properties": {"openbao_assignment_id": {"not": {}}},
    },
    {
        "required": ["openbao_assignment_id"],
        "properties": {"rpc_ssh_credential_pk": {"not": {}}},
    },
]


_LEGACY_KEY = "rpc_ssh_credential_pk"
_OPENBAO_KEY = "openbao_assignment_id"

logger = logging.getLogger("netbox_rpc.migrations")


def _is_applied(schema) -> bool:
    properties = schema.get("properties") if isinstance(schema, dict) else None
    return (
        isinstance(properties, dict)
        and properties.get(_OPENBAO_KEY) == _OPENBAO_ASSIGNMENT_REF
        and schema.get("oneOf") == _ONE_OF_CREDENTIAL
    )


def _unsafe_reason(schema) -> str | None:
    if not isinstance(schema, dict) or not isinstance(schema.get("properties"), dict):
        return "params_schema is not an object schema with properties"
    if _OPENBAO_KEY in schema["properties"]:
        return f"an existing {_OPENBAO_KEY} property conflicts"
    if "oneOf" in schema:
        return "an existing oneOf would be overwritten"
    return None


def _forward_schema(schema: dict) -> dict:
    updated = dict(schema)
    updated["properties"] = {
        **schema["properties"],
        _OPENBAO_KEY: _OPENBAO_ASSIGNMENT_REF,
    }
    required = [key for key in schema.get("required", []) if key != _LEGACY_KEY]
    if required:
        updated["required"] = required
    else:
        updated.pop("required", None)
    updated["oneOf"] = _ONE_OF_CREDENTIAL
    return updated


def _reverse_schema(schema: dict) -> dict:
    updated = {key: value for key, value in schema.items() if key != "oneOf"}
    updated["properties"] = {
        key: value for key, value in schema["properties"].items() if key != _OPENBAO_KEY
    }
    required = list(schema.get("required", []))
    if _LEGACY_KEY not in required:
        required.insert(0, _LEGACY_KEY)
    updated["required"] = required
    return updated


def _apply(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in RPCProcedure.objects.filter(name__in=_PACKER_PROCEDURE_NAMES):
        schema = procedure.params_schema
        if _is_applied(schema):
            continue
        reason = _unsafe_reason(schema)
        if reason:
            logger.warning(
                "Skipping %s: %s; add %s support to its params_schema manually.",
                procedure.name,
                reason,
                _OPENBAO_KEY,
            )
            continue
        procedure.params_schema = _forward_schema(schema)
        procedure.save(update_fields=["params_schema"])


def _reverse(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    for procedure in RPCProcedure.objects.filter(name__in=_PACKER_PROCEDURE_NAMES):
        if not _is_applied(procedure.params_schema):
            continue
        procedure.params_schema = _reverse_schema(procedure.params_schema)
        procedure.save(update_fields=["params_schema"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0094_add_openbao_assignment_id"),
    ]

    operations = [
        migrations.RunPython(_apply, _reverse),
    ]
