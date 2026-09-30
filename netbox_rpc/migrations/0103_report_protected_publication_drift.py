"""Report bounded drift evidence before protected-publication normalization."""

import importlib
import re

from django.db import migrations, transaction


def _contract():
    return importlib.import_module(
        "netbox_rpc.migrations.0104_seed_protected_publication_pair"
    )


def _rows(contract):
    return (
        (contract._PROVE, contract._PROVE_DEFAULTS, "gitea-protected-publication-pair-prove"),
        (
            contract._PROVISION,
            contract._PROVISION_DEFAULTS,
            "gitea-protected-publication-pair-provision",
        ),
    )


def _mismatched_fields(instance, expected, *, excluded=()):
    return sorted(
        field
        for field, value in expected.items()
        if field not in excluded and getattr(instance, field, None) != value
    )


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MARKER_KEYS = {"migration", "procedure", "contract_sha256"}


def _marker_evidence(marker, *, name):
    if not isinstance(marker, dict):
        return {"type": type(marker).__name__}
    contract_hash = marker.get("contract_sha256")
    migration_name = marker.get("migration")
    return {
        "type": "dict",
        "keys_exact": set(marker) == _MARKER_KEYS,
        "key_count": "0" if not marker else "1-3" if len(marker) <= 3 else "4+",
        "migration_mode": (
            migration_name
            if migration_name
            in {
                "0103_seed_protected_publication_pair",
                "0104_seed_protected_publication_pair",
            }
            else "other"
        ),
        "procedure_matches": marker.get("procedure") == name,
        "contract_sha256": (
            contract_hash
            if isinstance(contract_hash, str) and _SHA256_RE.fullmatch(contract_hash)
            else None
        ),
    }


def diagnose(apps, schema_editor):
    """Fail with bounded field-level evidence only when the pair has drifted."""
    contract = _contract()
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    evidence = []
    for name, defaults, operation in _rows(contract):
        procedure = Procedure.objects.filter(name=name).first()
        if procedure is None:
            evidence.append({"name": name, "procedure": "missing"})
            continue
        commands = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
        item = {
            "name": name,
            "procedure_fields": _mismatched_fields(procedure, defaults),
            "command_count": len(commands),
        }
        if len(commands) == 1:
            expected = contract._command(operation)
            command = commands[0]
            item.update(
                {
                    "sequence": getattr(command, "sequence", None),
                    "command_fields": _mismatched_fields(
                        command, expected, excluded=("custom_field_data",)
                    ),
                    "marker": _marker_evidence(
                        getattr(command, "custom_field_data", None), name=name
                    ),
                }
            )
        evidence.append(item)

    normalizer = importlib.import_module(
        "netbox_rpc.migrations.0103_normalize_protected_publication_provenance"
    )
    try:
        normalizer._validate(apps)
    except RuntimeError as exc:
        raise RuntimeError(
            f"Protected publication drift evidence: {evidence!r}"
        ) from exc


def reverse(apps, schema_editor):
    """The diagnostic migration has no database side effects."""

    del apps, schema_editor
    _ = transaction


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")
    ]
    run_before = [  # noqa: RUF012
        ("netbox_rpc", "0103_normalize_protected_publication_provenance")
    ]
    operations = [migrations.RunPython(diagnose, reverse)]  # noqa: RUF012
