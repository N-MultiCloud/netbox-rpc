"""Adopt the exact enabled, unmarked protected-publication pair."""

import importlib

from django.db import migrations, transaction


def _normalizer():
    return importlib.import_module(
        "netbox_rpc.migrations.0103_normalize_protected_publication_provenance"
    )


def _validate(apps, *, enabled):
    normalizer = _normalizer()
    contract = normalizer._contract()
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    validated = []
    present = []
    for name, defaults, operation in normalizer._rows(contract):
        procedure = Procedure.objects.filter(name=name).first()
        present.append(procedure is not None)
        if procedure is None:
            continue
        expected_procedure = {**defaults, "enabled": enabled}
        expected_command = {**contract._command(operation), "custom_field_data": {}}
        commands = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
        if (
            not contract._matches(procedure, expected_procedure)
            or len(commands) != 1
            or getattr(commands[0], "sequence", None) != 1
            or not contract._matches(commands[0], expected_command)
        ):
            raise RuntimeError(
                f"Refusing to adopt enabled protected publication row {name}"
            )
        validated.append(procedure)
    if any(present) and not all(present):
        raise RuntimeError("Refusing partial enabled protected publication pair")
    return validated


def seed(apps, schema_editor):
    """Disable only the exact complete enabled, unmarked production pair."""
    with transaction.atomic():
        for procedure in _validate(apps, enabled=True):
            procedure.enabled = False
            procedure.save(update_fields=["enabled"])


def reverse(apps, schema_editor):
    """Restore enabled state only while the complete exact pair remains safe."""
    with transaction.atomic():
        for procedure in _validate(apps, enabled=False):
            procedure.enabled = True
            procedure.save(update_fields=["enabled"])


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")
    ]
    run_before = [  # noqa: RUF012
        ("netbox_rpc", "0103_report_protected_publication_drift")
    ]
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
