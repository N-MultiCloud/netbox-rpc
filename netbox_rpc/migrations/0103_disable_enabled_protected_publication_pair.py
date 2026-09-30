"""Restore the exact enabled legacy publication pair to default-dark state."""

import importlib

from django.db import migrations, transaction


def _contract():
    normalizer = importlib.import_module(
        "netbox_rpc.migrations.0103_normalize_protected_publication_provenance"
    )
    return normalizer, normalizer._contract()


def _validate(apps):
    normalizer, contract = _contract()
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    rows = []
    present = []
    modes = []
    for name, defaults, operation in normalizer._rows(contract):
        procedure = Procedure.objects.filter(name=name).first()
        present.append(procedure is not None)
        if procedure is None:
            continue
        expected = {**defaults, "enabled": procedure.enabled}
        commands = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
        command_defaults = {**contract._command(operation), "custom_field_data": {}}
        if (
            procedure.enabled not in {True, False}
            or not contract._matches(procedure, expected)
            or len(commands) != 1
            or getattr(commands[0], "sequence", None) != 1
            or not contract._matches(commands[0], command_defaults)
        ):
            raise RuntimeError(f"Refusing enabled publication row {name}")
        modes.append(procedure.enabled)
        rows.append(procedure)
    if any(present) and not all(present):
        raise RuntimeError("Refusing partial enabled publication pair")
    if len(set(modes)) > 1:
        raise RuntimeError("Refusing mixed enabled publication pair")
    return rows


def seed(apps, schema_editor):
    """Disable only an exact complete uniform legacy pair."""
    with transaction.atomic():
        rows = _validate(apps)
        if rows and rows[0].enabled:
            for procedure in rows:
                procedure.enabled = False
                procedure.save(update_fields=["enabled"])


def reverse(apps, schema_editor):
    """Validate the safe state without re-enabling protected publication."""
    with transaction.atomic():
        _validate(apps)


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")
    ]
    run_before = [  # noqa: RUF012
        ("netbox_rpc", "0103_report_protected_publication_drift")
    ]
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
