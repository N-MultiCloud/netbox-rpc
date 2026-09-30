"""Mark the exact unmarked legacy pair for the immutable adoption migration."""

import importlib

from django.db import migrations, transaction

_PREDECESSOR_HASHES = {
    "service.gitea.actions_runner.protected_pair.prove": (
        "769bc782b2455743ce3434798de8978f606c26f3c67919e554ab92bde2028943"
    ),
    "service.gitea.actions_runner.protected_pair.provision": (
        "ecc792a599e791babff150fe41a8949f359bd830edd7375fbe96648efaeca1e3"
    ),
}


def _contract():
    return importlib.import_module(
        "netbox_rpc.migrations.0104_seed_protected_publication_pair"
    )


def _marker(name):
    return {
        "migration": "0103_seed_protected_publication_pair",
        "procedure": name,
        "contract_sha256": _PREDECESSOR_HASHES[name],
    }


def _rows(contract):
    return (
        (contract._PROVE, contract._PROVE_DEFAULTS, "gitea-protected-publication-pair-prove"),
        (
            contract._PROVISION,
            contract._PROVISION_DEFAULTS,
            "gitea-protected-publication-pair-provision",
        ),
    )


def _validate(apps, marker):
    contract = _contract()
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    commands = []
    present = []
    for name, defaults, operation in _rows(contract):
        procedure = Procedure.objects.filter(name=name).first()
        present.append(procedure is not None)
        if procedure is None:
            continue
        rows = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
        expected = {**contract._command(operation), "custom_field_data": marker(name)}
        if (
            not contract._matches(procedure, defaults)
            or len(rows) != 1
            or getattr(rows[0], "sequence", None) != 1
            or not contract._matches(rows[0], expected)
        ):
            raise RuntimeError(
                f"Refusing to adopt unmarked protected publication row {name}"
            )
        commands.append((rows[0], name))
    if any(present) and not all(present):
        raise RuntimeError("Refusing partial unmarked protected publication pair")
    return commands


def seed(apps, schema_editor):
    """Rotate only the exact complete unmarked pair to predecessor provenance."""
    with transaction.atomic():
        commands = _validate(apps, lambda _name: {})
        for command, name in commands:
            command.custom_field_data = _marker(name)
            command.save(update_fields=["custom_field_data"])


def reverse(apps, schema_editor):
    """Restore unmarked provenance only for the exact predecessor pair."""
    with transaction.atomic():
        commands = _validate(apps, _marker)
        for command, _name in commands:
            command.custom_field_data = {}
            command.save(update_fields=["custom_field_data"])


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")
    ]
    run_before = [  # noqa: RUF012
        ("netbox_rpc", "0103_adopt_protected_publication_predecessor")
    ]
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
