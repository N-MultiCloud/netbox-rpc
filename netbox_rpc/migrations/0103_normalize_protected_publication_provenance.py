"""Normalize an exact legacy publication pair before immutable adoption."""

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


def _predecessor_marker(name):
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


def _validate(apps):
    contract = _contract()
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    validated = []
    present = []
    observed_mode = None
    for name, defaults, operation in _rows(contract):
        procedure = Procedure.objects.filter(name=name).first()
        present.append(procedure is not None)
        if procedure is None:
            continue
        command_defaults = contract._command(operation)
        commands = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
        markers = {
            "unmarked": {},
            "predecessor": _predecessor_marker(name),
            "current": contract._provenance_marker(name, defaults, command_defaults),
        }
        mode = next(
            (
                candidate
                for candidate, marker in markers.items()
                if len(commands) == 1
                and contract._matches(
                    commands[0],
                    {**command_defaults, "custom_field_data": marker},
                )
            ),
            None,
        )
        if (
            not contract._matches(procedure, defaults)
            or len(commands) != 1
            or getattr(commands[0], "sequence", None) != 1
            or mode is None
            or observed_mode not in {None, mode}
        ):
            raise RuntimeError(
                f"Refusing to normalize protected publication row {name}"
            )
        observed_mode = mode
        validated.append(commands[0])
    if any(present) and not all(present):
        raise RuntimeError("Refusing partial protected publication pair")
    return validated


def seed(apps, schema_editor):
    """Normalize an exact uniform pair to the selected unmarked precursor."""
    with transaction.atomic():
        for command in _validate(apps):
            command.custom_field_data = {}
            command.save(update_fields=["custom_field_data"])


def reverse(apps, schema_editor):
    """Retain the safe unmarked form; the source mode cannot be inferred."""
    _validate(apps)


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")
    ]
    run_before = [  # noqa: RUF012
        ("netbox_rpc", "0103_adopt_unmarked_protected_publication_pair")
    ]
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
