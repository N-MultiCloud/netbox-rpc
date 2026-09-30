"""Adopt the exact protected-publication rows from their pre-rebase migration.

This migration is intentionally inserted before 0104. Production run 28830
failed inside 0104 and therefore never recorded 0104 as applied; deploying this
graph to a database that already records 0104 as applied is unsupported because
Django must reject that inconsistent history before executing any migration.
"""

import importlib

from django.db import migrations, transaction

_PROVE = "service.gitea.actions_runner.protected_pair.prove"
_PROVISION = "service.gitea.actions_runner.protected_pair.provision"
_PREDECESSOR_HASHES = {
    _PROVE: "769bc782b2455743ce3434798de8978f606c26f3c67919e554ab92bde2028943",
    _PROVISION: "ecc792a599e791babff150fe41a8949f359bd830edd7375fbe96648efaeca1e3",
}


def _contract():
    return importlib.import_module(
        "netbox_rpc.migrations.0104_seed_protected_publication_pair"
    )


def _marker(name, contract_hash):
    return {
        "migration": "0103_seed_protected_publication_pair",
        "procedure": name,
        "contract_sha256": contract_hash,
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


def _validate_pair(apps, provenances):
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
        expected_command = contract._command(operation)
        commands = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
        candidates = provenances(name, contract, expected_command)
        mode = next(
            (
                candidate_mode
                for candidate_mode, marker in candidates.items()
                if contract._matches(
                    commands[0],
                    {**expected_command, "custom_field_data": marker},
                )
            ),
            None,
        ) if len(commands) == 1 else None
        if (
            not contract._matches(procedure, defaults)
            or len(commands) != 1
            or getattr(commands[0], "sequence", None) != 1
            or mode is None
            or observed_mode not in {None, mode}
        ):
            raise RuntimeError(
                f"Refusing to adopt pre-existing protected publication row {name}"
            )
        observed_mode = mode
        validated.append((commands[0], name, defaults, expected_command))
    if any(present) and not all(present):
        raise RuntimeError("Refusing partial protected publication predecessor state")
    return validated


def seed(apps, schema_editor):
    """Rotate only the exact, complete predecessor pair to current provenance."""
    contract = _contract()

    def predecessor(name, _contract, _command):
        return {
            "predecessor": _marker(name, _PREDECESSOR_HASHES[name]),
            "unmarked": {},
        }

    with transaction.atomic():
        validated = _validate_pair(apps, predecessor)
        for command, name, defaults, expected_command in validated:
            command.custom_field_data = contract._provenance_marker(
                name, defaults, expected_command
            )
            command.save(update_fields=["custom_field_data"])


def reverse(apps, schema_editor):
    """Restore unmarked legacy provenance only for the exact current pair."""

    def current(name, contract, command):
        defaults = (
            contract._PROVE_DEFAULTS
            if name == contract._PROVE
            else contract._PROVISION_DEFAULTS
        )
        return {"current": contract._provenance_marker(name, defaults, command)}

    with transaction.atomic():
        validated = _validate_pair(apps, current)
        for command, _name, _defaults, _expected_command in validated:
            command.custom_field_data = {}
            command.save(update_fields=["custom_field_data"])


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")
    ]
    run_before = [  # noqa: RUF012
        ("netbox_rpc", "0104_seed_protected_publication_pair")
    ]
    operations = [migrations.RunPython(seed, reverse)]  # noqa: RUF012
