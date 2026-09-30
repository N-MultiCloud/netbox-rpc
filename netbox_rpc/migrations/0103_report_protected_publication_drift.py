"""Report exact protected-publication row drift before normalization."""

import hashlib
import importlib
import json

from django.db import migrations


def _contract():
    return importlib.import_module(
        "netbox_rpc.migrations.0103_normalize_protected_publication_provenance"
    )


def _digest(value):
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _field_drift(instance, expected, *, exclude=()):
    return sorted(
        key
        for key, value in expected.items()
        if key not in exclude and getattr(instance, key, None) != value
    )


def report(apps, schema_editor):
    """Fail with non-sensitive field names and hashes for an unknown exact state."""
    normalizer = _contract()
    contract = normalizer._contract()
    Procedure = apps.get_model("netbox_rpc", "RPCProcedure")
    Command = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    reports = []
    present = []
    observed_modes = []
    for name, defaults, operation in normalizer._rows(contract):
        procedure = Procedure.objects.filter(name=name).first()
        present.append(procedure is not None)
        if procedure is None:
            continue
        commands = list(Command.objects.filter(procedure=procedure).order_by("sequence"))
        command_defaults = contract._command(operation)
        procedure_drift = _field_drift(procedure, defaults)
        if len(commands) != 1:
            reports.append(
                f"{name}:procedure_fields={procedure_drift}:command_count={len(commands)}"
            )
            continue
        command = commands[0]
        command_drift = _field_drift(
            command,
            command_defaults,
            exclude=("custom_field_data",),
        )
        markers = {
            "unmarked": {},
            "predecessor": normalizer._predecessor_marker(name),
            "current": contract._provenance_marker(name, defaults, command_defaults),
        }
        marker = getattr(command, "custom_field_data", None)
        mode = next((key for key, value in markers.items() if marker == value), "unknown")
        observed_modes.append(mode)
        if procedure_drift or command_drift or command.sequence != 1 or mode == "unknown":
            reports.append(
                f"{name}:procedure_fields={procedure_drift}:"
                f"command_fields={command_drift}:sequence={command.sequence}:"
                f"marker_mode={mode}:marker_sha256={_digest(marker)}"
            )
    if any(present) and not all(present):
        reports.append("pair_state=partial")
    if len(set(observed_modes)) > 1:
        reports.append(f"pair_modes={sorted(observed_modes)}")
    if reports:
        raise RuntimeError("Protected publication drift: " + "; ".join(reports))


def noop(apps, schema_editor):
    """Keep the diagnostic irreversible without mutating catalog state."""


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012
        ("netbox_rpc", "0103_seed_ubuntu_26_samba_ad_dc_procedures")
    ]
    run_before = [  # noqa: RUF012
        ("netbox_rpc", "0103_normalize_protected_publication_provenance")
    ]
    operations = [migrations.RunPython(report, noop)]  # noqa: RUF012
