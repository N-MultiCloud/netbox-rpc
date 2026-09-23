"""Remap legacy netbox-nms DeviceCredential references to their netbox-openbao
CredentialAssignment equivalents, for every allowlist row that still only
carries ``ssh_credential_override``.

netbox-openbao's ``openbao_import_nms_credentials`` command copies
``netbox_nms.DeviceCredential`` rows into ``netbox_openbao.Credential`` and
tags each import with ``import_source="netbox_nms.DeviceCredential:<pk>"``
(unique). This command uses that marker, via ``apps.get_model`` guarded by
``apps.is_installed`` (never a hard import), to resolve the migrated
``Credential``, then finds or -- when the target is unambiguous -- creates an
**enabled, purpose=login** ``netbox_openbao.CredentialAssignment`` for it, and
stores the assignment's pk (not the raw credential pk) in
``openbao_assignment_id`` on ``RPCLinuxServiceAllowlist`` and
``RPCNetBoxPluginAllowlist`` rows.

**Why "creates" only sometimes applies here.** Unlike a single object (e.g. a
K8sCluster), an ``RPCLinuxServiceAllowlist``/``RPCNetBoxPluginAllowlist`` row
is not bound to one target device -- ``target_models`` names the *types* of
object a service may run on (``dcim.device``, ``virtualization.virtualmachine``,
...), and the same row can dispatch against many different devices. The
dispatch-time normalizer (``domain/normalization.resolve_openbao_assignment_reference``)
enforces that the assignment used at execution time is bound to that
execution's *actual* target device -- so a single "the target" does not exist
at the allowlist-row level to create an assignment against. This command
therefore:

- **Looks up** an existing enabled ``purpose="login"`` assignment for the
  migrated credential. Exactly one match is used. Zero or more than one match
  is reported and the row is left unchanged -- the operator must create or
  disambiguate the assignment for the specific device(s) this row will
  actually dispatch to, since this command cannot infer that device.
- **Creates** one only in the disambiguated case where the migrated
  credential currently has exactly one existing ``CredentialAssignment``
  regardless of purpose or enabled state, letting the command adopt that
  assignment's ``assigned_object`` and create the missing ``purpose="login"``
  row against the *same* object -- i.e. "the same place this credential is
  already known to apply", never a guess.

The legacy ``ssh_credential_override`` value is NEVER cleared or overwritten:
this command only ever sets ``openbao_assignment_id`` when it is currently
unset and an unambiguous outcome exists.

Usage:
    python manage.py rpc_remap_credentials_to_openbao
    python manage.py rpc_remap_credentials_to_openbao --dry-run

Exit codes:
    0  completed (including zero matches)
    1  netbox-openbao is not installed
"""

from __future__ import annotations

from argparse import ArgumentParser
from dataclasses import dataclass, field
from typing import Any

from django.apps import apps as django_apps
from django.core.management.base import BaseCommand, CommandError

_IMPORT_SOURCE_PREFIX = "netbox_nms.DeviceCredential"
_LOGIN_PURPOSE = "login"


@dataclass(frozen=True)
class _RemapOutcome:
    updated: int = 0
    already_set: int = 0
    no_legacy_value: int = 0
    unmatched_credential: list[str] = field(default_factory=list)
    ambiguous_credential: list[str] = field(default_factory=list)
    needs_manual_assignment: list[str] = field(default_factory=list)

    def merged(self, other: "_RemapOutcome") -> "_RemapOutcome":
        return _RemapOutcome(
            updated=self.updated + other.updated,
            already_set=self.already_set + other.already_set,
            no_legacy_value=self.no_legacy_value + other.no_legacy_value,
            unmatched_credential=self.unmatched_credential + other.unmatched_credential,
            ambiguous_credential=self.ambiguous_credential + other.ambiguous_credential,
            needs_manual_assignment=(
                self.needs_manual_assignment + other.needs_manual_assignment
            ),
        )


def _require_openbao_models() -> tuple[Any, Any]:
    if not django_apps.is_installed("netbox_openbao"):
        raise CommandError(
            "netbox-openbao is not installed; there is nothing to remap to."
        )
    return (
        django_apps.get_model("netbox_openbao", "Credential"),
        django_apps.get_model("netbox_openbao", "CredentialAssignment"),
    )


def _resolve_credential_pk(credential_model: Any, legacy_pk: int) -> int | None:
    """Resolve one legacy DeviceCredential pk to its openbao Credential pk.

    Returns None on zero or more-than-one match; the caller distinguishes
    those two outcomes for reporting.
    """
    marker = f"{_IMPORT_SOURCE_PREFIX}:{legacy_pk}"
    matches = list(
        credential_model.objects.filter(import_source=marker).values_list(
            "pk", flat=True
        )[:2]
    )
    return matches[0] if len(matches) == 1 else None


def _resolve_or_create_assignment(
    assignment_model: Any, credential_pk: int, *, dry_run: bool
) -> int | None:
    """Find (or, when unambiguous, create) a purpose=login assignment.

    Returns the assignment pk, or None when the outcome is ambiguous or the
    target object cannot be inferred (see module docstring).
    """
    existing_login = list(
        assignment_model.objects.filter(
            credential_id=credential_pk, purpose=_LOGIN_PURPOSE, enabled=True
        ).values_list("pk", flat=True)[:2]
    )
    if len(existing_login) == 1:
        return existing_login[0]
    if len(existing_login) > 1:
        return None  # ambiguous -- caller reports as needs_manual_assignment

    # No login-purpose assignment yet. Only create one when the credential
    # has exactly one assignment of any purpose to adopt its target from --
    # otherwise there is no way to infer which object this row's credential
    # should be bound to.
    any_assignments = list(
        assignment_model.objects.filter(credential_id=credential_pk).values_list(
            "pk", "assigned_object_type_id", "assigned_object_id"
        )[:2]
    )
    if len(any_assignments) != 1:
        return None

    _, object_type_id, object_id = any_assignments[0]
    if dry_run:
        return -1  # sentinel: "would create", never persisted
    created = assignment_model(
        credential_id=credential_pk,
        assigned_object_type_id=object_type_id,
        assigned_object_id=object_id,
        purpose=_LOGIN_PURPOSE,
        enabled=True,
        description="Created by rpc_remap_credentials_to_openbao.",
    )
    # full_clean() applies netbox-openbao's own assignment validation
    # (assignable-model allowlist, uniqueness) that objects.create() skips.
    created.full_clean()
    created.save()
    return created.pk


def _remap_row(
    row: Any, credential_model: Any, assignment_model: Any, *, dry_run: bool
) -> _RemapOutcome:
    if row.openbao_assignment_id is not None:
        return _RemapOutcome(already_set=1)
    legacy_pk = row.ssh_credential_override
    if legacy_pk is None:
        return _RemapOutcome(no_legacy_value=1)

    label = f"{row._meta.model_name}:{row.pk} (legacy pk {legacy_pk})"
    credential_pk = _resolve_credential_pk(credential_model, legacy_pk)
    if credential_pk is None:
        return _RemapOutcome(unmatched_credential=[label])

    assignment_pk = _resolve_or_create_assignment(
        assignment_model, credential_pk, dry_run=dry_run
    )
    if assignment_pk is None:
        return _RemapOutcome(needs_manual_assignment=[label])

    if not dry_run:
        row.openbao_assignment_id = assignment_pk
        row.save(update_fields=["openbao_assignment_id"])
    return _RemapOutcome(updated=1)


class Command(BaseCommand):
    help = (
        "Remap RPCLinuxServiceAllowlist/RPCNetBoxPluginAllowlist "
        "ssh_credential_override values to a netbox-openbao "
        "CredentialAssignment (openbao_assignment_id) via import_source."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report the intended remap without writing.",
        )

    def handle(self, *_args: Any, **options: Any) -> None:
        from netbox_rpc.models import RPCLinuxServiceAllowlist, RPCNetBoxPluginAllowlist

        dry_run = bool(options.get("dry_run"))
        credential_model, assignment_model = _require_openbao_models()

        totals = _RemapOutcome()
        for model in (RPCLinuxServiceAllowlist, RPCNetBoxPluginAllowlist):
            for row in model.objects.all().iterator():
                totals = totals.merged(
                    _remap_row(row, credential_model, assignment_model, dry_run=dry_run)
                )

        verb = "Would update" if dry_run else "Updated"
        self.stdout.write(f"{verb} {totals.updated} row(s).")
        self.stdout.write(f"Already had openbao_assignment_id: {totals.already_set}")
        self.stdout.write(
            f"No legacy ssh_credential_override: {totals.no_legacy_value}"
        )
        if totals.unmatched_credential:
            self.stdout.write(self.style.WARNING("No migrated credential found:"))
            for entry in totals.unmatched_credential:
                self.stdout.write(f"  {entry}")
        if totals.needs_manual_assignment:
            self.stdout.write(
                self.style.WARNING(
                    "Credential migrated but the target assignment is "
                    "ambiguous or unknown -- create/disambiguate manually:"
                )
            )
            for entry in totals.needs_manual_assignment:
                self.stdout.write(f"  {entry}")
