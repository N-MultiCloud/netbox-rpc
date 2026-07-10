"""Read or toggle the netbox-rpc opt-in settings singleton.

Host-side operator path for the same ``RpcPluginSettings`` the UI and the
``/api/plugins/rpc/settings/`` REST endpoint expose. netbox-rpc is standalone:
this command only manages netbox-rpc's own config and never touches Proxbox or
the NMS stack.

Usage:
    python manage.py rpc_settings --show
    python manage.py rpc_settings --enable
    python manage.py rpc_settings --disable
    python manage.py rpc_settings --enable --backend "netbox-rpc-backend"
    python manage.py rpc_settings --clear-backend
    python manage.py rpc_settings --enable --dry-run

``--backend`` resolves an ``RPCBackend`` by primary key (integer) or by name.
``--dry-run`` reports the intended state without writing. With no action flag the
command behaves like ``--show``.

Exit codes:
    0  completed
    non-zero  bad argument (e.g. unknown backend) or unexpected error
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Show or toggle the netbox-rpc opt-in settings singleton (enabled/backend)."

    def add_arguments(self, parser: ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--enable",
            action="store_true",
            help="Set the global RPC integration enabled flag to True.",
        )
        group.add_argument(
            "--disable",
            action="store_true",
            help="Set the global RPC integration enabled flag to False.",
        )
        parser.add_argument(
            "--backend",
            metavar="NAME_OR_ID",
            help="Select the RPCBackend used by the integration (name or primary key).",
        )
        parser.add_argument(
            "--clear-backend",
            action="store_true",
            help="Clear the selected RPCBackend (fall back to the default resolver).",
        )
        parser.add_argument(
            "--show",
            action="store_true",
            help="Print the current settings and exit (implied when no action is given).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report the intended change without writing.",
        )

    def _resolve_backend(self, value: str) -> Any:
        from netbox_rpc.models import RPCBackend

        token = value.strip()
        if token.isdigit():
            backend = RPCBackend.objects.filter(pk=int(token)).first()
        else:
            backend = RPCBackend.objects.filter(name=token).first()
        if backend is None:
            raise CommandError(f"No RPCBackend matches {value!r} (by name or id).")
        return backend

    def _report(self, settings_obj: Any) -> None:
        backend = settings_obj.backend
        self.stdout.write("netbox-rpc settings:")
        self.stdout.write(f"  enabled: {bool(settings_obj.enabled)}")
        if backend is not None:
            self.stdout.write(f"  backend: {backend} (id={backend.pk})")
            self.stdout.write(f"  backend_url: {backend.backend_url or '(unset)'}")
        else:
            self.stdout.write("  backend: (none — default resolver)")

    def handle(self, *args: object, **options: Any) -> None:
        from netbox_rpc.models import RpcPluginSettings

        settings_obj = RpcPluginSettings.get_solo()

        enable = options.get("enable")
        disable = options.get("disable")
        backend_value = options.get("backend")
        clear_backend = options.get("clear_backend")
        dry_run = options.get("dry_run")

        has_action = bool(enable or disable or backend_value or clear_backend)
        if not has_action or options.get("show"):
            self._report(settings_obj)
            if not has_action:
                return

        changes: list[str] = []
        if enable and not settings_obj.enabled:
            settings_obj.enabled = True
            changes.append("enabled -> True")
        elif disable and settings_obj.enabled:
            settings_obj.enabled = False
            changes.append("enabled -> False")

        if clear_backend and settings_obj.backend_id is not None:
            settings_obj.backend = None
            changes.append("backend -> (none)")
        elif backend_value:
            backend = self._resolve_backend(backend_value)
            if settings_obj.backend_id != backend.pk:
                settings_obj.backend = backend
                changes.append(f"backend -> {backend} (id={backend.pk})")

        if not changes:
            self.stdout.write(self.style.SUCCESS("No changes needed."))
            self._report(settings_obj)
            return

        if dry_run:
            self.stdout.write("Dry run — would apply:")
            for change in changes:
                self.stdout.write(f"  {change}")
            return

        settings_obj.full_clean()
        settings_obj.save()
        self.stdout.write(self.style.SUCCESS("Applied:"))
        for change in changes:
            self.stdout.write(f"  {change}")
        self._report(settings_obj)
