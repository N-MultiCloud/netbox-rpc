from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Callable


@dataclass(frozen=True)
class BackendTarget:
    url: str
    headers: dict[str, str]
    verify_ssl: bool


def resolve_backend(pk: object) -> BackendTarget | None:
    resolver_path = _plugin_setting("backend_resolver")
    if resolver_path:
        resolver = _import_dotted_path(str(resolver_path))
        return resolver(pk)

    nms_backend = _resolve_nms_backend(pk)
    if nms_backend is not _NMS_MISSING:
        if nms_backend is None:
            return None
        return _adapt_backend(nms_backend)

    return _resolve_local_backend(pk)


def _plugin_setting(key: str, default: object | None = None) -> object | None:
    try:
        from django.conf import settings
    except ImportError:
        return default

    try:
        plugin_config = getattr(settings, "PLUGINS_CONFIG", {}) or {}
    except Exception:
        return default
    return (plugin_config.get("netbox_rpc") or {}).get(key, default)


def _import_dotted_path(path: str) -> Callable[[object], BackendTarget | None]:
    module_path, separator, attribute = path.rpartition(".")
    if not separator:
        raise ImportError(f"{path!r} is not a dotted import path.")
    module = import_module(module_path)
    resolver = getattr(module, attribute)
    if not callable(resolver):
        raise TypeError(f"{path!r} is not callable.")
    return resolver


_NMS_MISSING = object()


def _resolve_nms_backend(pk: object) -> Any:
    try:
        backend_module = import_module("netbox_nms.backend")
    except ImportError:
        return _NMS_MISSING
    return backend_module.get_backend(pk)


def _resolve_local_backend(pk: object) -> BackendTarget | None:
    if pk in (None, ""):
        return None
    try:
        backend_pk = int(pk)
    except (TypeError, ValueError):
        return None

    from .models import RPCBackend

    backend = RPCBackend.objects.filter(pk=backend_pk).first()
    if backend is None:
        return None
    return _adapt_backend(backend)


def _adapt_backend(backend: object) -> BackendTarget:
    return BackendTarget(
        url=str(getattr(backend, "backend_url")),
        headers=dict(backend.get_auth_headers()),
        verify_ssl=bool(getattr(backend, "verify_ssl")),
    )


def local_rpcbackend_resolver(pk: object) -> BackendTarget | None:
    """``backend_resolver`` that routes dispatch to a local ``RPCBackend``.

    Set ``PLUGINS_CONFIG["netbox_rpc"]["backend_resolver"] =
    "netbox_rpc.backends.local_rpcbackend_resolver"`` to send RPC executions to
    the ``netbox-rpc-backend`` service (configured as an ``RPCBackend`` row)
    instead of ``nms-backend`` — even when ``netbox-nms`` is installed. Uses the
    given ``pk``; when none is supplied it falls back to the single configured
    ``RPCBackend`` so a one-backend deployment needs no per-execution selection.
    """
    target = _resolve_local_backend(pk)
    if target is not None:
        return target

    from .models import RPCBackend

    rows = list(RPCBackend.objects.all()[:2])
    if len(rows) == 1:
        return _adapt_backend(rows[0])
    return None
