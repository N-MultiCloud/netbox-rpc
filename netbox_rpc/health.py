"""Best-effort reachability probe for the configured netbox-rpc backend.

Shared by the landing page and the Settings "Test connection" action. Issues a
single, fixed ``GET {backend_url}/status/ping`` — never caller-controlled host
or shell input — and always returns a structured result instead of raising.
"""

from __future__ import annotations

import time
from typing import Any

import requests

# Liveness route exposed by the netbox-rpc-backend service.
PING_PATH = "/status/ping"


def probe_backend(target: Any, *, timeout: float = 5.0) -> dict[str, Any]:
    """Probe a ``backends.BackendTarget`` for reachability.

    Args:
        target: a ``netbox_rpc.backends.BackendTarget`` (``url`` / ``headers`` /
            ``verify_ssl``) or ``None`` when no backend is configured.
        timeout: request timeout in seconds.

    Returns:
        ``{"ok": bool, "latency_ms": int | None, "error": str | None,
        "url": str}`` — never raises.
    """
    base = str(getattr(target, "url", "") or "").rstrip("/") if target is not None else ""
    if not base:
        return {
            "ok": False,
            "latency_ms": None,
            "error": "No backend configured",
            "url": "",
        }

    url = f"{base}{PING_PATH}"
    headers = dict(getattr(target, "headers", {}) or {})
    verify = bool(getattr(target, "verify_ssl", True))

    try:
        started = time.monotonic()
        response = requests.get(url, headers=headers, verify=verify, timeout=timeout)
        latency_ms = round((time.monotonic() - started) * 1000)
        if response.status_code == 200:
            try:
                ok = response.json().get("status") == "ok"
            except (ValueError, AttributeError):
                # 200 with a non-JSON / non-dict body still means it is serving.
                ok = True
            return {
                "ok": bool(ok),
                "latency_ms": latency_ms,
                "error": None if ok else "Backend reported a non-ok status",
                "url": base,
            }
        return {
            "ok": False,
            "latency_ms": latency_ms,
            "error": f"HTTP {response.status_code}",
            "url": base,
        }
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "latency_ms": None, "error": str(exc), "url": base}
    except Exception as exc:  # noqa: BLE001 - probe must never raise
        return {"ok": False, "latency_ms": None, "error": str(exc), "url": base}
