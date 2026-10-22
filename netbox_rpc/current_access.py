"""Reads of the requesting user that must not reuse NetBox's per-request caches.

NetBox caches object-permission grants on the user instance. A grant that changes
after the request has started is therefore invisible to that instance.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model


def reload_requesting_user(user: object) -> object | None:
    """Return the requesting user read from the database, or None.

    Call it after the procedure row is locked, so the approve decision uses the
    grants committed when the write happens.
    """
    pk = getattr(user, "pk", None)
    if pk is None:
        return None
    model = get_user_model()
    try:
        return model.objects.get(pk=pk)
    except model.DoesNotExist:
        return None
