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


APPROVAL_SCOPE_GAIN_MESSAGE = (
    "This change would add RPC procedures to your netbox_rpc.approve_rpcprocedure "
    "scope, which only a user who already holds that permission on them may do."
)


# Key of the PostgreSQL transaction-level advisory lock that serializes procedure edits.
PROCEDURE_SCOPE_LOCK_KEY = 0x4E425250


def lock_procedure_scope() -> None:
    """Serialize procedure edits until the current transaction ends.

    An approve constraint can follow a relation between procedures, so two concurrent
    edits to different procedures could each see no scope gain and together grant
    one. Every edit takes this lock first, inside its transaction and before the row
    lock, so the approve-scope reads before and after one edit cannot interleave with
    another edit. PostgreSQL is NetBox's only database; other backends skip the lock.
    """
    from django.db import connection

    if connection.vendor != "postgresql":
        return
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [PROCEDURE_SCOPE_LOCK_KEY])


def approvable_procedure_pks(user: object) -> frozenset[object]:
    """Return the primary keys of the procedures that ``user`` may approve.

    Read with NetBox's own constraint evaluation, so a constraint over any field or
    relation is honoured. Call it with a freshly reloaded user.
    """
    if user is None:
        return frozenset()
    from .models import RPCProcedure

    return frozenset(
        RPCProcedure.objects.restrict(user, "approve").values_list("pk", flat=True)
    )


def refuse_approval_scope_gain(
    user: object, approvable_before: frozenset[object], error: type[Exception]
) -> None:
    """Raise ``error`` when a write added any procedure to ``user``'s approve scope.

    Object-permission constraints can match any field or relation, so an edit that
    is allowed on its own can bring this or another procedure into the editor's
    approve scope. Take ``approvable_before`` under the row lock before the write and
    call this after the write, inside the write's transaction: NetBox evaluates the
    constraints against the written rows, and the raised error rolls the write back.
    """
    if approvable_procedure_pks(reload_requesting_user(user)) - approvable_before:
        raise error(APPROVAL_SCOPE_GAIN_MESSAGE)
