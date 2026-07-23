"""Shared helpers for the netbox-rpc integration tests."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType

from netbox_rpc import models


def make_user(username: str = "rpc-tester", *, superuser: bool = True):
    User = get_user_model()
    user, _ = User.objects.get_or_create(username=username)
    if superuser and not user.is_superuser:
        user.is_superuser = True
        user.is_staff = True
        user.save()
    return user


def make_procedure(name: str = "os.linux.test.echo", **kwargs) -> models.RPCProcedure:
    defaults = {"handler_id": name}
    defaults.update(kwargs)
    proc, _ = models.RPCProcedure.objects.get_or_create(name=name, defaults=defaults)
    return proc


def device_ct() -> ContentType:
    return ContentType.objects.get(app_label="dcim", model="device")


def make_device(name: str = "rpc-test-device"):
    """Build the minimal real NetBox device stack.

    The ORM ``create`` path accepts a bare ``assigned_object_id`` without
    checking existence, but the REST serializer resolves the generic relation,
    so API-level tests need a device that actually exists.
    """
    from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

    site, _ = Site.objects.get_or_create(name="RPC Test Site", slug="rpc-test-site")
    mfr, _ = Manufacturer.objects.get_or_create(
        name="RPC Test Mfr", slug="rpc-test-mfr"
    )
    dtype, _ = DeviceType.objects.get_or_create(
        manufacturer=mfr, model="RPC Test Model", slug="rpc-test-model"
    )
    role, _ = DeviceRole.objects.get_or_create(
        name="RPC Test Role", slug="rpc-test-role"
    )
    device, _ = Device.objects.get_or_create(
        name=name, defaults={"device_type": dtype, "role": role, "site": site}
    )
    return device


def make_execution(*, procedure=None, user=None) -> models.RPCExecution:
    return models.RPCExecution.objects.create(
        procedure=procedure or make_procedure(),
        assigned_object_type=device_ct(),
        assigned_object_id=1,
        requested_by=user or make_user(),
    )


def event_names(execution) -> list[str]:
    return list(execution.events.order_by("sequence").values_list("event", flat=True))


def make_intent(
    name: str = "intent.test.stack",
    *,
    execution_mode: str | None = None,
    procedures=None,
) -> models.RPCIntent:
    defaults = {}
    if execution_mode:
        defaults["execution_mode"] = execution_mode
    intent, _ = models.RPCIntent.objects.get_or_create(name=name, defaults=defaults)
    if procedures:
        models.RPCIntentProcedure.objects.filter(intent=intent).delete()
        models.RPCIntentProcedure.objects.bulk_create(
            [
                models.RPCIntentProcedure(intent=intent, procedure=proc, sequence=index)
                for index, proc in enumerate(procedures, start=1)
            ]
        )
    return intent


def make_backend(
    name: str = "rpc-test-backend",
    base_url: str = "http://rpc-backend.test:16005",
) -> "models.RPCBackend":
    backend, _ = models.RPCBackend.objects.get_or_create(
        name=name, defaults={"base_url": base_url}
    )
    return backend


def enable_rpc_integration(*, backend=None) -> "models.RpcPluginSettings":
    """Opt the netbox-rpc integration in for tests that exercise create/run.

    #166 makes ``RpcPluginSettings.enabled`` + the selected backend
    authoritative, so any test that creates or dispatches an execution must
    first opt in (the singleton defaults to ``enabled=False``).
    """
    settings_row = models.RpcPluginSettings.get_solo()
    settings_row.enabled = True
    settings_row.backend = backend or make_backend()
    settings_row.save()
    return settings_row
