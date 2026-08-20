from __future__ import annotations

import base64
import hashlib
import importlib
import sys
import types
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from jsonschema import validate


PROCEDURE_ID = "service.gitea.production.upgrade_1_27_1"
_HOST_ALGORITHM = "ssh-ed25519"
_HOST_KEY_BLOB = (
    len(_HOST_ALGORITHM).to_bytes(4, "big")
    + _HOST_ALGORITHM.encode("ascii")
    + (32).to_bytes(4, "big")
    + (b"x" * 32)
)
KNOWN_HOSTS_ENTRY = (
    "10.0.30.96 ssh-ed25519 "
    + base64.b64encode(_HOST_KEY_BLOB).decode("ascii")
)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_gitea_upgrade_normalizer_emits_exact_backend_contract(jobs_module) -> None:
    from netbox_rpc import gitea_upgrade_contract as contract

    normalized = jobs_module.normalize_execution_params(_execution({}))
    assert normalized == {
        "target": "Gitea",
        "target_object": {
            "content_type": "virtualization.virtualmachine",
            "object_id": 170,
        },
        "vmid": 222,
        "cluster_id": 6,
        "node": "pve03",
        "ipv4": "10.0.30.96",
        "expected_source_version": "1.26.2",
        "target_version": "1.27.1",
        "artifact_sha256": contract.ARTIFACT_SHA256,
        "ssh_service_id": 901,
        "ssh_service_revision": "2026-08-17T12:00:00Z",
        "ssh_identity_id": 902,
        "ssh_identity_revision": "2026-08-17T11:00:00Z",
        "ssh_principal": "gitea-admin",
        "ssh_method": "key",
        "ssh_host": "10.0.30.96",
        "ssh_port": 22,
        "ssh_known_hosts_sha256": hashlib.sha256(
            KNOWN_HOSTS_ENTRY.encode("utf-8")
        ).hexdigest(),
        "ssh_policy_ref": (
            "target-owned-ssh:virtualization.virtualmachine:170"
        ),
        "command_fingerprint": {
            "handler_id": PROCEDURE_ID,
            "target": "Gitea",
            "assigned_object_id": 170,
            "target_object_sha256": contract.TARGET_OBJECT_SHA256,
            "vmid": 222,
            "cluster_id": 6,
            "node": "pve03",
            "ipv4": "10.0.30.96",
            "expected_source_version": "1.26.2",
            "target_version": "1.27.1",
            "artifact_sha256": contract.ARTIFACT_SHA256,
            "ssh_service_id": 901,
            "ssh_service_revision": "2026-08-17T12:00:00Z",
            "ssh_identity_id": 902,
            "ssh_identity_revision": "2026-08-17T11:00:00Z",
            "ssh_principal": "gitea-admin",
            "ssh_method": "key",
            "ssh_host": "10.0.30.96",
            "ssh_port": 22,
            "ssh_known_hosts_sha256": hashlib.sha256(
                KNOWN_HOSTS_ENTRY.encode("utf-8")
            ).hexdigest(),
            "ssh_policy_ref": (
                "target-owned-ssh:virtualization.virtualmachine:170"
            ),
        },
    }
    validate(normalized, contract.NORMALIZED_PARAMS_SCHEMA)
    validate(
        normalized["command_fingerprint"],
        contract.COMMAND_FINGERPRINT_SCHEMA,
    )


@pytest.mark.parametrize(
    "params",
    [
        {"target": "Gitea"},
        {"rpc_ssh_host": "10.0.30.96"},
        {"rpc_ssh_credential_pk": 1},
        {"artifact_sha256": "caller-controlled"},
        {"ssh_policy_ref": "caller-controlled"},
        {"target_version": "1.27.1"},
        [],
        "command=upgrade",
    ],
)
def test_gitea_upgrade_normalizer_rejects_all_caller_params(
    jobs_module,
    params: object,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution(params))
    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("assigned_object_id", 171),
        ("target_display", "gitea"),
        ("target_model_label", "dcim.device"),
        ("name", "Other"),
        ("cluster_id", 7),
        ("cluster_name", "other-cluster"),
        ("device_id", 28),
        ("device_name", "pve04"),
        ("vmid", 223),
        ("ipv4", "10.0.30.97/24"),
        ("status", "offline"),
    ],
)
def test_gitea_upgrade_normalizer_rejects_target_drift(
    jobs_module,
    field: str,
    value: object,
) -> None:
    execution = _execution({})
    target = execution.assigned_object
    if field == "assigned_object_id":
        execution.assigned_object_id = value
    elif field == "target_display":
        execution.target_display = value
    elif field == "target_model_label":
        execution.target_model_label = value
        execution.assigned_object_type = SimpleNamespace(app_label="dcim", model="device")
    elif field == "name":
        target.name = value
    elif field == "cluster_id":
        target.cluster_id = value
    elif field == "cluster_name":
        target.cluster.name = value
    elif field == "device_id":
        target.device_id = value
    elif field == "device_name":
        target.device.name = value
    elif field == "vmid":
        target.custom_field_data["proxmox_vm_id"] = value
    elif field == "ipv4":
        target.primary_ip4.address = value
    elif field == "status":
        target.status = value

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)
    assert exc_info.value.code == "RPC_TARGET_INVALID"


def test_gitea_upgrade_requires_production_tag_when_orm_tags_are_available(
    jobs_module,
) -> None:
    execution = _execution({})
    execution.assigned_object.tags = SimpleNamespace(
        values_list=lambda *args, **kwargs: ["staging"]
    )
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)
    assert exc_info.value.code == "RPC_TARGET_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", False),
        ("management_host", SimpleNamespace(address="10.0.30.97/24")),
        ("port", None),
        ("ssh_strict_host_key_checking", False),
        ("ssh_known_hosts_entry", ""),
        ("credential", None),
    ],
)
def test_gitea_upgrade_rejects_ssh_service_drift(
    jobs_module,
    field: str,
    value: object,
) -> None:
    service = sys.modules["netbox_network.models"].DeviceService.objects.service
    setattr(service, field, value)
    if field == "credential":
        service.credential_id = None
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution({}))
    assert exc_info.value.code == "RPC_TARGET_INVALID"


@pytest.mark.parametrize(
    "entry",
    [
        "@cert-authority 10.0.30.96 ssh-ed25519 AAAA",
        "* ssh-ed25519 AAAA",
        "10.0.30.96,git.nmulti.cloud ssh-ed25519 AAAA",
        "|1|hashed|host ssh-ed25519 AAAA",
        "git.nmulti.cloud ssh-ed25519 AAAA",
        "[10.0.30.96]:22 ssh-ed25519 AAAA",
        "10.0.30.96 ssh-rsa AAAA",
        "10.0.30.96 ssh-ed25519 not-base64!",
        f"10.0.30.96 ssh-ed25519 {'A' * 257}",
        f"{KNOWN_HOSTS_ENTRY}=",
        (
            "10.0.30.96 ssh-ed25519 "
            + base64.b64encode(
                (7).to_bytes(4, "big")
                + b"ssh-rsa"
                + (32).to_bytes(4, "big")
                + (b"x" * 32)
            ).decode("ascii")
        ),
        (
            "10.0.30.96 ssh-ed25519 "
            + base64.b64encode(
                len(_HOST_ALGORITHM).to_bytes(4, "big")
                + _HOST_ALGORITHM.encode("ascii")
                + (31).to_bytes(4, "big")
                + (b"x" * 31)
            ).decode("ascii")
        ),
        f"{KNOWN_HOSTS_ENTRY} comment",
    ],
)
def test_gitea_upgrade_rejects_non_exact_known_hosts_records(
    jobs_module,
    entry: str,
) -> None:
    service = sys.modules["netbox_network.models"].DeviceService.objects.service
    service.ssh_known_hosts_entry = entry
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution({}))
    assert exc_info.value.code == "RPC_TARGET_INVALID"


def test_gitea_read_timeout_returns_closed_indeterminate_result(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _execution({})
    execution.pk = 1700
    execution.procedure.timeout_seconds = 1800
    monkeypatch.setattr(
        jobs_module.requests,
        "post",
        MagicMock(side_effect=jobs_module.requests.exceptions.ReadTimeout("timed out")),
    )
    response = jobs_module._call_backend(_backend_target(jobs_module), execution)
    assert response == _closed_transport_response(stage="indeterminate")


def test_gitea_connect_timeout_returns_closed_pre_dispatch_result(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _execution({})
    execution.pk = 1701
    execution.procedure.timeout_seconds = 1800
    monkeypatch.setattr(
        jobs_module.requests,
        "post",
        MagicMock(
            side_effect=jobs_module.requests.exceptions.ConnectTimeout("not sent")
        ),
    )
    response = jobs_module._call_backend(_backend_target(jobs_module), execution)
    assert response == _closed_transport_response(stage="execute")


def test_gitea_http_error_preserves_valid_closed_result_and_maps_ambiguity(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _execution({})
    execution.pk = 1702
    execution.procedure.timeout_seconds = 1800
    closed = _closed_transport_response(stage="rolled_back")
    response = SimpleNamespace(
        status_code=500,
        json=MagicMock(return_value=_wire_response(closed)),
    )
    monkeypatch.setattr(jobs_module.requests, "post", MagicMock(return_value=response))
    assert jobs_module._call_backend(_backend_target(jobs_module), execution) == closed

    response.json.return_value = {"detail": "unknown backend failure"}
    assert jobs_module._call_backend(
        _backend_target(jobs_module), execution
    ) == _closed_transport_response(stage="indeterminate")

    response.status_code = 200
    response.json.return_value = ["not", "an", "envelope"]
    assert jobs_module._call_backend(
        _backend_target(jobs_module), execution
    ) == _closed_transport_response(stage="indeterminate")

    response.json.side_effect = ValueError("not json")
    assert jobs_module._call_backend(
        _backend_target(jobs_module), execution
    ) == _closed_transport_response(stage="indeterminate")


def test_gitea_conflicting_http_success_and_non_object_2xx_are_indeterminate(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _execution({})
    execution.pk = 1703
    success = {
        "ok": True,
        "result": {
            "ok": True,
            "procedure": PROCEDURE_ID,
            "target": "Gitea",
            "changed": True,
            "healthy": True,
            "stage": "complete",
        },
    }
    response = SimpleNamespace(
        status_code=500,
        json=MagicMock(return_value=_wire_response(success)),
    )
    monkeypatch.setattr(jobs_module.requests, "post", MagicMock(return_value=response))
    assert jobs_module._call_backend(
        _backend_target(jobs_module), execution
    ) == _closed_transport_response(stage="indeterminate")


@pytest.mark.parametrize("status_code", [301, 302, 307, 308])
def test_gitea_redirect_is_not_followed_or_parsed(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    execution = _execution({})
    execution.pk = 1704
    response = SimpleNamespace(
        status_code=status_code,
        json=MagicMock(side_effect=AssertionError("redirect body must not be parsed")),
    )
    post = MagicMock(return_value=response)
    monkeypatch.setattr(jobs_module.requests, "post", post)
    lease = SimpleNamespace(to_body=lambda: {"opaque": "signed-lease"})

    assert jobs_module._call_backend(
        _backend_target(jobs_module), execution, lease=lease
    ) == _closed_transport_response(stage="indeterminate")
    assert post.call_count == 1
    assert post.call_args.kwargs["allow_redirects"] is False
    assert post.call_args.kwargs["json"] == {
        "dispatch_lease": {"opaque": "signed-lease"}
    }
    response.json.assert_not_called()


def test_gitea_backend_diagnostics_are_discarded_before_persistence(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _execution({})
    execution.pk = 1705
    closed = _closed_transport_response(stage="rolled_back")
    opaque = "m8QvL2pR7xZ1nT6c"
    response = SimpleNamespace(
        status_code=500,
        json=MagicMock(
            return_value=_wire_response(
                closed,
                error_code=opaque,
                error_message=opaque,
            )
        ),
    )
    monkeypatch.setattr(jobs_module.requests, "post", MagicMock(return_value=response))

    projected = jobs_module._call_backend(_backend_target(jobs_module), execution)
    assert projected == closed
    assert opaque not in repr(projected)


def _execution(params: object):
    target = SimpleNamespace(
        pk=170,
        name="Gitea",
        cluster_id=6,
        cluster=SimpleNamespace(pk=6, name="PVE-CLUSTER-02"),
        device_id=27,
        device=SimpleNamespace(pk=27, name="pve03"),
        custom_field_data={"proxmox_vm_id": 222},
        primary_ip4=SimpleNamespace(address="10.0.30.96/24"),
        status="active",
    )
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name=PROCEDURE_ID,
            handler_id=PROCEDURE_ID,
            timeout_seconds=1800,
        ),
        params=params,
        target_display="Gitea",
        target_model_label="virtualization.virtualmachine",
        assigned_object_type=SimpleNamespace(
            pk=99,
            app_label="virtualization",
            model="virtualmachine",
        ),
        assigned_object_type_id=99,
        assigned_object_id=170,
        assigned_object=target,
    )


def _backend_target(jobs_module):
    return jobs_module.BackendTarget(
        url="https://backend.example",
        headers={},
        verify_ssl=True,
    )


def _closed_transport_response(*, stage: str) -> dict[str, object]:
    if stage == "rolled_back":
        changed, healthy = False, True
    elif stage == "execute":
        changed, healthy = False, False
    else:
        changed, healthy = None, None
    return {
        "ok": False,
        "result": {
            "ok": False,
            "procedure": PROCEDURE_ID,
            "target": "Gitea",
            "changed": changed,
            "healthy": healthy,
            "stage": stage,
        },
    }


def _wire_response(
    projected: dict[str, object],
    *,
    error_code: str = "RPC_HANDLER_RESULT_FAILED",
    error_message: str = "Production Gitea upgrade did not complete successfully.",
) -> dict[str, object]:
    if projected["ok"] is True:
        error_code = ""
        error_message = ""
    return {
        **projected,
        "events": [],
        "error_code": error_code,
        "error_message": error_message,
    }


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    plugins = types.ModuleType("netbox.plugins")
    plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    constants = types.ModuleType("netbox.constants")
    constants.RQ_QUEUE_DEFAULT = "default"
    jobs = types.ModuleType("netbox.jobs")
    jobs.JobRunner = type("JobRunner", (), {"enqueue": classmethod(lambda cls, *a, **k: None)})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    timezone = types.ModuleType("django.utils.timezone")
    timezone.now = MagicMock(return_value=None)
    django_utils.timezone = timezone
    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCExecution = type(
        "RPCExecution",
        (),
        {"TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY": "_timeout_seconds_snapshot"},
    )
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})
    requests = types.ModuleType("requests")
    requests.post = MagicMock()
    requests.get = MagicMock()
    exceptions = types.ModuleType("requests.exceptions")
    exceptions.RequestException = type("RequestException", (Exception,), {})
    exceptions.ConnectionError = type("ConnectionError", (exceptions.RequestException,), {})
    exceptions.ConnectTimeout = type("ConnectTimeout", (exceptions.RequestException,), {})
    exceptions.ReadTimeout = type("ReadTimeout", (exceptions.RequestException,), {})
    requests.exceptions = exceptions
    netbox_network = types.ModuleType("netbox_network")
    network_models = types.ModuleType("netbox_network.models")
    network_models.DeviceService = type(
        "DeviceService",
        (),
        {
            "SERVICE_SSH": "ssh",
            "objects": _FakeDeviceServiceManager(),
        },
    )
    for name, module in {
        "netbox": netbox,
        "netbox.plugins": plugins,
        "netbox.constants": constants,
        "netbox.jobs": jobs,
        "django": django,
        "django.db": django_db,
        "django.utils": django_utils,
        "django.utils.timezone": timezone,
        "netbox_rpc.models": models,
        "requests": requests,
        "requests.exceptions": exceptions,
        "netbox_network": netbox_network,
        "netbox_network.models": network_models,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)


class _FakeDeviceServiceQuery(list):
    def select_related(self, *args):
        return self


class _FakeDeviceServiceManager:
    def __init__(self):
        identity = SimpleNamespace(
            pk=902,
            last_updated=datetime(2026, 8, 17, 11, tzinfo=timezone.utc),
            username="gitea-admin",
            auth_method="key",
            storage_backend="local",
            ssh_private_key_encrypted="encrypted-not-returned",
        )
        self.service = SimpleNamespace(
            pk=901,
            last_updated=datetime(2026, 8, 17, 12, tzinfo=timezone.utc),
            assigned_object_type_id=99,
            assigned_object_id=170,
            service_type="ssh",
            enabled=True,
            management_host=SimpleNamespace(address="10.0.30.96/24"),
            port=22,
            credential=identity,
            credential_id=902,
            ssh_known_hosts_entry=KNOWN_HOSTS_ENTRY,
            ssh_strict_host_key_checking=True,
        )

    def filter(self, **kwargs):
        service = self.service
        matches = all(getattr(service, key) == value for key, value in kwargs.items())
        return _FakeDeviceServiceQuery([service] if matches else [])
