from __future__ import annotations

import base64
import hashlib
import http.server
import importlib
import json
import sys
import threading
import time
import types
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests as real_requests
from jsonschema import FormatChecker, validate


PROCEDURE_ID = "service.gitea.production.upgrade_1_27_1"
_HOST_ALGORITHM = "ssh-ed25519"
_HOST_KEY_BLOB = (
    len(_HOST_ALGORITHM).to_bytes(4, "big")
    + _HOST_ALGORITHM.encode("ascii")
    + (32).to_bytes(4, "big")
    + (b"x" * 32)
)
KNOWN_HOSTS_ENTRY = "10.0.30.96 ssh-ed25519 " + base64.b64encode(_HOST_KEY_BLOB).decode(
    "ascii"
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
        "ssh_policy_ref": ("target-owned-ssh:virtualization.virtualmachine:170"),
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
            "ssh_policy_ref": ("target-owned-ssh:virtualization.virtualmachine:170"),
        },
    }
    validate(
        normalized,
        contract.NORMALIZED_PARAMS_SCHEMA,
        format_checker=FormatChecker(),
    )
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
        execution.assigned_object_type = SimpleNamespace(
            app_label="dcim", model="device"
        )
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


def _runner_target() -> SimpleNamespace:
    return SimpleNamespace(
        pk=399,
        name="nmultifibra-ci-untrusted-01",
        cluster_id=8,
        cluster=SimpleNamespace(pk=8, name="CLUSTER01-DC01"),
        device_id=34,
        device=SimpleNamespace(pk=34, name="node01"),
        tenant_id=14,
        tenant=SimpleNamespace(pk=14, name="N-MultiFibra"),
        role_id=5,
        role=SimpleNamespace(pk=5, name="Virtual Machine (QEMU)"),
        vcpus=8,
        memory=16_384,
        disk=122_880,
        custom_field_data={"proxmox_vm_id": 10_040},
        primary_ip4=SimpleNamespace(address="10.0.30.199/24"),
        status="active",
    )


def _runner_registration_execution() -> SimpleNamespace:
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name="service.gitea.runner.register",
            handler_id="service.gitea.runner.register",
            timeout_seconds=360,
        ),
        params={"operation": "register", "scope": "nmulticloud-org"},
        target_display="nmultifibra-ci-untrusted-01",
        target_model_label="virtualization.virtualmachine",
        assigned_object_type=SimpleNamespace(
            pk=99,
            app_label="virtualization",
            model="virtualmachine",
        ),
        assigned_object_type_id=99,
        assigned_object_id=399,
        assigned_object=_runner_target(),
    )


def test_runner_normalizer_binds_two_targets_snapshots_and_fingerprint(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netbox_rpc import gitea_runner_contract as contract

    normalization = sys.modules["netbox_rpc.domain.normalization"]
    monkeypatch.setattr(normalization, "_GITEA_RUNNER_REGISTER_AVAILABLE", True)
    monkeypatch.setattr(
        normalization,
        "validate_gitea_upgrade_target",
        lambda *args, **kwargs: {
            "target": "Gitea",
            "target_object": contract.GITEA_TARGET_OBJECT,
            "ipv4": contract.GITEA_IPV4_ADDRESS,
        },
    )

    snapshots = {
        399: {
            "ssh_service_id": 401,
            "ssh_service_revision": "2026-08-26T12:00:00.000001Z",
            "ssh_identity_id": 501,
            "ssh_identity_revision": "2026-08-26T12:00:00.000002Z",
            "ssh_storage_backend": "local",
            "ssh_principal": "nms-runner-bootstrap",
            "ssh_method": "key",
            "ssh_host": "10.0.30.199",
            "ssh_port": 22,
            "ssh_known_hosts_sha256": "a" * 64,
            "ssh_policy_ref": contract.RUNNER_SSH_POLICY_REF,
        },
        170: {
            "ssh_service_id": 402,
            "ssh_service_revision": "2026-08-26T12:00:00.000003Z",
            "ssh_identity_id": 502,
            "ssh_identity_revision": "2026-08-26T12:00:00.000004Z",
            "ssh_storage_backend": "local",
            "ssh_principal": "nms-gitea-runner-control",
            "ssh_method": "key",
            "ssh_host": "10.0.30.96",
            "ssh_port": 22,
            "ssh_known_hosts_sha256": "b" * 64,
            "ssh_policy_ref": contract.GITEA_SSH_POLICY_REF,
        },
    }
    observed: list[tuple[int, str, str]] = []

    def resolve_snapshot(
        *,
        assigned_object_type_id: object,
        assigned_object_id: int,
        expected_host: str,
        policy_ref: str,
    ) -> dict[str, object]:
        assert assigned_object_type_id in {99, 100}
        observed.append((assigned_object_id, expected_host, policy_ref))
        return dict(snapshots[assigned_object_id])

    monkeypatch.setattr(normalization, "_resolve_locked_ssh_identity", resolve_snapshot)

    class _VMManager:
        def select_related(self, *fields: str) -> _VMManager:
            assert fields == ("cluster", "device")
            return self

        def get(self, *, pk: int) -> SimpleNamespace:
            assert pk == 170
            return _execution({}).assigned_object

    contenttypes = types.ModuleType("django.contrib.contenttypes.models")
    contenttypes.ContentType = SimpleNamespace(
        objects=SimpleNamespace(
            get_for_model=lambda model, for_concrete_model: SimpleNamespace(pk=100)
        )
    )
    virtualization = types.ModuleType("virtualization.models")
    virtualization.VirtualMachine = SimpleNamespace(objects=_VMManager())
    monkeypatch.setitem(sys.modules, "django.contrib.contenttypes.models", contenttypes)
    monkeypatch.setitem(sys.modules, "virtualization.models", virtualization)

    normalized = jobs_module.normalize_execution_params(
        _runner_registration_execution()
    )

    validate(
        normalized,
        contract.NORMALIZED_PARAMS_SCHEMA,
        format_checker=FormatChecker(),
    )
    fingerprint_source = {
        key: value for key, value in normalized.items() if key != "command_fingerprint"
    }
    assert normalized["command_fingerprint"] == {
        "handler_id": contract.HANDLER_ID,
        "assigned_object_id": 399,
        "target_object_sha256": contract.RUNNER_TARGET_OBJECT_SHA256,
        "runner_target_object_sha256": contract.RUNNER_TARGET_OBJECT_SHA256,
        "gitea_target_object_sha256": contract.GITEA_TARGET_OBJECT_SHA256,
        **fingerprint_source,
    }
    assert observed == [
        (399, "10.0.30.199", contract.RUNNER_SSH_POLICY_REF),
        (170, "10.0.30.96", contract.GITEA_SSH_POLICY_REF),
    ]
    assert normalized["runner_node_id"] == 34
    assert normalized["runner_proxmox_vmid"] == 10_040


def test_runner_registration_rejects_passbolt_without_bound_secret_revision(
    jobs_module,
) -> None:
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    identity = SimpleNamespace(
        storage_backend="passbolt",
        passbolt_resource_id="opaque-resource-id",
        ssh_private_key_encrypted="stale-local-copy",
    )

    with pytest.raises(jobs_module.RPCExecutionError, match="local revision-bound"):
        normalization._require_locked_ssh_identity_material(identity, "key")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "other-runner"),
        ("cluster_id", 9),
        ("device_id", 35),
        ("tenant_id", 15),
        ("role_id", 6),
        ("vcpus", 4),
        ("memory", 8192),
        ("disk", 61_440),
        ("custom_field_data", {"proxmox_vm_id": 10_041}),
        ("primary_ip4", None),
        ("status", "offline"),
    ],
)
def test_runner_target_policy_rejects_inventory_drift(
    jobs_module,
    field: str,
    value: object,
) -> None:
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    target = _runner_target()
    setattr(target, field, value)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        normalization.validate_gitea_runner_target(
            target,
            target_model_label="virtualization.virtualmachine",
            assigned_object_id=399,
            target_display="nmultifibra-ci-untrusted-01",
        )

    assert exc_info.value.code == "RPC_TARGET_INVALID"


def _runner_execution() -> SimpleNamespace:
    return SimpleNamespace(
        pk=2350,
        procedure=SimpleNamespace(
            name="service.gitea.runner.register",
            handler_id="service.gitea.runner.register",
            timeout_seconds=360,
        ),
        params={"operation": "register", "scope": "nmulticloud-org"},
        normalized_params={"fence_expected_sha256": "0" * 64},
    )


def _runner_closed_response(
    *,
    stage: str,
    ok: bool = False,
) -> dict[str, object]:
    if ok:
        registered: bool | None = True
        token_invalidated = True
        token_reset_required = False
        token_sha256: str | None = "a" * 64
        reset_state = "rotated"
        prior_token_id: int | None = 11
        replacement_token_id: int | None = 12
    elif stage == "generate_token":
        registered = False
        token_invalidated = False
        token_reset_required = False
        token_sha256 = None
        reset_state = "not_started"
        prior_token_id = None
        replacement_token_id = None
    elif stage == "register":
        registered = False
        token_invalidated = True
        token_reset_required = False
        token_sha256 = "a" * 64
        reset_state = "rotated"
        prior_token_id = 11
        replacement_token_id = 12
    else:
        registered = None
        token_invalidated = False
        token_reset_required = True
        token_sha256 = None
        reset_state = "indeterminate"
        prior_token_id = None
        replacement_token_id = None
    return {
        "ok": ok,
        "result": {
            "ok": ok,
            "procedure": "service.gitea.runner.register",
            "target": "nmultifibra-ci-untrusted-01",
            "operation": "register",
            "scope": "nmulticloud-org",
            "registered": registered,
            "reconciled": None,
            "token_invalidated": token_invalidated,
            "token_reset_required": token_reset_required,
            "token_sha256": token_sha256,
            "reset_state": reset_state,
            "prior_token_id": prior_token_id,
            "prior_active_sha256": None,
            "replacement_token_id": replacement_token_id,
            "stage": stage,
        },
    }


class _StreamResponse:
    def __init__(
        self,
        *,
        status_code: int,
        body: bytes,
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = (
            headers if headers is not None else {"Content-Length": str(len(body))}
        )
        self._chunks = chunks if chunks is not None else [body]
        self.socket_timeouts: list[float] = []
        self.raw = SimpleNamespace(
            _connection=SimpleNamespace(
                sock=SimpleNamespace(settimeout=self.socket_timeouts.append)
            )
        )
        self.iter_content = MagicMock(side_effect=lambda **kwargs: iter(self._chunks))
        self.json = MagicMock(
            side_effect=AssertionError("protected response must not use eager json()")
        )
        self.close = MagicMock()


def _runner_wire_response(projected: dict[str, object]) -> dict[str, object]:
    ok = projected["ok"] is True
    return {
        **projected,
        "events": [],
        "error_code": "" if ok else "RPC_HANDLER_RESULT_FAILED",
        "error_message": "" if ok else "Gitea runner registration did not complete.",
    }


def test_runner_backend_transport_failures_are_closed_and_redirects_are_not_followed(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _runner_execution()
    post = MagicMock(
        side_effect=jobs_module.requests.exceptions.ConnectTimeout("not sent")
    )
    monkeypatch.setattr(jobs_module.requests, "post", post)
    assert jobs_module._call_backend(_backend_target(jobs_module), execution) == (
        _runner_closed_response(stage="generate_token")
    )
    assert post.call_args.kwargs["allow_redirects"] is False

    post.side_effect = jobs_module.requests.exceptions.ReadTimeout("unknown")
    assert jobs_module._call_backend(_backend_target(jobs_module), execution) == (
        _runner_closed_response(stage="indeterminate")
    )

    redirect = SimpleNamespace(
        status_code=307,
        json=MagicMock(side_effect=AssertionError("redirect body must not be parsed")),
        close=MagicMock(),
    )
    post.side_effect = None
    post.return_value = redirect
    assert jobs_module._call_backend(_backend_target(jobs_module), execution) == (
        _runner_closed_response(stage="indeterminate")
    )
    redirect.json.assert_not_called()
    redirect.close.assert_called_once_with()


def test_runner_backend_accepts_only_closed_secret_silent_wire_envelopes(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _runner_execution()
    success = _runner_closed_response(stage="complete", ok=True)
    response = _StreamResponse(
        status_code=200,
        body=json.dumps(_runner_wire_response(success)).encode("utf-8"),
    )
    monkeypatch.setattr(jobs_module.requests, "post", MagicMock(return_value=response))
    assert jobs_module._call_backend(_backend_target(jobs_module), execution) == success

    token_shaped = "A1" * 20
    response = _StreamResponse(
        status_code=200,
        body=json.dumps(
            {
                **_runner_wire_response(success),
                "events": [{"message": token_shaped}],
            }
        ).encode("utf-8"),
    )
    jobs_module.requests.post.return_value = response
    projected = jobs_module._call_backend(_backend_target(jobs_module), execution)
    assert projected == _runner_closed_response(stage="indeterminate")
    assert token_shaped not in repr(projected)

    explicit_failure = _runner_closed_response(stage="register")
    response = _StreamResponse(
        status_code=500,
        body=json.dumps(_runner_wire_response(explicit_failure)).encode("utf-8"),
    )
    jobs_module.requests.post.return_value = response
    assert jobs_module._call_backend(_backend_target(jobs_module), execution) == (
        explicit_failure
    )


@pytest.mark.parametrize(
    "response",
    [
        _StreamResponse(
            status_code=200,
            body=b"{}",
            headers={"Content-Length": "4097"},
        ),
        _StreamResponse(
            status_code=200,
            body=b"{}",
            headers={"Content-Length": "3"},
        ),
        _StreamResponse(
            status_code=200,
            body=b"{}",
            headers={"Content-Encoding": "gzip"},
        ),
        _StreamResponse(
            status_code=200,
            body=b"x" * 4097,
            headers={},
        ),
    ],
)
def test_runner_backend_rejects_oversized_truncated_or_encoded_bodies(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
    response: _StreamResponse,
) -> None:
    monkeypatch.setattr(
        jobs_module.requests,
        "post",
        MagicMock(return_value=response),
    )

    projected = jobs_module._call_backend(
        _backend_target(jobs_module),
        _runner_execution(),
    )

    assert projected == _runner_closed_response(stage="indeterminate")
    response.close.assert_called_once_with()


def test_runner_backend_enforces_streaming_and_total_deadline(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _StreamResponse(
        status_code=200,
        body=b"{}",
        headers={},
        chunks=[b"{", b"}"],
    )
    post = MagicMock(return_value=response)
    monkeypatch.setattr(jobs_module.requests, "post", post)
    monotonic = iter((100.0, 100.1, 401.0))
    monkeypatch.setattr(jobs_module.time, "monotonic", lambda: next(monotonic))

    projected = jobs_module._call_backend(
        _backend_target(jobs_module),
        _runner_execution(),
    )

    assert projected == _runner_closed_response(stage="indeterminate")
    assert post.call_args.kwargs["stream"] is True
    assert post.call_args.kwargs["allow_redirects"] is False
    timeout = post.call_args.kwargs["timeout"]
    assert timeout.total == 300
    assert timeout.connect_timeout == 10
    assert timeout.read_timeout == 290
    response.close.assert_called_once_with()


def test_runner_backend_allows_delayed_headers_inside_the_route_budget(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projected = _runner_closed_response(stage="generate_token")
    response = _StreamResponse(
        status_code=200,
        body=json.dumps(_runner_wire_response(projected)).encode("utf-8"),
    )

    def delayed_header_post(*args, **kwargs):
        del args
        timeout = kwargs["timeout"]
        assert timeout.total == 300
        assert timeout.connect_timeout == 10
        assert timeout.read_timeout == 290
        return response

    monkeypatch.setattr(jobs_module.requests, "post", delayed_header_post)

    assert (
        jobs_module._call_backend(
            _backend_target(jobs_module),
            _runner_execution(),
        )
        == projected
    )
    response.close.assert_called_once_with()


def test_runner_backend_total_deadline_interrupts_a_blocked_body_read(
    jobs_module,
) -> None:
    release_body = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            release_body.wait(timeout=2)

        def log_message(self, _format: str, *args: object) -> None:
            del args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    response = real_requests.post(
        f"http://127.0.0.1:{server.server_port}/",
        json={},
        stream=True,
        timeout=(1, 1),
    )
    started = time.monotonic()
    try:
        with pytest.raises(real_requests.exceptions.RequestException):
            jobs_module._read_bounded_json_response(
                response,
                deadline=time.monotonic() + 0.05,
                max_bytes=4096,
            )
        assert time.monotonic() - started < 0.5
    finally:
        response.close()
        release_body.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


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
    jobs.JobRunner = type(
        "JobRunner", (), {"enqueue": classmethod(lambda cls, *a, **k: None)}
    )
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    timezone = types.ModuleType("django.utils.timezone")
    timezone.now = MagicMock(return_value=None)
    django_utils.timezone = timezone
    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    # netbox_rpc.domain.normalization imports this alongside the service
    # allowlist for netbox.plugin.install (#262); without it every module
    # that stubs netbox_rpc.models fails at import, not just that one.
    models.RPCNetBoxPluginAllowlist = type("RPCNetBoxPluginAllowlist", (), {})
    models.RPCExecution = type(
        "RPCExecution",
        (),
        {"TIMEOUT_SECONDS_SNAPSHOT_PARAM_KEY": "_timeout_seconds_snapshot"},
    )
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})
    models.RPCGiteaRunnerScopeFence = type(
        "RPCGiteaRunnerScopeFence",
        (),
        {
            "STATE_CLEAR": "clear",
            "STATE_PENDING": "pending",
            "STATE_BLOCKED": "blocked",
            "objects": SimpleNamespace(
                get=lambda **kwargs: SimpleNamespace(
                    canonical_scope=kwargs["canonical_scope"],
                    state="clear",
                    blocking_execution_id=None,
                    reconciliation_execution_id=None,
                    expected_token_sha256="",
                )
            ),
        },
    )
    requests = types.ModuleType("requests")
    requests.post = MagicMock()
    requests.get = MagicMock()
    exceptions = types.ModuleType("requests.exceptions")
    exceptions.RequestException = type("RequestException", (Exception,), {})
    exceptions.ConnectionError = type(
        "ConnectionError", (exceptions.RequestException,), {}
    )
    exceptions.ConnectTimeout = type(
        "ConnectTimeout", (exceptions.RequestException,), {}
    )
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


def test_runner_normalizer_requires_the_operation_appropriate_fence_state(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    monkeypatch.setattr(normalization, "_GITEA_RUNNER_REGISTER_AVAILABLE", True)
    fence_model = sys.modules["netbox_rpc.models"].RPCGiteaRunnerScopeFence
    execution = _runner_registration_execution()
    execution.params["operation"] = "reconcile"
    contenttypes = types.ModuleType("django.contrib.contenttypes.models")
    contenttypes.ContentType = SimpleNamespace()
    virtualization = types.ModuleType("virtualization.models")
    virtualization.VirtualMachine = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "django.contrib.contenttypes.models", contenttypes)
    monkeypatch.setitem(sys.modules, "virtualization.models", virtualization)

    with pytest.raises(jobs_module.RPCExecutionError) as caught:
        jobs_module.normalize_execution_params(execution)
    assert caught.value.code == "RPC_SCOPE_FENCE_CLEAR"

    fence_model.objects.get = lambda **kwargs: SimpleNamespace(
        canonical_scope=kwargs["canonical_scope"],
        state="blocked",
        blocking_execution_id=2351,
        reconciliation_execution_id=2352,
        expected_token_sha256="a" * 64,
    )
    with pytest.raises(jobs_module.RPCExecutionError) as caught:
        jobs_module.normalize_execution_params(execution)
    assert caught.value.code == "RPC_SCOPE_FENCE_CLEAR"


def test_runner_reconciliation_quiescence_requires_terminal_owner_and_age(
    jobs_module,
) -> None:
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    blocking = SimpleNamespace(pk=2351, status="failed")
    fence = SimpleNamespace(
        state="blocked",
        blocking_execution_id=2351,
        blocking_execution=blocking,
        last_updated=datetime(2026, 8, 27, tzinfo=timezone.utc),
    )
    now = datetime.now(timezone.utc)
    fence.last_updated = now.replace(year=2025)

    assert normalization._gitea_runner_fence_is_quiescent(
        fence,
        delay_seconds=360,
    )

    blocking.status = "running"
    assert not normalization._gitea_runner_fence_is_quiescent(
        fence,
        delay_seconds=360,
    )
    fence.state = "pending"
    assert normalization._gitea_runner_fence_is_quiescent(
        fence,
        delay_seconds=360,
    )
    blocking.status = "failed"
    fence.last_updated = now
    assert not normalization._gitea_runner_fence_is_quiescent(
        fence,
        delay_seconds=360,
    )


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
