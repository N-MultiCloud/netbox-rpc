"""Normalizer tests for the Ubuntu 26.04 Samba AD DC bootstrap procedures.

Expected payloads are transcribed by hand from the shared contract and the
installer's defaults; they are never derived from the code under test. The
security properties asserted here are the point of the procedure family:

* no password is accepted, scrubbed, hashed, stored or forwarded — the domain
  Administrator password is referenced only by ``admin_credential_pk``;
* ``provision`` refuses every ``rpc_ssh_*`` override, so the execution runs
  against the object named in the request;
* ``dry_run`` defaults to true and a live run requires the credential reference
  and an SSH allowlist;
* there is deliberately no hard-coded code gate: the explicit backend-capability
  requirement is what keeps the procedures undispatchable until the backend ships.
"""

from __future__ import annotations

import ast
import importlib
import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PREFLIGHT = "os.linux.ubuntu.26.samba_ad_dc.preflight"
PROVISION = "os.linux.ubuntu.26.samba_ad_dc.provision"
VERIFY = "os.linux.ubuntu.26.samba_ad_dc.verify"
ALL_PROCEDURES = (PREFLIGHT, PROVISION, VERIFY)
READ_PROCEDURES = (PREFLIGHT, VERIFY)

SSH_OVERRIDES = {
    "rpc_ssh_credential_pk": 73,
    "rpc_ssh_host": "dc-console.example.net",
    "rpc_ssh_port": 2222,
    "rpc_ssh_known_hosts_entry": "dc-console.example.net ssh-ed25519 AAAAC3Nza",
    "rpc_ssh_strict_host_key_checking": False,
}

VALID_PROVISION = {
    "domain": "ad.example.com",
    "netbios": "EXAMPLE",
    "hostname": "ad01",
    "ip": "10.0.30.10",
    "forwarder": "10.0.30.1",
    "client_networks": ["10.0.30.0/24"],
}

# Transcribed from the installer's defaults for VALID_PROVISION.
EXPECTED_DEFAULT_SETTINGS = {
    "dry_run": True,
    "domain": "ad.example.com",
    "netbios": "EXAMPLE",
    "hostname": "ad01",
    "ip": "10.0.30.10",
    "forwarder": "10.0.30.1",
    "client_networks": ["10.0.30.0/24"],
    "ntp_servers": ["a.ntp.br", "b.ntp.br", "c.ntp.br"],
    "timezone": "America/Sao_Paulo",
    "share_name": "shared",
    "share_path": "/srv/samba/shared",
    "ssh_ports": [],
    "ssh_networks": [],
    "ban_exempt_networks": [],
    "fail2ban_findtime": 600,
    "smb_max_retry": 10,
    "smb_bantime": 900,
    "ssh_max_retry": 5,
    "ssh_bantime": 3600,
    "legacy_netbios": False,
    "freeze_cloud_init": True,
}
LIVE_PARAMS = {
    **VALID_PROVISION,
    "dry_run": False,
    "admin_credential_pk": 73,
    "ssh_ports": [22],
    "ssh_networks": ["10.0.50.0/24"],
}
SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "token", "hash")


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    monkeypatch.setattr(normalization, "_resolve_locked_ssh_identity", _fake_ssh)
    _install_fake_netbox_nms(monkeypatch)
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


SSH_IDENTITY_ID = 900
REVISION = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def _fake_ssh(
    *, assigned_object_type_id, assigned_object_id, expected_host, policy_ref
):
    return {
        "ssh_service_id": 64,
        "ssh_service_revision": "2026-09-01T12:00:00Z",
        "ssh_identity_id": SSH_IDENTITY_ID,
        "ssh_identity_revision": "2026-09-01T11:00:00Z",
        "ssh_storage_backend": "local",
        "ssh_principal": "ops",
        "ssh_method": "key",
        "ssh_host": expected_host,
        "ssh_port": 22,
        "ssh_known_hosts_sha256": "a" * 64,
        "ssh_policy_ref": policy_ref,
    }


# pk -> (auth_method, storage_backend, password_encrypted, viewer user pks)
CREDENTIALS = {
    73: ("password", "local", "enc", {1, 2}),
    74: ("password", "local", "enc", {2}),  # the requester (pk 1) cannot view it
    75: ("key", "local", "enc", {1, 2}),
    76: ("password", "local", "", {1, 2}),  # no stored material
    77: ("password", "openbao", "enc", {1, 2}),
    SSH_IDENTITY_ID: ("password", "local", "enc", {1, 2}),  # the SSH login itself
}


def _install_fake_netbox_nms(monkeypatch: pytest.MonkeyPatch) -> None:
    class Query:
        def __init__(self, user_pk):
            self.user_pk = user_pk
            self.pk = None

        def filter(self, *, pk):
            self.pk = pk
            return self

        def first(self):
            row = CREDENTIALS.get(self.pk)
            if row is None or self.user_pk not in row[3]:
                return None
            return SimpleNamespace(
                pk=self.pk,
                auth_method=row[0],
                storage_backend=row[1],
                password_encrypted=row[2],
                last_updated=REVISION,
            )

    class Manager:
        def restrict(self, user, action):
            assert action == "view"
            return Query(getattr(user, "pk", None))

    models = types.ModuleType("netbox_nms.models")
    models.DeviceCredential = SimpleNamespace(objects=Manager())
    monkeypatch.setitem(sys.modules, "netbox_nms", types.ModuleType("netbox_nms"))
    monkeypatch.setitem(sys.modules, "netbox_nms.models", models)


def _normalize(jobs_module, name: str, params: dict, **kwargs):
    return jobs_module.normalize_execution_params(_execution(name, params, **kwargs))


def _reject(
    jobs_module, name: str, params: dict, code: str = "RPC_PARAM_INVALID", **kw
):
    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        _normalize(jobs_module, name, params, **kw)
    assert excinfo.value.code == code
    return excinfo.value


def _flatten_keys(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _flatten_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten_keys(child)


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("procedure_name", ALL_PROCEDURES)
def test_there_is_no_hard_coded_code_gate(jobs_module, procedure_name: str) -> None:
    """The protected, explicit-capability path is the gate; a second flag would
    only add a rollout step (compare the Proxmox OCI pull precedent)."""

    normalization = sys.modules["netbox_rpc.domain.normalization"]
    assert not hasattr(normalization, "_UBUNTU_26_SAMBA_AD_DC_AVAILABLE")
    assert normalization.code_gate_unavailable_reason(procedure_name) is None


def test_family_is_routed_through_the_table_not_the_dispatcher() -> None:
    source = (ROOT / "netbox_rpc/domain/normalization.py").read_text(encoding="utf-8")
    assert "name: _normalize_ubuntu_26_samba_ad_dc_execution" in source
    assert "_normalize_ubuntu_26_samba_ad_dc_execution(execution, target)" not in source


def test_out_of_family_procedure_fails_closed(jobs_module) -> None:
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    with pytest.raises(normalization.RPCExecutionError) as excinfo:
        normalization._normalize_ubuntu_26_samba_ad_dc_execution(
            _execution("os.linux.ubuntu.26.samba_ad_dc.unknown_new", {}), "dc01"
        )
    assert excinfo.value.code == "RPC_PROCEDURE_NOT_NORMALIZABLE"


# --------------------------------------------------------------------------- #
# Target identity (derived only from the assigned NetBox object)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("procedure_name", ALL_PROCEDURES)
def test_normalizer_binds_the_immutable_assigned_object_identity(
    jobs_module, procedure_name: str
) -> None:
    params = dict(VALID_PROVISION) if procedure_name == PROVISION else {}
    normalized = _normalize(
        jobs_module,
        procedure_name,
        params,
        target_model_label="dcim.device",
        object_id=77,
    )

    assert normalized["target"] == "dc01"
    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 77,
    }
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["handler_id"] == procedure_name
    assert fingerprint["procedure"] == procedure_name
    assert fingerprint["target_content_type"] == "dcim.device"
    assert fingerprint["target_object_id"] == 77


@pytest.mark.parametrize("procedure_name", ALL_PROCEDURES)
@pytest.mark.parametrize(
    "kwargs",
    [
        {"object_id": None},
        {"object_id": 0},
        {"object_id": -1},
        {"object_id": "42"},
        {"object_id": True},  # True is an int in Python; never a primary key
        {"target_model_label": "ipam.ipaddress"},
        {"target_model_label": "netbox_proxbox.proxmoxendpoint"},
        {"target_model_label": "dcim.device", "content_type": "ipam.ipaddress"},
        {
            "target_model_label": "virtualization.virtualmachine",
            "content_type": "dcim.device",
        },
    ],
)
def test_normalizer_requires_a_supported_existing_assigned_object(
    jobs_module, procedure_name: str, kwargs: dict
) -> None:
    params = dict(VALID_PROVISION) if procedure_name == PROVISION else {}
    _reject(jobs_module, procedure_name, params, code="RPC_TARGET_INVALID", **kwargs)


@pytest.mark.parametrize("label", ["dcim.device", "virtualization.virtualmachine"])
def test_both_declared_target_models_are_accepted(jobs_module, label: str) -> None:
    normalized = _normalize(jobs_module, PREFLIGHT, {}, target_model_label=label)
    assert normalized["target_object"]["content_type"] == label


# --------------------------------------------------------------------------- #
# preflight / verify (read-only)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("procedure_name", READ_PROCEDURES)
def test_read_procedures_normalize_to_target_and_fingerprint_only(
    jobs_module, procedure_name: str
) -> None:
    normalized = _normalize(jobs_module, procedure_name, {})

    assert normalized == {
        "target": "dc01",
        "target_object": {
            "content_type": "virtualization.virtualmachine",
            "object_id": 42,
        },
        "command_fingerprint": {
            "handler_id": procedure_name,
            "procedure": procedure_name,
            "target_content_type": "virtualization.virtualmachine",
            "target_object_id": 42,
        },
    }


@pytest.mark.parametrize("procedure_name", READ_PROCEDURES)
def test_read_procedures_pass_through_the_shared_ssh_overrides(
    jobs_module, procedure_name: str
) -> None:
    normalized = _normalize(jobs_module, procedure_name, dict(SSH_OVERRIDES))

    assert normalized["rpc_ssh_credential_pk"] == 73
    assert normalized["rpc_ssh_host"] == "dc-console.example.net"
    assert normalized["rpc_ssh_port"] == 2222
    assert (
        normalized["rpc_ssh_known_hosts_entry"]
        == SSH_OVERRIDES["rpc_ssh_known_hosts_entry"]
    )
    assert normalized["rpc_ssh_strict_host_key_checking"] is False
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["rpc_ssh_credential_pk"] == 73
    assert fingerprint["rpc_ssh_host"] == "dc-console.example.net"
    assert fingerprint["rpc_ssh_port"] == 2222
    assert fingerprint["rpc_ssh_strict_host_key_checking"] is False
    # The known_hosts entry is fingerprinted by digest, never verbatim.
    assert "rpc_ssh_known_hosts_entry" not in fingerprint
    assert len(fingerprint["rpc_ssh_known_hosts_entry_sha256"]) == 64


@pytest.mark.parametrize("procedure_name", READ_PROCEDURES)
@pytest.mark.parametrize(
    "extra",
    [
        "dry_run",
        "domain",
        "admin_credential_pk",
        "password",
        "admin_password",
        "token",
        "command",
        "argv",
        "unknown_param",
    ],
)
def test_read_procedures_reject_every_unknown_parameter(
    jobs_module, procedure_name: str, extra: str
) -> None:
    exc = _reject(jobs_module, procedure_name, {extra: "x"})
    assert extra in str(exc)


@pytest.mark.parametrize("procedure_name", READ_PROCEDURES)
def test_read_procedures_tolerate_platform_stamped_internal_keys(
    jobs_module, procedure_name: str
) -> None:
    normalized = _normalize(
        jobs_module,
        procedure_name,
        {"_intent": 3, "_intent_name": "bootstrap", "_timeout_seconds_snapshot": 120},
    )
    assert not any(key.startswith("_") for key in normalized if key != "target")


@pytest.mark.parametrize("procedure_name", READ_PROCEDURES)
@pytest.mark.parametrize(
    "params",
    [
        {"rpc_ssh_host": ""},
        {"rpc_ssh_host": "host id"},
        {"rpc_ssh_port": 0},
        {"rpc_ssh_port": 70000},
        {"rpc_ssh_credential_pk": 0},
    ],
)
def test_read_procedures_reject_malformed_ssh_overrides(
    jobs_module, procedure_name: str, params: dict
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError):
        _normalize(jobs_module, procedure_name, params)


# --------------------------------------------------------------------------- #
# provision
# --------------------------------------------------------------------------- #


def test_provision_defaults_are_resolved_and_bound_in_both_payloads(
    jobs_module,
) -> None:
    normalized = _normalize(jobs_module, PROVISION, dict(VALID_PROVISION))

    for key, value in EXPECTED_DEFAULT_SETTINGS.items():
        assert normalized[key] == value, key
        assert normalized["command_fingerprint"][key] == value, key
    assert normalized["dry_run"] is True
    assert "admin_credential_pk" not in normalized
    assert "admin_credential_pk" not in normalized["command_fingerprint"]
    expected_keys = {
        "target",
        "target_object",
        "command_fingerprint",
        "ssh_snapshot",
        "ssh_policy_ref",
        *EXPECTED_DEFAULT_SETTINGS,
    }
    assert set(normalized) == expected_keys
    assert set(normalized["command_fingerprint"]) == {
        "handler_id",
        "procedure",
        "target_content_type",
        "target_object_id",
        "target_object_sha256",
        "ssh_snapshot",
        "ssh_policy_ref",
        *EXPECTED_DEFAULT_SETTINGS,
    }


def test_provision_normalization_is_deterministic(jobs_module) -> None:
    first = _normalize(jobs_module, PROVISION, dict(VALID_PROVISION))
    second = _normalize(jobs_module, PROVISION, dict(VALID_PROVISION))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_provision_canonicalizes_domain_netbios_hostname(jobs_module) -> None:
    normalized = _normalize(
        jobs_module,
        PROVISION,
        {
            **VALID_PROVISION,
            "domain": "AD.Example.COM",
            "netbios": "example",
            "hostname": "AD01",
        },
    )
    for payload in (normalized, normalized["command_fingerprint"]):
        assert payload["domain"] == "ad.example.com"
        assert payload["netbios"] == "EXAMPLE"
        assert payload["hostname"] == "ad01"


def test_provision_live_run_forwards_only_the_credential_reference(jobs_module) -> None:
    normalized = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))

    assert normalized["dry_run"] is False
    assert normalized["admin_credential_pk"] == 73
    assert normalized["command_fingerprint"]["admin_credential_pk"] == 73
    assert normalized["command_fingerprint"]["dry_run"] is False
    assert normalized["ssh_ports"] == [22]
    assert normalized["ssh_networks"] == ["10.0.50.0/24"]
    frozen = {
        "admin_credential_id": 73,
        "admin_credential_revision": "2026-09-01T12:00:00Z",
    }
    assert normalized["admin_credential_snapshot"] == frozen
    assert normalized["command_fingerprint"]["admin_credential_snapshot"] == frozen


def test_the_resolved_ssh_destination_and_identity_are_frozen(jobs_module) -> None:
    normalized = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS), object_id=77)

    snapshot = normalized["ssh_snapshot"]
    assert snapshot["ssh_host"] == "10.0.30.10"
    assert snapshot["ssh_port"] == 22
    assert snapshot["ssh_known_hosts_sha256"] == "a" * 64
    assert snapshot["ssh_identity_id"] == SSH_IDENTITY_ID
    assert snapshot["ssh_strict_host_key_checking"] is True
    assert normalized["ssh_policy_ref"] == (
        "target-owned-ssh:virtualization.virtualmachine:77"
    )
    fingerprint = normalized["command_fingerprint"]
    assert fingerprint["ssh_snapshot"] == snapshot
    assert fingerprint["ssh_policy_ref"] == normalized["ssh_policy_ref"]
    assert len(fingerprint["target_object_sha256"]) == 64


def test_ssh_drift_changes_the_normalized_payload(
    jobs_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Approval/claim re-normalize; a changed host key or identity must differ."""

    normalization = sys.modules["netbox_rpc.domain.normalization"]
    before = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))

    def drifted(**kwargs):
        return {**_fake_ssh(**kwargs), "ssh_known_hosts_sha256": "b" * 64}

    monkeypatch.setattr(normalization, "_resolve_locked_ssh_identity", drifted)
    after = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))
    assert after != before
    assert after["command_fingerprint"] != before["command_fingerprint"]


def test_admin_credential_revision_drift_changes_the_payload(
    jobs_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))
    global REVISION
    monkeypatch.setattr(
        sys.modules[__name__], "REVISION", datetime(2026, 9, 2, tzinfo=timezone.utc)
    )
    after = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))
    assert after["admin_credential_snapshot"] != before["admin_credential_snapshot"]


@pytest.mark.parametrize(
    ("pk", "needle"),
    [
        (74, "not viewable"),  # exists, but the requester may not view it
        (999, "not viewable"),  # does not exist
        (75, "password credential"),  # not a password credential
        (76, "password credential"),  # no stored material
        (77, "password credential"),  # not locally stored
        (SSH_IDENTITY_ID, "password credential"),  # reuses the SSH login identity
    ],
)
def test_the_admin_credential_is_authorized_at_admission(
    jobs_module, pk: int, needle: str
) -> None:
    exc = _reject(
        jobs_module,
        PROVISION,
        {**LIVE_PARAMS, "admin_credential_pk": pk},
        code="RPC_CREDENTIAL_FORBIDDEN",
    )
    assert needle in str(exc)


def test_the_admin_credential_needs_netbox_nms(
    jobs_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "netbox_nms", None)
    monkeypatch.setitem(sys.modules, "netbox_nms.models", None)
    _reject(
        jobs_module, PROVISION, dict(LIVE_PARAMS), code="RPC_CREDENTIAL_UNAVAILABLE"
    )


def test_the_approver_is_authorized_with_the_same_rule(jobs_module) -> None:
    normalization = sys.modules["netbox_rpc.domain.normalization"]
    requester_ok = normalization.resolve_samba_ad_dc_admin_credential(
        73, SimpleNamespace(pk=1), ssh_identity_id=SSH_IDENTITY_ID
    )
    approver_ok = normalization.resolve_samba_ad_dc_admin_credential(
        73, SimpleNamespace(pk=2), ssh_identity_id=SSH_IDENTITY_ID
    )
    assert requester_ok == approver_ok
    with pytest.raises(normalization.RPCExecutionError):
        normalization.resolve_samba_ad_dc_admin_credential(
            73, SimpleNamespace(pk=3), ssh_identity_id=SSH_IDENTITY_ID
        )


def test_a_dry_run_without_a_credential_freezes_no_credential(jobs_module) -> None:
    normalized = _normalize(jobs_module, PROVISION, dict(VALID_PROVISION))
    assert "admin_credential_snapshot" not in normalized
    assert "admin_credential_snapshot" not in normalized["command_fingerprint"]


def test_the_ip_must_equal_the_targets_primary_ipv4(jobs_module) -> None:
    exc = _reject(jobs_module, PROVISION, {**VALID_PROVISION, "ip": "10.0.30.99"})
    assert "primary IPv4" in str(exc)


def test_a_target_without_a_primary_ipv4_is_refused(jobs_module) -> None:
    execution = _execution(PROVISION, dict(VALID_PROVISION))
    execution.assigned_object = SimpleNamespace(primary_ip4=None)
    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(execution)
    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_the_read_procedures_freeze_nothing(jobs_module) -> None:
    normalized = _normalize(jobs_module, PREFLIGHT, {})
    assert "ssh_snapshot" not in normalized
    assert "admin_credential_snapshot" not in normalized


def test_dry_run_and_live_fingerprints_differ(jobs_module) -> None:
    """An approval of a live run must not be satisfiable by a dry-run payload."""

    dry = _normalize(jobs_module, PROVISION, {**LIVE_PARAMS, "dry_run": True})
    live = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))
    assert dry["command_fingerprint"] != live["command_fingerprint"]


def test_provision_fingerprint_and_payload_hold_no_password_material(
    jobs_module,
) -> None:
    normalized = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))

    keys = {key.lower() for key in _flatten_keys(normalized)}
    for word in SECRET_WORDS:
        assert not any(word in key for key in keys), (word, sorted(keys))
    rendered = json.dumps(normalized, sort_keys=True).lower()
    for word in ("password", "passwd", "passphrase"):
        assert word not in rendered


@pytest.mark.parametrize("override", sorted(SSH_OVERRIDES))
def test_provision_refuses_every_ssh_override(jobs_module, override: str) -> None:
    exc = _reject(
        jobs_module,
        PROVISION,
        {**VALID_PROVISION, override: SSH_OVERRIDES[override]},
    )
    assert override in str(exc)
    assert "assigned NetBox object" in str(exc)


@pytest.mark.parametrize(
    "extra",
    [
        "password",
        "admin_password",
        "administrator_password",
        "password_hash",
        "password_sha256",
        "token",
        "secret",
        "passphrase",
        "command",
        "argv",
        "shell",
        "stdin",
        "unknown_param",
    ],
)
def test_provision_rejects_password_shaped_and_unknown_parameters(
    jobs_module, extra: str
) -> None:
    exc = _reject(jobs_module, PROVISION, {**VALID_PROVISION, extra: "x"})
    assert extra in str(exc)
    # The offending value is never echoed.
    assert "x'" not in str(exc)


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"dry_run": False, "admin_credential_pk": 73}, "ssh_ports"),
        (
            {"dry_run": False, "ssh_ports": [22], "ssh_networks": ["10.0.50.0/24"]},
            "admin_credential_pk",
        ),
        ({"ssh_ports": [22]}, "ssh_networks"),
        ({"ssh_networks": ["10.0.50.0/24"]}, "ssh_networks"),
        ({"hostname": "example"}, "hostname"),
        ({"forwarder": "10.0.30.10"}, "forwarder"),
        ({"dry_run": "false"}, "dry_run"),
        ({"domain": "corp.local"}, "domain"),
        ({"ip": "127.0.0.1"}, "ip"),
        ({"client_networks": ["0.0.0.0/0"]}, "client_networks"),
        ({"ntp_servers": ["::1"]}, "ntp_servers"),
        ({"timezone": "../etc"}, "timezone"),
        ({"share_name": "sysvol"}, "share_name"),
        ({"share_path": "/etc/samba"}, "share_path"),
        ({"ssh_ports": [445], "ssh_networks": ["10.0.50.0/24"]}, "ssh_ports"),
        ({"fail2ban_findtime": 59}, "fail2ban_findtime"),
        ({"smb_max_retry": 2}, "smb_max_retry"),
        ({"ssh_bantime": 86401}, "ssh_bantime"),
        ({"legacy_netbios": "no"}, "legacy_netbios"),
        ({"freeze_cloud_init": 0}, "freeze_cloud_init"),
        ({"admin_credential_pk": 0}, "admin_credential_pk"),
    ],
)
def test_provision_rejects_invalid_values_with_a_param_error(
    jobs_module, override: dict, match: str
) -> None:
    exc = _reject(jobs_module, PROVISION, {**VALID_PROVISION, **override})
    assert match in str(exc)


@pytest.mark.parametrize("missing", sorted(VALID_PROVISION))
def test_provision_requires_every_identity_and_network_parameter(
    jobs_module, missing: str
) -> None:
    params = {key: value for key, value in VALID_PROVISION.items() if key != missing}
    exc = _reject(jobs_module, PROVISION, params)
    assert missing in str(exc)


def test_provision_lists_are_independent_copies(jobs_module) -> None:
    normalized = _normalize(jobs_module, PROVISION, dict(LIVE_PARAMS))
    normalized["client_networks"].append("192.0.2.0/24")
    normalized["ssh_ports"].append(2222)
    assert normalized["command_fingerprint"]["client_networks"] == ["10.0.30.0/24"]
    assert normalized["command_fingerprint"]["ssh_ports"] == [22]


def test_provision_platform_stamped_internal_keys_are_tolerated(jobs_module) -> None:
    normalized = _normalize(
        jobs_module,
        PROVISION,
        {**VALID_PROVISION, "_intent": 1, "_timeout_seconds_snapshot": 3600},
    )
    assert "_intent" not in normalized
    assert "_timeout_seconds_snapshot" not in normalized


# --------------------------------------------------------------------------- #
# Password-scrub registration must NOT include these procedures
# --------------------------------------------------------------------------- #


def _password_bearing_handler_ids() -> set[str]:
    tree = ast.parse(
        (ROOT / "netbox_rpc/application/command_handlers.py").read_text(
            encoding="utf-8"
        )
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_PASSWORD_BEARING_HANDLER_IDS"
            for t in node.targets
        ):
            return {
                str(child.value)
                for child in ast.walk(node.value)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            }
    raise AssertionError("_PASSWORD_BEARING_HANDLER_IDS not found")


def test_samba_ad_dc_handlers_are_not_password_bearing() -> None:
    """They carry no password at all, so the scrub set must not name them."""

    listed = _password_bearing_handler_ids()
    assert listed == {
        "service.samba_1.user_create",
        "service.samba_1.user_set_password",
    }
    assert not listed & set(ALL_PROCEDURES)


def test_assigned_object_admission_check_covers_all_three_procedures() -> None:
    source = (ROOT / "netbox_rpc/application/command_handlers.py").read_text(
        encoding="utf-8"
    )
    assert "UBUNTU_26_SAMBA_AD_DC_PROCEDURE_NAMES" in source
    assert "    | UBUNTU_26_SAMBA_AD_DC_PROCEDURE_NAMES\n" in source


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _execution(
    procedure_name: str,
    params: dict[str, object],
    *,
    target_model_label: str = "virtualization.virtualmachine",
    content_type: str | None = None,
    object_id: object = 42,
):
    label = content_type if content_type is not None else target_model_label
    app_label, _, model = label.partition(".")
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=procedure_name),
        params=params,
        target_display="dc01",
        target_model_label=target_model_label,
        assigned_object_type=SimpleNamespace(app_label=app_label, model=model),
        assigned_object_id=object_id,
        assigned_object_type_id=7,
        assigned_object=SimpleNamespace(
            primary_ip4=SimpleNamespace(address="10.0.30.10/24")
        ),
        requested_by=SimpleNamespace(pk=1),
    )


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig

    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"

    netbox_jobs = types.ModuleType("netbox.jobs")

    class JobRunner:
        @classmethod
        def enqueue(cls, *args, **kwargs):
            return None

    netbox_jobs.JobRunner = JobRunner

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    netbox_rpc_models.RPCNetBoxPluginAllowlist = type(
        "RPCNetBoxPluginAllowlist", (), {}
    )
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")

    class _RequestException(Exception):
        pass

    class _ConnectionError(_RequestException):
        pass

    requests_exceptions.RequestException = _RequestException
    requests_exceptions.ConnectionError = _ConnectionError
    requests_mod.exceptions = requests_exceptions

    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
