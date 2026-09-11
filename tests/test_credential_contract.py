"""Hostile-input and non-secret persistence contract tests."""

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

_spec = importlib.util.spec_from_file_location(
    "rpc_credential_contract_tested",
    Path(__file__).resolve().parents[1] / "netbox_rpc/credential_contract.py",
)
_contract = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _contract
_spec.loader.exec_module(_contract)
CredentialContractError = _contract.CredentialContractError
CredentialReferenceV1 = _contract.CredentialReferenceV1
apply_credential_fingerprint = _contract.apply_credential_fingerprint
canonical_hash = _contract.canonical_hash
public_credential_metadata = _contract.public_credential_metadata
validate_named_references = _contract.validate_named_references


def reference():
    return {
        "schema_version": 1,
        "provider": "netbox-openbao",
        "assignment_id": 7,
        "target": {"object_type": "dcim.device", "object_id": 9},
        "purpose": "login",
        "fields": ["private_key", "passphrase"],
        "version": {"policy": "pinned", "number": 3},
    }


def test_reference_round_trip_and_frozen_bundle():
    original = reference()
    parsed = CredentialReferenceV1.from_mapping(original)
    original["fields"].append("password")
    assert parsed.fields == ("private_key", "passphrase")
    assert parsed.to_mapping() == reference()


@pytest.mark.parametrize(
    "path",
    [
        ("schema_version",),
        ("assignment_id",),
        ("target", "object_id"),
        ("version", "number"),
    ],
)
@pytest.mark.parametrize("invalid", [True, 1.0, "1", 0, -1, None, 9007199254740992])
def test_identifiers_are_exact_bounded_json_integers(path, invalid):
    value = reference()
    holder = value
    for key in path[:-1]:
        holder = holder[key]
    holder[path[-1]] = invalid
    with pytest.raises(CredentialContractError):
        CredentialReferenceV1.from_mapping(value)


@pytest.mark.parametrize(
    "patch",
    [
        {"secret": "canary"},
        {"credential_uuid": "00000000-0000-0000-0000-000000000001"},
        {"fields": ["private_key", "private_key"]},
        {"fields": ["password\n"]},
        {"fields": ["x"] * 17},
        {"fields": []},
        {"purpose": "root"},
        {"target": {"object_type": "dcim.device\n", "object_id": 9}},
        {"version": {"policy": "live", "number": 3}},
        {"version": {"policy": "pinned"}},
    ],
)
def test_unknown_or_ambiguous_contracts_are_rejected(patch):
    value = reference() | patch
    with pytest.raises(
        CredentialContractError, match="Invalid credential reference contract"
    ):
        CredentialReferenceV1.from_mapping(value)


def test_uuid_reference_and_live_policy():
    value = reference()
    del value["assignment_id"]
    value["credential_uuid"] = "00000000-0000-0000-0000-000000000001"
    value["version"] = {"policy": "live"}
    assert CredentialReferenceV1.from_mapping(value).to_mapping() == value


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        "canary",
        {"Bad": {}},
        {"good\n": {}},
        {str(index): {} for index in range(17)},
    ],
)
def test_named_map_rejects_invalid_shape(value):
    with pytest.raises(CredentialContractError):
        validate_named_references(value)


def test_fingerprint_is_reference_only_and_bound_to_full_snapshot():
    references = {"ssh": reference()}
    snapshot = {"references": references, "executor_id": 5}
    normalized = {"command_fingerprint": {"operation": "read"}}
    execution = SimpleNamespace(
        credential_references=references, credential_authority=snapshot
    )
    apply_credential_fingerprint(execution, normalized)
    assert normalized["credential_references"] == references
    assert normalized["command_fingerprint"][
        "credential_authority_sha256"
    ] == canonical_hash(snapshot)
    changed = deepcopy(snapshot)
    changed["executor_id"] = 6
    assert canonical_hash(changed) != canonical_hash(snapshot)
    execution.credential_authority = {"references": {}}
    with pytest.raises(CredentialContractError):
        apply_credential_fingerprint(execution, normalized)


def test_legacy_payload_is_unchanged():
    normalized = {"operation": "read"}
    apply_credential_fingerprint(SimpleNamespace(), normalized)
    assert normalized == {"operation": "read"}


def test_event_metadata_exception_is_shape_checked_not_a_key_name_exemption():
    refs = {"ssh": reference()}
    assert public_credential_metadata(refs, "credential_references") == refs
    refs["ssh"]["password"] = "canary"
    assert public_credential_metadata(refs, "credential_references") is None
    assert public_credential_metadata("canary", "credential_authority_sha256") is None
    assert public_credential_metadata("canary", "credential_policy_ref") is None
