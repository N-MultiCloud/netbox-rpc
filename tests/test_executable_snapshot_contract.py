"""Independent golden vectors and hostile public-wire cases; no NetBox or backend."""

import hashlib
import importlib.util
import json
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "isolated_executable_snapshot_contract", ROOT / "netbox_rpc/executable_snapshot_contract.py"
)
assert SPEC and SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)
FIXTURE = ROOT / "tests/fixtures/executable_snapshot_v1.json"


def fixture():
    # Generated independently from the accepted portable definition, not module constants.
    return json.loads(FIXTURE.read_bytes())


def projection():
    return fixture()["projection"]


def snapshot():
    return projection()["command_snapshot"]


def validate(value):
    return contract.validate_projection(value, execution_id=9001, backend_id=7,
                                        audience="netbox-rpc-backend")


def test_fixed_independent_fixture_and_all_digest_vectors():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == (
        "e75a734b5f4c0bf33d785e6d7bd8721d2622766a42d614e9b876a399c7ebe966"
    )
    public = projection()
    assert contract.digest(public["procedure"]["definition"]) == (
        "bba2411b9728fcf09902f7dd835bf83cdeb46109a567f5305d0974f61bedcc19"
    )
    assert contract.capability_contract_hash() == (
        "cb847cb86efbbb4dc4667f4fe43d66cafa3aba98025069bccb10a2065d51f22f"
    )
    assert contract.digest(contract.validate_snapshot(snapshot())) == (
        "bbef2f9d85dc9632a03459095006b684a25d707b999743a3cf1724a037a57be3"
    )
    assert contract.fingerprint(snapshot()) == {
        "executable_snapshot_schema_version": 1,
        "executable_snapshot_sha256": "bbef2f9d85dc9632a03459095006b684a25d707b999743a3cf1724a037a57be3",
        "executable_definition_sha256": "bba2411b9728fcf09902f7dd835bf83cdeb46109a567f5305d0974f61bedcc19",
        "target_object_sha256": "604ce563e2c1022c42b2b57cf7c5413533fbd3adb2afb7f0baa923686731c896",
        "inputs_sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        "transport_policy_sha256": "deee2d67a4ab93f1a2448a8adab558d62187c317dfef4e7bbd517108760cde13",
    }
    assert contract.digest(contract.fingerprint(snapshot())) == (
        "180ab20ec794d36724debeb2dfef61935d6566e88ee9fc825ebc12d94ffd735c"
    )
    assert contract.digest(fixture()["claims"]) == (
        "498c520371e1e163a48a891a6b5f4e1d4728f004f001a12bd600831f29ea0e19"
    )
    assert validate(contract.parse_json(contract.canonical_bytes(public))) == public


def test_legacy_command_only_hash_is_unchanged():
    # Fixed historical seed identity and command fields, not alias constants.
    legacy = {"handler_id": "service.samba_1.config_test", "version": 1, "effect": "read",
              "commands": fixture()["projection"]["procedure"]["definition"]["commands"]}
    assert contract.digest(legacy) == (
        "a41ed619060aca779dfadcc61c03d7a8f968160aa6b441b6ec18cb10dfee8c3f"
    )


def test_canonical_order_unicode_and_detached_results():
    assert contract.canonical_bytes({"z": "é😀", "a": [True, None, 0]}) == (
        b'{"a":[true,null,0],"z":"\\u00e9\\ud83d\\ude00"}'
    )
    value = snapshot()
    frozen = contract.validate_snapshot(value)
    value["steps"][0]["argv"][0] = "changed"
    assert frozen["steps"][0]["argv"] == ["/usr/bin/testparm", "-s"]
    reviewed = contract.definition()
    reviewed.clear()
    assert contract.definition() == fixture()["projection"]["procedure"]["definition"]
    public = projection()
    detached = validate(public)
    public["target"]["display"] = "changed"
    assert detached["target"]["display"] == "snapshot-test-device"


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}', b'{"a":1,"\\u0061":2}',
    b'{"x":"\\u0000"}', b'{"x":"\\ud800"}', b'{"x":"\xff"}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1.0}',
    b'{"x":1e0}', b'{"x":9007199254740992}', b'{"x":-9007199254740992}',
    b'[]', b'null', b'42', b'"string"', b'{', b'{} {}', b'\xef\xbb\xbf{}',
    b' ' * 32769, b'{"x":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}',
    "{}", bytearray(b'{}'), None,
])
def test_raw_json_rejects_lossy_or_malformed_shapes(raw):
    with pytest.raises(contract.SnapshotContractError, match="^Executable snapshot contract is invalid.$"):
        contract.parse_json(raw)


@pytest.mark.parametrize("value", [
    {"x": 1.0}, {"x": float("nan")}, {"x": float("inf")}, {"x": -9007199254740992},
    {"x": 9007199254740992}, {1: "x"}, {"x": b"bytes"}, {"x": (1,)},
    {"x": {1}}, {"x": object()}, {"x": "\u0000"}, {"x": "\udfff"},
    {"x": "a" * 32769}, {"x": [0] * 2049}, dict.fromkeys(map(str, range(2049))),
    {"x": [0] * 2048}, {"a": "x" * 20000, "b": "x" * 20000},
])
def test_native_json_has_bounded_exact_types(value):
    with pytest.raises(contract.SnapshotContractError):
        contract.canonical_bytes(value)


@pytest.mark.parametrize("base", [dict, list, str, int, bytes])
def test_native_subclasses_are_not_wire_values(base):
    class Foreign(base):
        pass
    with pytest.raises(contract.SnapshotContractError):
        contract.canonical_bytes(Foreign())


def test_depth_cycles_and_exact_byte_limits():
    value = 0
    for _ in range(16):
        value = [value]
    contract.canonical_bytes(value)
    with pytest.raises(contract.SnapshotContractError):
        contract.canonical_bytes([value])
    cycle = []
    cycle.append(cycle)
    with pytest.raises(contract.SnapshotContractError):
        contract.canonical_bytes(cycle)
    assert contract.canonical_bytes("x" * 16382, limit=16384) == b'"' + b'x' * 16382 + b'"'
    with pytest.raises(contract.SnapshotContractError):
        contract.canonical_bytes("x" * 16383, limit=16384)
    with pytest.raises(contract.SnapshotContractError):
        contract.canonical_bytes("é" * 6000)
    with pytest.raises(contract.SnapshotContractError):
        contract.parse_json(b'{} ', limit=2)


@pytest.mark.parametrize("limit", [0, -1, True, 1.0, 32769, None])
def test_callers_cannot_expand_or_coerce_resource_limits(limit):
    for function, value in ((contract.canonical_bytes, {}), (contract.parse_json, b'{}')):
        with pytest.raises(contract.SnapshotContractError):
            function(value, limit=limit)


def alter(value, path, replacement):
    parts = path.split(".")
    parent = value
    for part in parts[:-1]:
        parent = parent[int(part)] if type(parent) is list else parent[part]
    key = int(parts[-1]) if type(parent) is list else parts[-1]
    parent[key] = replacement
    return value


@pytest.mark.parametrize("path,replacement", [
    ("schema_version", True), ("runtime_version", 1.0), ("runtime", "device_cli"),
    ("procedure.id", False), ("procedure.id", 0), ("procedure.id", 9007199254740992),
    ("procedure.definition.catalog.approval_required", 0),
    ("procedure.definition.catalog.handler_id", "service.samba_1.config_test"),
    ("procedure.definition.commands.0.render_mode", "jinja"),
    ("procedure.definition.commands.0.capture_kind", "stdout"),
    ("backend.id", "7"), ("backend.audience", ""), ("backend.audience", "x" * 256),
    ("requested_by_id", 23.0), ("approved_by_id", 23),
    ("target.object_type", "virtualization.virtualmachine"), ("target.object_id", -1),
    ("target.display", ""), ("target.display", "x" * 256),
    ("inputs", {"password": "opaque-input-canary"}),
    ("transport.policy.credential_reference_providers", ["netbox-openbao"]),
    ("transport.policy.allow_fallback", True), ("transport.policy.max_output_bytes", 1),
    ("transport.ssh.ssh_service_id", True), ("transport.ssh.ssh_identity_id", 0),
    ("transport.ssh.ssh_service_revision", "2026-09-10T12:00:00+00:00"),
    ("transport.ssh.ssh_identity_revision", "2026-09-10T12:00:00.1234567Z"),
    ("transport.ssh.ssh_identity_revision", "2026-09-10T12:00:00Z\n"),
    ("transport.ssh.ssh_storage_backend", "openbao"),
    ("transport.ssh.ssh_principal", " reader"), ("transport.ssh.ssh_principal", "reader "),
    ("transport.ssh.ssh_principal", "read\ter"), ("transport.ssh.ssh_principal", "read\x7fer"),
    ("transport.ssh.ssh_principal", ""), ("transport.ssh.ssh_principal", "x" * 201),
    ("transport.ssh.ssh_method", "agent"), ("transport.ssh.ssh_method", []),
    ("transport.ssh.ssh_host", "192.000.002.010"), ("transport.ssh.ssh_host", "localhost"),
    ("transport.ssh.ssh_host", "::1"), ("transport.ssh.ssh_host", 3221225994),
    ("transport.ssh.ssh_port", 22.0), ("transport.ssh.ssh_port", 2222),
    ("transport.ssh.ssh_policy_ref", "target-owned-ssh:dcim.device:43"),
    ("transport.ssh.ssh_known_hosts_sha256", "A" * 64),
    ("transport.ssh.ssh_known_hosts_sha256", "f" * 63),
    ("transport.ssh.ssh_known_hosts_sha256", "f" * 64 + "\n"),
    ("steps", []), ("steps", {}), ("steps", [None]),
    ("steps.0.command_id", True), ("steps.0.step_id", "command:0520"),
    ("steps.0.step_id", "command:521"), ("steps.0.sequence", True),
    ("steps.0.argv", ["/usr/bin/testparm", "-s", "unapproved"]),
    ("steps.0.timeout_seconds", 21), ("steps.0.max_output_bytes", False),
    ("steps.0.captures", ["stdout"]),
])
def test_snapshot_denials_happen_before_hashing(path, replacement):
    value = alter(snapshot(), path, replacement)
    with mock.patch.object(contract.hashlib, "sha256", side_effect=AssertionError("hash before admission")):
        with pytest.raises(contract.SnapshotContractError):
            contract.fingerprint(value)


@pytest.mark.parametrize("path", [
    "", "procedure", "procedure.definition", "backend", "target", "transport",
    "transport.ssh", "steps.0",
])
def test_snapshot_unknown_and_missing_properties_are_denied(path):
    value = snapshot()
    node = value
    for part in path.split(".") if path else []:
        node = node[int(part)] if type(node) is list else node[part]
    node["credential_references"] = {}
    with pytest.raises(contract.SnapshotContractError):
        contract.validate_snapshot(value)
    del node["credential_references"]
    del node[next(iter(node))]
    with pytest.raises(contract.SnapshotContractError):
        contract.validate_snapshot(value)


@pytest.mark.parametrize("path,replacement", [
    ("id", True), ("id", 9002), ("status", "queued"),
    ("procedure.enabled", 1), ("procedure.enabled", False),
    ("backend.id", 8), ("requested_by_id", 24), ("approved_by_id", 24),
    ("target.display", "changed"), ("inputs", {"secret": "opaque-canary"}),
    ("transport.ssh.ssh_principal", "other"),
    ("command_snapshot_sha256", "0" * 64), ("resolved_command_hash", "0" * 64),
    ("command_fingerprint.executable_snapshot_schema_version", True),
    ("command_fingerprint.target_object_sha256", "0" * 64),
    ("stream_version", 0), ("stream_version", 5),
    ("dispatch_lease_binding.issued_stream_version", True),
    ("dispatch_lease_binding.claims_sha256", "F" * 64),
])
def test_projection_rechecks_all_current_frozen_bindings(path, replacement):
    with pytest.raises(contract.SnapshotContractError):
        validate(alter(projection(), path, replacement))


@pytest.mark.parametrize("field", ["credential_references", "commands", "params", "events"])
def test_projection_rejects_legacy_or_secret_metadata(field):
    value = projection()
    value[field] = {}
    with pytest.raises(contract.SnapshotContractError):
        validate(value)


@pytest.mark.parametrize("options", [
    {"execution_id": True}, {"backend_id": 7.0}, {"backend_id": 8},
    {"audience": "other"}, {"audience": ""},
])
def test_expected_authority_is_strict_and_exact(options):
    kwargs = {"execution_id": 9001, "backend_id": 7, "audience": "netbox-rpc-backend"}
    kwargs.update(options)
    with pytest.raises(contract.SnapshotContractError):
        contract.validate_projection(projection(), **kwargs)


@pytest.mark.parametrize("method", ["key", "key_with_passphrase", "password"])
def test_all_supported_local_identity_methods_and_revision_precision(method):
    value = snapshot()
    value["transport"]["ssh"]["ssh_method"] = method
    value["transport"]["ssh"]["ssh_service_revision"] = "2026-09-10T12:00:00Z"
    value["transport"]["ssh"]["ssh_identity_revision"] = "2026-09-10T12:00:00.1Z"
    assert contract.validate_snapshot(value) == value


@pytest.mark.parametrize("field", [
    "procedure", "backend", "requested_by_id", "target", "transport", "steps",
])
def test_valid_identity_changes_change_fixed_snapshot_fingerprint(field):
    value = snapshot()
    paths = {"procedure": "procedure.id", "backend": "backend.id",
             "requested_by_id": "requested_by_id", "target": "target.display",
             "transport": "transport.ssh.ssh_identity_id", "steps": "steps.0.command_id"}
    alter(value, paths[field], "another-device" if field == "target" else 999)
    if field == "steps":
        value["steps"][0]["step_id"] = "command:999"
    assert contract.digest(contract.fingerprint(value)) != (
        "180ab20ec794d36724debeb2dfef61935d6566e88ee9fc825ebc12d94ffd735c"
    )


def test_fixed_oracle_kills_definition_and_digest_mutants():
    changed = contract.definition()
    changed["commands"][0]["argv"] = ["/usr/bin/testparm", "--version"]
    with mock.patch.object(contract, "_DEFINITION_JSON", json.dumps(changed)):
        with pytest.raises((AssertionError, contract.SnapshotContractError)):
            test_fixed_independent_fixture_and_all_digest_vectors()
    with mock.patch.object(contract, "digest", return_value="0" * 64):
        with pytest.raises(AssertionError):
            test_fixed_independent_fixture_and_all_digest_vectors()


def test_denial_oracle_kills_omitted_transport_and_duplicate_key_checks():
    with mock.patch.object(contract, "_validate_transport", return_value=None):
        with pytest.raises(AssertionError, match="hash before admission"):
            test_snapshot_denials_happen_before_hashing("transport.ssh.ssh_port", 2222)
    with mock.patch.object(contract, "_unique_object", side_effect=dict):
        with pytest.raises(pytest.fail.Exception):
            test_raw_json_rejects_lossy_or_malformed_shapes(b'{"x":1,"x":2}')


def test_denial_oracle_kills_omitted_projection_binding():
    original = contract.exact

    def omit_current_target(actual, expected):
        if type(actual) is dict and "display" in actual:
            return None
        return original(actual, expected)

    with mock.patch.object(contract, "exact", side_effect=omit_current_target):
        with pytest.raises(pytest.fail.Exception):
            test_projection_rechecks_all_current_frozen_bindings("target.display", "changed")


def test_definition_drift_is_denied_before_any_fingerprint_is_emitted():
    # Source drift must be rejected by snapshot admission itself, not only by the
    # separately called capability helper.
    drifted = contract.definition()
    drifted["runtime"]["command_timeout_seconds"] = 19
    with mock.patch.object(contract, "_DEFINITION_JSON", json.dumps(drifted)):
        assert contract.digest(contract.definition()) != contract.DEFINITION_SHA256
        value = snapshot()
        value["procedure"]["definition"] = drifted
        with pytest.raises(contract.SnapshotContractError):
            contract.validate_snapshot(value)
        with pytest.raises(contract.SnapshotContractError):
            contract.fingerprint(value)
