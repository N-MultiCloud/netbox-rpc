"""Closed, public-only wire contract for the fixed Samba snapshot runtime.

This module has no Django, provider or backend dependency. It validates data,
not execution authority: callers must independently enforce permissions, locks,
capability admission and signed leases. No existing handler hash is changed.
The mirrored backend contract and independent fixture pin canonical bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from ipaddress import IPv4Address
from typing import Any

HANDLER_ID = "service.samba_1.config_test.snapshot_v1"
CATALOG_NAME = "service.samba.1.config_test_snapshot"
DEFINITION_SHA256 = "bba2411b9728fcf09902f7dd835bf83cdeb46109a567f5305d0974f61bedcc19"
CONTRACT_SHA256 = "cb847cb86efbbb4dc4667f4fe43d66cafa3aba98025069bccb10a2065d51f22f"
MAX_SNAPSHOT_BYTES = 16384
MAX_PROJECTION_BYTES = 32768
MAX_ID = 9007199254740991
MAX_DEPTH = 16
MAX_NODES = 2048
_REVISION = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"
)
_HASH = re.compile(r"[0-9a-f]{64}")

# Reviewed portable definition, excluding installation-specific primary keys.
_DEFINITION_JSON = r'''{"definition_schema_version":1,"catalog":{"name":"service.samba.1.config_test_snapshot","handler_id":"service.samba_1.config_test.snapshot_v1","version":1,"effect":"read","approval_required":false,"target_models":["dcim.device"],"timeout_seconds":30,"params_schema":{"type":"object","additionalProperties":false,"properties":{}}},"runtime":{"execution_mode":"shell_argv","runtime_version":1,"snapshot_schema_version":1,"transport_driver":"asyncssh","transport_driver_chain":["asyncssh"],"transport_pinned":true,"allow_fallback":false,"strict_auth":true,"credential_channel":"target-owned-local-ssh-v1","target_address_family":"ipv4","ssh_port":22,"ssh_host_key_algorithm":"ssh-ed25519","credential_reference_providers":[],"output_parser":"none","output_schema":{},"capture_kinds":[],"stdin":"closed","output":"discard","request_timeout_seconds":30,"command_timeout_seconds":20,"cleanup_timeout_seconds":3,"max_output_bytes":0,"max_response_bytes":4096,"max_snapshot_bytes":16384},"commands":[{"sequence":1,"step_type":"shell_argv","device_cli_mode":"","argv":["/usr/bin/testparm","-s"],"render_mode":"literal","produces_var":"","capture_kind":"","capture_expression":"","condition_param":"","condition_negate":false,"for_each_param":"","continue_on_error":false}],"result_schema":{"type":"object","additionalProperties":false,"required":["ok","procedure","target","valid","exit_code","stage"],"properties":{"ok":{"type":"boolean"},"procedure":{"const":"service.samba.1.config_test_snapshot"},"target":{"type":"string","minLength":1,"maxLength":255},"valid":{"type":["boolean","null"]},"exit_code":{"type":["integer","null"],"minimum":0,"maximum":255},"stage":{"enum":["complete","execute","indeterminate"]}},"oneOf":[{"properties":{"ok":{"const":true},"valid":{"const":true},"exit_code":{"const":0},"stage":{"const":"complete"}}},{"properties":{"ok":{"const":false},"valid":{"const":false},"exit_code":{"type":"integer","minimum":1,"maximum":255},"stage":{"const":"complete"}}},{"properties":{"ok":{"const":false},"valid":{"type":"null"},"exit_code":{"type":"null"},"stage":{"enum":["execute","indeterminate"]}}}]}}'''


class SnapshotContractError(ValueError):
    """Closed failure which never contains rejected values or provider material."""


def _reject() -> None:
    raise SnapshotContractError("Executable snapshot contract is invalid.")


def definition() -> dict[str, Any]:
    """Return an independent copy of the reviewed fixed definition."""
    return json.loads(_DEFINITION_JSON)


def _text(value: Any, minimum: int = 0, maximum: int = MAX_PROJECTION_BYTES) -> int:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _reject()
    if "\u0000" in value:
        _reject()
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise SnapshotContractError("Executable snapshot contract is invalid.") from None


def _tree_children(value: Any) -> list[Any]:
    kind = type(value)
    if kind is dict:
        if len(value) > MAX_NODES:
            _reject()
        children = []
        for key, item in value.items():
            _text(key)
            children.extend((key, item))
        return children
    if kind is list:
        if len(value) > MAX_NODES:
            _reject()
        return value
    if kind is int:
        if abs(value) > MAX_ID:
            _reject()
    elif kind not in (str, bool, type(None)):
        _reject()
    return []


def _check_tree(value: Any) -> None:
    pending = [(value, 0)]
    nodes = text_bytes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            _reject()
        if type(item) is str:
            text_bytes += _text(item)
            if text_bytes > MAX_PROJECTION_BYTES:
                _reject()
        pending.extend((child, depth + 1) for child in _tree_children(item))


def canonical_bytes(value: Any, *, limit: int = MAX_PROJECTION_BYTES) -> bytes:
    """Bound and validate native JSON types before canonical serialization.

This is a syntax primitive, not semantic admission. Use validate_snapshot or
validate_projection before hashing an executable object from an untrusted input.
"""
    if type(limit) is not int or not 0 < limit <= MAX_PROJECTION_BYTES:
        _reject()
    _check_tree(value)
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    if len(encoded) > limit:
        _reject()
    return encoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            _reject()
        value[key] = item
    return value


def parse_json(raw: bytes, *, limit: int = MAX_PROJECTION_BYTES) -> dict[str, Any]:
    """Reject duplicate keys before a lossy parse; no coercion or JSON extensions."""
    if type(raw) is not bytes or type(limit) is not int or not 0 < limit <= MAX_PROJECTION_BYTES:
        _reject()
    if len(raw) > limit:
        _reject()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(value) is not dict:
            _reject()
        canonical_bytes(value, limit=limit)
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise SnapshotContractError("Executable snapshot contract is invalid.") from None


def digest(value: Any, *, limit: int = MAX_PROJECTION_BYTES) -> str:
    return hashlib.sha256(canonical_bytes(value, limit=limit)).hexdigest()


def exact(actual: Any, expected: Any) -> None:
    """Type-preserving comparison; Python's True == 1 is not wire equality."""
    if canonical_bytes(actual) != canonical_bytes(expected):
        _reject()


def _object(value: Any, keys: str) -> None:
    if type(value) is not dict or set(value) != set(keys.split()):
        _reject()


def _positive_id(value: Any) -> None:
    if type(value) is not int or not 0 < value <= MAX_ID:
        _reject()


def _hash(value: Any) -> None:
    _text(value, 64, 64)
    if _HASH.fullmatch(value) is None:
        _reject()


def _validate_procedure(value: Any) -> None:
    _object(value, "id definition")
    _positive_id(value["id"])
    exact(value["definition"], definition())


def _validate_backend(value: Any) -> None:
    _object(value, "id audience")
    _positive_id(value["id"])
    _text(value["audience"], 1, 255)


def _validate_target(value: Any) -> None:
    _object(value, "object_type object_id display")
    exact(value["object_type"], "dcim.device")
    _positive_id(value["object_id"])
    _text(value["display"], 1, 255)


def _validate_ssh(ssh: Any, object_id: int) -> None:
    _object(ssh, "ssh_service_id ssh_service_revision ssh_identity_id ssh_identity_revision "
            "ssh_storage_backend ssh_principal ssh_method ssh_host ssh_port "
            "ssh_known_hosts_sha256 ssh_policy_ref")
    for field in ("ssh_service_id", "ssh_identity_id"):
        _positive_id(ssh[field])
    for field in ("ssh_service_revision", "ssh_identity_revision"):
        _text(ssh[field], 1, 64)
        if _REVISION.fullmatch(ssh[field]) is None:
            _reject()
    _text(ssh["ssh_principal"], 1, 200)
    principal = ssh["ssh_principal"]
    if principal != principal.strip() or any(ord(char) < 32 or ord(char) == 127 for char in principal):
        _reject()
    if ssh["ssh_method"] not in ("key", "key_with_passphrase", "password"):
        _reject()
    _validate_ssh_endpoint(ssh, object_id)


def _validate_ssh_endpoint(ssh: dict[str, Any], object_id: int) -> None:
    _text(ssh["ssh_host"], 1, 15)
    try:
        exact(str(IPv4Address(ssh["ssh_host"])), ssh["ssh_host"])
    except ValueError:
        raise SnapshotContractError("Executable snapshot contract is invalid.") from None
    exact(ssh["ssh_port"], 22)
    exact(ssh["ssh_storage_backend"], "local")
    exact(ssh["ssh_policy_ref"], f"target-owned-ssh:dcim.device:{object_id}")
    _hash(ssh["ssh_known_hosts_sha256"])


def _validate_transport(value: Any, object_id: int) -> None:
    _object(value, "policy ssh")
    exact(value["policy"], definition()["runtime"])
    _validate_ssh(value["ssh"], object_id)


def _validate_steps(value: Any) -> None:
    if type(value) is not list or len(value) != 1:
        _reject()
    step = value[0]
    _object(step, "step_id command_id sequence argv timeout_seconds max_output_bytes captures")
    _positive_id(step["command_id"])
    exact(step, {
        "step_id": f"command:{step['command_id']}", "command_id": step["command_id"],
        "sequence": 1, "argv": ["/usr/bin/testparm", "-s"],
        "timeout_seconds": 20, "max_output_bytes": 0, "captures": [],
    })


def validate_snapshot(value: Any) -> dict[str, Any]:
    """Validate the closed executable object before digesting; return a detached copy."""
    encoded = canonical_bytes(value, limit=MAX_SNAPSHOT_BYTES)
    _object(value, "schema_version runtime runtime_version procedure backend requested_by_id "
            "approved_by_id target inputs transport steps")
    exact(value["schema_version"], 1)
    exact(value["runtime_version"], 1)
    exact(value["runtime"], "shell_argv")
    _validate_procedure(value["procedure"])
    _validate_backend(value["backend"])
    _positive_id(value["requested_by_id"])
    exact(value["approved_by_id"], None)
    _validate_target(value["target"])
    exact(value["inputs"], {})
    _validate_transport(value["transport"], value["target"]["object_id"])
    _validate_steps(value["steps"])
    # Every denial above completes before this first hash. The reviewed definition is
    # module text, so source drift must be proven here rather than only by the
    # separately called capability helper, which a consumer need never invoke.
    exact(digest(definition()), DEFINITION_SHA256)
    return json.loads(encoded)


def fingerprint(snapshot: Any) -> dict[str, Any]:
    frozen = validate_snapshot(snapshot)
    return {
        "executable_snapshot_schema_version": 1,
        "executable_snapshot_sha256": digest(frozen, limit=MAX_SNAPSHOT_BYTES),
        "executable_definition_sha256": DEFINITION_SHA256,
        "target_object_sha256": digest(frozen["target"]),
        "inputs_sha256": digest(frozen["inputs"]),
        "transport_policy_sha256": digest(frozen["transport"]),
    }


def capability_contract_hash() -> str:
    """Hash only the distinct alias; legacy command-contract derivation is untouched."""
    reviewed = definition()
    exact(digest(reviewed), DEFINITION_SHA256)
    result = digest({
        "handler_id": HANDLER_ID, "version": 1, "effect": "read",
        "commands": reviewed["commands"],
        "semantic_contract": {"executable_snapshot_v1": DEFINITION_SHA256},
    })
    exact(result, CONTRACT_SHA256)
    return result


def validate_projection(
    value: Any, *, execution_id: int, backend_id: int, audience: str
) -> dict[str, Any]:
    """Recompute all public bindings; this does not verify signatures or live rights."""
    encoded = canonical_bytes(value)
    _positive_id(execution_id)
    _positive_id(backend_id)
    _text(audience, 1, 255)
    _object(value, "id status procedure backend requested_by_id approved_by_id target inputs "
            "transport command_snapshot command_snapshot_sha256 command_fingerprint "
            "resolved_command_hash stream_version dispatch_lease_binding")
    frozen = validate_snapshot(value["command_snapshot"])
    exact(value["id"], execution_id)
    exact(value["status"], "running")
    exact(frozen["backend"], {"id": backend_id, "audience": audience})
    for field in ("backend", "requested_by_id", "approved_by_id", "target", "inputs", "transport"):
        exact(value[field], frozen[field])
    exact(value["procedure"], {**frozen["procedure"], "enabled": True})
    expected = fingerprint(frozen)
    exact(value["command_snapshot_sha256"], expected["executable_snapshot_sha256"])
    exact(value["command_fingerprint"], expected)
    exact(value["resolved_command_hash"], digest(expected))
    _validate_binding(value)
    return json.loads(encoded)


def _validate_binding(value: dict[str, Any]) -> None:
    _positive_id(value["stream_version"])
    binding = value["dispatch_lease_binding"]
    _object(binding, "claims_sha256 issued_stream_version")
    _positive_id(binding["issued_stream_version"])
    _hash(binding["claims_sha256"])
    exact(value["stream_version"], binding["issued_stream_version"])
