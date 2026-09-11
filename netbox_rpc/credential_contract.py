"""Dependency-light, immutable metadata contract shared with credential providers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from jsonschema import Draft202012Validator
from jsonschema import ValidationError as SchemaValidationError

MAX_REFERENCE_LEASE_SECONDS = 300

_NAME_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_POSITIVE_ID = {"type": "integer", "minimum": 1, "maximum": 9007199254740991}
_REFERENCE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "provider",
        "target",
        "purpose",
        "fields",
        "version",
    ],
    "properties": {
        "schema_version": {"type": "integer", "const": 1},
        "provider": {"const": "netbox-openbao"},
        "assignment_id": _POSITIVE_ID,
        "credential_uuid": {"type": "string", "minLength": 36, "maxLength": 36},
        "target": {
            "type": "object",
            "additionalProperties": False,
            "required": ["object_type", "object_id"],
            "properties": {
                "object_type": {
                    "type": "string",
                    "maxLength": 129,
                    "pattern": r"^[a-z][a-z0-9_]{0,63}\.[a-z][a-z0-9_]{0,63}$",
                },
                "object_id": _POSITIVE_ID,
            },
        },
        "purpose": {
            "enum": ["login", "enable", "console", "oob", "api", "agent", "backup"]
        },
        "fields": {
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "uniqueItems": True,
            "items": {"type": "string", "maxLength": 64, "pattern": _NAME_PATTERN},
        },
        "version": {
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["policy"],
                    "properties": {"policy": {"const": "live"}},
                },
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["policy", "number"],
                    "properties": {
                        "policy": {"const": "pinned"},
                        "number": _POSITIVE_ID,
                    },
                },
            ],
        },
    },
    "oneOf": [{"required": ["assignment_id"]}, {"required": ["credential_uuid"]}],
}


class CredentialContractError(ValueError):
    """Value-free failure: callers must never render validation input in errors."""


def canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class TargetReference:
    object_type: str
    object_id: int


@dataclass(frozen=True)
class CredentialVersionPolicy:
    policy: str
    number: int | None = None


@dataclass(frozen=True)
class CredentialReferenceV1:
    schema_version: int
    provider: str
    assignment_id: int | None
    credential_uuid: str | None
    target: TargetReference
    purpose: str
    fields: tuple[str, ...]
    version: CredentialVersionPolicy

    @classmethod
    def from_mapping(cls, value: object) -> CredentialReferenceV1:
        try:
            Draft202012Validator(_REFERENCE_SCHEMA).validate(value)
            _strict_reference_integers(value)
            identifier = value.get("credential_uuid")
            if identifier is not None and str(UUID(identifier)) != identifier:
                raise ValueError("noncanonical UUID")
            # JSON Schema's `$` accepts a trailing newline; use fullmatch too.
            for field in value["fields"]:
                if re.fullmatch(_NAME_PATTERN, field) is None:
                    raise ValueError("invalid field")
            label = value["target"]["object_type"]
            if (
                re.fullmatch(r"[a-z][a-z0-9_]{0,63}\.[a-z][a-z0-9_]{0,63}", label)
                is None
            ):
                raise ValueError("invalid target")
        except (SchemaValidationError, ValueError, TypeError, AttributeError):
            raise CredentialContractError(
                "Invalid credential reference contract."
            ) from None
        return cls(
            schema_version=1,
            provider="netbox-openbao",
            assignment_id=value.get("assignment_id"),
            credential_uuid=identifier,
            target=TargetReference(label, value["target"]["object_id"]),
            purpose=value["purpose"],
            fields=tuple(value["fields"]),
            version=CredentialVersionPolicy(
                value["version"]["policy"], value["version"].get("number")
            ),
        )

    def to_mapping(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "target": {
                "object_type": self.target.object_type,
                "object_id": self.target.object_id,
            },
            "purpose": self.purpose,
            "fields": list(self.fields),
            "version": {"policy": self.version.policy},
        }
        if self.assignment_id is not None:
            value["assignment_id"] = self.assignment_id
        else:
            value["credential_uuid"] = self.credential_uuid
        if self.version.number is not None:
            value["version"]["number"] = self.version.number
        return value


def _strict_reference_integers(value: dict) -> None:
    numbers = [value["schema_version"], value["target"]["object_id"]]
    if "assignment_id" in value:
        numbers.append(value["assignment_id"])
    if "number" in value["version"]:
        numbers.append(value["version"]["number"])
    if any(type(number) is not int for number in numbers):
        raise CredentialContractError("Reference identifiers require exact integers.")


def validate_named_references(value: object) -> dict[str, Any]:
    """Normalize a bounded mapping without ever accepting material or selectors."""
    if not isinstance(value, dict) or len(value) > 16:
        raise CredentialContractError("Invalid named credential references.")
    result = {}
    for name, reference in value.items():
        if not isinstance(name, str) or re.fullmatch(_NAME_PATTERN, name) is None:
            raise CredentialContractError("Invalid credential reference name.")
        result[name] = CredentialReferenceV1.from_mapping(reference).to_mapping()
    return result


def apply_credential_fingerprint(execution: object, normalized: dict[str, Any]) -> None:
    references = getattr(execution, "credential_references", None)
    if not references:
        return
    references = validate_named_references(references)
    snapshot = getattr(execution, "credential_authority", {})
    if not snapshot or snapshot.get("references") != references:
        raise CredentialContractError("Credential authority snapshot does not match.")
    normalized["credential_references"] = references
    fingerprint = normalized.setdefault("command_fingerprint", {})
    fingerprint["credential_authority_sha256"] = canonical_hash(snapshot)
    normalized["credential_policy_ref"] = "credential-authority:" + canonical_hash(
        snapshot
    )


def public_credential_metadata(value: object, key: str) -> object | None:
    """Allow only validated public references through event redaction."""
    if key == "credential_references":
        try:
            return validate_named_references(value)
        except CredentialContractError:
            return None
    patterns = {
        "credential_authority_sha256": r"[0-9a-f]{64}",
        "credential_policy_ref": r"credential-authority:[0-9a-f]{64}",
    }
    if (
        key in patterns
        and isinstance(value, str)
        and re.fullmatch(patterns[key], value)
    ):
        return value
    return None
