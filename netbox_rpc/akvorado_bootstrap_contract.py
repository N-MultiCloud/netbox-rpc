"""Semantic capability contract for the Debian 13 Akvorado bootstrap."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .constants import (
    AKVORADO_1_PROCEDURE_NAMES,
    AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL,
    AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL_HANDLER,
    AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT,
    AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT_HANDLER,
)

AKVORADO_BOOTSTRAP_HANDLER_IDS = frozenset(
    {
        AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT_HANDLER,
        AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL_HANDLER,
    }
)
AKVORADO_LIFECYCLE_HANDLER_IDS = frozenset(AKVORADO_1_PROCEDURE_NAMES)

# A complete Akvorado response is small, but keep enough room for all bounded
# service and warning fields while preventing an authenticated backend from
# streaming an unbounded body into the worker.
BACKEND_RESPONSE_MAX_BYTES = 64 * 1024

_TARGET_OBJECT_SCHEMA = {
    "type": "object",
    "required": ["content_type", "object_id"],
    "additionalProperties": False,
    "properties": {
        "content_type": {"const": "dcim.device"},
        "object_id": {"type": "integer", "minimum": 1},
    },
}

_SSH_APPROVAL_SNAPSHOT_SCHEMA = {
    "type": "object",
    "required": [
        "ssh_service_id",
        "ssh_service_revision",
        "ssh_identity_id",
        "ssh_identity_revision",
        "ssh_storage_backend",
        "ssh_principal",
        "ssh_method",
        "ssh_host",
        "ssh_port",
        "ssh_strict_host_key_checking",
        "ssh_known_hosts_sha256",
        "ssh_policy_ref",
    ],
    "additionalProperties": False,
    "properties": {
        "ssh_service_id": {"type": "integer", "minimum": 1},
        "ssh_service_revision": {"type": "string", "format": "date-time"},
        "ssh_identity_id": {"type": "integer", "minimum": 1},
        "ssh_identity_revision": {"type": "string", "format": "date-time"},
        "ssh_storage_backend": {"const": "local"},
        "ssh_principal": {"type": "string", "minLength": 1, "maxLength": 200},
        "ssh_method": {"enum": ["password", "key", "key_with_passphrase"]},
        "ssh_host": {"type": "string", "format": "ipv4"},
        "ssh_port": {"const": 22},
        "ssh_strict_host_key_checking": {"const": True},
        "ssh_known_hosts_sha256": {
            "type": "string",
            "pattern": r"^[0-9a-f]{64}$",
        },
        "ssh_policy_ref": {
            "type": "string",
            "pattern": r"^target-owned-ssh:dcim\.device:[1-9][0-9]*$",
        },
    },
}


def _command_fingerprint_schema(
    procedure: str,
    handler_id: str,
    *,
    install: bool,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "handler_id": {"const": handler_id},
        "procedure": {"const": procedure},
        "target_content_type": {"const": "dcim.device"},
        "target_object_id": {"type": "integer", "minimum": 1},
    }
    required = list(properties)
    if install:
        properties.update(
            {
                "allow_resource_shortfall": {"type": "boolean"},
                "target_object_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "ssh_snapshot": _SSH_APPROVAL_SNAPSHOT_SCHEMA,
                "ssh_policy_ref": {
                    "type": "string",
                    "pattern": r"^target-owned-ssh:dcim\.device:[1-9][0-9]*$",
                },
            }
        )
        required.extend(
            [
                "allow_resource_shortfall",
                "target_object_sha256",
                "ssh_snapshot",
                "ssh_policy_ref",
            ]
        )
    return {
        "type": "object",
        "required": required,
        "additionalProperties": False,
        "properties": properties,
    }


def _normalized_params_schema(
    procedure: str,
    handler_id: str,
    *,
    install: bool,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "target": {"type": "string", "minLength": 1, "maxLength": 255},
        "target_object": _TARGET_OBJECT_SCHEMA,
        "command_fingerprint": _command_fingerprint_schema(
            procedure,
            handler_id,
            install=install,
        ),
    }
    required = list(properties)
    if install:
        properties.update(
            {
                "allow_resource_shortfall": {"type": "boolean"},
                "ssh_snapshot": _SSH_APPROVAL_SNAPSHOT_SCHEMA,
                "ssh_policy_ref": {
                    "type": "string",
                    "pattern": r"^target-owned-ssh:dcim\.device:[1-9][0-9]*$",
                },
            }
        )
        required.extend(
            ["allow_resource_shortfall", "ssh_snapshot", "ssh_policy_ref"]
        )
    return {
        "type": "object",
        "required": required,
        "additionalProperties": False,
        "properties": properties,
    }


AKVORADO_BOOTSTRAP_COMMAND_FINGERPRINT_SCHEMAS = {
    AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT: _command_fingerprint_schema(
        AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT,
        AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT_HANDLER,
        install=False,
    ),
    AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL: _command_fingerprint_schema(
        AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL,
        AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL_HANDLER,
        install=True,
    ),
}
AKVORADO_BOOTSTRAP_NORMALIZED_PARAMS_SCHEMAS = {
    AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT: _normalized_params_schema(
        AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT,
        AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT_HANDLER,
        install=False,
    ),
    AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL: _normalized_params_schema(
        AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL,
        AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL_HANDLER,
        install=True,
    ),
}

_LIFECYCLE_TARGET_OBJECT_SCHEMA = {
    "type": "object",
    "required": ["content_type", "object_id"],
    "additionalProperties": False,
    "properties": {
        "content_type": {
            "enum": ["dcim.device", "virtualization.virtualmachine"]
        },
        "object_id": {"type": "integer", "minimum": 1},
    },
}


def _lifecycle_command_fingerprint_schema(
    procedure: str,
    *,
    config_deploy: bool,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "handler_id": {"const": procedure},
        "procedure": {"const": procedure},
        "target_object": _LIFECYCLE_TARGET_OBJECT_SCHEMA,
    }
    required = list(properties)
    if config_deploy:
        properties.update(
            {
                "config_content_sha256": {
                    "type": "string",
                    "pattern": r"^[0-9a-f]{64}$",
                },
                "config_content_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1024 * 1024,
                },
            }
        )
        required.extend(["config_content_sha256", "config_content_bytes"])
    return {
        "type": "object",
        "required": required,
        "additionalProperties": False,
        "properties": properties,
    }


def _lifecycle_normalized_params_schema(
    procedure: str,
    *,
    config_deploy: bool,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "target": {"type": "string", "minLength": 1, "maxLength": 255},
        "target_object": _LIFECYCLE_TARGET_OBJECT_SCHEMA,
        "command_fingerprint": _lifecycle_command_fingerprint_schema(
            procedure,
            config_deploy=config_deploy,
        ),
    }
    required = list(properties)
    if config_deploy:
        properties["config_content"] = {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024 * 1024,
        }
        required.append("config_content")
    return {
        "type": "object",
        "required": required,
        "additionalProperties": False,
        "properties": properties,
    }


AKVORADO_LIFECYCLE_COMMAND_FINGERPRINT_SCHEMAS = {
    procedure: _lifecycle_command_fingerprint_schema(
        procedure,
        config_deploy=procedure == "service.akvorado.1.config_deploy",
    )
    for procedure in AKVORADO_1_PROCEDURE_NAMES
}
AKVORADO_LIFECYCLE_NORMALIZED_PARAMS_SCHEMAS = {
    procedure: _lifecycle_normalized_params_schema(
        procedure,
        config_deploy=procedure == "service.akvorado.1.config_deploy",
    )
    for procedure in AKVORADO_1_PROCEDURE_NAMES
}
# Populated with reviewed full semantic digests after both repositories derive
# identical contracts. Verification uses these exact values to bound the one-
# release command-only compatibility window; arbitrary policy drift cannot use it.
AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES: dict[str, str] = {
    "service.akvorado.1.config_deploy": (
        "6a8d8fee107c3c825db6bf334ccecfdec8a71135bd6cd2e89734b85a00de2082"
    ),
    "service.akvorado.1.config_read": (
        "5c9faf273d18d2316c1f00453d03cdce0ea6ca6eae416a1f0168f7dd412f53e6"
    ),
    "service.akvorado.1.restart_stack": (
        "472ed07c0582ebeaaaa7b5da8490bdab2386f1183910a3593c5eee8d5c707d49"
    ),
    "service.akvorado.1.status_stack": (
        "682f89b76b6246cbc88d4ac223c9201cd69efabacaf8dcf2da7137a6b484b785"
    ),
}
AKVORADO_BOOTSTRAP_CURRENT_CAPABILITY_HASHES: dict[str, str] = {
    "os.linux.debian.13.preflight_akvorado": (
        "50ab427bb1f4fee18a76fbe00f19a65b9cbb03d3c1951d9f500b0da6938ece03"
    ),
    "os.linux.debian.13.install_akvorado": (
        "b9ec74c18c69c53c494155671c638f878b1c74b6d1cf478b8665f822ab4469a6"
    ),
}

AKVORADO_BOOTSTRAP_RUNTIME_CONTRACT = {
    "platform": {
        "os_id": "debian",
        "version_id": "13",
        "architectures": ["amd64", "arm64"],
        "init": "systemd",
    },
    "minimum_resources": {
        "vcpus": 8,
        "memory_bytes": 16 * 1024**3,
        "root_free_bytes": 50 * 1024**3,
    },
    "packages": {
        "source": "isolated-official-debian-13-trixie-and-security",
        "uris": [
            "http://deb.debian.org/debian",
            "http://deb.debian.org/debian-security",
        ],
        "suites": ["trixie", "trixie-updates", "trixie-security"],
        "signed_by": "/usr/share/keyrings/debian-archive-keyring.gpg",
        "selection": "candidate-version-pinned-and-postinstall-verified",
        "names": [
            "ca-certificates",
            "curl",
            "docker.io",
            "docker-compose",
            "iproute2",
        ],
    },
    "images": [
        "apache/kafka:4.2.0@sha256:9516fb7634bad307d17c33b589fde9023003b0cb761374f500002b980a3149b9",
        "clickhouse/clickhouse-server:26.3@sha256:6bd7fcbc7cf9c4ba0c7ef565c96534a065fde17c086a750539c1a947ca7aa3f7",
        "quay.io/akvorado/akvorado:2.4.0@sha256:e2db22ad28989523a300cee8d0d05de5070235ad0c9583c69a12075e1399cdb0",
        "valkey/valkey:9.0@sha256:2437dbc85bb67005fa7db135dfbc45075b800f4afa1ab2a301e3b878b0c273e2",
    ],
    "services": [
        "clickhouse",
        "console",
        "inlet",
        "kafka",
        "orchestrator",
        "outlet",
        "redis",
    ],
    "paths": {
        "compose_dir": "/opt/nmulticloud/deploy/compose/akvorado",
        "compose": "/opt/nmulticloud/deploy/compose/akvorado/docker-compose.yml",
        "environment": "/opt/nmulticloud/deploy/compose/akvorado/.env",
        "configuration": "/opt/nmulticloud/deploy/compose/akvorado/akvorado.yaml",
        "ownership": (
            "/opt/nmulticloud/deploy/compose/akvorado/"
            ".netbox-rpc-bootstrap-owner"
        ),
    },
    "ingress_ports": [
        {"protocol": "tcp", "port": 8080, "purpose": "console-loopback"},
        {"protocol": "tcp", "port": 10179, "purpose": "bmp"},
        {"protocol": "udp", "port": 2055, "purpose": "netflow"},
        {"protocol": "udp", "port": 4739, "purpose": "ipfix"},
        {"protocol": "udp", "port": 6343, "purpose": "sflow"},
    ],
    "configuration_policy": "create-if-absent-preserve-existing",
    "managed_file_policy": "marker-required-atomic-replace-with-rollback",
    "ownership_marker": "netbox-rpc-backend:akvorado-debian13:v1",
    "host_key_policy": "preflight-observe-then-probe-pinned-install-pinned",
    "credential_policy": "assigned-device-enabled-ssh-service-only",
    "approval_ssh_snapshot_policy": (
        "service-and-local-credential-revisions-host-port-principal-method-"
        "strict-known-host-policy-ref"
    ),
    "sudo_policy": "stdin-secret-consumed-before-nopasswd-validation",
    "bootstrap_lock": "/run/lock/netbox-rpc-akvorado-bootstrap.lock",
    "configuration_lock": (
        "/opt/nmulticloud/deploy/compose/akvorado/.config-activate.lock"
    ),
    "backend_deadline_seconds": 1140,
    "route_deadline_seconds": {"preflight": 90, "install": 1200},
    "required_proxy_read_timeout_seconds": 7260,
    "asset_sha256": {
        "environment": "c738844aeae5da9be9c39e67d479c5abb25cb1c8feb712d8e5d5669b6a188c12",
        "compose": "2f255cf3aaf0d927acfb920ea57943870906832f357c67a02989a73c75328a1b",
        "initial_configuration": "9605ce0614ae5dc7eb47a7aa1f79404f0e7476816e3d49641f417ab1d7c26513",
        "preflight_script": "ae2f4eda7ca551a8399eaccd14a81a571c637c287b446c56f9ef8836c6d6d948",
        "install_script": "72ecd06f7fc526419e6643843ffc4e4d53e26f3a219b6e6713d0fdfd8aedec25",
        "sudo_wrapper": "fd005d45662534e7ab4a6511719bf0747d9a650b7a80f9a2455a29e30ef5d765",
    },
    "result_states": {
        "success": "complete-exact-seven-services-ready-empty-error",
        "known_failure": "noncomplete-known-booleans-nonempty-error",
        "unknown": "outcome_unknown-null-mutation-state-nonempty-error",
    },
}

AKVORADO_LIFECYCLE_SEMANTIC_CONTRACT = {
    "assets": {
        "environment_sha256": "c738844aeae5da9be9c39e67d479c5abb25cb1c8feb712d8e5d5669b6a188c12",
        "compose_sha256": "2f255cf3aaf0d927acfb920ea57943870906832f357c67a02989a73c75328a1b",
        "image_references": AKVORADO_BOOTSTRAP_RUNTIME_CONTRACT["images"],
        "console_binding": "127.0.0.1:8080/tcp",
        "compose_path": "/opt/nmulticloud/deploy/compose/akvorado/docker-compose.yml",
        "configuration_path": "/opt/nmulticloud/deploy/compose/akvorado/akvorado.yaml",
        "configuration_lock": (
            "/opt/nmulticloud/deploy/compose/akvorado/.config-activate.lock"
        ),
        "ownership_path": (
            "/opt/nmulticloud/deploy/compose/akvorado/"
            ".netbox-rpc-bootstrap-owner"
        ),
        "ownership_marker": "netbox-rpc-backend:akvorado-debian13:v1",
        "mutation_protocol": (
            "one-flock-stage-atomic-activate-converge-verify-rollback"
        ),
        "restart_stack_script_sha256": (
            "caef16c00375dafaa6ef7167fad6f37acaa0bab14263d95eeb67addb321c3b73"
        ),
        "orchestrator_restart_command_sha256": (
            "ae8ed9c034f17fa0f4e2bd24bf8149ee454344eb3080c7c2fcc22586cc553db4"
        ),
    }
}


def _fingerprint(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


canonical_sha256 = _fingerprint


def semantic_capability_extension(procedure: Any) -> dict[str, Any]:
    """Bind capability compatibility to catalog policy and runtime semantics."""
    procedure_name = str(getattr(procedure, "name", ""))
    return {
        "procedure_policy": {
            "name": str(getattr(procedure, "name", "")),
            "description": str(getattr(procedure, "description", "")),
            "target_models": sorted(getattr(procedure, "target_models", []) or []),
            "timeout_seconds": int(getattr(procedure, "timeout_seconds", 0) or 0),
            "approval_required": bool(
                getattr(procedure, "approval_required", False)
            ),
            "transport_driver": str(
                getattr(procedure, "transport_driver", "")
            ),
            "transport_pinned": bool(
                getattr(procedure, "transport_pinned", False)
            ),
            "transport_driver_chain": list(
                getattr(procedure, "transport_driver_chain", []) or []
            ),
            "output_parser": str(getattr(procedure, "output_parser", "")),
            "output_schema_sha256": _fingerprint(
                getattr(procedure, "output_schema", {}) or {}
            ),
            "params_schema_sha256": _fingerprint(
                getattr(procedure, "params_schema", {}) or {}
            ),
            "result_schema_sha256": _fingerprint(
                getattr(procedure, "result_schema", {}) or {}
            ),
            "normalized_params_schema_sha256": _fingerprint(
                AKVORADO_BOOTSTRAP_NORMALIZED_PARAMS_SCHEMAS[procedure_name]
            ),
            "command_fingerprint_schema_sha256": _fingerprint(
                AKVORADO_BOOTSTRAP_COMMAND_FINGERPRINT_SCHEMAS[procedure_name]
            ),
        },
        "runtime": AKVORADO_BOOTSTRAP_RUNTIME_CONTRACT,
    }


def lifecycle_semantic_capability_extension(procedure: Any) -> dict[str, Any]:
    """Bind each lifecycle handler to its authorization and normalized policy."""
    procedure_name = str(getattr(procedure, "name", ""))
    return {
        "procedure_policy": {
            "name": procedure_name,
            "description": str(getattr(procedure, "description", "")),
            "target_models": sorted(getattr(procedure, "target_models", []) or []),
            "timeout_seconds": int(getattr(procedure, "timeout_seconds", 0) or 0),
            "approval_required": bool(
                getattr(procedure, "approval_required", False)
            ),
            "transport_driver": str(
                getattr(procedure, "transport_driver", "")
            ),
            "transport_pinned": bool(
                getattr(procedure, "transport_pinned", False)
            ),
            "transport_driver_chain": list(
                getattr(procedure, "transport_driver_chain", []) or []
            ),
            "output_parser": str(getattr(procedure, "output_parser", "")),
            "output_schema_sha256": _fingerprint(
                getattr(procedure, "output_schema", {}) or {}
            ),
            "params_schema_sha256": _fingerprint(
                getattr(procedure, "params_schema", {}) or {}
            ),
            "result_schema_sha256": _fingerprint(
                getattr(procedure, "result_schema", {}) or {}
            ),
            "normalized_params_schema_sha256": _fingerprint(
                AKVORADO_LIFECYCLE_NORMALIZED_PARAMS_SCHEMAS[procedure_name]
            ),
            "command_fingerprint_schema_sha256": _fingerprint(
                AKVORADO_LIFECYCLE_COMMAND_FINGERPRINT_SCHEMAS[procedure_name]
            ),
        },
        "runtime": AKVORADO_LIFECYCLE_SEMANTIC_CONTRACT,
    }


__all__ = [
    "AKVORADO_BOOTSTRAP_CURRENT_CAPABILITY_HASHES",
    "AKVORADO_BOOTSTRAP_HANDLER_IDS",
    "AKVORADO_BOOTSTRAP_COMMAND_FINGERPRINT_SCHEMAS",
    "AKVORADO_BOOTSTRAP_NORMALIZED_PARAMS_SCHEMAS",
    "AKVORADO_BOOTSTRAP_RUNTIME_CONTRACT",
    "AKVORADO_LIFECYCLE_HANDLER_IDS",
    "AKVORADO_LIFECYCLE_CURRENT_CAPABILITY_HASHES",
    "AKVORADO_LIFECYCLE_COMMAND_FINGERPRINT_SCHEMAS",
    "AKVORADO_LIFECYCLE_NORMALIZED_PARAMS_SCHEMAS",
    "AKVORADO_LIFECYCLE_SEMANTIC_CONTRACT",
    "BACKEND_RESPONSE_MAX_BYTES",
    "canonical_sha256",
    "lifecycle_semantic_capability_extension",
    "semantic_capability_extension",
]
