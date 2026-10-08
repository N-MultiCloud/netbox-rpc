"""Diagnostic compatibility and hostile-manifest projection contracts."""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import pytest

from test_capability_route import _load_capabilities


def _setup(monkeypatch):
    capabilities = _load_capabilities(monkeypatch)
    diagnostics = importlib.reload(importlib.import_module("netbox_rpc.capability_diagnostics"))
    monkeypatch.setattr(capabilities, "derive_command_contract_hash", lambda procedure: "a" * 64)
    procedure = SimpleNamespace(pk=151, handler_id="service.runner.diagnose", version=1, effect="read")
    return capabilities, diagnostics, procedure


@pytest.mark.parametrize("change,reason", [
    ({}, "compatible"),
    ({"version": 2}, "version_mismatch"),
    ({"effect": "write"}, "effect_mismatch"),
    ({"contract_hash": "b" * 64}, "contract_mismatch"),
    ({"contract_hash": "b" * 64, "compatible_contract_hashes": ["a" * 64]}, "compatible"),
])
def test_comparison_matches_authoritative_verifier(monkeypatch, change, reason):
    capabilities, diagnostics, procedure = _setup(monkeypatch)
    identity = dict(handler_id=procedure.handler_id, version=1, effect="read", contract_hash="a" * 64)
    identity.update(change)
    manifest = capabilities.BackendCapabilityManifest(envelope_version=1, handlers=[identity])
    entry = diagnostics.project_capabilities(1, [procedure], manifest)["procedures"][0]
    assert entry["reason"] == reason
    assert entry["status"] == capabilities.verify_procedure_capability(procedure, manifest).value
    assert entry["expected"]["contract_hash"] == "a" * 64


@pytest.mark.parametrize("envelope,handlers,reason", [(1, [], "missing_handler"), (2, [], "envelope_mismatch")])
def test_envelope_and_missing_handler_reasons(monkeypatch, envelope, handlers, reason):
    capabilities, diagnostics, procedure = _setup(monkeypatch)
    manifest = capabilities.BackendCapabilityManifest(envelope_version=envelope, handlers=handlers)
    assert diagnostics.project_capabilities(1, [procedure], manifest)["procedures"][0]["reason"] == reason


def test_unknown_manifest_is_explicit(monkeypatch):
    _, diagnostics, procedure = _setup(monkeypatch)
    result = diagnostics.project_capabilities(1, [procedure], None)
    assert result["manifest_available"] is False
    assert result["procedures"][0]["reason"] == "unknown_manifest"
    assert result["procedures"][0]["status"] == "unknown"


def test_secrets_and_unknown_handlers_are_never_projected(monkeypatch):
    capabilities, diagnostics, procedure = _setup(monkeypatch)
    manifest = capabilities.BackendCapabilityManifest(envelope_version=1, handlers=[
        dict(handler_id=procedure.handler_id, version=1, effect="read", contract_hash="Bearer private-secret"),
        dict(handler_id="private-secret", version=1, effect="read", contract_hash="a" * 64),
    ], authorization="private-secret", build_version="private-secret")
    result = diagnostics.project_capabilities(1, [procedure], manifest)
    assert "private-secret" not in json.dumps(result)
    assert "build_version" not in result
    assert result["procedures"][0]["advertised"] is None
    assert result["procedures"][0]["advertised_projection_valid"] is False


def test_catalog_and_envelope_bounds(monkeypatch):
    capabilities, diagnostics, procedure = _setup(monkeypatch)
    manifest = capabilities.BackendCapabilityManifest(envelope_version=2**100, handlers=[])
    result = diagnostics.project_capabilities(1, [procedure] * 201, manifest)
    assert result["catalog_truncated"] is True
    assert len(result["procedures"]) == 200
    assert result["advertised_envelope_version"] is None
    assert result["advertised_envelope_projection_valid"] is False
    assert len(json.dumps(result)) < 200000
