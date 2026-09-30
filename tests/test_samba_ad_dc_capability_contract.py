"""Fixed-fixture tests for the Samba AD DC semantic capability attestation.

``tests/fixtures/samba_ad_dc_capability_contract.json`` is the cross-repository
contract: netbox-rpc-backend pins the same installer digest, protocol and hashes.
Regenerate it after a deliberate installer or schema change with::

    python tests/test_samba_ad_dc_capability_contract.py --write-fixture
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/samba_ad_dc_capability_contract.json"
SEED = ROOT / "netbox_rpc/migrations/0103_seed_ubuntu_26_samba_ad_dc_procedures.py"

# Transcribed by hand from netbox-rpc-backend netbox_rpc_backend/rpc/samba_ad_dc.py
# and assets/samba_ad_dc_installer.py (MODES, PROTOCOL_VERSION).
EXPECTED_INSTALLER_SHA256 = (
    "df7a5fc827c56418e3b3b10320ed76c31395b87aa20a6bc5808ff2f0398caa0a"
)
EXPECTED_MODES = [
    "confirm_firewall",
    "preflight",
    "provision",
    "provision_continue",
    "rollback_firewall",
    "verify",
]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seed_module():
    stubs = {}
    for name in ("django", "django.db", "django.db.migrations"):
        stubs[name] = types.ModuleType(name)
    stubs["django.db.migrations"].Migration = type("Migration", (), {})
    stubs["django.db.migrations"].RunPython = lambda *a, **k: None
    stubs["django.db"].migrations = stubs["django.db.migrations"]
    stubs["django"].db = stubs["django.db"]
    saved = {k: sys.modules.get(k) for k in stubs}
    sys.modules.update(stubs)
    try:
        return _load(
            "samba_seed_for_capability_fixture", SEED.relative_to(ROOT).as_posix()
        )
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def _capabilities(monkeypatch: pytest.MonkeyPatch):
    netbox = types.ModuleType("netbox")
    plugins = types.ModuleType("netbox.plugins")
    plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", plugins)
    monkeypatch.delitem(sys.modules, "netbox_rpc.capabilities", raising=False)
    return importlib.import_module("netbox_rpc.capabilities")


def _procedure(row: dict, command: dict):
    cmd = SimpleNamespace(
        sequence=1, **{k: v for k, v in command.items() if k != "sequence"}
    )
    return SimpleNamespace(
        name=row["name"],
        handler_id=row["handler_id"],
        version=1,
        effect=row["effect"],
        target_models=list(_seed_module()._TARGET_MODELS),
        timeout_seconds=row["timeout_seconds"],
        approval_required=row["approval_required"],
        transport_driver="asyncssh",
        transport_pinned=True,
        transport_driver_chain=[],
        output_parser="none",
        output_schema={},
        params_schema=row["params_schema"],
        result_schema=row["result_schema"],
        commands=[cmd],
    )


def build_fixture(capabilities) -> dict:
    seed = _seed_module()
    contract = _load(
        "samba_cap_contract_fixture", "netbox_rpc/samba_ad_dc_capability_contract.py"
    )
    handlers = {}
    for row in seed._PROCEDURES:
        procedure = _procedure(row, seed._command(row["command_slug"]))
        extension = contract.semantic_capability_extension(procedure)
        handlers[row["handler_id"]] = {
            "params_schema_sha256": extension["procedure_policy"][
                "params_schema_sha256"
            ],
            "result_schema_sha256": extension["procedure_policy"][
                "result_schema_sha256"
            ],
            "semantic_contract_sha256": contract.canonical_sha256(extension),
            "contract_hash": capabilities.derive_command_contract_hash(procedure),
        }
    return {
        "contract_version": contract.CONTRACT_VERSION,
        "installer_sha256": contract.INSTALLER_SHA256,
        "protocol": contract.protocol_contract(),
        "handlers": handlers,
    }


def test_the_pinned_installer_and_protocol_match_the_reviewed_backend() -> None:
    contract = _load(
        "samba_cap_contract", "netbox_rpc/samba_ad_dc_capability_contract.py"
    )
    assert contract.INSTALLER_SHA256 == EXPECTED_INSTALLER_SHA256
    assert sorted(contract.INSTALLER_MODES) == EXPECTED_MODES
    assert contract.STDIN_PROTOCOL_VERSION == 1
    assert contract.FIREWALL_PROOF_PROTOCOL == "fresh-ssh-connection-confirm-v1"
    assert contract.RESULT_PROTOCOL == "samba-ad-dc-result-v1"


def test_the_fixture_equals_the_hashes_derived_from_the_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capabilities = _capabilities(monkeypatch)
    assert json.loads(FIXTURE.read_text()) == build_fixture(capabilities)


def test_the_fixture_pins_three_distinct_well_formed_hashes() -> None:
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["installer_sha256"] == EXPECTED_INSTALLER_SHA256
    for handler_id, entry in fixture["handlers"].items():
        assert handler_id.startswith("os.linux.ubuntu.26.samba_ad_dc.")
        for key, value in entry.items():
            assert len(value) == 64 and set(value) <= set("0123456789abcdef"), key
    assert len(fixture["handlers"]) == 3
    for key in ("contract_hash", "semantic_contract_sha256", "result_schema_sha256"):
        assert len({entry[key] for entry in fixture["handlers"].values()}) == 3, key
    # preflight and verify legitimately share the same closed params schema.
    params = {e["params_schema_sha256"] for e in fixture["handlers"].values()}
    assert len(params) == 2


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: setattr(p, "timeout_seconds", 1),
        lambda p: setattr(p, "approval_required", not p.approval_required),
        lambda p: setattr(p, "transport_pinned", False),
        lambda p: setattr(p, "transport_driver", "ansible"),
        lambda p: setattr(p, "target_models", ["dcim.device"]),
        lambda p: setattr(p, "params_schema", {**p.params_schema, "x": 1}),
        lambda p: setattr(p, "result_schema", {**p.result_schema, "x": 1}),
        lambda p: setattr(p.commands[0], "argv", ["backend-orchestrated", "x"]),
    ],
)
def test_any_catalog_drift_changes_the_contract_hash(
    monkeypatch: pytest.MonkeyPatch, mutate
) -> None:
    capabilities = _capabilities(monkeypatch)
    seed = _seed_module()
    row = seed._PROCEDURES[1]
    baseline = _procedure(row, seed._command(row["command_slug"]))
    drifted = _procedure(row, seed._command(row["command_slug"]))
    mutate(drifted)
    assert capabilities.derive_command_contract_hash(
        drifted
    ) != capabilities.derive_command_contract_hash(baseline)


def test_a_new_installer_digest_changes_every_handler_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capabilities = _capabilities(monkeypatch)
    seed = _seed_module()
    contract = (
        sys.modules["netbox_rpc.samba_ad_dc_capability_contract"]
        if ("netbox_rpc.samba_ad_dc_capability_contract" in sys.modules)
        else importlib.import_module("netbox_rpc.samba_ad_dc_capability_contract")
    )
    before = {}
    for row in seed._PROCEDURES:
        p = _procedure(row, seed._command(row["command_slug"]))
        before[row["name"]] = capabilities.derive_command_contract_hash(p)
    monkeypatch.setattr(contract, "INSTALLER_SHA256", "0" * 64)
    for row in seed._PROCEDURES:
        p = _procedure(row, seed._command(row["command_slug"]))
        assert capabilities.derive_command_contract_hash(p) != before[row["name"]]


def test_the_capability_hash_uses_the_semantic_contract_for_these_handlers() -> None:
    source = (ROOT / "netbox_rpc/capabilities.py").read_text()
    assert "if handler_id in SAMBA_AD_DC_HANDLER_IDS:" in source
    assert (
        'payload["semantic_contract"] = samba_semantic_extension(procedure)' in source
    )


if __name__ == "__main__":
    if "--write-fixture" not in sys.argv:
        raise SystemExit(
            "usage: test_samba_ad_dc_capability_contract.py --write-fixture"
        )
    sys.path.insert(0, str(ROOT))
    plugins = types.ModuleType("netbox.plugins")
    plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    sys.modules["netbox"] = types.ModuleType("netbox")
    sys.modules["netbox.plugins"] = plugins
    caps = importlib.import_module("netbox_rpc.capabilities")
    FIXTURE.write_text(json.dumps(build_fixture(caps), indent=2, sort_keys=True) + "\n")
    print(f"wrote {FIXTURE}")
