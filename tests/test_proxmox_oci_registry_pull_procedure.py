from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "netbox_rpc/migrations/0093_seed_proxmox_oci_registry_pull.py"
HANDLER_ID = "os.linux_proxmox.oci_registry_pull"


def _literal_assignment(name: str) -> dict[str, object]:
    module = ast.parse(MIGRATION.read_text())
    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in statement.targets
        ):
            value = ast.literal_eval(statement.value)
            assert isinstance(value, dict)
            return value
    raise AssertionError(f"Missing migration assignment: {name}")


def test_migration_is_expand_only_and_approval_gated() -> None:
    source = MIGRATION.read_text()

    assert '("netbox_rpc", "0092_seed_gitea_org_docker_network_recovery")' in source
    assert 'effect="write"' in source
    assert "approval_required=True" in source
    assert "transport_pinned=True" in source
    assert 'transport_driver="asyncssh"' in source
    assert "transport_driver_chain=[]" in source
    assert 'target_models=["netbox_proxbox.proxmoxendpoint"]' in source
    assert "DeleteModel" not in source
    assert "RemoveField" not in source
    assert "AlterField" not in source


def test_schema_is_closed_and_restricts_the_public_repository() -> None:
    schema = _literal_assignment("_PARAMS_SCHEMA")

    assert schema["additionalProperties"] is False
    assert schema["required"] == [
        "proxmox_endpoint_id",
        "node",
        "storage",
        "reference",
    ]
    reference = schema["properties"]["reference"]
    assert "emersonfelipesp/netbox-proxbox" in reference["pattern"]
    assert reference["maxLength"] <= 255
    assert schema["properties"]["filename"]["maxLength"] == 255


def test_handler_has_a_documented_command_contract_exemption() -> None:
    spec = importlib.util.spec_from_file_location(
        "proxmox_oci_pull_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec is not None and spec.loader is not None
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    assert HANDLER_ID in command_contract.EXEMPT_HANDLER_IDS
    assert command_contract.EXEMPT_HANDLER_RATIONALE[HANDLER_ID].strip()
