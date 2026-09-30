from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "netbox_rpc/migrations/0093_seed_proxmox_oci_registry_pull.py"
HANDLER_ID = "os.linux_proxmox.oci_registry_pull"
PROCEDURE_NAME = "os.linux.proxmox.oci_registry_pull"


class _MigrationLiteralNames(ast.NodeTransformer):
    values = {
        "_NAME": PROCEDURE_NAME,
        "_HANDLER": HANDLER_ID,
    }

    def visit_Name(self, node: ast.Name):  # noqa: N802
        if node.id in self.values:
            return ast.copy_location(ast.Constant(self.values[node.id]), node)
        if node.id in {"_PARAMS_SCHEMA", "_RESULT_SCHEMA"}:
            return ast.copy_location(
                ast.Constant(_literal_assignment(node.id)),
                node,
            )
        return node


def _literal_assignment(name: str) -> dict[str, object]:
    module = ast.parse(MIGRATION.read_text())
    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in statement.targets
        ):
            expression = statement.value
            for node in ast.walk(expression):
                if isinstance(node, ast.Name) and node.id == "_HANDLER":
                    node.__class__ = ast.Constant
                    node.value = HANDLER_ID
                    del node.id
            value = ast.literal_eval(expression)
            assert isinstance(value, dict)
            return value
    raise AssertionError(f"Missing migration assignment: {name}")


def _create_kwargs(model_name: str) -> dict[str, object]:
    module = ast.parse(MIGRATION.read_text())
    for node in ast.walk(module):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if (
            node.func.attr != "create"
            or not isinstance(owner, ast.Attribute)
            or owner.attr != "objects"
            or not isinstance(owner.value, ast.Name)
            or owner.value.id != model_name
        ):
            continue
        values = {}
        for keyword in node.keywords:
            assert keyword.arg is not None
            if keyword.arg == "procedure":
                continue
            expression = _MigrationLiteralNames().visit(keyword.value)
            ast.fix_missing_locations(expression)
            values[keyword.arg] = ast.literal_eval(expression)
        return values
    raise AssertionError(f"Missing {model_name}.objects.create call")


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


def _load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pull_is_registered_as_a_protected_two_person_procedure() -> None:
    constants = _load_module("proxmox_oci_constants", "netbox_rpc/constants.py")

    assert PROCEDURE_NAME in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert PROCEDURE_NAME in constants.EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES


def test_immutable_contract_matches_seeded_catalog() -> None:
    contract = _load_module(
        "proxmox_oci_pull_contract_under_test",
        "netbox_rpc/proxmox_oci_pull_contract.py",
    )

    procedure = _create_kwargs("RPCProcedure")
    command = _create_kwargs("RPCProcedureCommand")
    expected_policy = {
        key: value
        for key, value in procedure.items()
        if key not in {"description", "params_schema", "result_schema"}
    }
    expected_policy["command_contract_sha256"] = contract.canonical_sha256([command])

    assert contract.PARAMS_SCHEMA == _literal_assignment("_PARAMS_SCHEMA")
    assert contract.RESULT_SCHEMA == _literal_assignment("_RESULT_SCHEMA")
    assert contract.PROCEDURE_POLICY == expected_policy
    assert contract.COMMAND_CONTRACT == [command]


def test_pull_is_registered_in_every_protected_runtime_map() -> None:
    source = (ROOT / "netbox_rpc/application/command_handlers.py").read_text()

    assert "LINUX_PROXMOX_OCI_REGISTRY_PULL: proxmox_oci_pull_contract" in source
    assert (
        "LINUX_PROXMOX_OCI_REGISTRY_PULL: _PROXMOX_OCI_PULL_APPROVAL_REASON" in source
    )
    assert (
        "LINUX_PROXMOX_OCI_REGISTRY_PULL: _PROXMOX_OCI_PULL_REJECTION_REASON" in source
    )
    assert 'LINUX_PROXMOX_OCI_REGISTRY_PULL: "Proxmox OCI registry pull"' in source
