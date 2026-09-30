"""Contracts for the default-dark protected publication runner pair."""

from __future__ import annotations

import importlib.util
import runpy
import sys
import types
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
contract = SimpleNamespace(
    **runpy.run_path(
        str(ROOT / "netbox_rpc/gitea_protected_publication_pair_contract.py")
    )
)
constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))


class _Query:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows

    def first(self):
        return self.rows[0] if self.rows else None

    def order_by(self, _field: str):
        return self

    def __iter__(self):
        return iter(self.rows)

    def update(self, **values: object) -> int:
        for row in self.rows:
            for key, value in values.items():
                setattr(row, key, value)
        return len(self.rows)


class _Manager:
    def __init__(self, *, command: bool = False) -> None:
        self.rows: list[object] = []
        self.command = command

    def filter(self, **values: object) -> _Query:
        if "name__in" in values:
            return _Query([row for row in self.rows if row.name in values["name__in"]])
        if self.command:
            return _Query(
                [row for row in self.rows if row.procedure is values["procedure"]]
            )
        return _Query([row for row in self.rows if row.name == values["name"]])

    def create(self, **values: object):
        row = SimpleNamespace(pk=len(self.rows) + 1, **values)
        row.save = lambda **_kwargs: None
        self.rows.append(row)
        return row


def _load_migration(monkeypatch: pytest.MonkeyPatch):
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")

    class Migration:
        pass

    django_db.migrations = SimpleNamespace(
        Migration=Migration,
        RunPython=lambda *args, **kwargs: None,
    )
    django_db.transaction = SimpleNamespace(atomic=nullcontext)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    path = ROOT / "netbox_rpc/migrations/0104_seed_protected_publication_pair.py"
    spec = importlib.util.spec_from_file_location("publication_pair_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.transaction, "atomic", nullcontext)
    procedures = _Manager()
    commands = _Manager(command=True)

    class Apps:
        @staticmethod
        def get_model(_app: str, model: str):
            manager = procedures if model == "RPCProcedure" else commands
            return SimpleNamespace(objects=manager)

    return module, Apps(), procedures, commands


def _valid_result(procedure: str) -> dict[str, object]:
    operation = "prove" if procedure == contract.PROVE_PROCEDURE else "provision"
    runner_ids = {"builder": 1, "publisher": 2, "validator": 3}
    role = lambda name: {  # noqa: E731 - compact independent fixture builder
        "runner_id": runner_ids[name],
        "runner_name": f"ci-release-{name}-netbox-rpc-backend",
        "labels": [f"release-{name}"],
        "online": True,
        "busy": False,
        "service_active": True,
        "service_user": f"nmc-rpc-release-{name}",
        "service_name": f"nmc-rpc-release-{name}.service",
        "process_identity": f"pid:{runner_ids[name]}",
        "workspace_root": f"/var/lib/nmc-rpc-release-{name}/work",
        "state_root": f"/var/lib/nmc-rpc-release-{name}",
        "cache_root": f"/var/cache/nmc-rpc-release-{name}",
        "config_path": f"/etc/nmc-protected-publication/{name}.yaml",
        "launcher_sha256": (
            "7cc722a0de44af661d299c0b86eeee03231f993effa517718e48a45c2c188ef1"
        ),
        "scope_owner": "N-MultiCloud",
        "scope_type": "organization",
        "scope_sha256": "b" * 64,
        "runtime_inventory_sha256": contract.RUNTIME_INVENTORY_SHA256,
        "accepts_pull_requests": False,
        "control_plane_https": "same-origin-gitea-only",
        "candidate_build_network": "none",
        "package_write_credential_present": False,
        "package_mutation": "broker-socket-only" if name == "publisher" else "none",
    }
    return {
        "ok": True,
        "schema_version": 1,
        "procedure": procedure,
        "operation": operation,
        "stage": "complete",
        "target": "Gitea-Runner",
        "target_object": contract.TARGET_OBJECT,
        "scope": {"owner": "N-MultiCloud", "type": "organization"},
        "host_generation_sha256": contract.HOST_GENERATION_SHA256,
        "runtime_inventory_sha256": contract.RUNTIME_INVENTORY_SHA256,
        "helper_sha256": (
            contract.PROVE_HELPER_SHA256
            if operation == "prove"
            else contract.PROVISION_HELPER_SHA256
        ),
        "sandbox_path": contract.BUILD_SANDBOX,
        "sandbox_owner": "root",
        "sandbox_mode": "0755",
        "sandbox_sha256": contract.BUILD_SANDBOX_SHA256,
        "roles": {
            "builder": role("builder"),
            "publisher": role("publisher"),
            "validator": role("validator"),
        },
        "pair": {
            "distinct_runner_ids": True,
            "distinct_service_users": True,
            "distinct_processes": True,
            "distinct_workspaces": True,
            "distinct_state_roots": True,
            "distinct_cache_roots": True,
            "crossover_absent": True,
        },
        "set": {field: True for field in contract._SET_FIELDS},
        "isolation": {field: True for field in contract._ISOLATION_FIELDS},
        "publication_broker": {
            "socket_path": "/run/nmc-release-control/publish.sock",
            "service_template": "nmc-release-publish@.service",
            "credential_scope": "netbox-rpc-backend-package-write-only",
            "broker_sha256": contract.PUBLICATION_BROKER_SHA256,
            "policy_sha256": contract.PUBLICATION_POLICY_SHA256,
            "credential_exposed_to_runner": False,
            "credential_exposed_to_candidate": False,
            "canonical_main_reauthorized": True,
            "active_run_reauthorized": True,
            "workflow_digest_reauthorized": True,
            "same_origin_https_only": True,
            "redirects_denied": True,
            "mutations_scoped": True,
        },
    }


def test_migration_is_default_dark_and_history_preserving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration, apps, procedures, commands = _load_migration(monkeypatch)
    migration.seed(apps, None)
    assert len(procedures.rows) == len(commands.rows) == 2
    assert all(row.enabled is False for row in procedures.rows)
    assert {row.effect for row in procedures.rows} == {"read", "destructive"}
    assert all(row.params_schema == contract.PARAMS_SCHEMA for row in procedures.rows)
    by_name = {row.name: row for row in procedures.rows}
    for name in contract.PROCEDURE_NAMES:
        assert by_name[name].result_schema == contract.RESULT_SCHEMAS[name]
    migration.reverse(apps, None)
    assert len(procedures.rows) == len(commands.rows) == 2
    assert all(row.enabled is False for row in procedures.rows)
    migration.seed(apps, None)
    assert len(procedures.rows) == len(commands.rows) == 2


def test_migration_refuses_preexisting_row_with_spoofed_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration, apps, _procedures, commands = _load_migration(monkeypatch)
    migration.seed(apps, None)
    migration.reverse(apps, None)
    commands.rows[0].custom_field_data = {
        **commands.rows[0].custom_field_data,
        "contract_sha256": "0" * 64,
    }
    with pytest.raises(
        RuntimeError, match="Refusing .*protected publication"
    ):
        migration.seed(apps, None)


def test_migration_adopts_exact_pre_rebase_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration, apps, procedures, commands = _load_migration(monkeypatch)
    migration.seed(apps, None)
    procedure_by_name = {row.name: row for row in procedures.rows}
    predecessor_markers = {
        contract.PROVE_PROCEDURE: {
            "migration": "0103_seed_protected_publication_pair",
            "procedure": contract.PROVE_PROCEDURE,
            "contract_sha256": (
                "769bc782b2455743ce3434798de8978f606c26f3c67919e554ab92bde2028943"
            ),
        },
        contract.PROVISION_PROCEDURE: {
            "migration": "0103_seed_protected_publication_pair",
            "procedure": contract.PROVISION_PROCEDURE,
            "contract_sha256": (
                "ecc792a599e791babff150fe41a8949f359bd830edd7375fbe96648efaeca1e3"
            ),
        },
    }
    for command in commands.rows:
        name = command.procedure.name
        command.custom_field_data = predecessor_markers[name]

    identities = [(row.pk, id(row)) for row in procedures.rows]
    command_identities = [(row.pk, id(row)) for row in commands.rows]
    migration.seed(apps, None)

    assert [(row.pk, id(row)) for row in procedures.rows] == identities
    assert [(row.pk, id(row)) for row in commands.rows] == command_identities
    assert len(procedures.rows) == len(commands.rows) == 2
    for command in commands.rows:
        assert command.custom_field_data["migration"] == (
            "0104_seed_protected_publication_pair"
        )


@pytest.mark.parametrize(
    "mutation",
    ["procedure", "command", "extra", "missing", "sequence", "mixed"],
)
def test_migration_refuses_drifted_pre_rebase_rows(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    migration, apps, procedures, commands = _load_migration(monkeypatch)
    migration.seed(apps, None)
    predecessor_hashes = {
        contract.PROVE_PROCEDURE: (
            "769bc782b2455743ce3434798de8978f606c26f3c67919e554ab92bde2028943"
        ),
        contract.PROVISION_PROCEDURE: (
            "ecc792a599e791babff150fe41a8949f359bd830edd7375fbe96648efaeca1e3"
        ),
    }
    for command in commands.rows:
        command.custom_field_data = {
            "migration": "0103_seed_protected_publication_pair",
            "procedure": command.procedure.name,
            "contract_sha256": predecessor_hashes[command.procedure.name],
        }
    if mutation == "procedure":
        procedures.rows[0].description = "drift"
    elif mutation == "command":
        commands.rows[0].argv = ["backend-orchestrated", "drift"]
    elif mutation == "extra":
        duplicate = SimpleNamespace(**vars(commands.rows[0]))
        duplicate.pk = 99
        commands.rows.append(duplicate)
    elif mutation == "missing":
        commands.rows.pop(0)
    elif mutation == "sequence":
        commands.rows[0].sequence = 2
    else:
        commands.rows[0].custom_field_data["migration"] = (
            "0104_seed_protected_publication_pair"
        )

    with pytest.raises(RuntimeError, match="Refusing .*protected publication"):
        migration.seed(apps, None)


def test_catalog_registry_and_code_gate_are_default_dark() -> None:
    assert contract.ACTIVATION_ELIGIBLE is True
    procedure_names = constants["GITEA_PROTECTED_PUBLICATION_PAIR_PROCEDURE_NAMES"]
    assert procedure_names <= (constants["EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES"])
    provision = constants["GITEA_PROTECTED_PUBLICATION_PAIR_PROVISION"]
    assert provision in (constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"])
    assert (
        contract.PROVE_PROCEDURE not in constants["PROTECTED_APPROVAL_PROCEDURE_NAMES"]
    )
    source = (ROOT / "netbox_rpc/domain/normalization.py").read_text()
    assert "_GITEA_PROTECTED_PUBLICATION_PAIR_AVAILABLE = False" in source
    assert (
        "procedure_name in GITEA_PROTECTED_PUBLICATION_PAIR_PROCEDURE_NAMES" in source
    )
    assert contract.BACKEND_RESPONSE_MAX_BYTES == 32_768
    assert contract.ROUTE_BUDGET_SECONDS == {
        contract.PROVE_PROCEDURE: 300,
        contract.PROVISION_PROCEDURE: 1740,
    }
    assert (
        contract.PROCEDURE_POLICIES[contract.PROVE_PROCEDURE]["timeout_seconds"] == 300
    )
    assert (
        contract.PROCEDURE_POLICIES[contract.PROVISION_PROCEDURE]["timeout_seconds"]
        == 1800
    )
    jobs = (ROOT / "netbox_rpc/jobs.py").read_text()
    assert "_BackendTransportKind.GITEA_PROTECTED_PUBLICATION_PAIR" in jobs
    assert "contract.BACKEND_RESPONSE_MAX_BYTES" in jobs
    assert "_BackendTransportKind.GITEA_PROTECTED_PUBLICATION_PAIR," in jobs
    assert "_normalize_protected_publication_pair_closed_response" in jobs
    for procedure in contract.PROCEDURE_NAMES:
        semantic = contract.SEMANTIC_CAPABILITY_EXTENSIONS[procedure]
        assert semantic["params_schema"] == contract.PARAMS_SCHEMA
        assert semantic["normalized_params_schema"] == contract.NORMALIZED_PARAMS_SCHEMA
        assert (
            semantic["command_fingerprint_schema"]
            == contract.COMMAND_FINGERPRINT_SCHEMA
        )
        assert semantic["result_schema"] == contract.RESULT_SCHEMAS[procedure]


@pytest.mark.parametrize("procedure", sorted(contract.PROCEDURE_NAMES))
def test_result_schema_rejects_role_crossover_shared_identity_and_extra_labels(
    procedure: str,
) -> None:
    schema = contract.RESULT_SCHEMAS[procedure]
    valid = _valid_result(procedure)
    jsonschema.validate(valid, schema)
    hostile = []
    shared_id = deepcopy(valid)
    shared_id["roles"]["publisher"]["runner_id"] = shared_id["roles"]["builder"][
        "runner_id"
    ]
    shared_id["pair"]["distinct_runner_ids"] = False
    hostile.append(shared_id)
    crossover = deepcopy(valid)
    crossover["roles"]["publisher"]["labels"] = ["release-builder"]
    hostile.append(crossover)
    extra_label = deepcopy(valid)
    extra_label["roles"]["builder"]["labels"] = ["release-builder", "prod-deploy"]
    hostile.append(extra_label)
    credential = deepcopy(valid)
    credential["roles"]["publisher"]["package_write_credential_present"] = True
    hostile.append(credential)
    egress = deepcopy(valid)
    egress["roles"]["publisher"]["control_plane_https"] = "unrestricted"
    hostile.append(egress)
    validator_authority = deepcopy(valid)
    validator_authority["roles"]["validator"]["package_mutation"] = "broker-socket-only"
    hostile.append(validator_authority)
    shared_validator = deepcopy(valid)
    shared_validator["roles"]["validator"]["runner_id"] = shared_validator["roles"][
        "builder"
    ]["runner_id"]
    shared_validator["set"]["all_runner_ids_distinct"] = False
    hostile.append(shared_validator)
    extra = deepcopy(valid)
    extra["operator_command"] = "sh"
    hostile.append(extra)
    for value in hostile:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(value, schema)


@pytest.mark.parametrize(
    "field",
    [
        "runner_id",
        "process_identity",
        "service_user",
        "workspace_root",
        "state_root",
        "cache_root",
    ],
)
def test_semantic_validation_rejects_duplicates_when_proof_flags_stay_true(
    field: str,
) -> None:
    result = _valid_result(contract.PROVE_PROCEDURE)
    result["roles"]["validator"][field] = result["roles"]["builder"][field]
    assert contract.result_semantics_are_valid(result) is False


def test_semantic_validation_accepts_pairwise_distinct_fixed_roles() -> None:
    result = _valid_result(contract.PROVE_PROCEDURE)
    assert contract.result_semantics_are_valid(result) is True


def test_fixed_commands_and_empty_params_leave_no_caller_selected_operation() -> None:
    assert contract.PARAMS_SCHEMA == {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"role": "publisher"}, contract.PARAMS_SCHEMA)
    assert contract.COMMAND_CONTRACTS[contract.PROVE_PROCEDURE][0]["argv"] == [
        "backend-orchestrated",
        "gitea-protected-publication-pair-prove",
    ]
    assert contract.COMMAND_CONTRACTS[contract.PROVISION_PROCEDURE][0]["argv"] == [
        "backend-orchestrated",
        "gitea-protected-publication-pair-provision",
    ]


def test_normalized_params_bind_approved_ssh_snapshot_and_procedure() -> None:
    snapshot = {
        "ssh_service_id": 1,
        "ssh_service_revision": "2026-09-30T12:00:00Z",
        "ssh_identity_id": 2,
        "ssh_identity_revision": "2026-09-30T12:00:00Z",
        "ssh_storage_backend": "local",
        "ssh_principal": "nms-runner-bootstrap",
        "ssh_method": "key",
        "ssh_host": "10.0.30.241",
        "ssh_port": 22,
        "ssh_known_hosts_sha256": "a" * 64,
        "ssh_policy_ref": contract.TARGET_SSH_POLICY_REF,
    }
    fingerprint = {
        "handler_id": contract.PROVE_PROCEDURE,
        "procedure": contract.PROVE_PROCEDURE,
        "assigned_object_id": 416,
        "target_object_sha256": contract.TARGET_OBJECT_SHA256,
        "ssh_snapshot_sha256": "b" * 64,
        "ssh_policy_ref": contract.TARGET_SSH_POLICY_REF,
        "pair_contract_sha256": contract.PAIR_CONTRACT_SHA256,
        "host_generation_sha256": contract.HOST_GENERATION_SHA256,
        "provision_helper_sha256": contract.PROVISION_HELPER_SHA256,
        "prove_helper_sha256": contract.PROVE_HELPER_SHA256,
        "build_sandbox_sha256": contract.BUILD_SANDBOX_SHA256,
    }
    normalized = {
        "target": contract.TARGET_NAME,
        "target_object": contract.TARGET_OBJECT,
        "ssh_snapshot": snapshot,
        "ssh_policy_ref": contract.TARGET_SSH_POLICY_REF,
        "command_fingerprint": fingerprint,
    }
    jsonschema.validate(normalized, contract.NORMALIZED_PARAMS_SCHEMA)

    crossover = deepcopy(normalized)
    crossover["command_fingerprint"]["handler_id"] = contract.PROVISION_PROCEDURE
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(crossover, contract.NORMALIZED_PARAMS_SCHEMA)

    injected = deepcopy(normalized)
    injected["ssh_snapshot"]["private_key"] = "forbidden"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(injected, contract.NORMALIZED_PARAMS_SCHEMA)
