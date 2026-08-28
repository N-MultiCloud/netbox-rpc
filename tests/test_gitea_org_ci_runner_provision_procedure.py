from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import runpy
import sys
import types
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validate


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = "netbox_rpc.migrations.0087_extend_gitea_org_ci_runner_contract"
PROCEDURE_ID = "service.gitea.actions_runner.provision_org_ci_runner"
SECRET_REF = "nms-secret:11111111-1111-4111-8111-111111111111"
CONTRACT = runpy.run_path(str(ROOT / "netbox_rpc/gitea_org_ci_runner_contract.py"))
LANES = CONTRACT["LANES"]


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_forward_migration_updates_the_disabled_single_chain_row(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()

    migration.extend_gitea_org_ci_runner_contract(
        _apps(procedures, commands),
        None,
    )

    row = procedures.rows[PROCEDURE_ID]
    assert row == migration._PROCEDURE_DEFAULTS
    assert row["enabled"] is False
    assert row["version"] == 1
    assert row["effect"] == "write"
    assert row["approval_required"] is True
    assert row["timeout_seconds"] == 1800
    assert row["transport_driver"] == "asyncssh"
    assert row["transport_pinned"] is True
    assert row["transport_driver_chain"] == []
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0086_seed_akvorado_debian13_bootstrap_procedures")
    ]
    assert len(migration.Migration.operations) == 3
    command = commands.rows[(PROCEDURE_ID, 1)]
    assert command["argv"] == [
        "backend-orchestrated",
        "gitea-org-ci-runner-provision",
    ]
    assert command["render_mode"] == "literal"
    assert len(row["description"]) <= 255
    assert len(command["description"]) <= 255
    legacy = procedures.rows["service.gitea.runner.register"]
    assert legacy == migration._LEGACY_PROCEDURE_DEFAULTS
    assert legacy["enabled"] is False
    assert (
        legacy["result_schema"]
        == runpy.run_path(str(ROOT / "netbox_rpc/gitea_runner_contract.py"))[
            "RESULT_SCHEMA"
        ]
    )
    assert commands.rows[("service.gitea.runner.register", 1)] == (
        migration._LEGACY_REPRESENTATIVE_COMMAND
    )


def test_reverse_helper_disables_without_deleting_audited_history(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    migration.extend_gitea_org_ci_runner_contract(_apps(procedures, commands), None)
    procedures.rows["unrelated"] = {"enabled": True}

    migration.disable_gitea_org_ci_runner_contract(
        _apps(procedures, commands),
        None,
    )

    assert set(procedures.rows) == {
        PROCEDURE_ID,
        "service.gitea.runner.register",
        "unrelated",
    }
    assert procedures.rows[PROCEDURE_ID]["enabled"] is False
    assert procedures.rows["service.gitea.runner.register"]["enabled"] is False
    assert procedures.rows["unrelated"]["enabled"] is True
    assert procedures.deleted == []


def test_reverse_refuses_to_delete_durable_takeover_generation(migration) -> None:
    with pytest.raises(
        migration.IrreversibleError,
        match="durable Gitea runner takeover generation",
    ):
        migration.refuse_takeover_generation_removal(None, None)


def test_migration_and_fixture_are_exactly_the_immutable_contract(migration) -> None:
    assert migration._LANES == LANES
    assert migration._PARAMS_SCHEMA == CONTRACT["PARAMS_SCHEMA"]
    assert migration._RESULT_SCHEMA == CONTRACT["RESULT_SCHEMA"]
    assert (
        migration._CAPABILITY_CONTRACT_SHA256 == CONTRACT["CAPABILITY_CONTRACT_SHA256"]
    )
    assert (
        migration._SEMANTIC_CAPABILITY_SHA256 == CONTRACT["SEMANTIC_CAPABILITY_SHA256"]
    )

    fixture = json.loads(
        (ROOT / "tests/fixtures/gitea_org_ci_runner_capability.json").read_text()
    )
    assert fixture["canonical_json"].encode() == CONTRACT["CAPABILITY_CONTRACT_BYTES"]
    assert (
        fixture["semantic_canonical_json"].encode()
        == CONTRACT["SEMANTIC_CAPABILITY_BYTES"]
    )
    assert (
        hashlib.sha256(fixture["canonical_json"].encode()).hexdigest()
        == fixture["sha256"]
    )
    assert fixture["sha256"] == CONTRACT["CAPABILITY_CONTRACT_SHA256"]
    assert fixture["semantic_sha256"] == CONTRACT["SEMANTIC_CAPABILITY_SHA256"]


def test_capability_fixture_has_an_independent_exact_size_and_hash_oracle() -> None:
    fixture_path = ROOT / "tests/fixtures/gitea_org_ci_runner_capability.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture = json.loads(fixture_bytes)
    canonical = fixture["canonical_json"].encode("utf-8")
    semantic = fixture["semantic_canonical_json"].encode("utf-8")

    assert len(canonical) == 40_283
    assert hashlib.sha256(canonical).hexdigest() == (
        "bae186285d7e23a6bc664eb0b119e9d71ed11d5ca273f910cfef5a934420573c"
    )
    assert len(semantic) == 39_850
    assert hashlib.sha256(semantic).hexdigest() == (
        "6eec5dd6e61ada82329998e5867a2275a8e07d89340d77a89dd0a6a89a8dc41b"
    )
    assert len(fixture_bytes) == 89_632
    assert hashlib.sha256(fixture_bytes).hexdigest() == (
        "e74f52466a4833205404688873127a20f644cebf57f98380a4f6b646addfc7ae"
    )
    assert (
        json.dumps(
            json.loads(canonical),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        == canonical
    )
    assert (
        json.dumps(
            json.loads(semantic),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        == semantic
    )


def test_capability_hash_matches_the_runtime_derivation(migration) -> None:
    capabilities = importlib.import_module("netbox_rpc.capabilities")
    command = SimpleNamespace(sequence=1, **migration._REPRESENTATIVE_COMMAND)
    procedure = SimpleNamespace(
        handler_id=PROCEDURE_ID,
        version=1,
        effect="write",
        commands=SimpleNamespace(all=lambda: [command]),
    )
    assert (
        capabilities.derive_command_contract_hash(procedure)
        == CONTRACT["CAPABILITY_CONTRACT_SHA256"]
    )


def test_params_schema_is_operation_discriminated_and_secret_safe() -> None:
    schema = CONTRACT["PARAMS_SCHEMA"]
    Draft202012Validator.check_schema(schema)
    assert set(LANES) == {"root-python312"}
    assert schema["properties"]["lane"]["enum"] == ["root-python312"]
    for lane in LANES:
        validate(
            {
                "operation": "provision",
                "lane": lane,
                "registration_token_secret_ref": SECRET_REF,
            },
            schema,
        )
        validate({"operation": "reconcile", "lane": lane}, schema)

    hostile = (
        {},
        {"operation": "provision", "lane": "root-python312"},
        {
            "operation": "provision",
            "lane": "root-python312",
            "registration_token_secret_ref": f" {SECRET_REF}",
        },
        {
            "operation": "provision",
            "lane": "root-python312",
            "registration_token_secret_ref": f"{SECRET_REF}\n",
        },
        {
            "operation": "reconcile",
            "lane": "root-python312",
            "registration_token_secret_ref": SECRET_REF,
        },
        {"operation": "delete", "lane": "root-python312"},
        {"operation": "reconcile", "lane": "attacker-lane"},
        {
            "operation": "provision",
            "lane": "root-python312",
            "registration_token_secret_ref": SECRET_REF,
            "runner_image": "attacker/image:latest",
        },
        {
            "operation": "provision",
            "lane": "root-python312",
            "registration_token_secret_ref": SECRET_REF,
            "build_runner_image": True,
            "load_prebuilt_runner_image": True,
        },
    )
    for params in hostile:
        with pytest.raises(ValidationError):
            validate(params, schema)


def test_root_lane_is_fixed_isolated_and_activation_ineligible() -> None:
    root = LANES["root-python312"]
    assert root["runner_label"] == "ci-untrusted-root-python312"
    assert root["runner_labels"] == ["ci-untrusted-root-python312"]
    assert root["service_user"] == "gitea-runner-nmulticloud-org-root"
    assert root["service_user_login"] is False
    assert root["state_dir"] == "/var/lib/gitea-runner-nmulticloud-org-root"
    assert root["config_path"] == "/etc/gitea-runner/nmulticloud-org-root.yaml"
    assert root["capacity"] == 1
    assert root["fresh_container_per_job"] is True
    assert root["rootless_user_namespace"] is True
    assert root["container_uid0_maps_to_host_root"] is False
    assert root["container_privileged"] is False
    assert root["container_host_network"] is False
    assert root["container_host_pid"] is False
    assert root["container_host_ipc"] is False
    assert root["container_host_uts"] is False
    assert root["container_devices"] == []
    assert root["container_host_effective_capabilities"] == []
    assert root["container_host_ambient_capabilities"] == []
    assert root["job_cap_drop_all"] is True
    assert root["job_no_new_privileges"] is True
    assert root["container_cap_add"] == [
        "CHOWN",
        "SETUID",
        "SETGID",
        "FOWNER",
        "DAC_OVERRIDE",
    ]
    assert root["container_daemon_socket_in_job"] is False
    assert root["job_network_policy"] == {
        "default_action": "deny",
        "build": {"network_mode": "none", "dns_resolvers": [], "egress": []},
        "publisher": {
            "network_mode": "filtered",
            "dns_required": False,
            "dns_resolvers": [],
            "host_bindings": [{"hostname": "git.nmulti.cloud", "ipv4": "10.0.30.96"}],
            "https_origins": ["https://git.nmulti.cloud:443"],
            "ipv4_destinations": ["10.0.30.96/32"],
            "tcp_ports": [443],
            "tls_server_names": ["git.nmulti.cloud"],
            "tls_verify": True,
            "redirects": False,
        },
        "other_egress": "deny",
    }
    assert root["management_egress_policy"] == "deny-except-gitea-publisher"
    assert root["production_egress_policy"] == "deny-except-gitea-publisher"
    assert "bridge" not in json.dumps(root["job_network_policy"])
    assert root["job_resource_limits"] == {
        "cgroup_version": 2,
        "cpu_period_us": 100_000,
        "cpu_quota_us": 200_000,
        "cpu_weight": 100,
        "memory_max_bytes": 4_294_967_296,
        "memory_swap_max_bytes": 0,
        "pids_max": 512,
        "root_filesystem_read_only": True,
        "writable_paths": ["/workspace", "/tmp", "/run"],
        "workspace": {
            "path": "/workspace",
            "kind": "ephemeral-volume",
            "host_bind": False,
            "disk_quota_bytes": 8_589_934_592,
        },
        "tmpfs": [
            {
                "path": "/tmp",
                "size_bytes": 1_073_741_824,
                "options": ["nodev", "nosuid", "noexec"],
            },
            {
                "path": "/run",
                "size_bytes": 67_108_864,
                "options": ["nodev", "nosuid", "noexec"],
            },
        ],
        "ulimits": {
            "core": {"soft": 0, "hard": 0},
            "fsize": {"soft": 8_589_934_592, "hard": 8_589_934_592},
            "nofile": {"soft": 1024, "hard": 1024},
            "nproc": {"soft": 512, "hard": 512},
        },
        "wall_clock_timeout_seconds": 1800,
        "kill_grace_seconds": 10,
    }
    assert root["cross_scope_state"] is False
    assert root["activation_eligible"] is False
    assert root["activation_blocker"] == "N-MultiCloud/nmulticloud-context#411"
    assert root["runner_image"] is None
    assert root["provision_helper_path"] is None
    assert root["provision_helper_sha256"] is None
    assert root["prove_helper_path"] is None
    assert root["prove_helper_sha256"] is None
    assert "sha256:" in root["base_image_reference"]
    assert root["base_image_reference"].endswith(root["base_image_digest"])
    assert CONTRACT["RECONCILIATION_QUIESCENCE_SECONDS"] == 1800


def test_every_advertised_lane_has_one_exact_root_backend_policy() -> None:
    advertised = set(CONTRACT["LANES"])
    assert advertised == {"root-python312"}
    assert set(CONTRACT["SCOPE_BY_LANE"]) == advertised
    assert set(CONTRACT["LANE_CONTRACT_SHA256"]) == advertised
    assert CONTRACT["PARAMS_SCHEMA"]["properties"]["lane"]["enum"] == sorted(advertised)
    assert CONTRACT["RESULT_SCHEMA"]["properties"]["lane"]["enum"] == sorted(advertised)
    assert CONTRACT["NORMALIZED_PARAMS_SCHEMA"]["properties"]["lane"]["enum"] == sorted(
        advertised
    )
    assert CONTRACT["COMMAND_FINGERPRINT_SCHEMA"]["properties"]["lane"][
        "enum"
    ] == sorted(advertised)
    assert set(CONTRACT["FUTURE_LANE_DESIGNS"]) == {
        "general-ubuntu",
        "untrusted-python312",
    }


def test_closed_result_schema_matches_the_pinned_reset_helper_proof() -> None:
    schema = CONTRACT["RESULT_SCHEMA"]
    Draft202012Validator.check_schema(schema)
    provision = _root_result(
        ok=True,
        operation="provision",
        provisioned=True,
        registered=True,
        reconciled=None,
        stage="complete",
        token_invalidated=True,
        token_reset_required=False,
        token_sha256="a" * 64,
        reset_state="rotated",
        prior_token_id=11,
        replacement_token_id=12,
    )
    validate(provision, schema)
    validate(
        {
            **provision,
            "operation": "reconcile",
            "fence_execution_id": 72,
            "fence_generation": 8,
            "provisioned": None,
            "registered": None,
            "reconciled": True,
            "reset_state": "reconciled_expected_active",
        },
        schema,
    )

    hostile_overrides = (
        {"reset_state": "deleted"},
        {"replacement_token_id": None},
        {"replacement_token_id": 9_007_199_254_740_992},
        {"fence_generation": 9_007_199_254_740_992},
        {"token_invalidated": False},
        {"runner_labels": ["attacker"]},
        {
            "job_network_policy": {
                **LANES["root-python312"]["job_network_policy"],
                "default_action": "allow",
            }
        },
        {
            "job_resource_limits": {
                **LANES["root-python312"]["job_resource_limits"],
                "memory_max_bytes": 8_589_934_592,
            }
        },
        {"error": "opaque credential-shaped backend diagnostic"},
    )
    for override in hostile_overrides:
        with pytest.raises(ValidationError):
            validate({**provision, **override}, schema)


def test_normalized_and_fingerprint_schemas_bind_both_ssh_snapshots() -> None:
    normalized = _root_reconcile_normalized()
    validate(
        normalized,
        CONTRACT["NORMALIZED_PARAMS_SCHEMA"],
        format_checker=FormatChecker(),
    )
    validate(
        normalized["command_fingerprint"],
        CONTRACT["COMMAND_FINGERPRINT_SCHEMA"],
    )

    hostile = (
        {"registration_token_secret_ref": SECRET_REF},
        {
            "runner_ssh_snapshot": {
                **normalized["runner_ssh_snapshot"],
                "ssh_principal": "root",
            }
        },
        {
            "gitea_ssh_snapshot": {
                **normalized["gitea_ssh_snapshot"],
                "ssh_policy_ref": CONTRACT["TARGET_SSH_POLICY_REF"],
            }
        },
    )
    for override in hostile:
        with pytest.raises(ValidationError):
            validate(
                {**normalized, **override},
                CONTRACT["NORMALIZED_PARAMS_SCHEMA"],
            )
    with pytest.raises(ValidationError):
        validate(
            {
                **normalized["command_fingerprint"],
                "lane_contract_sha256": "f" * 64,
            },
            CONTRACT["COMMAND_FINGERPRINT_SCHEMA"],
        )
    for schema_name, candidate in (
        ("NORMALIZED_PARAMS_SCHEMA", normalized),
        ("COMMAND_FINGERPRINT_SCHEMA", normalized["command_fingerprint"]),
    ):
        with pytest.raises(ValidationError):
            validate(
                {**candidate, "fence_execution_id": 9_007_199_254_740_992},
                CONTRACT[schema_name],
            )
        with pytest.raises(ValidationError):
            validate(
                {**candidate, "fence_generation": 9_007_199_254_740_992},
                CONTRACT[schema_name],
            )


@pytest.fixture()
def normalization_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.domain.normalization")
    yield module
    sys.modules.pop("netbox_rpc.domain.normalization", None)


def test_catalog_code_gate_stays_closed_by_default(normalization_module) -> None:
    reason = normalization_module.code_gate_unavailable_reason(PROCEDURE_ID)
    assert reason is not None
    assert PROCEDURE_ID in reason
    assert "netbox-rpc-backend" in reason
    with pytest.raises(normalization_module.RPCExecutionError) as excinfo:
        normalization_module.normalize_execution_params(_execution({}))
    assert excinfo.value.code == "RPC_PROCEDURE_NOT_AVAILABLE"


def test_root_provision_refuses_missing_host_generation_before_target_io(
    normalization_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(normalization_module, "_GITEA_ORG_CI_RUNNER_AVAILABLE", True)
    execution = _execution(
        {
            "operation": "provision",
            "lane": "root-python312",
            "registration_token_secret_ref": SECRET_REF,
        },
        assigned_object=_ExplodingTarget(),
    )
    with pytest.raises(normalization_module.RPCExecutionError) as excinfo:
        normalization_module.normalize_execution_params(execution)
    assert excinfo.value.code == "RPC_HOST_GENERATION_UNAVAILABLE"
    assert "nmulticloud-context#411" in str(excinfo.value)


@pytest.mark.parametrize("secret_ref", [f" {SECRET_REF}", f"{SECRET_REF} ", "   "])
def test_provision_rejects_non_exact_secret_reference_before_target_io(
    normalization_module,
    monkeypatch: pytest.MonkeyPatch,
    secret_ref: str,
) -> None:
    monkeypatch.setattr(normalization_module, "_GITEA_ORG_CI_RUNNER_AVAILABLE", True)
    with pytest.raises(normalization_module.RPCExecutionError) as excinfo:
        normalization_module.normalize_execution_params(
            _execution(
                {
                    "operation": "provision",
                    "lane": "root-python312",
                    "registration_token_secret_ref": secret_ref,
                },
                assigned_object=_ExplodingTarget(),
            )
        )
    assert excinfo.value.code == "RPC_PARAM_INVALID"


def test_docs_and_contract_name_the_default_dark_dependency() -> None:
    for path in (
        ROOT / "CLAUDE.md",
        ROOT / "docs/gitea-org-ci-runner-provision.md",
    ):
        text = path.read_text(encoding="utf-8")
        assert PROCEDURE_ID in text
        assert "nmulticloud-context#411" in text
        assert "root-python312" in text
        for prerequisite in (
            "publisher dispatcher",
            "credentials outside the untrusted job container",
            "inode quota",
            "block-I/O BPS/IOPS",
            "stdout/stderr/log byte",
        ):
            assert prerequisite in text

    contract_doc = (ROOT / "docs/gitea-org-ci-runner-provision.md").read_text(
        encoding="utf-8"
    )
    for frozen_term in (
        "network_mode=none",
        "https://git.nmulti.cloud:443",
        "git.nmulti.cloud -> 10.0.30.96",
        "4,294,967,296-byte memory maximum",
        "512-PID maximum",
        "8,589,934,592-byte",
        "10-second kill grace",
    ):
        assert frozen_term in contract_doc

    for path in (ROOT / "README.md", ROOT / "AGENTS.md"):
        text = path.read_text(encoding="utf-8")
        assert PROCEDURE_ID in text
        assert "tracked source prerequisite" in text
        assert "root-python312" in text


def _root_result(**overrides: object) -> dict[str, object]:
    return {
        "ok": False,
        "procedure": PROCEDURE_ID,
        "target": CONTRACT["TARGET_NAME"],
        "operation": "provision",
        "scope": "nmulticloud-org-root",
        "lane": "root-python312",
        "fence_execution_id": None,
        "fence_generation": 1,
        "provisioned": False,
        "registered": False,
        "reconciled": None,
        "stage": "preconditions",
        "organization": CONTRACT["DEFAULT_ORGANIZATION"],
        "gitea_instance_url": CONTRACT["DEFAULT_GITEA_INSTANCE_URL"],
        "token_invalidated": False,
        "token_reset_required": False,
        "token_sha256": None,
        "reset_state": "not_started",
        "prior_token_id": None,
        "prior_active_sha256": None,
        "replacement_token_id": None,
        **deepcopy(LANES["root-python312"]),
        **overrides,
    }


def _ssh_snapshot(*, gitea: bool) -> dict[str, object]:
    return {
        "ssh_service_id": 902 if gitea else 901,
        "ssh_service_revision": "2026-08-28T12:00:00Z",
        "ssh_identity_id": 904 if gitea else 903,
        "ssh_identity_revision": "2026-08-28T11:00:00Z",
        "ssh_storage_backend": "local",
        "ssh_principal": (
            CONTRACT["GITEA_SSH_PRINCIPAL"]
            if gitea
            else CONTRACT["TARGET_SSH_PRINCIPAL"]
        ),
        "ssh_method": "key",
        "ssh_host": (
            CONTRACT["GITEA_IPV4_ADDRESS"] if gitea else CONTRACT["TARGET_IPV4_ADDRESS"]
        ),
        "ssh_port": 22,
        "ssh_known_hosts_sha256": ("b" if gitea else "a") * 64,
        "ssh_policy_ref": (
            CONTRACT["GITEA_SSH_POLICY_REF"]
            if gitea
            else CONTRACT["TARGET_SSH_POLICY_REF"]
        ),
    }


def _root_reconcile_normalized() -> dict[str, object]:
    runner_ssh = _ssh_snapshot(gitea=False)
    gitea_ssh = _ssh_snapshot(gitea=True)
    fingerprint = {
        "handler_id": PROCEDURE_ID,
        "procedure": PROCEDURE_ID,
        "assigned_object_id": 416,
        "target_object_sha256": CONTRACT["TARGET_OBJECT_SHA256"],
        "gitea_target_object_sha256": CONTRACT["GITEA_TARGET_OBJECT_SHA256"],
        "operation": "reconcile",
        "scope": "nmulticloud-org-root",
        "gitea_scope": "N-MultiCloud",
        "fence_state": "blocked",
        "fence_expected_sha256": "c" * 64,
        "fence_execution_id": 72,
        "fence_generation": 8,
        "lane": "root-python312",
        "lane_contract_sha256": CONTRACT["LANE_CONTRACT_SHA256"]["root-python312"],
        "gitea_instance_url": CONTRACT["DEFAULT_GITEA_INSTANCE_URL"],
        "organization": CONTRACT["DEFAULT_ORGANIZATION"],
        "runner_ssh_snapshot_sha256": CONTRACT["canonical_sha256"](runner_ssh),
        "gitea_ssh_snapshot_sha256": CONTRACT["canonical_sha256"](gitea_ssh),
        "install_docker": True,
        "build_runner_image": True,
        "load_prebuilt_runner_image": False,
        "force_recreate": False,
    }
    return {
        "target": CONTRACT["TARGET_NAME"],
        "target_object": CONTRACT["TARGET_OBJECT"],
        "runner_ipv4": CONTRACT["TARGET_IPV4_ADDRESS"],
        "gitea_target": CONTRACT["GITEA_TARGET_NAME"],
        "gitea_target_object": CONTRACT["GITEA_TARGET_OBJECT"],
        "gitea_ipv4": CONTRACT["GITEA_IPV4_ADDRESS"],
        "ssh_policy_ref": CONTRACT["TARGET_SSH_POLICY_REF"],
        "runner_ssh_snapshot": runner_ssh,
        "gitea_ssh_snapshot": gitea_ssh,
        "operation": "reconcile",
        "scope": "nmulticloud-org-root",
        "gitea_scope": "N-MultiCloud",
        "fence_state": "blocked",
        "fence_expected_sha256": "c" * 64,
        "fence_execution_id": 72,
        "fence_generation": 8,
        "lane": "root-python312",
        "gitea_instance_url": CONTRACT["DEFAULT_GITEA_INSTANCE_URL"],
        "organization": CONTRACT["DEFAULT_ORGANIZATION"],
        "register_helper_sha256": CONTRACT["RUNNER_REGISTER_HELPER_SHA256"],
        "token_reset_helper_sha256": CONTRACT["GITEA_TOKEN_RESET_HELPER_SHA256"],
        "install_docker": True,
        "build_runner_image": True,
        "load_prebuilt_runner_image": False,
        "force_recreate": False,
        **deepcopy(LANES["root-python312"]),
        "command_fingerprint": fingerprint,
    }


def _execution(params: object, *, assigned_object: object | None = None):
    if assigned_object is None:
        assigned_object = SimpleNamespace(
            pk=416,
            name="Gitea-Runner",
            primary_ip4=SimpleNamespace(address="10.0.30.241/24"),
            status=SimpleNamespace(value="active"),
        )
    return SimpleNamespace(
        procedure=SimpleNamespace(name=PROCEDURE_ID, handler_id=PROCEDURE_ID),
        params=params,
        target_display="Gitea-Runner",
        target_model_label="virtualization.virtualmachine",
        assigned_object_type=SimpleNamespace(
            app_label="virtualization",
            model="virtualmachine",
        ),
        assigned_object_type_id=99,
        assigned_object_id=416,
        assigned_object=assigned_object,
    )


class _ExplodingTarget:
    def __getattribute__(self, name: str):
        raise AssertionError(
            f"target inventory was read before the default-dark gate: {name}"
        )


def _apps(procedures, commands):
    def get_model(app_label: str, model_name: str):
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure"):
            return SimpleNamespace(objects=procedures)
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedureCommand"):
            return SimpleNamespace(objects=commands)
        raise AssertionError((app_label, model_name))

    return SimpleNamespace(get_model=get_model)


class _ProcedureQuery:
    def __init__(self, manager: "_FakeProcedureManager", names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def update(self, **fields: object) -> int:
        matched = [name for name in self.manager.rows if name in self.names]
        for name in matched:
            self.manager.rows[name].update(fields)
        return len(matched)


class _FakeProcedure:
    def __init__(self, name: str, data: dict[str, object]) -> None:
        self.name = name
        self.handler_id = str(data["handler_id"])


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.deleted: list[str] = []

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.rows[name] = dict(defaults)
        return _FakeProcedure(name, self.rows[name]), True

    def filter(self, *, name: str):
        return _ProcedureQuery(self, {name})


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def update_or_create(
        self,
        *,
        procedure: _FakeProcedure,
        sequence: int,
        defaults: dict[str, object],
    ):
        self.rows[(procedure.handler_id, sequence)] = dict(defaults)
        return SimpleNamespace(), True


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_migrations.AddField = lambda *args, **kwargs: (args, kwargs)
    django_migration_exceptions = types.ModuleType("django.db.migrations.exceptions")
    django_migration_exceptions.IrreversibleError = type(
        "IrreversibleError", (RuntimeError,), {}
    )
    django_models = types.ModuleType("django.db.models")
    django_models.PositiveBigIntegerField = lambda *args, **kwargs: (args, kwargs)
    django_db.models = django_models
    django_db.migrations = django_migrations
    django.db = django_db
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.models", django_models)
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)
    monkeypatch.setitem(
        sys.modules,
        "django.db.migrations.exceptions",
        django_migration_exceptions,
    )


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_migration_import_stubs(monkeypatch)
    django_conf = types.ModuleType("django.conf")
    django_conf.settings = SimpleNamespace(PLUGINS_CONFIG={})
    django_db = sys.modules["django.db"]
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone
    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCNetBoxPluginAllowlist = type("RPCNetBoxPluginAllowlist", (), {})
    models.RPCExecution = type("RPCExecution", (), {})
    monkeypatch.setitem(sys.modules, "django.conf", django_conf)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
