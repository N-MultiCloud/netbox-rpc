from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import runpy
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = "netbox_rpc.migrations.0084_seed_gitea_org_ci_runner_provision"
PROCEDURE_ID = "service.gitea.actions_runner.provision_org_ci_runner"
SECRET_REF = "nms-secret:11111111-1111-4111-8111-111111111111"
LANES = {
    "untrusted-python312": {
        "runner_name": "ci-untrusted-nmulticloud-org-241",
        "runner_labels": ["ci-untrusted-python312:host"],
        "runner_image": "nmc/ci-untrusted-runner:python312-241",
        "compose_project_dir": "/opt/nmc-ci-untrusted-org-241",
        "executor": "host",
        "runner_mounts_docker_socket": False,
        "jobs_mount_docker_socket": False,
        "runner_cap_drop_all": True,
        "runner_no_new_privileges": True,
        "job_user": "cirunner",
    },
    "general-ubuntu": {
        "runner_name": "ci-ubuntu-nmulticloud-org-241",
        "runner_labels": [
            "ubuntu-latest:docker://nmulti/gitea-act-ubuntu:22.04-actions",
            "ubuntu-24.04:docker://nmulti/gitea-act-ubuntu:22.04-actions",
            "ubuntu-22.04:docker://nmulti/gitea-act-ubuntu:22.04-actions",
        ],
        "runner_image": "nmulti/gitea-act-ubuntu:22.04-actions",
        "compose_project_dir": "/opt/nmc-ci-ubuntu-241",
        "executor": "docker",
        "runner_mounts_docker_socket": True,
        "jobs_mount_docker_socket": False,
        "runner_cap_drop_all": False,
        "runner_no_new_privileges": False,
        "job_user": None,
    },
}
FORBIDDEN_SSH_OVERRIDES = (
    "rpc_ssh_credential_pk",
    "rpc_ssh_host",
    "rpc_ssh_port",
    "rpc_ssh_known_hosts_entry",
    "rpc_ssh_strict_host_key_checking",
)
_DEFAULT_TARGET = object()


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_seed_creates_disabled_approval_bound_runner_procedure(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()

    migration.seed_gitea_org_ci_runner_provision(
        _apps(procedures, commands),
        None,
    )

    row = procedures.rows[PROCEDURE_ID]
    assert row["handler_id"] == PROCEDURE_ID
    assert row["version"] == 1
    assert row["enabled"] is False
    assert row["target_models"] == ["virtualization.virtualmachine"]
    assert row["effect"] == "write"
    assert row["approval_required"] is True
    assert row["timeout_seconds"] == 1800
    assert row["transport_driver"] == "asyncssh"
    assert row["transport_pinned"] is True
    assert row["transport_driver_chain"] == []
    assert row["output_parser"] == "none"
    assert row["output_schema"] == {}

    command = commands.rows[(PROCEDURE_ID, 1)]
    assert command["argv"] == ["backend-orchestrated", "gitea-org-ci-runner-provision"]
    assert command["render_mode"] == "literal"
    assert command["capture_kind"] == ""
    assert len(row["description"]) <= 255
    assert len(command["description"]) <= 255


def test_migration_is_renumbered_onto_the_single_main_chain(migration) -> None:
    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0083_seed_netbox_plugin_install")
    ]
    assert not (
        ROOT / "netbox_rpc/migrations/0080_seed_gitea_org_ci_runner_provision.py"
    ).exists()
    assert (
        ROOT / "netbox_rpc/migrations/0084_seed_gitea_org_ci_runner_provision.py"
    ).is_file()


def test_migration_matches_the_immutable_active_contract(migration) -> None:
    contract = runpy.run_path(str(ROOT / "netbox_rpc/gitea_org_ci_runner_contract.py"))

    assert migration._LANES == contract["LANES"] == LANES
    assert migration._PARAMS_SCHEMA == contract["PARAMS_SCHEMA"]
    assert migration._RESULT_SCHEMA == contract["RESULT_SCHEMA"]
    assert migration._TARGET_MODELS == contract["TARGET_MODELS"]
    assert contract["TARGET_OBJECT"] == {
        "content_type": "virtualization.virtualmachine",
        "object_id": 416,
    }
    assert contract["TARGET_NAME"] == "Gitea-Runner"
    assert contract["TARGET_IPV4_ADDRESS"] == "10.0.30.241"
    assert contract["PROCEDURE_POLICY"]["enabled"] is True
    assert contract["SEMANTIC_CAPABILITY_EXTENSION"]["lanes"] == LANES

    capabilities = importlib.import_module("netbox_rpc.capabilities")
    command = SimpleNamespace(sequence=1, **migration._REPRESENTATIVE_COMMAND)
    procedure = SimpleNamespace(
        handler_id=PROCEDURE_ID,
        version=1,
        effect="write",
        commands=SimpleNamespace(all=lambda: [command]),
    )
    capability_command = {
        key: getattr(command, key)
        for key in (
            "sequence",
            "step_type",
            "device_cli_mode",
            "argv",
            "render_mode",
            "produces_var",
            "capture_kind",
            "capture_expression",
            "condition_param",
            "condition_negate",
            "for_each_param",
            "continue_on_error",
        )
    }
    expected_payload = {
        "handler_id": PROCEDURE_ID,
        "version": 1,
        "effect": "write",
        "commands": [capability_command],
        "semantic_contract": contract["SEMANTIC_CAPABILITY_EXTENSION"],
    }
    expected_hash = hashlib.sha256(
        json.dumps(
            expected_payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    assert capabilities.derive_command_contract_hash(procedure) == expected_hash


def test_params_schema_accepts_only_bounded_runner_inputs(migration) -> None:
    schema = migration._PARAMS_SCHEMA
    Draft202012Validator.check_schema(schema)

    for lane in LANES:
        validate({"lane": lane, "registration_token_secret_ref": SECRET_REF}, schema)
        validate(
            {
                "lane": lane,
                "registration_token_secret_ref": SECRET_REF,
                "install_docker": True,
                "build_runner_image": True,
                "force_recreate": False,
            },
            schema,
        )
    for invalid in (
        {},
        # The Gitea origin and organization are frozen server-side: a caller who
        # could choose the origin could choose where the resolved registration
        # credential is delivered.
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "gitea_instance_url": "http://attacker.example:3000",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "gitea_instance_url": "http://10.0.30.96:3000",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "organization": "N-MultiCloud",
        },
        {"registration_token_secret_ref": SECRET_REF},
        {"lane": "unknown", "registration_token_secret_ref": SECRET_REF},
        {"lane": "untrusted-python312", "registration_token_secret_ref": "plain-token"},
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": f"{SECRET_REF}\n",
        },
        {"lane": "untrusted-python312", "registration_token": "plain-token"},
        {"lane": "untrusted-python312", "password": "runner-password"},
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "runner_name": "caller-shaped-name",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "runner_labels": ["prod-deploy"],
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "runner_image": "caller/image:latest",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "compose_project_dir": "/tmp/caller-shaped",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "gitea_instance_url": "http://10.0.30.96:3000/org/N-MultiCloud",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "gitea_instance_url": "http://user:pass@10.0.30.96:3000",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "organization": "-N-MultiCloud",
        },
        {
            "lane": "untrusted-python312",
            "registration_token_secret_ref": SECRET_REF,
            "build_runner_image": True,
            "load_prebuilt_runner_image": True,
        },
        *(
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                override: "x",
            }
            for override in FORBIDDEN_SSH_OVERRIDES
        ),
    ):
        with pytest.raises(ValidationError):
            validate(invalid, schema)


@pytest.mark.parametrize("lane", sorted(LANES))
def test_result_schema_binds_success_to_exact_lane_contract(
    migration, lane: str
) -> None:
    schema = migration._RESULT_SCHEMA
    Draft202012Validator.check_schema(schema)
    lane_contract = LANES[lane]
    success = {
        "ok": True,
        "procedure": PROCEDURE_ID,
        "target": "Gitea-Runner",
        "changed": True,
        "registered": True,
        "online": True,
        "stage": "complete",
        "lane": lane,
        "organization": "N-MultiCloud",
        "gitea_instance_url": "http://10.0.30.96:3000",
        "docker_installed": True,
        "image_ready": True,
        "compose_ready": True,
        **lane_contract,
    }

    validate(success, schema)
    for override in [
        {"registered": False},
        {"online": False},
        {"stage": "verify"},
        {"docker_installed": False},
        {"image_ready": False},
        {"compose_ready": False},
        {"target": "attacker-runner"},
        {"organization": "attacker-org"},
        {"gitea_instance_url": "http://attacker.example:3000"},
        {"runner_name": "caller-shaped-name"},
        {"runner_image": "caller/image:latest"},
        {"compose_project_dir": "/tmp/caller-shaped"},
        {"executor": "docker" if lane == "untrusted-python312" else "host"},
        {
            "runner_mounts_docker_socket": not lane_contract[
                "runner_mounts_docker_socket"
            ]
        },
        {"jobs_mount_docker_socket": True},
        {"runner_cap_drop_all": not lane_contract["runner_cap_drop_all"]},
        {"runner_no_new_privileges": not lane_contract["runner_no_new_privileges"]},
        {"job_user": None if lane_contract["job_user"] else "cirunner"},
        {
            "runner_labels": list(reversed(lane_contract["runner_labels"]))
            + ["extra:host"]
        },
    ]:
        with pytest.raises(ValidationError):
            validate({**success, **override}, schema)

    validate(
        {
            **success,
            "ok": False,
            "changed": None,
            "registered": False,
            "online": False,
            "stage": "register",
            "error": "registration token was refused by Gitea",
        },
        schema,
    )


def test_reverse_disables_without_deleting(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    migration.seed_gitea_org_ci_runner_provision(_apps(procedures, commands), None)
    procedures.rows["unrelated"] = {"enabled": True}

    migration.unseed_gitea_org_ci_runner_provision(_apps(procedures, commands), None)

    assert set(procedures.rows) == {PROCEDURE_ID, "unrelated"}
    assert procedures.rows[PROCEDURE_ID]["enabled"] is False
    assert procedures.rows["unrelated"]["enabled"] is True
    assert procedures.deleted == []


def test_constants_command_contract_and_docs_reference_the_procedure() -> None:
    constants_spec = importlib.util.spec_from_file_location(
        "gitea_runner_constants",
        ROOT / "netbox_rpc/constants.py",
    )
    assert constants_spec and constants_spec.loader
    constants = importlib.util.module_from_spec(constants_spec)
    constants_spec.loader.exec_module(constants)
    assert constants.GITEA_ORG_CI_RUNNER_PROVISION == PROCEDURE_ID
    assert constants.GITEA_ORG_CI_RUNNER_PROVISION_HANDLER == PROCEDURE_ID
    assert constants.GITEA_ORG_CI_RUNNER_PROCEDURE_NAMES == frozenset({PROCEDURE_ID})
    assert PROCEDURE_ID in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES

    command_spec = importlib.util.spec_from_file_location(
        "gitea_runner_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert command_spec and command_spec.loader
    command_contract = importlib.util.module_from_spec(command_spec)
    command_spec.loader.exec_module(command_contract)
    assert PROCEDURE_ID in command_contract.EXEMPT_HANDLER_RATIONALE

    for path in (
        ROOT / "README.md",
        ROOT / "AGENTS.md",
        ROOT / "CLAUDE.md",
        ROOT / "docs/gitea-org-ci-runner-provision.md",
    ):
        assert PROCEDURE_ID in path.read_text(encoding="utf-8")


@pytest.fixture()
def normalization_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.domain.normalization")
    yield module
    sys.modules.pop("netbox_rpc.domain.normalization", None)


def test_code_gate_blocks_runner_provision_by_default(normalization_module) -> None:
    reason = normalization_module.code_gate_unavailable_reason(PROCEDURE_ID)
    assert reason is not None
    assert PROCEDURE_ID in reason
    assert "netbox-rpc-backend" in reason

    with pytest.raises(normalization_module.RPCExecutionError) as excinfo:
        normalization_module.normalize_execution_params(_execution({}))
    assert excinfo.value.code == "RPC_PROCEDURE_NOT_AVAILABLE"


def test_normalizer_lane_contract_matches_immutable_contract(
    normalization_module,
) -> None:
    assert normalization_module._GITEA_ORG_CI_RUNNER_LANES == LANES
    assert (
        normalization_module._GITEA_ORG_CI_RUNNER_LANES
        == normalization_module.gitea_org_ci_runner_contract.LANES
    )


@pytest.mark.parametrize("lane", sorted(LANES))
def test_normalizer_emits_fixed_runner_contract_when_gate_is_open(
    normalization_module,
    monkeypatch: pytest.MonkeyPatch,
    lane: str,
) -> None:
    monkeypatch.setattr(normalization_module, "_GITEA_ORG_CI_RUNNER_AVAILABLE", True)

    normalized = normalization_module.normalize_execution_params(
        _execution(
            {
                "lane": lane,
                "registration_token_secret_ref": SECRET_REF,
                "force_recreate": True,
            }
        )
    )

    assert normalized["target_object"] == {
        "content_type": "virtualization.virtualmachine",
        "object_id": 416,
    }
    assert normalized["runner_ipv4"] == "10.0.30.241"
    assert normalized["gitea_instance_url"] == "http://10.0.30.96:3000"
    assert normalized["organization"] == "N-MultiCloud"
    assert normalized["registration_token_secret_ref"] == SECRET_REF
    assert normalized["lane"] == lane
    for key, value in LANES[lane].items():
        assert normalized[key] == value
    assert normalized["install_docker"] is True
    assert normalized["build_runner_image"] is True
    assert normalized["load_prebuilt_runner_image"] is False
    assert normalized["force_recreate"] is True

    fingerprint = normalized["command_fingerprint"]
    for key, value in fingerprint.items():
        assert not isinstance(value, (dict, list)), key
    assert fingerprint["target_content_type"] == "virtualization.virtualmachine"
    assert fingerprint["target_object_id"] == 416
    assert fingerprint["target_object_sha256"] == (
        normalization_module.gitea_org_ci_runner_contract.TARGET_OBJECT_SHA256
    )
    assert fingerprint["runner_ipv4"] == "10.0.30.241"
    assert fingerprint["registration_token_secret_ref"] == SECRET_REF
    assert fingerprint["lane"] == lane
    assert len(fingerprint["runner_labels_sha256"]) == 64
    for override in FORBIDDEN_SSH_OVERRIDES:
        assert override not in normalized


@pytest.mark.parametrize(
    ("params", "code"),
    [
        ({}, "RPC_PARAM_INVALID"),
        ({"registration_token_secret_ref": SECRET_REF}, "RPC_PARAM_INVALID"),
        (
            {"lane": "unknown", "registration_token_secret_ref": SECRET_REF},
            "RPC_PARAM_INVALID",
        ),
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": "plain-token",
            },
            "RPC_PARAM_INVALID",
        ),
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                "runner_name": "ci runner",
            },
            "RPC_PARAM_INVALID",
        ),
        # gitea_instance_url is no longer a caller parameter at all, so every
        # form of it is now rejected as unsupported rather than being parsed and
        # range-checked. That is the point: a caller who could name the origin
        # could name where the resolved registration credential is delivered.
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                "gitea_instance_url": "http://127.0.0.1:3000",
            },
            "RPC_PARAM_INVALID",
        ),
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                "gitea_instance_url": "http://attacker.example:3000",
            },
            "RPC_PARAM_INVALID",
        ),
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                "organization": "attacker-org",
            },
            "RPC_PARAM_INVALID",
        ),
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                "build_runner_image": True,
                "load_prebuilt_runner_image": True,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                "runner_labels": ["prod"],
            },
            "RPC_PARAM_INVALID",
        ),
        (
            {
                "lane": "untrusted-python312",
                "registration_token_secret_ref": SECRET_REF,
                "rpc_ssh_host": "10.0.30.99",
            },
            "RPC_PARAM_INVALID",
        ),
    ],
)
def test_normalizer_rejects_unsafe_inputs(
    normalization_module,
    monkeypatch: pytest.MonkeyPatch,
    params: dict,
    code: str,
) -> None:
    monkeypatch.setattr(normalization_module, "_GITEA_ORG_CI_RUNNER_AVAILABLE", True)

    with pytest.raises(normalization_module.RPCExecutionError) as excinfo:
        normalization_module.normalize_execution_params(_execution(params))
    assert excinfo.value.code == code


@pytest.mark.parametrize(
    "kwargs",
    [
        {"object_id": None},
        {"object_id": 0},
        {"object_id": True},
        {"object_id": 241},
        {"target_model_label": "ipam.ipaddress"},
        {"target_model_label": "dcim.device", "content_type": "ipam.ipaddress"},
        {"assigned_object": None},
        {"assigned_object": SimpleNamespace(pk=416, name="different-runner")},
        {
            "assigned_object": SimpleNamespace(
                pk=416,
                name="Gitea-Runner",
                primary_ip4=SimpleNamespace(address="10.0.30.242/24"),
                status=SimpleNamespace(value="active"),
            )
        },
        {
            "assigned_object": SimpleNamespace(
                pk=416,
                name="Gitea-Runner",
                primary_ip4=SimpleNamespace(address="10.0.30.241/24"),
                status=SimpleNamespace(value="offline"),
            )
        },
        {"target_display": "different-runner"},
    ],
)
def test_normalizer_requires_supported_assigned_object(
    normalization_module,
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict,
) -> None:
    monkeypatch.setattr(normalization_module, "_GITEA_ORG_CI_RUNNER_AVAILABLE", True)

    with pytest.raises(normalization_module.RPCExecutionError) as excinfo:
        normalization_module.normalize_execution_params(
            _execution(
                {
                    "lane": "untrusted-python312",
                    "registration_token_secret_ref": SECRET_REF,
                },
                **kwargs,
            )
        )
    assert excinfo.value.code == "RPC_TARGET_INVALID"


def _apps(procedures, commands):
    def get_model(app_label: str, model_name: str):
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure"):
            return SimpleNamespace(objects=procedures)
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedureCommand"):
            return SimpleNamespace(objects=commands)
        raise AssertionError((app_label, model_name))

    return SimpleNamespace(get_model=get_model)


def _execution(
    params: dict[str, object],
    *,
    target_model_label: str = "virtualization.virtualmachine",
    content_type: str | None = None,
    object_id: object = 416,
    assigned_object: object = _DEFAULT_TARGET,
    target_display: str = "Gitea-Runner",
):
    label = content_type if content_type is not None else target_model_label
    app_label, _, model = label.partition(".")
    if assigned_object is _DEFAULT_TARGET:
        # The reviewed policy pins the exact dedicated runner VM: pk, name,
        # primary_ip4, and active status must all match the contract, so the
        # default fixture object has to satisfy all of them for a test to reach
        # parameter validation at all.
        assigned_object = SimpleNamespace(
            pk=416,
            name="Gitea-Runner",
            primary_ip4=SimpleNamespace(address="10.0.30.241/24"),
            status=SimpleNamespace(value="active"),
        )
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name=PROCEDURE_ID,
            handler_id=PROCEDURE_ID,
            transport_driver="asyncssh",
            transport_pinned=True,
            transport_driver_chain=[],
            output_parser="none",
            output_schema={},
            commands=[],
        ),
        params=params,
        target_display=target_display,
        target_model_label=target_model_label,
        assigned_object_type=SimpleNamespace(app_label=app_label, model=model),
        assigned_object_id=object_id,
        assigned_object=assigned_object,
    )


class _ProcedureQuery:
    def __init__(self, manager: "_FakeProcedureManager", names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def _matching(self) -> list[str]:
        return [name for name in self.manager.rows if name in self.names]

    def update(self, **fields) -> int:
        matched = self._matching()
        for name in matched:
            self.manager.rows[name].update(fields)
        return len(matched)

    def delete(self) -> None:
        for name in self._matching():
            self.manager.deleted.append(name)
            self.manager.rows.pop(name, None)


class _FakeProcedure:
    def __init__(self, manager: "_FakeProcedureManager", name: str, data: dict) -> None:
        self._manager = manager
        self.name = name
        self.handler_id = str(data["handler_id"])


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.deleted: list[str] = []

    def update_or_create(self, *, name: str, defaults: dict[str, object]):
        self.rows[name] = dict(defaults)
        return _FakeProcedure(self, name, self.rows[name]), True

    def filter(self, *, name=None, name__in=None):
        if name is not None:
            return _ProcedureQuery(self, {name})
        return _ProcedureQuery(self, set(name__in or ()))


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def update_or_create(
        self, *, procedure: _FakeProcedure, sequence: int, defaults: dict
    ):
        self.rows[(procedure.handler_id, sequence)] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence, **defaults), True


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_migrations = types.ModuleType("django.db.migrations")
    django_migrations.Migration = type("Migration", (), {})
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    django.db = django_db

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})

    django = types.ModuleType("django")
    django_conf = types.ModuleType("django.conf")
    django_conf.settings = SimpleNamespace(PLUGINS_CONFIG={})
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCNetBoxPluginAllowlist = type("RPCNetBoxPluginAllowlist", (), {})
    models.RPCExecution = type("RPCExecution", (), {})

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.conf", django_conf)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)


def test_docs_attribute_this_procedure_to_migration_0084() -> None:
    """0080 belongs to service.gitea.runner.register, not this procedure.

    The renumber to 0084 was needed to escape a two-leaf migration graph, so a
    doc that still says 0080 sends a maintainer to the wrong migration. Checked
    as an exact attribution phrase rather than by paragraph proximity, because
    the register procedure is legitimately described as 0080/0081 nearby.
    """
    procedure = "service.gitea.actions_runner.provision_org_ci_runner"
    stale = f"Migration `0080` adds\n`{procedure}`"
    current = f"Migration `0084` adds\n`{procedure}`"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert stale not in readme
    assert current in readme
    for name in ("AGENTS.md", "CLAUDE.md"):
        path = ROOT / name
        if path.is_file():
            assert f"Migration `0080` adds\n`{procedure}`" not in path.read_text(
                encoding="utf-8"
            )


def test_transport_pin_is_extracted_from_the_live_row_not_the_contract(
    migration,
) -> None:
    """Guard the exact regression that a constant-comparison test would miss.

    The point of binding `transport_pinned` is drift detection: the extracted
    policy must read the LIVE row so that a row edited to False no longer
    matches the contract. If `_protected_procedure_policy()` were changed to
    `policy["transport_pinned"] = contract.TRANSPORT_PINNED`, the two sides
    would agree unconditionally, drift detection would be silently gone, and a
    test that only compares migration and contract constants would still pass.

    This is asserted at source level because `command_handlers` pulls in the
    full NetBox/DRF stack, which this module deliberately does not load. The
    executable end-to-end variant (build a procedure, flip only the live value,
    assert `_require_protected_procedure_policy()` raises) belongs in
    `netbox_rpc/tests/`, which runs under a real NetBox environment in CI.
    """

    import ast

    source = (ROOT / "netbox_rpc/application/command_handlers.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "_protected_procedure_policy"
    )
    body = ast.get_source_segment(source, func) or ""

    assert "transport_pinned" in body, (
        "_protected_procedure_policy() no longer mentions transport_pinned; the "
        "pin is unenforced again."
    )
    # it must read the live row...
    assert 'getattr(procedure, "transport_pinned"' in body, (
        "transport_pinned must be read from the live procedure row, otherwise "
        "the extracted policy can never disagree with the contract and drift "
        "detection is gone."
    )
    # ...and must NOT source the value from the contract, which would make the
    # comparison unconditionally true.
    assert "contract.TRANSPORT_PINNED" not in body, (
        "transport_pinned must not be sourced from the contract inside the "
        "extractor; that makes the policy comparison vacuous."
    )

    # and the two sides that are compared must genuinely start out equal
    from netbox_rpc import gitea_org_ci_runner_contract as contract

    assert contract.TRANSPORT_PINNED is True
    assert contract.PROCEDURE_POLICY["transport_pinned"] is True
    assert migration._PROCEDURE_DEFAULTS["transport_pinned"] is True


def test_org_ci_runner_dispatch_fails_closed_without_protected_transport() -> None:
    """The generic backend response path must be unreachable for this procedure.

    `_call_backend()` classifies only the production upgrade and the existing
    runner registration as secret-protected. On the generic path it follows
    redirects, calls unbounded `resp.json()`, and copies backend-controlled
    diagnostics into the event ledger -- where an opaque registration credential
    would not be recognised by the regex redactor.

    Until the closed response envelope exists (it belongs with the paired
    backend handler, netbox-rpc #280), dispatch must refuse rather than fall
    through.
    """

    source = (ROOT / "netbox_rpc/jobs.py").read_text(encoding="utf-8")
    assert "service.gitea.actions_runner.provision_org_ci_runner" in source, (
        "jobs.py no longer guards the org CI runner procedure; it would fall "
        "through to the generic, redirect-following, unbounded response path."
    )
    assert "RPC_PROCEDURE_NOT_AVAILABLE" in source


def test_transport_pin_binding_is_scoped_to_this_contract() -> None:
    """Only this contract declares a pin, so only this one is compared.

    `_protected_procedure_policy()` adds `transport_pinned` opt-in, mirroring the
    existing `semantic_contract_sha256` precedent, so the staging rotation, the
    Gitea 1.27.1 upgrade, and service.gitea.runner.register keep their exact
    policy shape and their computed PROCEDURE_POLICY_SHA256 unchanged.

    NOTE: migration 0075 pins service.netbox.staging.rotate_backend_token, and
    its contract does NOT bind that pin -- the same defect this fixes here, but
    pre-existing and independent of this procedure. Deliberately left alone
    rather than changing a sensitive unrelated procedure's admission behaviour
    on a feature branch; tracked separately.
    """

    from netbox_rpc import (
        gitea_org_ci_runner_contract,
        gitea_runner_contract,
        gitea_upgrade_contract,
        staging_rotation_contract,
    )

    assert gitea_org_ci_runner_contract.TRANSPORT_PINNED is True
    assert gitea_org_ci_runner_contract.PROCEDURE_POLICY["transport_pinned"] is True

    for other in (
        gitea_runner_contract,
        gitea_upgrade_contract,
        staging_rotation_contract,
    ):
        assert getattr(other, "TRANSPORT_PINNED", None) is None
        assert "transport_pinned" not in other.PROCEDURE_POLICY
