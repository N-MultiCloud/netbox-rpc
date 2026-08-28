"""Contract tests for the Debian 13 Akvorado bootstrap catalog."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
SEED_MODULE = "netbox_rpc.migrations.0086_seed_akvorado_debian13_bootstrap_procedures"
PREFLIGHT = "os.linux.debian.13.preflight_akvorado"
INSTALL = "os.linux.debian.13.install_akvorado"
HANDLERS = {
    PREFLIGHT: "os.linux_debian_13.preflight_akvorado",
    INSTALL: "os.linux_debian_13.install_akvorado",
}
FORBIDDEN_SSH_OVERRIDES = (
    "rpc_ssh_credential_pk",
    "rpc_ssh_host",
    "rpc_ssh_port",
    "rpc_ssh_known_hosts_entry",
    "rpc_ssh_strict_host_key_checking",
)
SSH_SNAPSHOT = {
    "ssh_service_id": 64,
    "ssh_service_revision": "2026-08-28T12:00:00Z",
    "ssh_identity_id": 35,
    "ssh_identity_revision": "2026-08-28T12:01:00Z",
    "ssh_storage_backend": "local",
    "ssh_principal": "akvorado",
    "ssh_method": "password",
    "ssh_host": "10.0.30.235",
    "ssh_port": 22,
    "ssh_known_hosts_sha256": "0" * 64,
    "ssh_policy_ref": "target-owned-ssh:dcim.device:235",
}


class _ProcedureQuery:
    def __init__(self, manager: "_ProcedureManager", names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def update(self, **fields: Any) -> int:
        matches = [name for name in self.names if name in self.manager.rows]
        for name in matches:
            self.manager.rows[name].update(fields)
        return len(matches)

    def first(self):
        for name in sorted(self.names):
            if name in self.manager.rows:
                return SimpleNamespace(name=name, **self.manager.rows[name])
        return None


class _ProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}

    def create(self, *, name: str, **fields: Any):
        self.rows[name] = dict(fields)
        return SimpleNamespace(name=name, **fields)

    def filter(self, *, name__in=None, name=None):
        names = set(name__in) if name__in is not None else {name}
        return _ProcedureQuery(self, names)


class _CommandQuery:
    def __init__(self, manager: "_CommandManager", procedure_name: str) -> None:
        self.manager = manager
        self.procedure_name = procedure_name

    def order_by(self, _field: str):
        return [
            SimpleNamespace(sequence=sequence, **fields)
            for (name, sequence), fields in sorted(self.manager.rows.items())
            if name == self.procedure_name
        ]


class _CommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, Any]] = {}

    def create(self, *, procedure, sequence: int, **fields: Any):
        self.rows[(procedure.name, sequence)] = dict(fields)
        return SimpleNamespace(sequence=sequence, **fields)

    def filter(self, *, procedure):
        return _CommandQuery(self, procedure.name)


def _apps(procedures: _ProcedureManager, commands: _CommandManager | None = None):
    def _get_model(app_label: str, model_name: str):
        assert app_label == "netbox_rpc"
        if model_name == "RPCProcedure":
            return SimpleNamespace(objects=procedures)
        assert model_name == "RPCProcedureCommand"
        assert commands is not None
        return SimpleNamespace(objects=commands)

    return SimpleNamespace(get_model=_get_model)


def _install_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})
    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    migrations = types.ModuleType("django.db.migrations")
    migrations.Migration = type("Migration", (), {})
    migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = migrations
    django.db = django_db
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.migrations", migrations)


@pytest.fixture()
def catalog(monkeypatch: pytest.MonkeyPatch):
    _install_import_stubs(monkeypatch)
    sys.modules.pop(SEED_MODULE, None)
    seed = importlib.import_module(SEED_MODULE)
    procedures = _ProcedureManager()
    commands = _CommandManager()
    seed.seed_akvorado_debian13_bootstrap_procedures(_apps(procedures, commands), None)
    return seed, procedures, commands


def test_seed_is_closed_target_owned_and_backend_orchestrated(catalog) -> None:
    seed, procedures, commands = catalog
    assert set(procedures.rows) == {PREFLIGHT, INSTALL}
    for name, handler_id in HANDLERS.items():
        row = procedures.rows[name]
        assert row["handler_id"] == handler_id
        assert row["enabled"] is False
        assert row["target_models"] == ["dcim.device"]
        assert row["transport_driver"] == "asyncssh"
        assert row["transport_pinned"] is True
        assert row["transport_driver_chain"] == []
        assert row["params_schema"]["additionalProperties"] is False
        assert row["result_schema"]["additionalProperties"] is False
        assert not set(FORBIDDEN_SSH_OVERRIDES) & set(
            row["params_schema"]["properties"]
        )
        command = commands.rows[(name, 1)]
        assert command["argv"][0] == "backend-orchestrated"
        assert command["description"] == row["description"]

    assert procedures.rows[PREFLIGHT]["effect"] == "read"
    assert procedures.rows[PREFLIGHT]["approval_required"] is False
    assert procedures.rows[PREFLIGHT]["timeout_seconds"] == 90
    assert procedures.rows[INSTALL]["effect"] == "write"
    assert procedures.rows[INSTALL]["approval_required"] is True
    assert procedures.rows[INSTALL]["timeout_seconds"] == 1200
    assert set(procedures.rows[INSTALL]["params_schema"]["properties"]) == {
        "allow_resource_shortfall"
    }
    assert seed.Migration.dependencies == [
        ("netbox_rpc", "0085_seed_dns_staging_deploy")
    ]


def test_seed_reverse_only_disables_durable_rows(catalog) -> None:
    seed, procedures, commands = catalog
    apps = _apps(procedures, commands)
    for row in procedures.rows.values():
        row["enabled"] = True
    seed.unseed_akvorado_debian13_bootstrap_procedures(apps, None)
    assert set(procedures.rows) == {PREFLIGHT, INSTALL}
    assert all(row["enabled"] is False for row in procedures.rows.values())


def test_seed_reapply_is_exact_and_existing_drift_fails_closed(catalog) -> None:
    seed, procedures, commands = catalog
    apps = _apps(procedures, commands)
    seed.seed_akvorado_debian13_bootstrap_procedures(apps, None)
    assert set(procedures.rows) == {PREFLIGHT, INSTALL}

    procedures.rows[INSTALL]["timeout_seconds"] = 30
    with pytest.raises(RuntimeError, match="timeout_seconds"):
        seed.seed_akvorado_debian13_bootstrap_procedures(apps, None)


def test_seed_rejects_extra_or_drifted_existing_command(catalog) -> None:
    seed, procedures, commands = catalog
    apps = _apps(procedures, commands)
    commands.rows[(PREFLIGHT, 2)] = dict(commands.rows[(PREFLIGHT, 1)])
    with pytest.raises(RuntimeError, match="exactly one command"):
        seed.seed_akvorado_debian13_bootstrap_procedures(apps, None)

    commands.rows.pop((PREFLIGHT, 2))
    commands.rows[(PREFLIGHT, 1)]["argv"] = ["backend-orchestrated", "drifted"]
    with pytest.raises(RuntimeError, match="argv"):
        seed.seed_akvorado_debian13_bootstrap_procedures(apps, None)


def _successful_install() -> dict[str, Any]:
    services = [
        "clickhouse",
        "console",
        "inlet",
        "kafka",
        "orchestrator",
        "outlet",
        "redis",
    ]
    return {
        "ok": True,
        "procedure": INSTALL,
        "target": "akvorado01",
        "installed": True,
        "changed": True,
        "config_created": True,
        "docker_package_version": "26.1.5+dfsg1-9",
        "compose_package_version": "2.26.1-4",
        "docker_version": "26.1.5",
        "compose_version": "2.26.1",
        "compose_path": "/opt/nmulticloud/deploy/compose/akvorado/docker-compose.yml",
        "config_path": "/opt/nmulticloud/deploy/compose/akvorado/akvorado.yaml",
        "stack_healthy": True,
        "services_expected": services,
        "services_running": services,
        "services_healthy": services,
        "console_ready": True,
        "ingress_ports_ready": True,
        "ready": True,
        "stage": "complete",
        "warnings": [],
        "error": "",
    }


def test_install_success_envelope_cannot_describe_partial_or_failed_work(
    catalog,
) -> None:
    _seed, procedures, _commands = catalog
    schema = procedures.rows[INSTALL]["result_schema"]
    valid = _successful_install()
    validate(valid, schema)

    for field, value in (
        ("installed", False),
        ("stack_healthy", False),
        ("console_ready", False),
        ("ingress_ports_ready", False),
        ("ready", False),
        ("stage", "verify"),
        ("services_expected", []),
        ("services_running", valid["services_running"][:-1]),
        ("services_healthy", valid["services_healthy"] + ["redis"]),
        ("error", "unexpected success diagnostic"),
        ("changed", None),
        ("config_created", None),
    ):
        invalid = {**valid, field: value}
        with pytest.raises(ValidationError):
            validate(invalid, schema)

    failure = {
        **valid,
        "ok": False,
        "ready": False,
        "stage": "verify",
        "stack_healthy": False,
        "services_running": [],
        "services_healthy": [],
        "console_ready": False,
        "ingress_ports_ready": False,
        "error": "health verification failed",
    }
    validate(failure, schema)

    for contradictory in (
        {**failure, "stage": "complete"},
        {**failure, "error": ""},
        {**failure, "changed": None},
        {
            **failure,
            "stack_healthy": True,
            "services_running": valid["services_running"],
            "services_healthy": valid["services_healthy"],
            "console_ready": True,
            "ingress_ports_ready": True,
        },
    ):
        with pytest.raises(ValidationError):
            validate(contradictory, schema)

    unknown = {
        **failure,
        "installed": None,
        "changed": None,
        "config_created": None,
        "stage": "outcome_unknown",
        "stack_healthy": False,
        "services_running": [],
        "services_healthy": [],
        "console_ready": False,
        "ingress_ports_ready": False,
        "error": "remote outcome is indeterminate",
    }
    validate(unknown, schema)


def _install_runtime_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_import_stubs(monkeypatch)
    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCNetBoxPluginAllowlist = type("RPCNetBoxPluginAllowlist", (), {})
    models.RPCExecution = type("RPCExecution", (), {})
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)


def _execution(
    name: str,
    params: dict[str, Any],
    *,
    model_label: str = "dcim.device",
    object_id: object = 235,
    primary_ip4: object = "10.0.30.235/24",
):
    app_label, _, model = model_label.partition(".")
    return SimpleNamespace(
        procedure=SimpleNamespace(name=name, handler_id=HANDLERS[name]),
        params=params,
        target_display="akvorado01",
        target_model_label=model_label,
        assigned_object_type=SimpleNamespace(app_label=app_label, model=model),
        assigned_object_type_id=17,
        assigned_object_id=object_id,
        assigned_object=SimpleNamespace(
            name="akvorado01",
            primary_ip4=SimpleNamespace(address=primary_ip4),
        ),
    )


@pytest.fixture()
def normalization(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.domain.normalization")
    monkeypatch.setattr(module, "_AKVORADO_BOOTSTRAP_DEBIAN13_AVAILABLE", True)
    monkeypatch.setattr(
        module,
        "_resolve_locked_ssh_identity",
        lambda **_kwargs: dict(SSH_SNAPSHOT),
    )
    yield module
    sys.modules.pop("netbox_rpc.domain.normalization", None)


def test_normalizer_binds_device_identity_and_only_boolean_override(
    normalization,
) -> None:
    preflight = normalization._normalize_akvorado_bootstrap_debian13_execution(
        _execution(PREFLIGHT, {}), "akvorado01"
    )
    assert preflight["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 235,
    }
    assert "allow_resource_shortfall" not in preflight

    install = normalization._normalize_akvorado_bootstrap_debian13_execution(
        _execution(INSTALL, {"allow_resource_shortfall": True}), "akvorado01"
    )
    assert install["allow_resource_shortfall"] is True
    assert install["command_fingerprint"]["allow_resource_shortfall"] is True
    assert install["command_fingerprint"]["target_object_sha256"] == (
        normalization._hash_json(install["target_object"])
    )
    expected_snapshot = {
        **SSH_SNAPSHOT,
        "ssh_strict_host_key_checking": True,
    }
    assert install["ssh_snapshot"] == expected_snapshot
    assert install["ssh_policy_ref"] == "target-owned-ssh:dcim.device:235"
    assert install["command_fingerprint"]["ssh_snapshot"] == expected_snapshot
    assert (
        install["command_fingerprint"]["ssh_policy_ref"]
        == "target-owned-ssh:dcim.device:235"
    )


def test_install_snapshot_is_bound_to_primary_ipv4_and_policy_ref(
    normalization, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    def _resolve(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return dict(SSH_SNAPSHOT)

    monkeypatch.setattr(normalization, "_resolve_locked_ssh_identity", _resolve)
    normalized = normalization._normalize_akvorado_bootstrap_debian13_execution(
        _execution(INSTALL, {}), "akvorado01"
    )

    assert calls == [
        {
            "assigned_object_type_id": 17,
            "assigned_object_id": 235,
            "expected_host": "10.0.30.235",
            "policy_ref": "target-owned-ssh:dcim.device:235",
        }
    ]
    assert normalized["ssh_snapshot"]["ssh_host"] == "10.0.30.235"


def test_install_rejects_missing_or_non_ipv4_primary_address(normalization) -> None:
    for primary_ip4 in (None, "2001:db8::235/64", "not-an-address"):
        with pytest.raises(normalization.RPCExecutionError) as excinfo:
            normalization._normalize_akvorado_bootstrap_debian13_execution(
                _execution(INSTALL, {}, primary_ip4=primary_ip4), "akvorado01"
            )
        assert excinfo.value.code == "RPC_TARGET_INVALID"


@pytest.mark.parametrize("override", FORBIDDEN_SSH_OVERRIDES)
def test_normalizer_rejects_every_ssh_override(normalization, override: str) -> None:
    with pytest.raises(normalization.RPCExecutionError) as excinfo:
        normalization._normalize_akvorado_bootstrap_debian13_execution(
            _execution(INSTALL, {override: "hostile"}), "akvorado01"
        )
    assert excinfo.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    ("model_label", "object_id"),
    [
        ("virtualization.virtualmachine", 1),
        ("dcim.device", None),
        ("dcim.device", True),
    ],
)
def test_normalizer_rejects_non_device_or_invalid_identity(
    normalization, model_label: str, object_id: object
) -> None:
    with pytest.raises(normalization.RPCExecutionError) as excinfo:
        normalization._normalize_akvorado_bootstrap_debian13_execution(
            _execution(INSTALL, {}, model_label=model_label, object_id=object_id),
            "akvorado01",
        )
    assert excinfo.value.code == "RPC_TARGET_INVALID"


def test_code_gate_is_shared_and_can_fail_closed(normalization, monkeypatch) -> None:
    monkeypatch.setattr(normalization, "_AKVORADO_BOOTSTRAP_DEBIAN13_AVAILABLE", False)
    reason = normalization.code_gate_unavailable_reason(INSTALL)
    assert reason is not None
    assert "netbox-rpc-backend" in reason
    monkeypatch.setattr(normalization, "_AKVORADO_BOOTSTRAP_DEBIAN13_AVAILABLE", True)
    assert normalization.code_gate_unavailable_reason(INSTALL) is None


def test_constants_and_command_contract_match_catalog(catalog) -> None:
    _seed, procedures, _commands = catalog
    constants = importlib.import_module("netbox_rpc.constants")
    command_contract = importlib.import_module("netbox_rpc.command_contract")
    assert constants.AKVORADO_BOOTSTRAP_DEBIAN13_PREFLIGHT == PREFLIGHT
    assert constants.AKVORADO_BOOTSTRAP_DEBIAN13_INSTALL == INSTALL
    assert INSTALL in constants.PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert constants.EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES == {
        PREFLIGHT,
        INSTALL,
        constants.NETBOX_STAGING_DEPLOY_DNS_PAIR,
        constants.GITEA_PRODUCTION_UPGRADE_1_27_1,
        constants.GITEA_RUNNER_REGISTER,
        constants.GITEA_ORG_CI_RUNNER_PROVISION,
    }
    assert set(constants.AKVORADO_BOOTSTRAP_DEBIAN13_PROCEDURE_NAMES) == set(
        procedures.rows
    )
    assert set(HANDLERS.values()) <= command_contract.EXEMPT_HANDLER_IDS


def test_semantic_capability_hashes_match_backend_ground_truth(catalog) -> None:
    _seed, procedures, commands = catalog
    capabilities = importlib.import_module("netbox_rpc.capabilities")

    class Commands:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self.rows

    expected = {
        PREFLIGHT: "50ab427bb1f4fee18a76fbe00f19a65b9cbb03d3c1951d9f500b0da6938ece03",
        INSTALL: "b9ec74c18c69c53c494155671c638f878b1c74b6d1cf478b8665f822ab4469a6",
    }
    for name, digest in expected.items():
        command_rows = [
            SimpleNamespace(sequence=sequence, **fields)
            for (procedure_name, sequence), fields in commands.rows.items()
            if procedure_name == name
        ]
        procedure = SimpleNamespace(
            name=name,
            **procedures.rows[name],
            commands=Commands(command_rows),
        )
        assert capabilities.derive_command_contract_hash(procedure) == digest

        procedure.timeout_seconds -= 1
        assert capabilities.derive_command_contract_hash(procedure) != digest


def test_capability_mid_body_failure_degrades_to_unknown_and_closes(
    catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capabilities = importlib.import_module("netbox_rpc.capabilities")
    closed: list[bool] = []

    class Raw:
        def read(self, *_args: Any, **_kwargs: Any):
            raise RuntimeError("connection reset mid-body")

    response = SimpleNamespace(
        status_code=200,
        raw=Raw(),
        close=lambda: closed.append(True),
    )
    monkeypatch.setattr(capabilities.requests, "get", lambda *_args, **_kwargs: response)
    target = SimpleNamespace(headers={}, verify_ssl=True)

    assert capabilities._fetch_uncached("https://backend.example", target, 1.0) is None
    assert closed == [True]
