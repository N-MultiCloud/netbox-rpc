"""Contract tests for the Debian 13 InfluxDB 3 Core installation catalog.

The properties that matter most are asserted against transcribed constants rather
than values re-derived from the code under test:

1. The seeded rows carry the intended gating — the installer is a write procedure
   that requires approval, the posture read is neither.
2. Neither procedure accepts a credential *or* an SSH override, so the execution
   backend can only reach the execution's assigned NetBox object.
3. The normalizer refuses, in the pure domain, every input the operator installer
   refuses — most importantly a remote bind with no TLS and no explicit
   ``allow_plaintext_remote`` opt-in, and any non-canonical data directory.
4. A success envelope cannot describe a failed or partial installation.

Administrative tokens for this product family belong exclusively to
``service.influxdb.1.bootstrap``.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ALLOWLIST_MIGRATION = "netbox_rpc.migrations.0071_seed_influxdb3_core_service_allowlist"
PROCEDURE_MIGRATION = (
    "netbox_rpc.migrations.0072_seed_influxdb3_debian13_install_procedures"
)

PREFLIGHT = "os.linux.debian.13.preflight_influxdb3_core"
INSTALL = "os.linux.debian.13.install_influxdb3_core"
HANDLERS = {
    PREFLIGHT: "os.linux_debian_13.preflight_influxdb3_core",
    INSTALL: "os.linux_debian_13.install_influxdb3_core",
}
# Transcribed once from the intended design, not read back from the migration.
EXPECTED_GATING = {
    PREFLIGHT: {"effect": "read", "approval_required": False, "timeout_seconds": 60},
    INSTALL: {"effect": "write", "approval_required": True, "timeout_seconds": 900},
}
SECRET_SHAPED_PARAM_NAMES = (
    "token",
    "admin_token",
    "password",
    "passphrase",
    "secret",
    "secret_ref",
    "admin_secret_ref",
    "credential",
    "generate_admin_token",
    "token_output_file",
    "admin_token_name",
)
# The shared connection-override contract, deliberately NOT offered here: a
# caller-supplied credential pk is not object-scoped against the requester, and a
# caller-supplied host would pivot SSH away from the audited target.
FORBIDDEN_SSH_OVERRIDES = (
    "rpc_ssh_credential_pk",
    "rpc_ssh_host",
    "rpc_ssh_port",
    "rpc_ssh_known_hosts_entry",
    "rpc_ssh_strict_host_key_checking",
)
A_SUCCESSFUL_INSTALL_RESULT = {
    "ok": True,
    "procedure": INSTALL,
    "target": "influx01",
    "installed": True,
    "package_version": "3.11.0-1",
    "service_state": "active",
    "service_enabled": "enabled",
    "http_bind": "127.0.0.1:8181",
    "node_id": "influx01-node",
    "data_dir": "/var/lib/influxdb3/data",
    "config_path": "/etc/influxdb3/influxdb3-core.conf",
    "plugins_enabled": False,
    "package_held": True,
    "ready": True,
    "stage": "complete",
}


# --------------------------------------------------------------------------- #
# Seed contract
# --------------------------------------------------------------------------- #


def test_allowlist_seed_adds_the_core3_unit_without_touching_the_oss2_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(ALLOWLIST_MIGRATION, None)
    migration = importlib.import_module(ALLOWLIST_MIGRATION)

    allowlist = _FakeAllowlistManager()
    # Pre-existing OSS 2 row seeded by migration 0053.
    allowlist.rows["influxdb"] = {"systemd_unit": "influxdb.service"}
    apps = SimpleNamespace(
        get_model=lambda app_label, model_name: _expect_model(
            (app_label, model_name),
            ("netbox_rpc", "RPCLinuxServiceAllowlist"),
            allowlist,
        )
    )

    migration.seed_influxdb3_core_service_allowlist(apps, None)

    assert allowlist.rows["influxdb3-core"]["systemd_unit"] == "influxdb3-core.service"
    assert allowlist.rows["influxdb3-core"]["enabled"] is True
    assert allowlist.rows["influxdb3-core"]["target_models"] == [
        "dcim.device",
        "virtualization.virtualmachine",
    ]
    # The OSS 2 row is a different unit and must survive untouched.
    assert allowlist.rows["influxdb"] == {"systemd_unit": "influxdb.service"}

    migration.unseed_influxdb3_core_service_allowlist(apps, None)
    assert "influxdb3-core" not in allowlist.rows
    assert "influxdb" in allowlist.rows


def test_allowlist_seed_declares_no_shell_text() -> None:
    source = (
        ROOT / "netbox_rpc/migrations/0071_seed_influxdb3_core_service_allowlist.py"
    ).read_text()

    for forbidden in ("subprocess", "os.system", "shell=True", "RPCProcedureCommand"):
        assert forbidden not in source


def test_seed_creates_two_procedures_with_the_intended_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedures, commands = _run_procedure_seed(monkeypatch)

    assert set(procedures.rows) == {PREFLIGHT, INSTALL}
    for name, expected in EXPECTED_GATING.items():
        row = procedures.rows[name]
        assert row["handler_id"] == HANDLERS[name]
        assert row["version"] == 1
        assert row["enabled"] is True
        assert row["target_models"] == [
            "dcim.device",
            "virtualization.virtualmachine",
        ]
        assert row["effect"] == expected["effect"]
        assert row["approval_required"] is expected["approval_required"]
        assert row["timeout_seconds"] == expected["timeout_seconds"]
        assert row["params_schema"]["additionalProperties"] is False
        assert row["result_schema"]["additionalProperties"] is False
        # One representative backend-orchestrated command row per procedure.
        command = commands.rows[(row["handler_id"], 1)]
        assert command["argv"][0] == "backend-orchestrated"
        assert command["step_type"] == "shell_argv"
        assert "_" not in command["argv"][1]


def test_seed_declares_no_credential_or_ssh_override_parameter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Token creation belongs to service.influxdb.1.bootstrap; SSH comes from target."""

    procedures, _ = _run_procedure_seed(monkeypatch)

    for name in (PREFLIGHT, INSTALL):
        row = procedures.rows[name]
        params_properties = set(row["params_schema"]["properties"])
        result_properties = set(row["result_schema"]["properties"])
        for forbidden in SECRET_SHAPED_PARAM_NAMES:
            assert forbidden not in params_properties, (name, forbidden)
            assert forbidden not in result_properties, (name, forbidden)
        for forbidden in FORBIDDEN_SSH_OVERRIDES:
            assert forbidden not in params_properties, (name, forbidden)
        # Nothing is required, so a run can be issued with no parameters at all.
        assert row["params_schema"]["required"] == []


def test_seed_patterns_are_anchored_against_the_trailing_newline_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """jsonschema applies ``pattern`` with ``re.search``; ``$`` matches before \\n."""

    procedures, _ = _run_procedure_seed(monkeypatch)

    for name in (PREFLIGHT, INSTALL):
        schema = procedures.rows[name]["params_schema"]
        patterns = [
            spec["pattern"]
            for spec in schema["properties"].values()
            if isinstance(spec, dict) and "pattern" in spec
        ]
        assert patterns, name
        for pattern in patterns:
            assert pattern.endswith(r"(?![\s\S])"), (name, pattern)

    install_schema = procedures.rows[INSTALL]["params_schema"]
    # A trailing newline must not slip a value past the charset.
    for field, value in (
        ("node_id", "influx01-node\n"),
        ("data_dir", "/var/lib/influxdb3/data\n"),
        ("http_bind", "127.0.0.1:8181\n"),
        ("wal_flush_interval", "100ms\n"),
        ("log_filter", "info\n"),
        ("package_version", "3.11.0-1\n"),
    ):
        with pytest.raises(ValidationError):
            validate({field: value}, install_schema)


def test_install_schema_rejects_unsafe_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedures, _ = _run_procedure_seed(monkeypatch)
    schema = procedures.rows[INSTALL]["params_schema"]

    for params in (
        {"data_dir": "/var/lib/../etc/influxdb3"},  # traversal
        {"data_dir": "/var/./tmp/influxdb3"},  # single-dot segment
        {"data_dir": "/./tmp/influxdb3"},
        {"data_dir": "/var/lib/influxdb3/."},
        {"data_dir": "/.."},
        {"data_dir": "relative/path"},  # not absolute
        {"data_dir": "/var/lib/influx db3"},  # whitespace
        {"data_dir": "/var/lib/influxdb3/"},  # trailing separator
        {"node_id": "-leading-hyphen"},  # could read as an option
        {"node_id": "trailing-hyphen-"},
        {"http_bind": "127.0.0.1"},  # missing port
        {"http_bind": "127.0.0.1:8181;id"},  # shell metacharacter
        {"wal_flush_interval": "100"},  # missing unit
        {"wal_flush_interval": "100m"},  # unsupported unit
        {"log_filter": "info;rm -rf /"},
        {"package_version": "3.11.0 && id"},
        {"tls_cert": "../relative.pem"},
        {"tls_cert": "/etc/influxdb3/../../root/key.pem"},
        {"unknown_param": "x"},  # additionalProperties: false
        # The shared SSH overrides are refused by the schema, not just the normalizer.
        *({override: "x"} for override in FORBIDDEN_SSH_OVERRIDES),
    ):
        with pytest.raises(ValidationError):
            validate(params, schema)

    # The documented default posture validates.
    validate(
        {
            "node_id": "influx01-node",
            "data_dir": "/var/lib/influxdb3/data",
            "http_bind": "127.0.0.1:8181",
            "wal_flush_interval": "100ms",
            "log_filter": "info",
            "enable_plugins": False,
            "disable_telemetry": True,
            "hold_package": True,
        },
        schema,
    )
    # A path whose *segment* merely contains a dot is legitimate.
    validate({"tls_cert": "/etc/influxdb3/tls/server.crt"}, schema)
    assert "\\u0000" not in json.dumps(schema)


def test_every_result_string_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """event_store silently clamps unbounded strings at 4096 characters.

    An unbounded audit field would therefore be truncated with no validation error,
    and a malformed backend could return an arbitrarily large valid result.
    """

    procedures, _ = _run_procedure_seed(monkeypatch)

    for name in (PREFLIGHT, INSTALL):
        schema = procedures.rows[name]["result_schema"]
        for field, spec in schema["properties"].items():
            if not isinstance(spec, dict):
                continue
            if spec.get("type") == "string" or "const" in spec:
                # A closed value set bounds the field just as well as maxLength.
                if "enum" in spec:
                    assert all(len(v) <= 4096 for v in spec["enum"]), (name, field)
                elif "const" in spec:
                    assert len(str(spec["const"])) <= 4096, (name, field)
                else:
                    assert "maxLength" in spec, (name, field)
                    assert 0 < spec["maxLength"] <= 4096, (name, field)
            if spec.get("type") == "array":
                assert "maxItems" in spec, (name, field)
                assert "maxLength" in spec["items"], (name, field)
        # The procedure identity is a constant, so a backend cannot relabel a run.
        assert schema["properties"]["procedure"] == {"const": name}


def test_install_result_cannot_report_success_for_a_failed_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """event_store derives ExecutionSucceeded from the outer envelope ok.

    So the nested result must not be allowed to say ok=true while describing an
    incomplete installation, or a partial install would be recorded as a success.
    """

    procedures, _ = _run_procedure_seed(monkeypatch)
    schema = procedures.rows[INSTALL]["result_schema"]

    validate(A_SUCCESSFUL_INSTALL_RESULT, schema)

    for override in (
        {"installed": False},
        {"ready": False},
        {"stage": "package"},
        {"stage": "activate"},
        {"stage": "verify"},
    ):
        with pytest.raises(ValidationError):
            validate({**A_SUCCESSFUL_INSTALL_RESULT, **override}, schema)

    # A genuine failure envelope stays representable, including a partial stage.
    validate(
        {
            **A_SUCCESSFUL_INSTALL_RESULT,
            "ok": False,
            "installed": False,
            "ready": False,
            "stage": "package",
            "error": "apt candidate 3.11.0 not offered by the repository",
        },
        schema,
    )

    # stage and ready are mandatory: an omitted field cannot mean "assume fine".
    for dropped in ("stage", "ready", "installed", "package_held"):
        incomplete = dict(A_SUCCESSFUL_INSTALL_RESULT)
        incomplete.pop(dropped)
        with pytest.raises(ValidationError):
            validate(incomplete, schema)

    # A relabelled procedure identity is refused.
    with pytest.raises(ValidationError):
        validate({**A_SUCCESSFUL_INSTALL_RESULT, "procedure": PREFLIGHT}, schema)


def test_seed_reverse_preserves_procedures_that_have_execution_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RPCExecution.procedure is PROTECT, so a bulk delete would abort the downgrade."""

    procedures, _ = _run_procedure_seed(monkeypatch)
    procedures.rows["service.influxdb.1.bootstrap"] = {"handler_id": "unrelated"}
    # The installer has run, so its row is protected; the read procedure has not.
    procedures.protected.add(INSTALL)

    migration = sys.modules[PROCEDURE_MIGRATION]
    apps = SimpleNamespace(
        get_model=lambda app_label, model_name: _expect_model(
            (app_label, model_name), ("netbox_rpc", "RPCProcedure"), procedures
        )
    )
    migration.unseed_influxdb3_debian13_procedures(apps, None)

    # Unreferenced seed row deleted; protected row preserved but forced disabled;
    # the unrelated procedure untouched.
    assert set(procedures.rows) == {INSTALL, "service.influxdb.1.bootstrap"}
    assert procedures.rows[INSTALL]["enabled"] is False


def test_seed_reverse_removes_both_rows_when_unreferenced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedures, _ = _run_procedure_seed(monkeypatch)
    procedures.rows["service.influxdb.1.bootstrap"] = {"handler_id": "unrelated"}

    migration = sys.modules[PROCEDURE_MIGRATION]
    apps = SimpleNamespace(
        get_model=lambda app_label, model_name: _expect_model(
            (app_label, model_name), ("netbox_rpc", "RPCProcedure"), procedures
        )
    )
    migration.unseed_influxdb3_debian13_procedures(apps, None)

    assert set(procedures.rows) == {"service.influxdb.1.bootstrap"}


def test_handlers_are_documented_command_contract_exemptions() -> None:
    spec = importlib.util.spec_from_file_location(
        "influxdb3_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    for handler_id in HANDLERS.values():
        assert handler_id in command_contract.EXEMPT_HANDLER_IDS
        assert command_contract.EXEMPT_HANDLER_RATIONALE[handler_id].strip()


def test_constants_match_the_seeded_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """A seeded procedure with no matching constant/dispatch fails at run time."""

    procedures, _ = _run_procedure_seed(monkeypatch)
    spec = importlib.util.spec_from_file_location(
        "influxdb3_constants",
        ROOT / "netbox_rpc/constants.py",
    )
    assert spec and spec.loader
    constants = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(constants)

    assert constants.INFLUXDB3_DEBIAN13_PREFLIGHT == PREFLIGHT
    assert constants.INFLUXDB3_DEBIAN13_INSTALL == INSTALL
    assert constants.INFLUXDB3_DEBIAN13_PREFLIGHT_HANDLER == HANDLERS[PREFLIGHT]
    assert constants.INFLUXDB3_DEBIAN13_INSTALL_HANDLER == HANDLERS[INSTALL]
    assert set(constants.INFLUXDB3_DEBIAN13_PROCEDURE_NAMES) == set(procedures.rows)
    # The new family is distinct from the management family, not folded into it.
    assert not constants.INFLUXDB3_DEBIAN13_PROCEDURE_NAMES & (
        constants.INFLUXDB_1_PROCEDURE_NAMES
    )


# --------------------------------------------------------------------------- #
# Normalizer contract
# --------------------------------------------------------------------------- #


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


def test_preflight_normalizes_to_a_read_only_posture_probe(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(_execution(PREFLIGHT, {}))

    assert normalized["target"] == "influx01"
    assert normalized["tls_enabled"] is False
    assert normalized["command_fingerprint"]["handler_id"] == HANDLERS[PREFLIGHT]
    assert normalized["command_fingerprint"]["procedure"] == PREFLIGHT
    # No SSH routing is emitted: the backend resolves it from the assigned object.
    for key in FORBIDDEN_SSH_OVERRIDES:
        assert key not in normalized
    # Install-only knobs are never invented for the read procedure.
    for key in ("hold_package", "node_id", "data_dir", "remote_bind"):
        assert key not in normalized


def test_install_applies_the_documented_defaults(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(_execution(INSTALL, {}))

    assert normalized["enable_plugins"] is False
    assert normalized["disable_telemetry"] is True
    assert normalized["hold_package"] is True
    assert normalized["upgrade_package"] is False
    assert normalized["force_reconfigure"] is False
    assert normalized["allow_plaintext_remote"] is False
    # Omitted http_bind means the backend's loopback default, so the security
    # posture is still evaluated as loopback rather than left undefined.
    assert normalized["remote_bind"] is False
    assert normalized["tls_enabled"] is False
    for key in FORBIDDEN_SSH_OVERRIDES:
        assert key not in normalized
    for key, value in normalized["command_fingerprint"].items():
        assert not isinstance(value, (dict, list)), key


def test_install_forwards_only_validated_configuration(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            INSTALL,
            {
                "node_id": "influx01-node",
                "data_dir": "/srv/influxdb3/data",
                "http_bind": "127.0.0.1:8181",
                "wal_flush_interval": "250ms",
                "log_filter": "info,influxdb3=debug",
                "package_version": "3.11.0-1",
                "enable_plugins": True,
                "disable_telemetry": False,
            },
        )
    )

    assert normalized["node_id"] == "influx01-node"
    assert normalized["data_dir"] == "/srv/influxdb3/data"
    assert normalized["http_bind"] == "127.0.0.1:8181"
    assert normalized["wal_flush_interval"] == "250ms"
    assert normalized["log_filter"] == "info,influxdb3=debug"
    assert normalized["package_version"] == "3.11.0-1"
    assert normalized["enable_plugins"] is True
    assert normalized["disable_telemetry"] is False
    fingerprint = normalized["command_fingerprint"]
    for key in ("node_id", "data_dir", "http_bind", "package_version"):
        assert fingerprint[key] == normalized[key]


def test_install_accepts_a_remote_bind_with_tls(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            INSTALL,
            {
                "http_bind": "10.0.30.150:8181",
                "tls_cert": "/etc/letsencrypt/live/influx.example.net/fullchain.pem",
                "tls_key": "/etc/letsencrypt/live/influx.example.net/privkey.pem",
            },
        )
    )

    assert normalized["tls_enabled"] is True
    assert normalized["remote_bind"] is True
    assert normalized["allow_plaintext_remote"] is False


def test_install_accepts_a_remote_plaintext_bind_only_on_explicit_opt_in(
    jobs_module,
) -> None:
    params = {"http_bind": "10.0.30.150:8181"}

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(_execution(INSTALL, dict(params)))
    assert excinfo.value.code == "RPC_PARAM_INVALID"
    assert "plaintext" in str(excinfo.value).lower()

    normalized = jobs_module.normalize_execution_params(
        _execution(INSTALL, {**params, "allow_plaintext_remote": True})
    )
    assert normalized["remote_bind"] is True
    assert normalized["tls_enabled"] is False
    assert normalized["allow_plaintext_remote"] is True


@pytest.mark.parametrize("procedure_name", [PREFLIGHT, INSTALL])
@pytest.mark.parametrize("override", FORBIDDEN_SSH_OVERRIDES)
def test_normalizer_refuses_caller_supplied_ssh_overrides(
    jobs_module, procedure_name: str, override: str
) -> None:
    """A caller must not choose the credential or the SSH destination.

    ``rpc_ssh_credential_pk`` is not object-scoped against the requester, and
    ``rpc_ssh_host`` would move execution off the audited NetBox target.
    """

    value = 22 if override in {"rpc_ssh_credential_pk", "rpc_ssh_port"} else "attacker"
    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(
            _execution(procedure_name, {override: value})
        )
    assert excinfo.value.code == "RPC_PARAM_INVALID"
    assert override in str(excinfo.value)


@pytest.mark.parametrize(
    ("procedure_name", "params", "expected_code"),
    [
        # A half-specified TLS pair is a caller bug on either procedure.
        (INSTALL, {"tls_cert": "/etc/influxdb3/tls/server.crt"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"tls_key": "/etc/influxdb3/tls/server.key"}, "RPC_PARAM_INVALID"),
        (PREFLIGHT, {"tls_cert": "/etc/influxdb3/tls/server.crt"}, "RPC_PARAM_INVALID"),
        # Sandboxed trees the packaged unit cannot write.
        (INSTALL, {"data_dir": "/tmp/influxdb3"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/var/tmp/influxdb3"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/root/influxdb3"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/home/influx/data"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/run/influxdb3"}, "RPC_PARAM_INVALID"),
        # Exact-root forms, not just prefixed children.
        (INSTALL, {"data_dir": "/tmp"}, "RPC_PARAM_INVALID"),
        # Non-canonical paths that resolve *into* a forbidden root: a literal
        # prefix comparison alone would let these through.
        (INSTALL, {"data_dir": "/var/./tmp/influxdb3"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/./tmp/influxdb3"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/var/lib/../tmp/influxdb3"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/var/lib/influxdb3/."}, "RPC_PARAM_INVALID"),
        (INSTALL, {"data_dir": "/var/lib/../etc/influxdb3"}, "RPC_PARAM_INVALID"),
        (
            PREFLIGHT,
            {"tls_cert": "/etc/./tls/a.pem", "tls_key": "/etc/tls/b.pem"},
            "RPC_PARAM_INVALID",
        ),
        (INSTALL, {"data_dir": "not-absolute"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"node_id": "-dash-first"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"node_id": "has space"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"node_id": "a" * 129}, "RPC_PARAM_INVALID"),
        (INSTALL, {"http_bind": "127.0.0.1"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"http_bind": "127.0.0.1:8181 ; id"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"http_bind": "127.0.0.1:0"}, "RPC_PARAM_OUT_OF_RANGE"),
        (INSTALL, {"http_bind": "127.0.0.1:70000"}, "RPC_PARAM_OUT_OF_RANGE"),
        (INSTALL, {"wal_flush_interval": "soon"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"log_filter": "info rm -rf /"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"package_version": "3.11.0 && id"}, "RPC_PARAM_INVALID"),
        # Unknown parameters are refused here too, not only by params_schema.
        (INSTALL, {"admin_token": "do-not-persist"}, "RPC_PARAM_INVALID"),
        (INSTALL, {"generate_admin_token": True}, "RPC_PARAM_INVALID"),
        (PREFLIGHT, {"hold_package": True}, "RPC_PARAM_INVALID"),
        (PREFLIGHT, {"data_dir": "/var/lib/influxdb3/data"}, "RPC_PARAM_INVALID"),
    ],
)
def test_normalizer_rejects_unsafe_inputs(
    jobs_module, procedure_name: str, params: dict, expected_code: str
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        jobs_module.normalize_execution_params(_execution(procedure_name, params))
    assert excinfo.value.code == expected_code


def test_normalizer_accepts_a_dot_inside_a_path_segment(jobs_module) -> None:
    """Rejecting '.' segments must not reject a legitimate dotted filename."""

    normalized = jobs_module.normalize_execution_params(
        _execution(
            INSTALL,
            {
                "tls_cert": "/etc/influxdb3/tls/server.crt",
                "tls_key": "/etc/influxdb3/tls/server.key",
                "data_dir": "/srv/influx.db3/data",
            },
        )
    )

    assert normalized["tls_cert"] == "/etc/influxdb3/tls/server.crt"
    assert normalized["data_dir"] == "/srv/influx.db3/data"


def test_normalizer_tolerates_platform_stamped_internal_params(jobs_module) -> None:
    """Intent markers and the frozen RQ timeout are platform-stamped, not input."""

    normalized = jobs_module.normalize_execution_params(
        _execution(
            INSTALL,
            {
                "_intent": 7,
                "_intent_name": "influxdb.provision",
                "_timeout_seconds_snapshot": 900,
            },
        )
    )

    assert normalized["hold_package"] is True


def test_normalizer_fails_closed_for_an_unrecognised_family_member(
    jobs_module,
) -> None:
    """A third name added to the dispatch set must not inherit installer params.

    Exercised through the private entry point because the public dispatch frozenset
    currently admits exactly the two seeded names; this guards the branch a future
    procedure would otherwise fall into silently.
    """

    normalization = importlib.import_module("netbox_rpc.domain.normalization")
    execution = SimpleNamespace(
        procedure=SimpleNamespace(
            name="os.linux.debian.13.uninstall_influxdb3_core",
            handler_id="os.linux_debian_13.uninstall_influxdb3_core",
        ),
        params={"data_dir": "/var/lib/influxdb3/data"},
        target_display="influx01",
        target_model_label="virtualization.virtualmachine",
    )

    with pytest.raises(jobs_module.RPCExecutionError) as excinfo:
        normalization._normalize_influxdb3_debian13_execution(execution, "influx01")
    assert excinfo.value.code == "RPC_PROCEDURE_NOT_NORMALIZABLE"


def test_normalized_payload_never_carries_secret_shaped_keys(jobs_module) -> None:
    for procedure_name in (PREFLIGHT, INSTALL):
        normalized = jobs_module.normalize_execution_params(
            _execution(procedure_name, {})
        )
        serialized = json.dumps(normalized).lower()
        for forbidden in ("token", "password", "passphrase", "nms-secret", "rpc_ssh"):
            assert forbidden not in serialized, (procedure_name, forbidden)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _expect_model(actual, expected, manager):
    if actual != expected:
        raise AssertionError(actual)
    return SimpleNamespace(objects=manager)


def _run_procedure_seed(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(PROCEDURE_MIGRATION, None)
    migration = importlib.import_module(PROCEDURE_MIGRATION)
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()

    def get_model(app_label: str, model_name: str):
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedure"):
            return SimpleNamespace(objects=procedures)
        if (app_label, model_name) == ("netbox_rpc", "RPCProcedureCommand"):
            return SimpleNamespace(objects=commands)
        raise AssertionError((app_label, model_name))

    migration.seed_influxdb3_debian13_procedures(
        SimpleNamespace(get_model=get_model), None
    )
    return procedures, commands


def _execution(procedure_name: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(
            name=procedure_name,
            handler_id=HANDLERS[procedure_name],
        ),
        params=params,
        target_display="influx01",
        target_model_label="virtualization.virtualmachine",
    )


class _ProtectedError(Exception):
    """Stand-in for django.db.models.deletion.ProtectedError."""


class _FakeProcedure:
    def __init__(self, manager: "_FakeProcedureManager", name: str, data: dict) -> None:
        self._manager = manager
        self.name = name
        self.handler_id = str(data["handler_id"])
        self.enabled = bool(data.get("enabled", True))

    def delete(self) -> None:
        if self.name in self._manager.protected:
            raise self._manager.protected_error_class(
                f"{self.name} is referenced by execution history"
            )
        self._manager.rows.pop(self.name, None)

    def save(self, update_fields=None) -> None:
        row = self._manager.rows.get(self.name)
        if row is None:
            raise AssertionError(f"saving a deleted row: {self.name}")
        for field in update_fields or ("enabled",):
            row[field] = getattr(self, field)


class _ProcedureQuery:
    def __init__(self, manager: "_FakeProcedureManager", names: set[str]) -> None:
        self.manager = manager
        self.names = names

    def __iter__(self):
        for name, row in list(self.manager.rows.items()):
            if name in self.names:
                yield _FakeProcedure(self.manager, name, row)

    def first(self):
        return next(iter(self), None)

    def delete(self) -> None:
        for procedure in list(self):
            procedure.delete()


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.protected: set[str] = set()
        self.protected_error_class = _ProtectedError

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


class _FakeAllowlistManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def update_or_create(self, *, slug: str, defaults: dict[str, object]):
        self.rows[slug] = dict(defaults)
        return SimpleNamespace(slug=slug, **defaults), True

    def filter(self, *, slug: str):
        return _AllowlistQuery(self, slug)


class _AllowlistQuery:
    def __init__(self, manager: _FakeAllowlistManager, slug: str) -> None:
        self.manager = manager
        self.slug = slug

    def delete(self) -> None:
        self.manager.rows.pop(self.slug, None)


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
    django_models = types.ModuleType("django.db.models")
    django_deletion = types.ModuleType("django.db.models.deletion")
    django_deletion.ProtectedError = _ProtectedError
    django_models.deletion = django_deletion
    django_db.models = django_models
    django.db = django_db

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)
    monkeypatch.setitem(sys.modules, "django.db.models", django_models)
    monkeypatch.setitem(sys.modules, "django.db.models.deletion", django_deletion)


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})

    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"
    netbox_jobs = types.ModuleType("netbox.jobs")
    netbox_jobs.JobRunner = type(
        "JobRunner",
        (),
        {"enqueue": classmethod(lambda cls, *args, **kwargs: None)},
    )

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCExecution = type("RPCExecution", (), {})
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")
    requests_exceptions.RequestException = type("RequestException", (Exception,), {})
    requests_exceptions.ConnectionError = type("ConnectionError", (Exception,), {})
    requests_mod.exceptions = requests_exceptions

    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)
    monkeypatch.setitem(sys.modules, "netbox.constants", netbox_constants)
    monkeypatch.setitem(sys.modules, "netbox.jobs", netbox_jobs)
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
    monkeypatch.setitem(sys.modules, "django.utils", django_utils)
    monkeypatch.setitem(sys.modules, "django.utils.timezone", django_timezone)
    monkeypatch.setitem(sys.modules, "requests", requests_mod)
    monkeypatch.setitem(sys.modules, "requests.exceptions", requests_exceptions)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
