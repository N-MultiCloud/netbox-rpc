"""Pure-domain tests for the ``netbox.plugin.install`` normalizer.

The properties worth testing here are all refusals. This procedure ends in a
``pip install`` and a NetBox restart, so what it declines to do is the whole
security argument: a caller may name an allowlist row and a version, and
nothing else they send may influence what is installed, imported, or restarted.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PROCEDURE = "netbox.plugin.install"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    from test_jobs_systemd_normalization import _install_import_stubs

    _install_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.fixture()
def open_gate(jobs_module, monkeypatch: pytest.MonkeyPatch):
    """Open the code-level gate so the normalizer body is reachable.

    Every test below except the gate test itself needs this. The gate is the
    outermost refusal and would otherwise mask everything behind it -- which is
    exactly what it is for, and exactly why it has to be lifted deliberately
    rather than left off.
    """
    normalization = importlib.import_module("netbox_rpc.domain.normalization")
    monkeypatch.setattr(normalization, "_NETBOX_PLUGIN_INSTALL_AVAILABLE", True)
    return normalization


def _allow(**overrides):
    row = SimpleNamespace(
        distribution="netbox-openbao",
        module="netbox_openbao",
        venv_python="/opt/netbox/venv/bin/python3",
        manage_py="/opt/netbox/netbox/manage.py",
        settings_file="/opt/netbox/netbox/netbox/configuration.py",
        service_slugs=["netbox", "netbox-rq"],
        target_models=["dcim.device"],
        ssh_credential_override_id=None,
    )
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


def _execution(params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=PROCEDURE, handler_id=PROCEDURE),
        params=params,
        target_display="netbox-01",
        target_model_label="dcim.device",
    )


def _mock_lookups(jobs_module, plugin_row, service_rows=None):
    """Point both allowlist managers at fixtures and return the filter mocks."""
    plugin_query = SimpleNamespace(first=MagicMock(return_value=plugin_row))
    plugin_filter = MagicMock(return_value=plugin_query)
    jobs_module.RPCNetBoxPluginAllowlist.objects = SimpleNamespace(filter=plugin_filter)

    if service_rows is None:
        service_rows = {
            "netbox": SimpleNamespace(systemd_unit="netbox.service"),
            "netbox-rq": SimpleNamespace(systemd_unit="netbox-rq.service"),
        }

    def _service_filter(slug: str, enabled: bool):
        return SimpleNamespace(first=MagicMock(return_value=service_rows.get(slug)))

    service_filter = MagicMock(side_effect=_service_filter)
    jobs_module.RPCLinuxServiceAllowlist.objects = SimpleNamespace(filter=service_filter)
    return plugin_filter, service_filter


def _error_code(excinfo) -> str:
    return getattr(excinfo.value, "code", "")


# --- the gate ---------------------------------------------------------------


def test_gate_blocks_before_any_lookup(jobs_module):
    """Closed by default, and closed *before* the allowlist is consulted.

    The ordering matters as much as the refusal: an execution that reached the
    lookup would have proved the gate is only cosmetic. This asserts the query
    is never made, which is the same shape as
    ``test_upsert_var_gate_blocks_by_default``.
    """
    plugin_filter, service_filter = _mock_lookups(jobs_module, _allow())
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    with pytest.raises(Exception) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert _error_code(excinfo) == "RPC_PROCEDURE_NOT_AVAILABLE"
    plugin_filter.assert_not_called()
    service_filter.assert_not_called()


# --- the happy path ---------------------------------------------------------


def test_normalizes_an_allowlisted_plugin(jobs_module, open_gate):
    plugin_filter, service_filter = _mock_lookups(jobs_module, _allow())
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["target"] == "netbox-01"
    assert normalized["distribution"] == "netbox-openbao"
    assert normalized["module"] == "netbox_openbao"
    assert normalized["version"] == "0.1.0"
    assert normalized["systemd_units"] == ["netbox.service", "netbox-rq.service"]
    assert normalized["dry_run"] is False
    plugin_filter.assert_called_once_with(slug="openbao", enabled=True)
    assert service_filter.call_count == 2


def test_fingerprint_names_the_artifact_not_the_slug(jobs_module, open_gate):
    """What an approver approves must be the thing that runs.

    A fingerprint carrying only the slug would be satisfied by any row the slug
    happened to point at when the worker got to it -- which, given the approval
    TOCTOU documented on this procedure, is precisely the case that matters.
    """
    _mock_lookups(jobs_module, _allow())
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    fingerprint = jobs_module.normalize_execution_params(execution)["command_fingerprint"]

    assert fingerprint["distribution"] == "netbox-openbao"
    assert fingerprint["version"] == "0.1.0"
    assert fingerprint["module"] == "netbox_openbao"
    assert fingerprint["settings_file"].endswith("configuration.py")
    assert fingerprint["systemd_units"] == ["netbox.service", "netbox-rq.service"]


def test_dry_run_is_carried_through(jobs_module, open_gate):
    _mock_lookups(jobs_module, _allow())
    execution = _execution(
        {"plugin_slug": "openbao", "version": "0.1.0", "dry_run": True}
    )

    assert jobs_module.normalize_execution_params(execution)["dry_run"] is True


def test_ssh_credential_override_is_forwarded_when_the_row_sets_one(
    jobs_module, open_gate
):
    _mock_lookups(jobs_module, _allow(ssh_credential_override_id=42))
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["rpc_ssh_credential_pk"] == 42


# --- refusals ---------------------------------------------------------------


def test_unallowlisted_plugin_is_refused(jobs_module, open_gate):
    _mock_lookups(jobs_module, None)
    execution = _execution({"plugin_slug": "anything", "version": "1.0"})

    with pytest.raises(Exception) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert _error_code(excinfo) == "RPC_NETBOX_PLUGIN_NOT_ALLOWLISTED"


def test_target_model_outside_the_rows_scope_is_refused(jobs_module, open_gate):
    _mock_lookups(jobs_module, _allow(target_models=["virtualization.virtualmachine"]))
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    with pytest.raises(Exception) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert _error_code(excinfo) == "RPC_NETBOX_PLUGIN_TARGET_DENIED"


@pytest.mark.parametrize(
    "version",
    [
        "",
        "latest",
        ">=1.0",
        "1.0; rm -rf /",
        "--index-url=http://evil",
        "0.1.0\n--extra-index-url=http://evil",
    ],
)
def test_non_exact_or_option_shaped_versions_are_refused(
    jobs_module, open_gate, version: str
):
    """The version is the one caller-supplied value that reaches pip.

    A range makes the audit record meaningless; anything starting with a dash
    would be read as an option rather than a version. The trailing-newline case
    is the specific reason the seed patterns end in ``(?![\\s\\S])`` rather than
    ``$`` -- ``re.search`` accepts a final newline before ``$``.
    """
    _mock_lookups(jobs_module, _allow())
    execution = _execution({"plugin_slug": "openbao", "version": version})

    with pytest.raises(Exception) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert _error_code(excinfo) == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("distribution", "https://evil.example/x.whl"),
        ("distribution", "/tmp/evil"),
        ("distribution", "--index-url=http://evil"),
        ("distribution", "git+ssh://evil/x"),
        ("module", "netbox openbao"),
        ("module", "netbox_openbao; import os"),
        ("venv_python", "relative/python"),
        ("venv_python", "/opt/../etc/passwd"),
        ("settings_file", "/opt/netbox/../../etc/shadow"),
        ("manage_py", ""),
    ],
)
def test_a_malformed_row_is_refused_even_though_clean_should_have_caught_it(
    jobs_module, open_gate, field: str, value: str
):
    """Rows written outside ``full_clean()`` must not reach the backend.

    ``RPCNetBoxPluginAllowlist.clean()`` enforces all of this already, but a
    fixture, data migration, or bulk update bypasses it -- and these particular
    strings become a pip target and a settings-file path, so the recheck is not
    ceremony. Same reasoning as the env-file path recheck.
    """
    _mock_lookups(jobs_module, _allow(**{field: value}))
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    with pytest.raises(Exception) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert _error_code(excinfo) == "RPC_NETBOX_PLUGIN_ROW_INVALID"


def test_a_service_the_service_catalog_does_not_allow_is_refused(
    jobs_module, open_gate
):
    """The plugin row cannot widen what may be restarted.

    Restart targets resolve through ``RPCLinuxServiceAllowlist``, so a plugin
    row naming a unit that catalog does not permit is refused rather than
    honoured -- the two allowlists cannot drift into letting this procedure
    bounce something an operator never approved.
    """
    _mock_lookups(
        jobs_module,
        _allow(service_slugs=["netbox", "postgresql"]),
        service_rows={"netbox": SimpleNamespace(systemd_unit="netbox.service")},
    )
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    with pytest.raises(Exception) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert _error_code(excinfo) == "RPC_LINUX_SERVICE_NOT_ALLOWLISTED"


def test_a_row_with_no_services_is_refused(jobs_module, open_gate):
    """Installing without restarting is a silent no-op, so it is not allowed.

    The plugin would land on disk and be absent from the running process; the
    execution would report success and the operator would see no plugin.
    """
    _mock_lookups(jobs_module, _allow(service_slugs=[]))
    execution = _execution({"plugin_slug": "openbao", "version": "0.1.0"})

    with pytest.raises(Exception) as excinfo:
        jobs_module.normalize_execution_params(execution)

    assert _error_code(excinfo) == "RPC_NETBOX_PLUGIN_NO_SERVICES"


def test_caller_params_cannot_redirect_the_install(jobs_module, open_gate):
    """Extra caller keys never reach the normalized payload.

    ``params_schema`` sets ``additionalProperties: false``, so these are
    rejected before this point in production. This asserts the normalizer does
    not independently honour them either -- defence in depth for a row created
    before the schema tightened, or by a path that skipped validation.
    """
    _mock_lookups(jobs_module, _allow())
    execution = _execution(
        {
            "plugin_slug": "openbao",
            "version": "0.1.0",
            "distribution": "evil-package",
            "module": "evil",
            "venv_python": "/tmp/python",
            "settings_file": "/tmp/settings.py",
            "systemd_units": ["postgresql.service"],
        }
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert normalized["distribution"] == "netbox-openbao"
    assert normalized["module"] == "netbox_openbao"
    assert normalized["venv_python"] == "/opt/netbox/venv/bin/python3"
    assert normalized["settings_file"].endswith("configuration.py")
    assert normalized["systemd_units"] == ["netbox.service", "netbox-rq.service"]
