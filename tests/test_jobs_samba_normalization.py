from __future__ import annotations

import importlib
import json
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MIGRATION_MODULE = "netbox_rpc.migrations.0049_seed_samba_read_procedures"
# Mirrors _STATUS_REPORT_OUTPUT_SCHEMA in 0049. Per Samba's
# source3/utils/status.c, `smbstatus --json` emits each section via
# add_section_to_json() -> json_new_object(), so sections are objects keyed by
# id (not arrays), the keys are sessions/tcons/open_files/byte_range_locks/
# notifies (there is no top-level `locks`), and which appear depends on the
# invocation flags -- hence no `required`.
SMBSTATUS_SECTION = {"type": "object", "additionalProperties": {"type": "object"}}

STATUS_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "smb_conf": {"type": "string"},
        "sessions": SMBSTATUS_SECTION,
        "tcons": SMBSTATUS_SECTION,
        "open_files": SMBSTATUS_SECTION,
        "byte_range_locks": SMBSTATUS_SECTION,
        "notifies": SMBSTATUS_SECTION,
    },
}

SAMBA_CASES = (
    ("service.samba.1.config_read", "service.samba_1.config_read", {}, {}),
    ("service.samba.1.config_test", "service.samba_1.config_test", {}, {}),
    (
        "service.samba.1.config_list_files",
        "service.samba_1.config_list_files",
        {},
        {},
    ),
    (
        "service.samba.1.include_file_read",
        "service.samba_1.include_file_read",
        {"include_path": "/etc/samba/includes/site.conf"},
        {"include_path": "/etc/samba/includes/site.conf"},
    ),
    ("service.samba.1.service_status", "service.samba_1.service_status", {}, {}),
    ("service.samba.1.version", "service.samba_1.version", {}, {}),
    ("service.samba.1.list_shares", "service.samba_1.list_shares", {}, {}),
    ("service.samba.1.status_report", "service.samba_1.status_report", {}, {}),
    ("service.samba.1.domain_info", "service.samba_1.domain_info", {}, {}),
    ("service.samba.1.user_list", "service.samba_1.user_list", {}, {}),
    ("service.samba.1.group_list", "service.samba_1.group_list", {}, {}),
    (
        "service.samba.1.share_acl_read",
        "service.samba_1.share_acl_read",
        {"share_name": "homes"},
        {"share_name": "homes"},
    ),
)


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)
    sys.modules.pop("netbox_rpc.domain.normalization", None)


@pytest.mark.parametrize(
    "procedure_name,handler_id,params,expected_extra",
    SAMBA_CASES,
)
def test_samba_read_procedure_normalizes(
    jobs_module,
    procedure_name: str,
    handler_id: str,
    params: dict[str, object],
    expected_extra: dict[str, object],
) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(procedure_name, handler_id, params)
    )

    assert normalized["target"] == "fileserver01"
    assert normalized["command_fingerprint"]["handler_id"] == handler_id
    assert normalized["command_fingerprint"]["procedure"] == procedure_name
    assert "command" not in normalized
    assert "commands" not in normalized
    for key, value in expected_extra.items():
        assert normalized[key] == value
        assert normalized["command_fingerprint"][key] == value

    if procedure_name == "service.samba.1.status_report":
        assert normalized["output_parser"] == "json"
        assert normalized["output_schema"] == STATUS_OUTPUT_SCHEMA
        assert "output_schema_sha256" in normalized["command_fingerprint"]


def test_samba_normalization_copies_optional_ssh_overrides(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.samba.1.config_read",
            "service.samba_1.config_read",
            {
                "rpc_ssh_host": "samba01.example.net",
                "rpc_ssh_port": 2222,
                "rpc_ssh_credential_pk": 17,
                "rpc_ssh_known_hosts_entry": "samba01.example.net ssh-ed25519 AAAA",
                "rpc_ssh_strict_host_key_checking": True,
            },
        )
    )

    assert normalized["rpc_ssh_host"] == "samba01.example.net"
    assert normalized["rpc_ssh_port"] == 2222
    assert normalized["rpc_ssh_credential_pk"] == 17
    fp = normalized["command_fingerprint"]
    assert fp["rpc_ssh_host"] == "samba01.example.net"
    assert fp["rpc_ssh_port"] == 2222
    assert fp["rpc_ssh_credential_pk"] == 17
    assert "rpc_ssh_known_hosts_entry_sha256" in fp


@pytest.mark.parametrize(
    "include_path",
    [
        "../secret.conf",
        "/etc/samba/../secret.conf",
        "/tmp/secret.conf",
        "includes/bad;name.conf",
        "includes/bad$(id).conf",
        "smb.conf\nrm -rf /",
    ],
)
def test_include_file_read_rejects_unconfined_or_injection_paths(
    jobs_module,
    include_path: str,
) -> None:
    execution = _execution(
        "service.samba.1.include_file_read",
        "service.samba_1.include_file_read",
        {"include_path": include_path},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    "share_name",
    ["bad;name", "../homes", "/etc/samba/homes", "bad name", "bad$(id)", "homes\nid"],
)
def test_share_acl_read_rejects_unsafe_share_names(
    jobs_module,
    share_name: str,
) -> None:
    execution = _execution(
        "service.samba.1.share_acl_read",
        "service.samba_1.share_acl_read",
        {"share_name": share_name},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_every_seeded_samba_procedure_has_normalizer_branch(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _load_seed_migration(monkeypatch)
    seeded_names = {procedure["name"] for procedure in migration._PROCEDURES}

    assert seeded_names == {case[0] for case in SAMBA_CASES}
    for name, handler_id, params, _expected in SAMBA_CASES:
        normalized = jobs_module.normalize_execution_params(
            _execution(name, handler_id, params)
        )
        assert normalized["command_fingerprint"]["handler_id"] == handler_id


def test_samba_seed_schema_confines_user_supplied_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _load_seed_migration(monkeypatch)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}

    for procedure in procedures.values():
        assert procedure["target_models"] == [
            "netbox_fileserver.sambadomain",
            "virtualization.virtualmachine",
            "dcim.device",
        ]
        assert procedure["effect"] == "read"
        assert procedure["approval_required"] is False

    include_schema = procedures["service.samba.1.include_file_read"]["params_schema"]
    include_pattern = re.compile(
        include_schema["properties"]["include_path"]["pattern"]
    )
    assert include_pattern.fullmatch("/etc/samba/includes/site.conf")
    assert include_pattern.fullmatch("includes/site.conf")
    assert not include_pattern.fullmatch("../secret.conf")
    assert not include_pattern.fullmatch("/etc/samba/../secret.conf")
    assert not include_pattern.fullmatch("/tmp/secret.conf")
    assert not include_pattern.fullmatch("includes/bad;name.conf")

    share_schema = procedures["service.samba.1.share_acl_read"]["params_schema"]
    share_pattern = re.compile(share_schema["properties"]["share_name"]["pattern"])
    assert share_pattern.fullmatch("homes")
    assert not share_pattern.fullmatch("bad;name")
    assert not share_pattern.fullmatch("../homes")

    status = procedures["service.samba.1.status_report"]
    assert status["output_parser"] == "json"
    assert status["output_schema"] == STATUS_OUTPUT_SCHEMA

    domain_schema = json.dumps(
        procedures["service.samba.1.domain_info"]["result_schema"],
        sort_keys=True,
    )
    user_schema = json.dumps(
        procedures["service.samba.1.user_list"]["result_schema"],
        sort_keys=True,
    )
    assert "password" not in domain_schema.lower()
    assert "hash" not in domain_schema.lower()
    assert "password" not in user_schema.lower()
    assert "hash" not in user_schema.lower()


def test_status_report_output_schema_matches_real_smbstatus_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status_report output_schema must describe real `smbstatus --json`.

    Ground truth is Samba's ``source3/utils/status.c`` / ``status_json.c``:
    sections are added with ``add_section_to_json()``, which calls
    ``json_new_object()`` -- so they are objects keyed by id, not arrays. The
    section keys are sessions/tcons/open_files/byte_range_locks/notifies; there
    is no top-level ``locks`` (``--locks`` is a CLI flag name). Sections are
    flag-dependent, so requiring any of them would reject a valid read.
    """
    migration = _load_seed_migration(monkeypatch)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}
    schema = procedures["service.samba.1.status_report"]["output_schema"]

    assert "locks" not in schema["properties"]
    assert "required" not in schema
    for section in ("sessions", "tcons", "open_files", "byte_range_locks"):
        assert schema["properties"][section]["type"] == "object", (
            f"{section} is an id-keyed object in smbstatus --json, not an array"
        )

    # A realistic single-session document must validate against the schema.
    document = {
        "version": "4.19.5",
        "smb_conf": "/etc/samba/smb.conf",
        "sessions": {
            "3218223226": {
                "session_id": "3218223226",
                "username": "alice",
                "remote_machine": "10.0.30.9",
            }
        },
        "tcons": {"1234": {"service": "shared", "machine": "10.0.30.9"}},
        "open_files": {},
    }
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(document, schema)


def test_samba_seed_schema_rejects_trailing_newline_under_search_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``params_schema`` patterns must not accept a trailing newline.

    ``jsonschema`` enforces ``pattern`` with ``re.search``, and Python's ``$``
    matches *before* a single trailing newline -- so a ``\\.conf$`` anchor would
    accept ``"smb.conf\\n"``. The seeds anchor with ``(?![\\s\\S])`` instead.
    Asserted with ``re.search`` because that is the real enforcement path;
    ``fullmatch`` hides the difference.
    """
    migration = _load_seed_migration(monkeypatch)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}

    include_pattern = procedures["service.samba.1.include_file_read"]["params_schema"][
        "properties"
    ]["include_path"]["pattern"]
    assert re.search(include_pattern, "includes/site.conf")
    assert not re.search(include_pattern, "includes/site.conf\n")
    assert not re.search(include_pattern, "/etc/samba/smb.conf\n")

    share_pattern = procedures["service.samba.1.share_acl_read"]["params_schema"][
        "properties"
    ]["share_name"]["pattern"]
    assert re.search(share_pattern, "homes")
    assert not re.search(share_pattern, "homes\n")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Relative paths must be resolved under /etc/samba, not forwarded raw:
        # the command rows run `cat {include_path}`, so a relative value would
        # read relative to the backend process cwd.
        ("smb.conf", "/etc/samba/smb.conf"),
        ("includes/site.conf", "/etc/samba/includes/site.conf"),
        # Surrounding whitespace is stripped before validation, so a trailing
        # newline is sanitized away rather than reaching the backend.
        ("  smb.conf  ", "/etc/samba/smb.conf"),
        ("smb.conf\n", "/etc/samba/smb.conf"),
        # Absolute paths already under the root are preserved.
        ("/etc/samba/includes/site.conf", "/etc/samba/includes/site.conf"),
        ("/etc/samba/includes/site.conf\n", "/etc/samba/includes/site.conf"),
    ],
)
def test_include_path_is_normalized_to_confined_absolute_path(
    jobs_module,
    raw: str,
    expected: str,
) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.samba.1.include_file_read",
            "service.samba_1.include_file_read",
            {"include_path": raw},
        )
    )

    assert normalized["include_path"] == expected
    assert normalized["include_path"].startswith("/etc/samba/")
    assert normalized["command_fingerprint"]["include_path"] == expected


def _execution(procedure_name: str, handler_id: str, params: dict[str, object]):
    procedure = SimpleNamespace(
        name=procedure_name,
        handler_id=handler_id,
        output_parser="none",
        output_schema={},
    )
    if procedure_name == "service.samba.1.status_report":
        procedure.output_parser = "json"
        procedure.output_schema = STATUS_OUTPUT_SCHEMA
    return SimpleNamespace(
        procedure=procedure,
        params=params,
        target_display="fileserver01",
        target_model_label="dcim.device",
    )


def _load_seed_migration(monkeypatch: pytest.MonkeyPatch):
    django_db = sys.modules.get("django.db")
    if django_db is None:
        django = types.ModuleType("django")
        django_db = types.ModuleType("django.db")
        django.db = django_db
        monkeypatch.setitem(sys.modules, "django", django)
        monkeypatch.setitem(sys.modules, "django.db", django_db)

    django_migrations = types.ModuleType("django.db.migrations")

    class Migration:
        pass

    django_migrations.Migration = Migration
    django_migrations.RunPython = lambda *args, **kwargs: (args, kwargs)
    django_db.migrations = django_migrations
    monkeypatch.setitem(sys.modules, "django.db.migrations", django_migrations)

    sys.modules.pop(MIGRATION_MODULE, None)
    return importlib.import_module(MIGRATION_MODULE)


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig
    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"
    netbox_jobs = types.ModuleType("netbox.jobs")

    class JobRunner:
        @classmethod
        def enqueue(cls, *args, **kwargs):
            return None

    netbox_jobs.JobRunner = JobRunner

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    netbox_rpc_models = types.ModuleType("netbox_rpc.models")
    netbox_rpc_models.RPCLinuxServiceAllowlist = type(
        "RPCLinuxServiceAllowlist", (), {}
    )
    netbox_rpc_models.RPCExecution = type("RPCExecution", (), {})
    netbox_rpc_models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")

    class _RequestException(Exception):
        pass

    class _ConnectionError(_RequestException):
        pass

    requests_exceptions.RequestException = _RequestException
    requests_exceptions.ConnectionError = _ConnectionError
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
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", netbox_rpc_models)
