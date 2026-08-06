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

READ_MIGRATION_MODULE = "netbox_rpc.migrations.0049_seed_samba_read_procedures"
WRITE_MIGRATION_MODULE = "netbox_rpc.migrations.0051_seed_samba_write_procedures"
WRITE_COMMAND_MIGRATION_MODULE = "netbox_rpc.migrations.0052_seed_samba_write_commands"
IDENTITY_MIGRATION_MODULE = (
    "netbox_rpc.migrations.0055_seed_samba_identity_procedures"
)
IDENTITY_COMMAND_MIGRATION_MODULE = (
    "netbox_rpc.migrations.0056_seed_samba_identity_commands"
)
INTENT_MIGRATION_MODULE = "netbox_rpc.migrations.0057_seed_fileserver_samba_intents"
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

SAMBA_WRITE_CASES = (
    (
        "service.samba.1.config_deploy",
        "service.samba_1.config_deploy",
        {"config_content": "[global]\n   workgroup = EXAMPLE\n"},
        {},
    ),
    (
        "service.samba.1.config_rollback",
        "service.samba_1.config_rollback",
        {"snapshot_id": "samba-20260717T010203Z"},
        {"snapshot_id": "samba-20260717T010203Z"},
    ),
    (
        "service.samba.1.include_file_write",
        "service.samba_1.include_file_write",
        {
            "include_path": "includes/site.conf",
            "content": "[share]\n   path = /srv/samba/share\n",
        },
        {"include_path": "/etc/samba/includes/site.conf"},
    ),
    (
        "service.samba.1.include_file_delete",
        "service.samba_1.include_file_delete",
        {"include_path": "/etc/samba/includes/old.conf"},
        {"include_path": "/etc/samba/includes/old.conf"},
    ),
    (
        "service.samba.1.share_upsert",
        "service.samba_1.share_upsert",
        {
            "share_name": "engineering",
            "path": "/srv/samba/engineering",
            "comment": "Engineering share",
            "read_only": False,
            "browseable": True,
            "guest_ok": False,
            "valid_users": ["@engineering"],
            "write_list": ["@engineering-admins"],
            "create_mask": "0660",
            "directory_mask": "0770",
            "force_group": "engineering",
        },
        {
            "share_name": "engineering",
            "path": "/srv/samba/engineering",
            "comment": "Engineering share",
            "read_only": False,
            "browseable": True,
            "guest_ok": False,
            "valid_users": ["@engineering"],
            "write_list": ["@engineering-admins"],
            "create_mask": "0660",
            "directory_mask": "0770",
            "force_group": "engineering",
        },
    ),
    (
        "service.samba.1.share_delete",
        "service.samba_1.share_delete",
        {"share_name": "oldshare"},
        {"share_name": "oldshare"},
    ),
    (
        "service.samba.1.service_control",
        "service.samba_1.service_control",
        {"unit": "smbd", "action": "reload"},
        {"unit": "smbd", "action": "reload", "systemd_unit": "smbd.service"},
    ),
)

SAMBA_BODY_PROCEDURES = (
    (
        "service.samba.1.config_deploy",
        "service.samba_1.config_deploy",
        "config_content",
        {},
    ),
    (
        "service.samba.1.include_file_write",
        "service.samba_1.include_file_write",
        "content",
        {"include_path": "includes/site.conf"},
    ),
)

# A fake-but-well-formed sha256 fingerprint. Simulates the value
# command_handlers._scrub_password_param() computes and persists BEFORE an
# RPCExecution row is ever saved (#160): by the time normalize_execution_params()
# runs, a raw "password" key must never be present -- only this fingerprint
# shape. These pure-domain cases construct that already-scrubbed state directly
# (they never touch command_handlers) to prove the normalizer forwards it
# without ever expecting or reading plaintext.
_FAKE_PASSWORD_SHA256 = "a" * 64
_FAKE_PASSWORD_BYTES = 12

SAMBA_IDENTITY_CASES = (
    (
        "service.samba.1.user_create",
        "service.samba_1.user_create",
        {
            "username": "alice",
            "password_sha256": _FAKE_PASSWORD_SHA256,
            "password_bytes": _FAKE_PASSWORD_BYTES,
            "full_name": "Alice Example",
            "disabled": False,
        },
        {"username": "alice"},
    ),
    (
        "service.samba.1.user_delete",
        "service.samba_1.user_delete",
        {"username": "alice"},
        {"username": "alice"},
    ),
    (
        "service.samba.1.user_set_password",
        "service.samba_1.user_set_password",
        {
            "username": "alice",
            "password_sha256": _FAKE_PASSWORD_SHA256,
            "password_bytes": _FAKE_PASSWORD_BYTES,
        },
        {"username": "alice"},
    ),
    (
        "service.samba.1.user_enable",
        "service.samba_1.user_enable",
        {"username": "alice"},
        {"username": "alice"},
    ),
    (
        "service.samba.1.user_disable",
        "service.samba_1.user_disable",
        {"username": "alice"},
        {"username": "alice"},
    ),
    (
        "service.samba.1.group_create",
        "service.samba_1.group_create",
        {"group_name": "engineering"},
        {"group_name": "engineering"},
    ),
    (
        "service.samba.1.group_delete",
        "service.samba_1.group_delete",
        {"group_name": "engineering"},
        {"group_name": "engineering"},
    ),
    (
        "service.samba.1.group_add_members",
        "service.samba_1.group_add_members",
        {"group_name": "engineering", "members": ["alice", "bob"]},
        {"group_name": "engineering", "members": ["alice", "bob"]},
    ),
    (
        "service.samba.1.group_remove_members",
        "service.samba_1.group_remove_members",
        {"group_name": "engineering", "members": ["alice"]},
        {"group_name": "engineering", "members": ["alice"]},
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


@pytest.mark.parametrize(
    "procedure_name,handler_id,params,expected_extra",
    SAMBA_WRITE_CASES,
)
def test_samba_write_procedure_normalizes(
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
        if key == "comment":
            assert "comment_sha256" in normalized["command_fingerprint"]
        else:
            assert normalized["command_fingerprint"][key] == value

    if procedure_name == "service.samba.1.config_deploy":
        content = params["config_content"]
        assert normalized["config_content"] == content
        fp = normalized["command_fingerprint"]
        assert "config_content" not in fp
        assert "config_content_sha256" in fp
        assert fp["config_content_bytes"] == len(str(content).encode("utf-8"))

    if procedure_name == "service.samba.1.include_file_write":
        content = params["content"]
        assert normalized["content"] == content
        fp = normalized["command_fingerprint"]
        assert "content" not in fp
        assert "content_sha256" in fp
        assert fp["content_bytes"] == len(str(content).encode("utf-8"))


@pytest.mark.parametrize(
    "procedure_name,handler_id,params,expected_extra",
    SAMBA_IDENTITY_CASES,
)
def test_samba_identity_procedure_normalizes(
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
    # #160 hard invariant: no identity procedure -- password-bearing or not --
    # may ever surface a raw "password" key in the normalized payload or its
    # fingerprint.
    assert "password" not in normalized
    assert "password" not in normalized["command_fingerprint"]
    for key, value in expected_extra.items():
        assert normalized[key] == value
        assert normalized["command_fingerprint"][key] == value

    if procedure_name in {
        "service.samba.1.group_add_members",
        "service.samba.1.group_remove_members",
    }:
        assert normalized["members_csv"] == ",".join(params["members"])
        # members_csv is a command-templating convenience, not part of the
        # audit fingerprint (members already covers it).
        assert "members_csv" not in normalized["command_fingerprint"]

    if procedure_name in {
        "service.samba.1.user_create",
        "service.samba.1.user_set_password",
    }:
        assert normalized["password_sha256"] == _FAKE_PASSWORD_SHA256
        assert normalized["password_bytes"] == _FAKE_PASSWORD_BYTES
        fp = normalized["command_fingerprint"]
        assert fp["password_sha256"] == _FAKE_PASSWORD_SHA256
        assert fp["password_bytes"] == _FAKE_PASSWORD_BYTES

    if procedure_name == "service.samba.1.user_create":
        assert normalized["full_name"] == "Alice Example"
        fp = normalized["command_fingerprint"]
        assert "full_name" not in fp
        assert "full_name_sha256" in fp
        assert normalized["disabled"] is False
        assert fp["disabled"] is False


def test_samba_identity_password_normalizer_rejects_without_precomputed_fingerprint(
    jobs_module,
) -> None:
    """Defense in depth for the #160 stdin-secret flow.

    ``_extract_samba_password_fingerprint`` only ever reads
    ``password_sha256``/``password_bytes`` -- fields that
    ``command_handlers._scrub_password_param()`` computes and substitutes for a
    raw ``password`` *before* the RPCExecution row is ever persisted. This
    normalizer must never accept a raw ``password`` key on its own (i.e. if a
    future bug ever bypassed the creation-time scrub, the run must fail closed
    here rather than silently proceed with -- or leak -- plaintext).
    """
    bad_params_cases = (
        {"username": "alice", "password": "hunter2-should-never-be-read"},
        {
            "username": "alice",
            "password": "hunter2-should-never-be-read",
            "password_bytes": 7,
        },
        {"username": "alice", "password_sha256": "not-hex-at-all", "password_bytes": 7},
        {
            "username": "alice",
            "password_sha256": _FAKE_PASSWORD_SHA256,
            "password_bytes": 0,
        },
        {"username": "alice", "password_sha256": _FAKE_PASSWORD_SHA256},
    )
    for bad_params in bad_params_cases:
        with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
            jobs_module.normalize_execution_params(
                _execution(
                    "service.samba.1.user_create",
                    "service.samba_1.user_create",
                    bad_params,
                )
            )
        assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_samba_identity_password_never_leaks_even_if_present_in_params(
    jobs_module,
) -> None:
    """Adversarial/buggy-caller simulation: a leftover raw ``password`` key is
    present in ``params`` *alongside* a valid pre-scrubbed fingerprint (the
    shape command_handlers.create_execution() guarantees today). Proves the
    normalized output can never leak the plaintext even in that case -- the
    single most security-critical assertion in this module.
    """
    secret = "hunter2-should-never-appear-anywhere"
    execution = _execution(
        "service.samba.1.user_create",
        "service.samba_1.user_create",
        {
            "username": "alice",
            "password": secret,
            "password_sha256": _FAKE_PASSWORD_SHA256,
            "password_bytes": _FAKE_PASSWORD_BYTES,
        },
    )

    normalized = jobs_module.normalize_execution_params(execution)

    assert "password" not in normalized
    assert "password" not in normalized["command_fingerprint"]
    serialized = json.dumps(normalized)
    assert secret not in serialized


@pytest.mark.parametrize(
    "procedure_name,handler_id,params,message_snippet",
    [
        (
            "service.samba.1.user_delete",
            "service.samba_1.user_delete",
            {"username": "-bad"},
            "identifier",
        ),
        (
            "service.samba.1.user_delete",
            "service.samba_1.user_delete",
            {"username": "bad;name"},
            "identifier",
        ),
        (
            "service.samba.1.group_delete",
            "service.samba_1.group_delete",
            {"group_name": "bad name"},
            "identifier",
        ),
        (
            "service.samba.1.group_add_members",
            "service.samba_1.group_add_members",
            {"group_name": "engineering", "members": []},
            "at least one",
        ),
        (
            "service.samba.1.group_add_members",
            "service.samba_1.group_add_members",
            {"group_name": "engineering", "members": ["alice", "alice"]},
            "unique",
        ),
        (
            "service.samba.1.group_add_members",
            "service.samba_1.group_add_members",
            {"group_name": "engineering", "members": ["bad;name"]},
            "identifier",
        ),
        (
            "service.samba.1.group_add_members",
            "service.samba_1.group_add_members",
            {
                "group_name": "engineering",
                "members": [f"user{i}" for i in range(200)],
            },
            "at most",
        ),
    ],
)
def test_samba_identity_normalizer_rejects_unsafe_or_malformed_values(
    jobs_module,
    procedure_name: str,
    handler_id: str,
    params: dict[str, object],
    message_snippet: str,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(
            _execution(procedure_name, handler_id, params)
        )

    assert exc_info.value.code == "RPC_PARAM_INVALID"
    assert message_snippet in str(exc_info.value).lower()


@pytest.mark.parametrize(
    "unsafe_directive",
    [
        "root preexec",
        "preexec",
        "add user script",
        "message command",
        "panic action",
        "RootPreexec",
        "root   preexec",
    ],
)
@pytest.mark.parametrize(
    "procedure_name,handler_id,body_param,base_params",
    SAMBA_BODY_PROCEDURES,
)
def test_samba_config_bodies_reject_command_executing_directives(
    jobs_module,
    unsafe_directive: str,
    procedure_name: str,
    handler_id: str,
    body_param: str,
    base_params: dict[str, object],
) -> None:
    params = {
        **base_params,
        body_param: f"[global]\n   {unsafe_directive} = /bin/id\n",
    }
    execution = _execution(procedure_name, handler_id, params)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    "split_body",
    [
        # Name split across a backslash line-continuation. Samba's tini.c joins
        # these into "root preexec = ..." before the name/value split, so a
        # physical-line scan would see "root pree\" (no '=') then "xec = ..."
        # and miss the directive entirely.
        "[global]\n   root pree\\\nxec = /bin/id\n",
        "[global]\n   roo\\\nt preexec = /bin/id\n",
        "[global]\n   add user scr\\\nipt = /bin/id\n",
        # Backslash followed by whitespace is also a continuation in tini.c.
        "[global]\n   root preexec\\\n = /bin/id\n",
    ],
)
@pytest.mark.parametrize(
    "procedure_name,handler_id,body_param,base_params",
    SAMBA_BODY_PROCEDURES,
)
def test_samba_config_bodies_reject_continuation_split_directives(
    jobs_module,
    split_body: str,
    procedure_name: str,
    handler_id: str,
    body_param: str,
    base_params: dict[str, object],
) -> None:
    params = {**base_params, body_param: split_body}
    execution = _execution(procedure_name, handler_id, params)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_samba_config_deploy_accepts_continued_value(jobs_module) -> None:
    # A legitimately continued *value* (not a directive name) must still pass —
    # the continuation join is for parity with Samba, not a blanket ban.
    content = "[global]\n   comment = hello \\\nworld\n   workgroup = EXAMPLE\n"

    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.samba.1.config_deploy",
            "service.samba_1.config_deploy",
            {"config_content": content},
        )
    )

    assert normalized["config_content"] == content


def test_samba_config_deploy_accepts_benign_smb_conf(jobs_module) -> None:
    content = (
        "[global]\n"
        "   workgroup = EXAMPLE\n"
        "   security = user\n"
        "\n"
        "[engineering]\n"
        "   path = /srv/samba/engineering\n"
        "   valid users = @engineering\n"
        "   read only = yes\n"
    )

    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.samba.1.config_deploy",
            "service.samba_1.config_deploy",
            {"config_content": content},
        )
    )

    assert normalized["config_content"] == content
    assert "config_content_sha256" in normalized["command_fingerprint"]


@pytest.mark.parametrize(
    "include_directive",
    [
        "include = /tmp/evil.conf",
        "include = registry",
    ],
)
@pytest.mark.parametrize(
    "procedure_name,handler_id,body_param,base_params",
    SAMBA_BODY_PROCEDURES,
)
def test_samba_config_bodies_reject_unsafe_include_directives(
    jobs_module,
    include_directive: str,
    procedure_name: str,
    handler_id: str,
    body_param: str,
    base_params: dict[str, object],
) -> None:
    params = {**base_params, body_param: f"[global]\n   {include_directive}\n"}
    execution = _execution(procedure_name, handler_id, params)

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    "procedure_name,handler_id,body_param,base_params",
    SAMBA_BODY_PROCEDURES,
)
def test_samba_config_bodies_accept_confined_include_directive(
    jobs_module,
    procedure_name: str,
    handler_id: str,
    body_param: str,
    base_params: dict[str, object],
) -> None:
    body = "[global]\n   include = /etc/samba/extra.conf\n"
    normalized = jobs_module.normalize_execution_params(
        _execution(
            procedure_name,
            handler_id,
            {**base_params, body_param: body},
        )
    )

    assert normalized[body_param] == body


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
@pytest.mark.parametrize(
    "procedure_name,handler_id,extra_params",
    [
        ("service.samba.1.include_file_read", "service.samba_1.include_file_read", {}),
        (
            "service.samba.1.include_file_write",
            "service.samba_1.include_file_write",
            {"content": "[global]\n"},
        ),
        (
            "service.samba.1.include_file_delete",
            "service.samba_1.include_file_delete",
            {},
        ),
    ],
)
def test_include_file_procedures_reject_unconfined_or_injection_paths(
    jobs_module,
    include_path: str,
    procedure_name: str,
    handler_id: str,
    extra_params: dict[str, object],
) -> None:
    execution = _execution(
        procedure_name,
        handler_id,
        {"include_path": include_path, **extra_params},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    "share_name",
    ["bad;name", "../homes", "/etc/samba/homes", "bad name", "bad$(id)", "homes\nid"],
)
@pytest.mark.parametrize(
    "procedure_name,handler_id,extra_params",
    [
        ("service.samba.1.share_acl_read", "service.samba_1.share_acl_read", {}),
        (
            "service.samba.1.share_upsert",
            "service.samba_1.share_upsert",
            {"path": "/srv/samba/homes"},
        ),
        ("service.samba.1.share_delete", "service.samba_1.share_delete", {}),
    ],
)
def test_share_procedures_reject_unsafe_share_names(
    jobs_module,
    share_name: str,
    procedure_name: str,
    handler_id: str,
    extra_params: dict[str, object],
) -> None:
    execution = _execution(
        procedure_name,
        handler_id,
        {"share_name": share_name, **extra_params},
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


@pytest.mark.parametrize(
    "params",
    [
        {"unit": "sshd", "action": "reload"},
        {"unit": "smbd", "action": "enable"},
    ],
)
def test_service_control_rejects_unknown_unit_or_action(
    jobs_module,
    params: dict[str, object],
) -> None:
    execution = _execution(
        "service.samba.1.service_control",
        "service.samba_1.service_control",
        params,
    )

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_share_upsert_uses_conservative_defaults(jobs_module) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.samba.1.share_upsert",
            "service.samba_1.share_upsert",
            {"share_name": "public", "path": "/srv/samba/public"},
        )
    )

    assert normalized["read_only"] is True
    assert normalized["browseable"] is True
    assert normalized["guest_ok"] is False
    assert normalized["command_fingerprint"]["read_only"] is True
    assert normalized["command_fingerprint"]["guest_ok"] is False


def test_every_seeded_samba_procedure_has_normalizer_branch(
    jobs_module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_migration = _load_seed_migration(monkeypatch, READ_MIGRATION_MODULE)
    write_migration = _load_seed_migration(monkeypatch, WRITE_MIGRATION_MODULE)
    identity_migration = _load_seed_migration(monkeypatch, IDENTITY_MIGRATION_MODULE)
    seeded_names = {
        procedure["name"]
        for migration in (read_migration, write_migration, identity_migration)
        for procedure in migration._PROCEDURES
    }
    all_cases = SAMBA_CASES + SAMBA_WRITE_CASES + SAMBA_IDENTITY_CASES

    assert seeded_names == {case[0] for case in all_cases}
    for name, handler_id, params, _expected in all_cases:
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


def test_samba_write_seed_schema_and_approval_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _load_seed_migration(monkeypatch, WRITE_MIGRATION_MODULE)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}

    assert set(procedures) == {case[0] for case in SAMBA_WRITE_CASES}
    for procedure in procedures.values():
        assert procedure["target_models"] == [
            "netbox_fileserver.sambadomain",
            "virtualization.virtualmachine",
            "dcim.device",
        ]

    destructive = {
        name
        for name, procedure in procedures.items()
        if procedure["effect"] == "destructive"
    }
    assert destructive == {
        "service.samba.1.config_rollback",
        "service.samba.1.include_file_delete",
        "service.samba.1.share_delete",
    }
    for name in destructive:
        assert procedures[name]["approval_required"] is True
    for name, procedure in procedures.items():
        if name not in destructive:
            assert procedure["approval_required"] is False


def test_config_deploy_result_schema_tracks_rollback_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _load_seed_migration(monkeypatch, WRITE_MIGRATION_MODULE)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}
    deploy = procedures["service.samba.1.config_deploy"]
    rollback = procedures["service.samba.1.config_rollback"]

    deploy_schema = deploy["result_schema"]
    deploy_props = deploy_schema["properties"]
    for field in (
        "stage",
        "snapshot_id",
        "activated",
        "reloaded",
        "rolled_back",
        "rollback_error",
    ):
        assert field in deploy_props
    assert set(deploy_props["stage"]["enum"]) == {
        "validate",
        "snapshot",
        "activate",
        "reload",
        "rollback",
    }
    assert deploy_props["activated"]["type"] == "boolean"
    assert deploy_props["rolled_back"]["type"] == "boolean"
    assert deploy_props["rollback_error"]["type"] == ["string", "null"]
    assert {
        "stage",
        "activated",
        "reloaded",
        "rolled_back",
    }.issubset(deploy_schema["required"])
    assert "snapshot_id" not in deploy_schema["required"]

    rollback_props = rollback["result_schema"]["properties"]
    for field in ("stage", "rolled_back", "rollback_error"):
        assert field in rollback_props
    assert "post-snapshot rollback" in deploy["description"]


def test_samba_write_seed_schema_rejects_invalid_structured_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _load_seed_migration(monkeypatch, WRITE_MIGRATION_MODULE)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}
    jsonschema = pytest.importorskip("jsonschema")

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"include_path": "../secret.conf", "content": "[global]\n"},
            procedures["service.samba.1.include_file_write"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"include_path": "/tmp/secret.conf"},
            procedures["service.samba.1.include_file_delete"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"share_name": "bad;name", "path": "/srv/samba/share"},
            procedures["service.samba.1.share_upsert"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"share_name": "engineering", "path": "../share"},
            procedures["service.samba.1.share_upsert"]["params_schema"],
        )

    service_schema = procedures["service.samba.1.service_control"]["params_schema"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"unit": "sshd", "action": "reload"}, service_schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"unit": "smbd", "action": "enable"}, service_schema)

    jsonschema.validate(
        {"unit": "samba-ad-dc", "action": "restart"},
        service_schema,
    )


def test_samba_write_command_rows_match_exemption_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_migration = _load_seed_migration(
        monkeypatch,
        WRITE_COMMAND_MIGRATION_MODULE,
    )
    commands = command_migration._COMMAND_STEPS_BY_HANDLER_ID
    exempt_handlers = {
        "service.samba_1.config_deploy",
        "service.samba_1.config_rollback",
        "service.samba_1.include_file_write",
        "service.samba_1.include_file_delete",
        "service.samba_1.share_upsert",
        "service.samba_1.share_delete",
    }

    spec = importlib.util.spec_from_file_location(
        "command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    for handler_id in exempt_handlers:
        assert handler_id in command_contract.EXEMPT_HANDLER_IDS
        assert commands[handler_id][0]["argv"][0] == "backend-orchestrated"

    assert "service.samba_1.service_control" not in command_contract.EXEMPT_HANDLER_IDS
    assert commands["service.samba_1.service_control"][0]["argv"] == [
        "sudo",
        "/bin/systemctl",
        "{action}",
        "--",
        "{unit}.service",
    ]


def test_samba_identity_seed_schema_and_approval_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _load_seed_migration(monkeypatch, IDENTITY_MIGRATION_MODULE)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}

    assert set(procedures) == {case[0] for case in SAMBA_IDENTITY_CASES}
    for procedure in procedures.values():
        assert procedure["target_models"] == [
            "netbox_fileserver.sambadomain",
            "virtualization.virtualmachine",
            "dcim.device",
        ]

    destructive = {
        name
        for name, procedure in procedures.items()
        if procedure["effect"] == "destructive"
    }
    assert destructive == {
        "service.samba.1.user_delete",
        "service.samba.1.group_delete",
    }
    for name in destructive:
        assert procedures[name]["approval_required"] is True
    for name, procedure in procedures.items():
        if name not in destructive:
            assert procedure["approval_required"] is False
            assert procedure["effect"] == "write"


def test_samba_identity_password_fields_never_appear_in_result_schemas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No identity procedure's *result* may ever carry a password value/hash.

    ``user_create``/``user_set_password`` legitimately accept ``password`` as
    *input* (delivered to samba-tool over stdin, scrubbed before persistence --
    see command_handlers._scrub_password_param()); their result_schema must
    still never round-trip the value or a hash of it. ``user_set_password``'s
    result legitimately reports a ``password_set`` *boolean flag* -- that is
    not a secret and is explicitly allowed. Every other procedure's
    params_schema must not mention "password" at all.
    """
    migration = _load_seed_migration(monkeypatch, IDENTITY_MIGRATION_MODULE)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}

    allowed_boolean_flags = {"password_set"}
    for name, procedure in procedures.items():
        for prop_name, prop_schema in procedure["result_schema"]["properties"].items():
            lowered = prop_name.lower()
            assert "hash" not in lowered, (name, prop_name)
            if "password" not in lowered:
                continue
            assert prop_name in allowed_boolean_flags, (name, prop_name)
            assert prop_schema["type"] == "boolean", (name, prop_name)

    password_bearing = {
        "service.samba.1.user_create",
        "service.samba.1.user_set_password",
    }
    for name in password_bearing:
        params_schema = procedures[name]["params_schema"]
        assert "password" in params_schema["required"]
        assert params_schema["properties"]["password"]["type"] == "string"

    for name, procedure in procedures.items():
        if name in password_bearing:
            continue
        params_schema_text = json.dumps(
            procedure["params_schema"], sort_keys=True
        ).lower()
        assert "password" not in params_schema_text, name


def test_samba_identity_seed_schema_rejects_invalid_structured_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _load_seed_migration(monkeypatch, IDENTITY_MIGRATION_MODULE)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}
    jsonschema = pytest.importorskip("jsonschema")

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"username": "bad;name", "password": "hunter2"},
            procedures["service.samba.1.user_create"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"username": "alice"},
            procedures["service.samba.1.user_create"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"username": "alice", "password": "hunter2", "extra": "nope"},
            procedures["service.samba.1.user_create"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"group_name": "engineering", "members": []},
            procedures["service.samba.1.group_add_members"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"group_name": "engineering", "members": ["alice"] * 200},
            procedures["service.samba.1.group_add_members"]["params_schema"],
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"group_name": "bad name"},
            procedures["service.samba.1.group_delete"]["params_schema"],
        )

    jsonschema.validate(
        {"username": "alice", "password": "hunter2"},
        procedures["service.samba.1.user_create"]["params_schema"],
    )
    jsonschema.validate(
        {"group_name": "engineering", "members": ["alice", "bob"]},
        procedures["service.samba.1.group_add_members"]["params_schema"],
    )


def test_samba_identity_seed_schema_rejects_trailing_newline_under_search_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mirrors the read/write seed test: ``jsonschema`` enforces ``pattern``
    with ``re.search``, so a bare ``$`` anchor would accept a trailing
    newline. The identity seed patterns anchor with ``(?![\\s\\S])`` instead.
    """
    migration = _load_seed_migration(monkeypatch, IDENTITY_MIGRATION_MODULE)
    procedures = {procedure["name"]: procedure for procedure in migration._PROCEDURES}

    username_pattern = procedures["service.samba.1.user_delete"]["params_schema"][
        "properties"
    ]["username"]["pattern"]
    assert re.search(username_pattern, "alice")
    assert not re.search(username_pattern, "alice\n")

    password_pattern = procedures["service.samba.1.user_create"]["params_schema"][
        "properties"
    ]["password"]["pattern"]
    assert re.search(password_pattern, "hunter2")
    assert not re.search(password_pattern, "hunter2\n")

    group_pattern = procedures["service.samba.1.group_delete"]["params_schema"][
        "properties"
    ]["group_name"]["pattern"]
    assert re.search(group_pattern, "engineering")
    assert not re.search(group_pattern, "engineering\n")


def test_samba_identity_command_rows_match_exemption_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_migration = _load_seed_migration(
        monkeypatch,
        IDENTITY_COMMAND_MIGRATION_MODULE,
    )
    commands = command_migration._COMMAND_STEPS_BY_HANDLER_ID
    exempt_handlers = {
        "service.samba_1.user_create",
        "service.samba_1.user_set_password",
    }

    spec = importlib.util.spec_from_file_location(
        "command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    command_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_contract)

    for handler_id in exempt_handlers:
        assert handler_id in command_contract.EXEMPT_HANDLER_IDS
        assert commands[handler_id][0]["argv"][0] == "backend-orchestrated"

    non_exempt_argv = {
        "service.samba_1.user_delete": [
            "sudo",
            "/usr/bin/samba-tool",
            "user",
            "delete",
            "{username}",
        ],
        "service.samba_1.user_enable": [
            "sudo",
            "/usr/bin/samba-tool",
            "user",
            "enable",
            "{username}",
        ],
        "service.samba_1.user_disable": [
            "sudo",
            "/usr/bin/samba-tool",
            "user",
            "disable",
            "{username}",
        ],
        "service.samba_1.group_create": [
            "sudo",
            "/usr/bin/samba-tool",
            "group",
            "add",
            "{group_name}",
        ],
        "service.samba_1.group_delete": [
            "sudo",
            "/usr/bin/samba-tool",
            "group",
            "delete",
            "{group_name}",
        ],
        "service.samba_1.group_add_members": [
            "sudo",
            "/usr/bin/samba-tool",
            "group",
            "addmembers",
            "{group_name}",
            "{members_csv}",
        ],
        "service.samba_1.group_remove_members": [
            "sudo",
            "/usr/bin/samba-tool",
            "group",
            "removemembers",
            "{group_name}",
            "{members_csv}",
        ],
    }
    for handler_id, expected_argv in non_exempt_argv.items():
        assert handler_id not in command_contract.EXEMPT_HANDLER_IDS
        assert commands[handler_id][0]["argv"] == expected_argv


def test_fileserver_samba_intents_seed_membership_and_ordering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pure-domain check of the #160 RPCIntent seed data shape.

    The intent *executor* (execute_intent(), #130) is DB-backed and out of
    scope here; this only proves the migration's inline ``_INTENTS`` data --
    membership, per-intent ``sequence`` ordering, and ``execution_mode`` --
    matches the issue's documented contract.
    """
    migration = _load_seed_migration(monkeypatch, INTENT_MIGRATION_MODULE)
    intents = {intent["name"]: intent for intent in migration._INTENTS}

    assert set(intents) == {
        "fileserver.samba.collect_state",
        "fileserver.samba.deploy_config",
    }

    collect_state = intents["fileserver.samba.collect_state"]
    assert collect_state["execution_mode"] == "parallel"
    assert collect_state["procedure_names"] == (
        "service.samba.1.version",
        "service.samba.1.service_status",
        "service.samba.1.config_read",
        "service.samba.1.config_test",
        "service.samba.1.list_shares",
        "service.samba.1.status_report",
        "service.samba.1.user_list",
        "service.samba.1.group_list",
        "service.samba.1.domain_info",
    )

    deploy_config = intents["fileserver.samba.deploy_config"]
    assert deploy_config["execution_mode"] == "sequential"
    assert deploy_config["procedure_names"] == (
        "service.samba.1.config_test",
        "service.samba.1.config_deploy",
        "service.samba.1.service_control",
        "service.samba.1.service_status",
    )

    # No intent procedure name may be invented -- every one must resolve to a
    # procedure actually seeded across the read/write/identity migrations.
    read_migration = _load_seed_migration(monkeypatch, READ_MIGRATION_MODULE)
    write_migration = _load_seed_migration(monkeypatch, WRITE_MIGRATION_MODULE)
    identity_migration = _load_seed_migration(monkeypatch, IDENTITY_MIGRATION_MODULE)
    all_seeded_names = {
        procedure["name"]
        for migration in (read_migration, write_migration, identity_migration)
        for procedure in migration._PROCEDURES
    }
    for intent in intents.values():
        for procedure_name in intent["procedure_names"]:
            assert procedure_name in all_seeded_names, procedure_name


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
@pytest.mark.parametrize(
    "procedure_name,handler_id,extra_params",
    [
        ("service.samba.1.include_file_read", "service.samba_1.include_file_read", {}),
        (
            "service.samba.1.include_file_write",
            "service.samba_1.include_file_write",
            {"content": "[global]\n"},
        ),
        (
            "service.samba.1.include_file_delete",
            "service.samba_1.include_file_delete",
            {},
        ),
    ],
)
def test_include_path_is_normalized_to_confined_absolute_path(
    jobs_module,
    raw: str,
    expected: str,
    procedure_name: str,
    handler_id: str,
    extra_params: dict[str, object],
) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(
            procedure_name,
            handler_id,
            {"include_path": raw, **extra_params},
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


def _load_seed_migration(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str = READ_MIGRATION_MODULE,
):
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

    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


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
