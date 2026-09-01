"""Contract tests for `service.openbao.1.provision_netbox_approle` (issue #296).

Three properties are worth pinning, and only the first is obvious.

1. **No field can carry a credential.** A SecretID in `RPCExecution.result`
   would put a live OpenBao credential into the NetBox database, which is what
   `netbox-openbao` exists to prevent.
2. **No parameter accepts free-form text.** `policy_write` is withheld from this
   catalogue precisely because it did, and withholding it is what makes "no
   seeded OpenBao procedure takes free-form text" structural rather than
   signature-dependent. This procedure writes a policy, so it is the obvious
   place for that guarantee to be lost by accident.
3. **No `rpc_ssh_*` override.** Params are persisted before the backend can
   refuse them, so not declaring the fields is the layer that prevents
   persistence — the same reasoning the rest of this catalogue records.

Django-free, matching the sibling catalogue tests.
"""

from __future__ import annotations

import ast
import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate

MIGRATION_MODULE = "netbox_rpc.migrations.0089_seed_openbao_netbox_approle"
NAME = "service.openbao.1.provision_netbox_approle"
HANDLER_ID = "service.openbao_1.provision_netbox_approle"
TARGET = "netbox-01.example.net"

#: Transcribed once, exhaustively. Any field added to either schema fails these
#: tests until somebody records why it is not a credential — which is the
#: property worth having on a procedure that mints one.
ALLOWED_PARAMS = {
    "mount", "role_name", "engine_slug", "path_prefix", "ttl_seconds",
    "restart_netbox",
}
ALLOWED_RESULT = {
    "ok", "procedure", "target", "mount", "policy", "role_name", "engine_slug",
    "env_prefix", "env_file", "approle_accessor", "ttl_seconds",
    "created_mount", "created_policy", "created_approle_method", "created_role",
    "netbox_restarted", "revocation_pending", "detail",
}
#: Credential-shaped names that are nonetheless not credentials, with the reason.
NON_SECRET_RATIONALE: dict[str, str] = {}


@pytest.fixture()
def migration(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    sys.modules.pop(MIGRATION_MODULE, None)
    module = importlib.import_module(MIGRATION_MODULE)
    yield module
    sys.modules.pop(MIGRATION_MODULE, None)


def test_seed_follows_the_catalogue_conventions(migration) -> None:
    procedures = _FakeProcedureManager()
    commands = _FakeCommandManager()
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = commands

    migration._seed(SimpleNamespace(get_model=_model_lookup), None)

    assert migration.Migration.dependencies == [
        ("netbox_rpc", "0088_rpcprocedurecommand_tags_and_custom_fields")
    ]
    row = procedures.rows[NAME]
    assert row["handler_id"] == HANDLER_ID
    # 0078 records why: the backend's OpenBao credential lookup rejects VM
    # identities, so a VM target must not be advertised.
    assert row["target_models"] == ["dcim.device"]
    assert row["effect"] == "write"
    assert row["approval_required"] is True
    # Unlike 0078's rows, seeded disabled: the handler and a scoped provisioning
    # token must exist first.
    assert row["enabled"] is False
    command = commands.rows[(NAME, 1)]
    assert command["argv"] == ["backend-orchestrated", "openbao-provision-netbox-approle"]


def test_no_parameter_accepts_free_form_text(migration) -> None:
    """The guarantee `policy_write` was withheld to protect.

    Every string parameter must be bounded by a pattern. A string field with no
    pattern is free-form text by definition, whatever it is named.
    """
    params = migration._PARAMS
    for field, schema in params["properties"].items():
        if schema.get("type") == "string":
            assert schema.get("pattern"), (
                f"{field} is an unconstrained string, which reintroduces the "
                "free-form-text path this catalogue withholds policy_write to avoid"
            )
            assert schema.get("maxLength"), f"{field} has no length bound"


def test_no_field_can_carry_a_credential(migration) -> None:
    assert migration._PARAMS["additionalProperties"] is False
    assert migration._RESULT["additionalProperties"] is False
    assert set(migration._PARAMS["properties"]) == ALLOWED_PARAMS
    assert set(migration._RESULT["properties"]) == ALLOWED_RESULT
    for field in {*migration._PARAMS["properties"], *migration._RESULT["properties"]}:
        if "secret" in field or "role_id" in field or "token" in field:
            assert field in NON_SECRET_RATIONALE, (
                f"{field} looks like a credential and has no recorded rationale"
            )


def test_result_schema_refuses_a_smuggled_credential(migration) -> None:
    """`additionalProperties: false` is only a guard if it actually refuses."""
    valid = {
        "ok": True, "procedure": HANDLER_ID, "target": TARGET,
        "mount": "netbox", "policy": "netbox", "role_name": "netbox",
        "engine_slug": "prod-core", "env_prefix": "NETBOX_BAO_PROD_CORE",
        "env_file": "/etc/netbox/openbao.env",
        "approle_accessor": "9a1e53b4-c1d5-5f4d-0532-9f67070b8d1e",
        "ttl_seconds": 0, "created_mount": False, "created_policy": False,
        "created_approle_method": False, "created_role": False,
        "netbox_restarted": False, "revocation_pending": 0,
    }
    validate(valid, migration._RESULT)
    for smuggled in ("secret_id", "role_id", "token"):
        with pytest.raises(ValidationError):
            validate({**valid, smuggled: "leaked"}, migration._RESULT)


def test_params_declare_no_ssh_override(migration) -> None:
    assert not [f for f in migration._PARAMS["properties"] if f.startswith("rpc_ssh")]


def test_params_reject_values_that_would_change_a_command(migration) -> None:
    schema = migration._PARAMS
    Draft202012Validator.check_schema(schema)
    base = {"mount": "netbox", "role_name": "netbox", "engine_slug": "prod-core"}
    validate(base, schema)

    for field, hostile in [
        ("role_name", "netbox; rm -rf /"),
        ("role_name", "netbox $(id)"),
        ("role_name", "netbox`id`"),
        # A trailing newline past an otherwise-valid value is why this
        # catalogue's patterns end in (?![\s\S]) rather than $.
        ("role_name", "netbox\nid"),
        ("role_name", "netbox mount"),
        ("engine_slug", "PROD-CORE"),
        ("engine_slug", "-prod"),
        ("mount", "netbox\nid"),
        ("mount", "netbox;id"),
    ]:
        with pytest.raises(ValidationError, match=".*"):
            validate({**base, field: hostile}, schema)


def test_forward_refuses_to_adopt_an_operator_owned_row(migration) -> None:
    procedures = _FakeProcedureManager()
    procedures.rows[NAME] = {"enabled": True}
    _FakeRPCProcedure.objects = procedures
    _FakeRPCProcedureCommand.objects = _FakeCommandManager()
    with pytest.raises(RuntimeError, match="already exists"):
        migration._seed(SimpleNamespace(get_model=_model_lookup), None)


def test_reverse_is_irreversible(migration) -> None:
    """An execution here is the audit record of a credential having been minted."""
    with pytest.raises(RuntimeError, match="irreversible"):
        migration._remove(SimpleNamespace(get_model=_model_lookup), None)



def test_no_result_field_is_destroyed_by_event_store_redaction(migration) -> None:
    """The names have to survive the redaction filter, not merely be honest.

    `event_store` redacts any key **containing** "secret", by substring, and
    replaces the value with the string "[REDACTED]". Naming a field
    `secret_id_accessor` was accurate and still wrong: the accessor was erased,
    and an integer `secret_id_ttl` became a string that then failed
    post-redaction schema validation — recording a mismatch *after* the
    credential had been minted and installed, so an operator retrying the
    apparent failure would mint another.

    This asserts the property directly against the real fragment list rather
    than against a remembered copy of it.
    """
    # Parsed from source, not imported: event_store pulls in Django settings,
    # and reading the real literal is what keeps this honest against a
    # remembered copy of it.
    source = (
        Path(__file__).resolve().parents[1] / "netbox_rpc" / "event_store.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    fragments: tuple[str, ...] = ()
    safe_keys: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name == "SENSITIVE_KEY_FRAGMENTS":
            fragments = tuple(ast.literal_eval(node.value))
        elif name == "SAFE_REFERENCE_KEYS":
            safe_keys = {str(v) for v in ast.literal_eval(node.value)}
    assert fragments, "could not read SENSITIVE_KEY_FRAGMENTS from event_store"

    fields = set(migration._RESULT["properties"]) | set(migration._PARAMS["properties"])
    for field in sorted(fields):
        if field.lower() in safe_keys:
            continue
        offending = [f for f in fragments if f in field.lower()]
        assert not offending, (
            f"{field} contains {offending}, so the event store will replace its "
            'value with "[REDACTED]". For a non-secret field that destroys the '
            "metadata; for a non-string field it also breaks schema validation."
        )


def test_a_successful_result_must_carry_every_recovery_field(migration) -> None:
    """A sparse success is unrecoverable: nothing to revoke, nothing to inspect."""
    complete = {
        "ok": True, "procedure": HANDLER_ID, "target": TARGET,
        "mount": "netbox", "policy": "netbox", "role_name": "netbox",
        "engine_slug": "prod-core", "env_prefix": "NETBOX_BAO_PROD_CORE",
        "env_file": "/etc/netbox/openbao.env",
        "approle_accessor": "9a1e53b4-c1d5-5f4d-0532-9f67070b8d1e",
        "ttl_seconds": 0, "created_mount": True, "created_policy": True,
        "created_approle_method": False, "created_role": True,
        "netbox_restarted": False, "revocation_pending": 0,
    }
    validate(complete, migration._RESULT)

    for omitted in ("approle_accessor", "env_file", "role_name", "mount"):
        sparse = {k: v for k, v in complete.items() if k != omitted}
        with pytest.raises(ValidationError):
            validate(sparse, migration._RESULT)

    # A failure may be sparse: there may be nothing to report.
    validate({"ok": False, "procedure": HANDLER_ID, "target": TARGET,
              "detail": "AppRole provisioning failed"}, migration._RESULT)



def test_a_successful_result_may_carry_an_empty_detail(migration) -> None:
    """`detail` is empty on success, and that must validate.

    An earlier draft typed it with a minimum length of one, which made every
    successful result fail validation *after* the credential had been published
    and its predecessor revoked — inviting a retry that mints another.
    """
    complete = {
        "ok": True, "procedure": HANDLER_ID, "target": TARGET,
        "mount": "netbox", "policy": "netbox", "role_name": "netbox",
        "engine_slug": "prod-core", "env_prefix": "NETBOX_BAO_PROD_CORE",
        "env_file": "/etc/netbox/openbao.env",
        "approle_accessor": "9a1e53b4-c1d5-5f4d-0532-9f67070b8d1e",
        "ttl_seconds": 0, "created_mount": False, "created_policy": False,
        "created_approle_method": False, "created_role": False,
        "netbox_restarted": False, "revocation_pending": 0, "detail": "",
    }
    validate(complete, migration._RESULT)


def test_the_timeout_exceeds_the_handler_route_budget(migration) -> None:
    """The catalogue deadline must be longer than the stages it bounds.

    Provisioning is bounded at 180s and each of the two service restarts at
    60s. A deadline equal to the provisioning stage alone would let the caller
    time out after publication, or between the two restarts, leaving one
    consumer on the superseded credential.
    """
    route_budget = 180 + 60 + 60
    assert migration._PROCEDURE["timeout_seconds"] > route_budget



def test_the_procedure_is_in_the_protected_approval_and_capability_paths() -> None:
    """It mints a credential, so it must not be self-approvable or replayable.

    Outside these sets a requester holding both execute and approve queues it
    immediately with no distinct approver, and dispatch stays id-only when no
    signing key is present — so replaying a backend execution id mints another
    credential without a new approval decision.
    """
    from netbox_rpc.constants import (
        EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES,
        OPENBAO_1_PROCEDURE_NAMES,
        PROTECTED_APPROVAL_PROCEDURE_NAMES,
    )

    assert NAME in OPENBAO_1_PROCEDURE_NAMES
    assert NAME in PROTECTED_APPROVAL_PROCEDURE_NAMES
    assert NAME in EXPLICIT_BACKEND_CAPABILITY_PROCEDURE_NAMES


def test_the_procedure_is_registered_with_the_runtime_normalizer() -> None:
    """Registration only. That the fields are *carried through* is a behavioural
    property, asserted against the real normalizer in test_openbao_catalog.py —
    a source-shape assertion here passed while every value was being discarded.
    """
    from netbox_rpc.constants import OPENBAO_1_PROCEDURE_NAMES

    assert NAME in OPENBAO_1_PROCEDURE_NAMES


# ── stubs ──────────────────────────────────────────────────────────────────


def _model_lookup(app_label: str, model_name: str):
    return {
        ("netbox_rpc", "RPCProcedure"): _FakeRPCProcedure,
        ("netbox_rpc", "RPCProcedureCommand"): _FakeRPCProcedureCommand,
    }[(app_label, model_name)]


class _FakeQuerySet:
    def __init__(self, manager: "_FakeProcedureManager", name: str) -> None:
        self.manager = manager
        self.name = name

    def exists(self) -> bool:
        return self.name in self.manager.rows


class _FakeProcedureManager:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

    def filter(self, *, name: str) -> _FakeQuerySet:
        return _FakeQuerySet(self, name)

    def create(self, *, name: str, **defaults: object):
        self.rows[name] = dict(defaults)
        return SimpleNamespace(name=name, pk=1, **defaults)


class _FakeCommandManager:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], dict[str, object]] = {}

    def create(self, *, procedure: SimpleNamespace, sequence: int, **defaults: object):
        self.rows[(procedure.name, sequence)] = dict(defaults)
        return SimpleNamespace(procedure=procedure, sequence=sequence, **defaults)


class _FakeRPCProcedure:
    objects: _FakeProcedureManager


class _FakeRPCProcedureCommand:
    objects: _FakeCommandManager


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Importing the migration imports `netbox_rpc/__init__.py`, which imports
    # netbox.plugins. Stub it, as the sibling catalogue tests do, so these run
    # without a NetBox settings module.
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")

    class PluginConfig:
        def ready(self) -> None:
            return None

    netbox_plugins.PluginConfig = PluginConfig
    monkeypatch.setitem(sys.modules, "netbox", netbox)
    monkeypatch.setitem(sys.modules, "netbox.plugins", netbox_plugins)

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")

    class RunPython:
        noop = staticmethod(lambda apps, schema_editor: None)

        def __init__(self, code, reverse_code=None) -> None:
            self.code = code
            self.reverse_code = reverse_code

    django_db.migrations = SimpleNamespace(Migration=object, RunPython=RunPython)
    django.db = django_db
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.db", django_db)
