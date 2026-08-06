from __future__ import annotations

import importlib
import importlib.util
import runpy
import sys
import types
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, validate

ROOT = Path(__file__).resolve().parents[1]
PROCEDURE_MIGRATION = (
    "netbox_rpc.migrations.0063_seed_ubuntu_upgrade_26_procedures"
)
COMMAND_MIGRATION = "netbox_rpc.migrations.0064_seed_ubuntu_upgrade_26_commands"
INTENT_MIGRATION = "netbox_rpc.migrations.0065_seed_ubuntu_upgrade_26_intent"
PROCEDURE_NAMES = (
    "os.linux.ubuntu.24.upgrade_26.analyze_preupgrade",
    "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state",
    "os.linux.ubuntu.24.upgrade_26.run_upgrade",
    "os.linux.ubuntu.24.upgrade_26.verify_postupgrade",
)
EXEMPT_HANDLER_IDS = frozenset(
    {
        "os.linux.ubuntu.24.upgrade_26.save_preupgrade_state",
        "os.linux.ubuntu.24.upgrade_26.run_upgrade",
    }
)


@pytest.fixture()
def migrations(monkeypatch: pytest.MonkeyPatch):
    _install_migration_import_stubs(monkeypatch)
    modules = []
    for module_name in (PROCEDURE_MIGRATION, COMMAND_MIGRATION, INTENT_MIGRATION):
        sys.modules.pop(module_name, None)
        modules.append(importlib.import_module(module_name))
    yield modules
    for module_name in (PROCEDURE_MIGRATION, COMMAND_MIGRATION, INTENT_MIGRATION):
        sys.modules.pop(module_name, None)


def _load_command_contract():
    spec = importlib.util.spec_from_file_location(
        "ubuntu_upgrade_26_command_contract",
        ROOT / "netbox_rpc/command_contract.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_catalog_constants_and_seed_names_are_complete(migrations) -> None:
    procedure_migration, _, intent_migration = migrations
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))

    expected = frozenset(PROCEDURE_NAMES)
    assert constants["UBUNTU_UPGRADE_26_PROCEDURE_NAMES"] == expected
    assert {
        constants["UBUNTU_UPGRADE_26_ANALYZE_PREUPGRADE"],
        constants["UBUNTU_UPGRADE_26_SAVE_PREUPGRADE_STATE"],
        constants["UBUNTU_UPGRADE_26_RUN_UPGRADE"],
        constants["UBUNTU_UPGRADE_26_VERIFY_POSTUPGRADE"],
    } == expected
    assert {row["name"] for row in procedure_migration._PROCEDURES} == expected
    assert tuple(intent_migration._PROCEDURE_NAMES) == PROCEDURE_NAMES
    assert intent_migration._INTENT_NAME == "Update Ubuntu OS from 24 LTS to 26 LTS"


def test_upgrade_effect_and_approval_policy(migrations) -> None:
    procedure_migration, _, _ = migrations
    procedures = {row["name"]: row for row in procedure_migration._PROCEDURES}

    upgrade = procedures["os.linux.ubuntu.24.upgrade_26.run_upgrade"]
    assert upgrade["effect"] == "destructive"
    assert upgrade["approval_required"] is True
    for name in set(PROCEDURE_NAMES) - {upgrade["name"]}:
        assert procedures[name]["approval_required"] is False

    assert procedures[PROCEDURE_NAMES[0]]["effect"] == "read"
    assert procedures[PROCEDURE_NAMES[1]]["effect"] == "write"
    assert procedures[PROCEDURE_NAMES[3]]["effect"] == "read"
    for procedure in procedures.values():
        assert procedure["handler_id"] == procedure["name"]
        assert procedure["target_models"] == [
            "dcim.device",
            "virtualization.virtualmachine",
        ]
        assert procedure["params_schema"]["additionalProperties"] is False


def test_seeded_schemas_are_valid_and_defaults_are_explicitly_normalized(
    migrations,
) -> None:
    procedure_migration, _, _ = migrations
    procedures = {row["name"]: row for row in procedure_migration._PROCEDURES}
    for procedure in procedures.values():
        Draft202012Validator.check_schema(procedure["params_schema"])
        Draft202012Validator.check_schema(procedure["result_schema"])

    upgrade_schema = procedures[PROCEDURE_NAMES[2]]["params_schema"]
    assert upgrade_schema["properties"]["dry_run"]["default"] is True
    assert upgrade_schema["properties"]["reboot_after_upgrade"]["default"] is False
    validate({}, upgrade_schema)
    validate({"dry_run": False, "reboot_after_upgrade": True}, upgrade_schema)

    verify_schema = procedures[PROCEDURE_NAMES[3]]["params_schema"]
    assert "compare_backup_dir" not in verify_schema["properties"]
    validate({"expected_version_id": "26.04"}, verify_schema)


def test_backend_orchestrated_handlers_are_documented_exemptions() -> None:
    command_contract = _load_command_contract()

    assert EXEMPT_HANDLER_IDS <= command_contract.EXEMPT_HANDLER_IDS
    assert EXEMPT_HANDLER_IDS <= command_contract.EXEMPT_HANDLER_RATIONALE.keys()


def test_non_exempt_seeded_argv_is_structurally_safe(migrations) -> None:
    _, command_migration, _ = migrations
    command_contract = _load_command_contract()

    assert set(command_migration._COMMAND_STEPS_BY_HANDLER_ID) == set(PROCEDURE_NAMES)
    for handler_id in (PROCEDURE_NAMES[0], PROCEDURE_NAMES[3]):
        for step in command_migration._COMMAND_STEPS_BY_HANDLER_ID[handler_id]:
            assert step["step_type"] == "shell_argv"
            assert isinstance(step["argv"], list) and step["argv"]
            for token in step["argv"]:
                assert command_contract.token_is_safe(token), (handler_id, token)
                assert command_contract.token_has_balanced_placeholders(token), (
                    handler_id,
                    token,
                )
                assert command_contract.extract_placeholders(token) == ()

    for handler_id in EXEMPT_HANDLER_IDS:
        [step] = command_migration._COMMAND_STEPS_BY_HANDLER_ID[handler_id]
        assert step["argv"][0] == "backend-orchestrated"
        assert all(command_contract.token_is_safe(token) for token in step["argv"])


def test_normalizer_dispatch_branch_is_registered() -> None:
    normalization = (ROOT / "netbox_rpc/domain/normalization.py").read_text(
        encoding="utf-8"
    )

    assert "UBUNTU_UPGRADE_26_PROCEDURE_NAMES" in normalization
    assert "if procedure_name in UBUNTU_UPGRADE_26_PROCEDURE_NAMES:" in normalization
    assert "_normalize_ubuntu_upgrade_26_execution(execution, target)" in normalization


def test_migrations_are_inline_and_ordered(migrations) -> None:
    procedure_migration, command_migration, intent_migration = migrations

    assert procedure_migration.Migration.dependencies == [
        ("netbox_rpc", "0062_merge_akvorado_and_linux_env_file")
    ]
    assert command_migration.Migration.dependencies == [
        ("netbox_rpc", "0063_seed_ubuntu_upgrade_26_procedures")
    ]
    assert intent_migration.Migration.dependencies == [
        ("netbox_rpc", "0064_seed_ubuntu_upgrade_26_commands")
    ]
    for filename in (
        "0063_seed_ubuntu_upgrade_26_procedures.py",
        "0064_seed_ubuntu_upgrade_26_commands.py",
        "0065_seed_ubuntu_upgrade_26_intent.py",
    ):
        source = (ROOT / "netbox_rpc/migrations" / filename).read_text(encoding="utf-8")
        assert "from netbox_rpc" not in source


def _install_migration_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type(
        "PluginConfig",
        (),
        {"ready": lambda self: None},
    )

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
