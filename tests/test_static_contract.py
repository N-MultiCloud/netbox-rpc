from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_plugin_uses_rpc_base_url_and_requires_netbox_nms() -> None:
    src = read("netbox_rpc/__init__.py")
    assert 'base_url = "rpc"' in src
    assert 'required_plugins = ["netbox_nms"]' in src


def test_procedure_catalog_stores_handler_ids_not_commands() -> None:
    models = read("netbox_rpc/models.py")
    constants = read("netbox_rpc/constants.py")
    assert "class RPCProcedure" in models
    assert "handler_id" in models
    assert "params_schema" in models
    assert "result_schema" in models
    assert "command =" not in constants
    assert "network.huawei_olt_ma5800_r024.start_ont" in constants
    assert "os.linux_ubuntu_24.restart_service" in constants


def test_systemd_procedure_catalog_names_are_seeded() -> None:
    constants = read("netbox_rpc/constants.py")
    assert "SYSTEMD_PROCEDURES" in constants
    for name in (
        "os.linux.ubuntu.24.status_service",
        "os.linux.ubuntu.24.start_service",
        "os.linux.ubuntu.24.stop_service",
        "os.linux.ubuntu.24.reload_service",
        "os.linux.ubuntu.24.enable_service",
        "os.linux.ubuntu.24.disable_service",
        "os.linux.ubuntu.24.daemon_reload",
        "os.linux.ubuntu.24.journal_tail",
    ):
        assert name in constants


def test_execution_job_delegates_to_nms_backend() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "get_backend" in jobs
    assert "/rpc/executions/{execution.pk}/run" in jobs
    assert "normalize_execution_params" in jobs
    assert "RPCLinuxServiceAllowlist" in jobs


def test_api_routes_are_registered() -> None:
    urls = read("netbox_rpc/api/urls.py")
    assert 'router.register("procedures"' in urls
    assert 'router.register("linux-service-allowlist"' in urls
    assert 'router.register("executions"' in urls
    assert 'router.register("execution-events"' in urls


def test_create_guards_enabled_and_approval_and_params_schema() -> None:
    views = read("netbox_rpc/api/views.py")
    assert "procedure.enabled" in views
    assert "procedure.approval_required" in views
    assert "jsonschema.validate" in views


def test_migration_does_not_import_live_constants() -> None:
    migration = read("netbox_rpc/migrations/0002_seed_initial_procedures.py")
    assert "from netbox_rpc" not in migration


def test_systemd_migration_does_not_import_live_constants() -> None:
    migration = read("netbox_rpc/migrations/0004_seed_systemd_management_procedures.py")
    assert "from netbox_rpc" not in migration


def test_event_creation_handles_integrity_error() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "IntegrityError" in jobs


def test_call_backend_handles_non_dict_json() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "not isinstance(data, dict)" in jobs


def test_install_ssh_key_procedure_is_defined_in_constants() -> None:
    constants = read("netbox_rpc/constants.py")
    assert "LINUX_INSTALL_SSH_KEY" in constants
    assert "os.linux.ubuntu.24.install_ssh_key" in constants
    assert "os.linux_ubuntu_24.install_ssh_key" in constants


def test_install_ssh_key_has_normalizer_branch_in_jobs() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "LINUX_INSTALL_SSH_KEY" in jobs
    assert "_normalize_ssh_install_key_execution" in jobs


def test_install_ssh_key_normalizer_strips_comment_before_forwarding() -> None:
    jobs = read("netbox_rpc/jobs.py")
    # Comment is stripped by splitting on whitespace and rejoining first two fields
    assert "split(None, 2)" in jobs
    assert 'key_parts[:2]' in jobs


def test_install_ssh_key_normalizer_validates_username_with_posix_regex() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "_POSIX_USERNAME_RE" in jobs
    assert "fullmatch" in jobs


def test_install_ssh_key_migration_depends_on_netbox_nms_user_ssh_key() -> None:
    migration = read("netbox_rpc/migrations/0006_seed_ssh_install_procedure.py")
    assert "netbox_nms" in migration
    assert "0029_user_ssh_key" in migration
    assert "from netbox_rpc" not in migration


def test_ssh_key_procedure_seeded_targets_device_and_vm() -> None:
    migration = read("netbox_rpc/migrations/0006_seed_ssh_install_procedure.py")
    assert '"dcim.device"' in migration
    assert '"virtualization.virtualmachine"' in migration
