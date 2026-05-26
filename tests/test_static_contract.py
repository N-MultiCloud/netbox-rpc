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


def test_event_creation_handles_integrity_error() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "IntegrityError" in jobs


def test_call_backend_handles_non_dict_json() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "not isinstance(data, dict)" in jobs
