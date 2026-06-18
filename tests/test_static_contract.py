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


def test_dell_os10_procedure_catalog_names_are_seeded() -> None:
    constants = read("netbox_rpc/constants.py")
    migration = read("netbox_rpc/migrations/0009_seed_dell_os10_procedures.py")

    assert "DELL_OS10_S5232F_PROCEDURES" in constants
    for name in (
        "network.device.dell_os10.s5232f_on.bootstrap_restconf",
        "network.device.dell_os10.s5232f_on.show_version",
        "network.device.dell_os10.s5232f_on.set_interface_description",
        "network.device.dell_os10.s5232f_on.set_vlan_description",
        "network.device.dell_os10.s5232f_on.write_memory",
    ):
        assert name in constants
        assert name in migration
    assert "network.dell_os10_s5232f_on.bootstrap_restconf" in constants
    assert "from netbox_rpc" not in migration
    assert "commands" not in migration


def test_execution_job_delegates_to_nms_backend() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "get_backend" in jobs
    assert "/rpc/executions/{execution.pk}/run" in jobs
    assert "normalize_execution_params" in jobs
    assert "RPCLinuxServiceAllowlist" in jobs


def test_execution_jobs_use_explicit_execution_pk_not_attached_object() -> None:
    views = read("netbox_rpc/api/views.py")
    jobs = read("netbox_rpc/jobs.py")
    assert "instance=execution" not in views
    assert "execution_pk=execution.pk" in views
    assert 'data["execution_pk"]' in jobs
    assert "def _get_execution(self, execution_pk:" in jobs
    assert "self.job.object_id" in jobs
    assert "Legacy fallback" in jobs


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


def test_create_marks_execution_failed_when_enqueue_fails() -> None:
    views = read("netbox_rpc/api/views.py")

    assert "def _mark_enqueue_failed(execution: models.RPCExecution) -> None:" in views
    helper_start = views.index("def _mark_enqueue_failed")
    helper_end = views.index("\n\n    def create", helper_start)
    helper = views[helper_start:helper_end]

    assert "execution.status = models.RPCExecution.STATUS_FAILED" in helper
    assert 'execution.error_code = "RPC_ENQUEUE_FAILED"' in helper
    assert "Check RQ/Redis connectivity." in helper
    assert 'update_fields=["status", "error_code", "error_message"]' in helper

    create_start = views.index("def create")
    create_end = views.index("\n\n    @extend_schema", create_start)
    create = views[create_start:create_end]
    assert "except Exception:" in create
    assert "self._mark_enqueue_failed(execution)" in create
    assert "raise" in create


def test_edit_forms_receive_request_context_for_security_policy() -> None:
    views = read("netbox_rpc/views.py")
    forms = read("netbox_rpc/forms.py")

    assert "class RequestAwareObjectEditView" in views
    assert "setattr(obj, forms.REQUEST_ATTR, request)" in views
    assert "class RPCProcedureEditView(RequestAwareObjectEditView)" in views
    assert "class RPCLinuxServiceAllowlistEditView(RequestAwareObjectEditView)" in views
    assert 'REQUEST_ATTR = "_netbox_rpc_request"' in forms


def test_allowlist_ssh_credentials_are_scoped_to_request_user() -> None:
    forms = read("netbox_rpc/forms.py")

    assert "DeviceCredential.objects.all()" not in forms
    assert 'DeviceCredential.objects.restrict(user, "view")' in forms
    assert "DeviceCredential.objects.none()" in forms


def test_approval_required_downgrade_requires_approve_permission() -> None:
    forms = read("netbox_rpc/forms.py")

    assert 'cleaned_data.get("approval_required") is not False' in forms
    assert 'user.has_perm("netbox_rpc.approve_rpcprocedure")' in forms
    assert "can disable " in forms
    assert "approval for an existing RPC procedure" in forms


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
    assert "key_parts[:2]" in jobs


def test_install_ssh_key_normalizer_validates_username_with_posix_regex() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "_POSIX_USERNAME_RE" in jobs
    assert "fullmatch" in jobs


def test_dell_os10_normalizer_branches_are_registered() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "DELL_OS10_S5232F_BOOTSTRAP_RESTCONF" in jobs
    assert "_normalize_dell_os10_bootstrap_execution" in jobs
    assert "_normalize_dell_os10_simple_execution" in jobs
    assert "_DELL_OS10_INTERFACE_RE" in jobs
    assert "description_sha256" in jobs


def test_install_ssh_key_migration_depends_on_netbox_nms_user_ssh_key() -> None:
    migration = read("netbox_rpc/migrations/0006_seed_ssh_install_procedure.py")
    assert "netbox_nms" in migration
    assert "0029_user_ssh_key" in migration
    assert "from netbox_rpc" not in migration


def test_ssh_key_procedure_seeded_targets_device_and_vm() -> None:
    migration = read("netbox_rpc/migrations/0006_seed_ssh_install_procedure.py")
    assert '"dcim.device"' in migration
    assert '"virtualization.virtualmachine"' in migration


def test_dell_os10_vlt_procedure_catalog_names_are_seeded() -> None:
    constants = read("netbox_rpc/constants.py")
    migration = read("netbox_rpc/migrations/0011_seed_dell_os10_vlt_procedures.py")

    for name in (
        "network.device.dell_os10.s5232f_on.show_vlt",
        "network.device.dell_os10.s5232f_on.configure_vlt_domain",
        "network.device.dell_os10.s5232f_on.configure_vlt_peer",
    ):
        assert name in constants
        assert name in migration
    assert "network.dell_os10_s5232f_on.show_vlt" in constants
    assert "from netbox_rpc" not in migration


def test_dell_os10_vlt_normalizer_branches_are_registered() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "DELL_OS10_S5232F_SHOW_VLT" in jobs
    assert "DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN" in jobs
    assert "DELL_OS10_S5232F_CONFIGURE_VLT_PEER" in jobs
    assert "_DELL_OS10_IP_RE" in jobs
    assert "_DELL_OS10_MAC_RE" in jobs
    assert "backup_destination" in jobs
    assert "vlt_mac" in jobs
