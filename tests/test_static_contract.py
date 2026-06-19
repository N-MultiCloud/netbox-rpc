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


# ---------------------------------------------------------------------------
# LLM Agent Safety Guardrails — security invariants
# ---------------------------------------------------------------------------


def test_mellanox_procedures_are_approval_required_and_destructive() -> None:
    """MELLANOX_PROCEDURES must always have approval_required=True and effect='destructive'.

    This is a load-bearing invariant: it ensures that any autonomous LLM agent
    dispatching an RPCExecution is blocked at the API layer unless a human
    operator has explicitly granted the approve_rpcprocedure permission AND the
    procedure has been manually approved in the session.
    """
    constants = read("netbox_rpc/constants.py")
    # The MELLANOX_PROCEDURES tuple must exist and contain exactly one entry
    assert "MELLANOX_PROCEDURES" in constants
    # Both safety flags must appear inside the constants file (in the procedure dict)
    assert '"approval_required": True' in constants or "'approval_required': True" in constants
    assert '"effect": "destructive"' in constants or "'effect': 'destructive'" in constants
    # The procedure name must reference Proxmox
    assert "os.linux.proxmox.convert_mellanox_nic_to_ethernet" in constants
    assert "netbox_proxbox.proxmoxendpoint" in constants


def test_mellanox_normalizer_uses_function_local_import() -> None:
    """The Mellanox normalizer must import resolve_proxmox_endpoint_ssh inside the
    function body, not at module level.

    A module-level import would make the entire jobs module fail to load when
    an older netbox-nms release does not expose the proxmox_ssh submodule.
    Keeping the import function-local means only a live Mellanox execution triggers
    the ImportError, and the error is surfaced with a descriptive RPCExecutionError
    rather than a silent import failure at Django startup.
    """
    jobs = read("netbox_rpc/jobs.py")
    # The import must appear inside the normalizer function (indented), not at the top
    assert "from netbox_nms.proxmox_ssh import resolve_proxmox_endpoint_ssh" in jobs
    # The comment describing the function-local rationale must be present
    assert "function-local" in jobs
    # The import must NOT appear at module top-level (no leading indent on the import)
    for line in jobs.splitlines():
        if "from netbox_nms.proxmox_ssh import resolve_proxmox_endpoint_ssh" in line:
            # The line must be indented (inside a function)
            assert line.startswith("    "), (
                "resolve_proxmox_endpoint_ssh import must be inside a function (indented), "
                "not at module level"
            )


def test_agents_md_contains_llm_agent_safety_guardrails() -> None:
    """AGENTS.md must document the LLM Agent Safety Guardrails for destructive procedures."""
    agents = read("AGENTS.md")
    assert "LLM Agent Safety Guardrails" in agents
    assert "approval_required" in agents
    assert "destructive" in agents
    assert "convert_mellanox_nic_to_ethernet" in agents


# ---------------------------------------------------------------------------
# netbox-packer integration (issue #69) — one-way soft dependency contract
# ---------------------------------------------------------------------------

_PACKER_PROCEDURE_NAMES = (
    "packer.vm.test_ssh_connectivity",
    "packer.vm.check_agent_running",
    "packer.vm.verify_services",
    "packer.vm.collect_info",
)


def test_packer_procedure_catalog_names_are_seeded() -> None:
    """All four read-only packer.vm.* procedures must be declared in constants and seeded."""
    constants = read("netbox_rpc/constants.py")
    migration = read("netbox_rpc/migrations/0018_seed_packer_procedures.py")

    assert "PACKER_PROCEDURES" in constants
    assert "PACKER_PROCEDURE_NAMES" in constants
    for name in _PACKER_PROCEDURE_NAMES:
        assert name in constants, f"{name} missing from constants.py"
        assert name in migration, f"{name} missing from migration 0018"


def test_packer_procedures_are_read_only_and_target_packertemplate() -> None:
    """Packer procedures must be read-only and target the lowercase PackerTemplate label."""
    constants = read("netbox_rpc/constants.py")
    migration = read("netbox_rpc/migrations/0018_seed_packer_procedures.py")

    # Lowercase content-type label is required for target_model_label matching
    # and the /procedures/available/?target_type= filter used by the nms UI.
    assert "netbox_packer.packertemplate" in constants
    assert "netbox_packer.packertemplate" in migration
    # The capitalized model name must NOT be used as a target label.
    assert "netbox_packer.PackerTemplate" not in constants
    assert "netbox_packer.PackerTemplate" not in migration
    # All packer procedures are read-only with no approval gate.
    assert '"effect": "destructive"' not in migration
    assert '"approval_required": True' not in migration


def test_packer_normalizer_lazy_imports_netbox_packer() -> None:
    """packer_normalizer.py must guard the netbox_packer import with try/except ImportError."""
    normalizer = read("netbox_rpc/packer_normalizer.py")
    assert "try:" in normalizer
    assert "from netbox_packer.models import PackerTemplate" in normalizer
    assert "except ImportError" in normalizer
    assert "RPC_PACKER_PLUGIN_MISSING" in normalizer
    # The lazy import must live inside the normalizer function (indented).
    for line in normalizer.splitlines():
        if "from netbox_packer.models import PackerTemplate" in line:
            assert line.startswith("    "), (
                "netbox_packer import must be function-local (indented), not module-level"
            )


def test_jobs_does_not_import_netbox_packer_at_module_level() -> None:
    """jobs.py must not import netbox_packer at top level; only the function-local
    packer_normalizer dispatch may reference it."""
    jobs = read("netbox_rpc/jobs.py")
    # jobs.py must reach the packer normalizer lazily (function-local import).
    assert "from .packer_normalizer import normalize_packer_vm_execution" in jobs
    assert "PACKER_PROCEDURE_NAMES" in jobs
    # jobs.py must never import netbox_packer directly.
    assert "import netbox_packer" not in jobs
    assert "from netbox_packer" not in jobs
    # The packer_normalizer import must be indented (inside the dispatch function).
    for line in jobs.splitlines():
        if "from .packer_normalizer import normalize_packer_vm_execution" in line:
            assert line.startswith("    "), (
                "packer_normalizer import must be function-local (indented), not module-level"
            )


def test_netbox_packer_does_not_reference_netbox_rpc() -> None:
    """Hard constraint: netbox-packer MUST NOT reference netbox-rpc in any way.

    netbox-packer is an open-source plugin; netbox-rpc is proprietary. The
    dependency is strictly one-way. When the sibling netbox-packer checkout is
    available (it is in the local workspace and the integration CI stack), assert
    that neither its pyproject.toml nor any Python source mentions netbox-rpc.
    Skips gracefully when the sibling source is not present (unit-only CI).
    """
    import os

    candidates = [
        os.environ.get("NETBOX_PACKER_SRC"),
        str(ROOT.parent / "netbox-packer"),
        str(ROOT.parent.parent / "netbox-packer"),
    ]
    packer_root = next(
        (Path(c) for c in candidates if c and (Path(c) / "pyproject.toml").exists()),
        None,
    )
    if packer_root is None:
        import pytest

        pytest.skip("netbox-packer sibling source not available; skipping cross-repo check")

    pyproject = (packer_root / "pyproject.toml").read_text(encoding="utf-8")
    assert "netbox-rpc" not in pyproject
    assert "netbox_rpc" not in pyproject

    for py_file in (packer_root / "netbox_packer").rglob("*.py"):
        src = py_file.read_text(encoding="utf-8")
        assert "netbox_rpc" not in src, f"{py_file} references netbox_rpc"
        assert "netbox-rpc" not in src, f"{py_file} references netbox-rpc"
