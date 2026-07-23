import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_constants() -> dict:
    return runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))


def test_plugin_uses_rpc_base_url_without_required_netbox_nms() -> None:
    src = read("netbox_rpc/__init__.py")
    assert 'base_url = "rpc"' in src
    assert "required_plugins" not in src
    assert "Audited RPC procedure catalog & execution framework for NetBox" in src


def test_backend_adapter_contract_is_local_and_optional() -> None:
    backends = read("netbox_rpc/backends.py")
    models = read("netbox_rpc/models.py")
    pyproject = read("pyproject.toml")

    assert "class BackendTarget" in backends
    assert "def resolve_backend" in backends
    assert '"backend_resolver"' in backends
    assert 'import_module("netbox_nms.backend")' in backends
    assert "class RPCBackend" in models
    assert "def get_auth_headers" in models
    assert "netbox-nms" not in pyproject.split("[project.optional-dependencies]")[0]
    assert 'nms = ["netbox-nms>=0.1.8,<0.2.0"]' in pyproject


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


def test_procedure_exposes_driver_and_parser_selection_fields() -> None:
    models = read("netbox_rpc/models.py")
    # Driver/parser selection is explicit data on the procedure model, never
    # encoded inside handler_id.
    assert "transport_driver = models.CharField" in models
    assert "output_parser = models.CharField" in models
    assert "output_schema = models.JSONField" in models
    for driver in ("asyncssh", "scrapli", "netmiko", "paramiko", "napalm"):
        assert f'"{driver}"' in models
    for parser in (
        "none",
        "auto",
        "json",
        "xml",
        "jc",
        "textfsm",
        "ttp",
        "genie",
        "regex",
    ):
        assert f'"{parser}"' in models


def test_driver_fields_migration_is_additive_and_depends_on_previous() -> None:
    migration = read("netbox_rpc/migrations/0030_rpcprocedure_driver_fields.py")
    assert '"0029_seed_minecraft_stack_procedures"' in migration
    assert "AddField" in migration
    assert "transport_driver" in migration
    assert "output_parser" in migration
    assert "output_schema" in migration
    # AsyncSSH + raw-output defaults preserve legacy behaviour.
    assert 'default="asyncssh"' in migration
    assert 'default="none"' in migration


def test_pipeline_exemplar_procedures_are_seeded_by_migration_0031() -> None:
    constants = read("netbox_rpc/constants.py")
    migration = read("netbox_rpc/migrations/0031_seed_pipeline_exemplar_procedures.py")

    for constant_name in (
        "LINUX_PROXMOX_PVESH_JSON",
        "LINUX_PROXMOX_PVESH_JSON_HANDLER",
        "LINUX_COLLECT_FACTS",
        "LINUX_COLLECT_FACTS_HANDLER",
        "DELL_OS10_S5232F_SHOW_VERSION_STRUCTURED",
        "DELL_OS10_S5232F_SHOW_VERSION_STRUCTURED_HANDLER",
    ):
        assert constant_name in constants

    for procedure, handler_id in (
        ("os.linux.proxmox.pvesh_json", "os.linux.proxmox.pvesh_json"),
        ("os.linux.collect_facts", "os.linux.collect_facts"),
        (
            "network.device.dell_os10.s5232f_on.show_version_structured",
            "network.dell_os10_s5232f_on.show_version_structured",
        ),
    ):
        assert procedure in constants
        assert handler_id in constants
        assert procedure in migration
        assert handler_id in migration
    assert '"effect": "read"' in migration
    assert '"approval_required": False' in migration
    assert '"enabled": True' in migration
    assert '"target_models": _TARGET_MODELS' in migration
    assert '"dcim.device"' in migration
    assert "from netbox_rpc" not in migration


def test_pipeline_exemplar_migration_declares_driver_parser_fields() -> None:
    migration = read("netbox_rpc/migrations/0031_seed_pipeline_exemplar_procedures.py")

    assert '"0030_rpcprocedure_driver_fields"' in migration
    assert '"transport_driver": "asyncssh"' in migration
    assert '"transport_driver": "scrapli"' in migration
    for parser in (
        '"output_parser": "json"',
        '"output_parser": "jc"',
        '"output_parser": "textfsm"',
    ):
        assert parser in migration
    assert '"jc_parser": "uname"' in migration
    assert '"textfsm_template": _DELL_OS10_SHOW_VERSION_TEXTFSM' in migration
    assert "Value OS_VERSION" in migration
    assert "commands" not in migration
    assert "shell_command" not in migration
    assert "raw_command" not in migration


def test_transport_and_parsing_selection_docs_are_present() -> None:
    guide = read("docs/transport-and-parsing-selection.md")
    readme = read("README.md")
    agents = read("AGENTS.md")
    claude = read("CLAUDE.md")

    assert "Transport-driver and output-parser selection" in guide
    assert "Transport-driver decision matrix" in guide
    assert "Output-parser decision ladder" in guide
    assert "Production availability" in guide
    assert "MUST NOT assemble, store, or accept free-text shell" in guide
    assert "Deploy nms-backend first" in guide
    for content in (readme, agents, claude):
        assert "docs/transport-and-parsing-selection.md" in content


def test_rpc_generated_core_jobs_docs_are_present() -> None:
    guide = read("docs/rpc-generated-core-jobs.md")
    readme = read("README.md")
    agents = read("AGENTS.md")
    architecture = read("docs/architecture.md")

    # The guide must explain where the command, output, and timing live.
    assert "Reading a netbox-rpc-generated NetBox core job" in guide
    assert "result.steps[].command" in guide
    assert "result.steps[].stdout" in guide
    assert "*.step.result" in guide
    # The core-job <-> execution link and the sanctioned read path.
    assert "job_id" in guide
    assert "rpc executions get" in guide
    assert "nms rpc events" in guide
    # The worked example must stay anchored to a concrete core job / execution.
    assert "core job 555" in guide
    # The guide must be cross-linked from the surfaces that point to it.
    for content in (readme, agents, architecture):
        assert "rpc-generated-core-jobs.md" in content


def test_normalizer_centrally_threads_driver_selection() -> None:
    normalization = read("netbox_rpc/domain/normalization.py")
    jobs = read("netbox_rpc/jobs.py")
    # The driver/parser routing is injected once in a wrapper, not per branch.
    assert "def _apply_driver_pipeline_overrides" in normalization
    assert "def _dispatch_normalize_execution_params" in normalization
    assert '_DEFAULT_TRANSPORT_DRIVER = "asyncssh"' in normalization
    assert '_DEFAULT_OUTPUT_PARSER = "none"' in normalization
    assert "_apply_driver_pipeline_overrides" in jobs
    assert "_dispatch_normalize_execution_params" in jobs


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


def test_execution_job_delegates_to_resolved_backend_target() -> None:
    jobs = read("netbox_rpc/jobs.py")
    command_handlers = read("netbox_rpc/application/command_handlers.py")
    assert "resolve_backend" in command_handlers
    assert "BackendTarget" in jobs
    assert "/rpc/executions/{execution.pk}/run" in jobs
    assert "normalize_execution_params" in command_handlers
    assert "RPCLinuxServiceAllowlist" in jobs


def test_execution_jobs_use_explicit_execution_pk_not_attached_object() -> None:
    views = read("netbox_rpc/api/views.py")
    command_handlers = read("netbox_rpc/application/command_handlers.py")
    jobs = read("netbox_rpc/jobs.py")
    assert "instance=execution" not in views
    assert "execution_pk=execution.pk" in command_handlers
    assert 'data["execution_pk"]' in jobs
    assert "def _get_execution(self, execution_pk:" in jobs
    assert "self.job.object_id" in jobs
    assert "Legacy fallback" in jobs


def test_api_routes_are_registered() -> None:
    urls = read("netbox_rpc/api/urls.py")
    assert 'router.register("backends"' in urls
    assert 'router.register("procedures"' in urls
    assert 'router.register("linux-service-allowlist"' in urls
    assert 'router.register("executions"' in urls
    assert 'router.register("execution-events"' in urls


def test_create_guards_enabled_and_approval_and_params_schema() -> None:
    command_handlers = read("netbox_rpc/application/command_handlers.py")
    assert "procedure.enabled" in command_handlers
    assert "procedure.approval_required" in command_handlers
    assert "jsonschema.validate" in command_handlers


def test_create_marks_execution_failed_when_enqueue_fails() -> None:
    command_handlers = read("netbox_rpc/application/command_handlers.py")

    create_start = command_handlers.index("def create_execution")
    create_end = command_handlers.index("\n\n\ndef run_execution", create_start)
    create = command_handlers[create_start:create_end]
    assert "except Exception:" in create
    assert "mark_execution_failed" in create
    assert '"RPC_ENQUEUE_FAILED"' in create
    assert "Check RQ/Redis connectivity." in create
    assert '"ExecutionEnqueueFailed"' in create
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
    assert "forms.IntegerField" in forms
    assert "clean_ssh_credential_override" in forms


def test_netbox_nms_imports_are_not_module_level_for_standalone_boot() -> None:
    serializers = read("netbox_rpc/api/serializers.py")
    forms = read("netbox_rpc/forms.py")
    jobs = read("netbox_rpc/jobs.py")

    assert "from netbox_nms" not in serializers
    assert "from netbox_nms.backend" not in jobs
    for line in forms.splitlines():
        if "from netbox_nms.models import DeviceCredential" in line:
            assert line.startswith("            ")


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
    event_store = read("netbox_rpc/event_store.py")
    assert "IntegrityError" in event_store
    assert "sequence collision exhausted retries" in event_store
    assert "Event dropped" not in event_store
    assert "raise RPCEventStoreError" in event_store
    assert "payload_hash" in event_store
    assert "redact_event_data" in event_store
    assert "transaction.atomic" in event_store


def test_execution_event_api_is_read_only_and_hashed() -> None:
    models = read("netbox_rpc/models.py")
    migration = read("netbox_rpc/migrations/0031_rpcexecutionevent_payload_hash.py")
    serializers = read("netbox_rpc/api/serializers.py")
    views = read("netbox_rpc/api/views.py")

    assert "payload_hash = models.CharField" in models
    assert "def hash_payload" in models
    assert "RPCExecutionEvent rows are append-only" in models
    assert "not self._state.adding" in models
    assert "payload_hash" in migration
    assert "backfill_payload_hash" in migration
    assert "netbox_rpc_rpcexecutionevent_no_update" in migration
    assert "netbox_rpc_rpcexecutionevent_no_delete" in migration
    assert '"payload_hash"' in serializers
    assert "read_only_fields = fields" in serializers
    assert "NetBoxReadOnlyModelViewSet" in views
    assert "class RPCExecutionEventViewSet(NetBoxReadOnlyModelViewSet)" in views


def test_execution_es_cqrs_contract_is_explicit() -> None:
    events = read("netbox_rpc/domain/events.py")
    projection = read("netbox_rpc/domain/projection.py")
    event_store = read("netbox_rpc/event_store.py")
    views = read("netbox_rpc/api/views.py")

    for event_name in (
        "ExecutionQueued",
        "ExecutionStarted",
        "ParametersNormalized",
        "JobEnqueued",
        "BackendEventRecorded",
        "ExecutionSucceeded",
        "ExecutionFailed",
        "ExecutionEnqueueFailed",
        "ExecutionCancelled",
    ):
        assert f"class {event_name}" in events
    assert "EVENT_TYPES" in events
    assert "def from_record" in events
    assert "class ProjectionState" in projection
    assert "def apply" in projection
    assert "def rebuild" in projection
    assert "def rebuild_projection" in event_store
    assert "def reproject" in event_store

    execution_view_start = views.index("class RPCExecutionViewSet")
    execution_view_end = views.index("\n\nclass RPCExecutionEventViewSet")
    execution_view = views[execution_view_start:execution_view_end]
    assert "http_method_names" in execution_view
    assert '"put"' not in execution_view
    assert '"patch"' not in execution_view
    # The execution aggregate and its append-only event ledger are immutable: no
    # arbitrary edits (put/patch) and no deletion (a cascade would hit the
    # append-only trigger). Writes happen only through commands (create/cancel).
    assert '"delete"' not in execution_view
    assert "def cancel" in execution_view


def test_execution_state_changes_go_through_event_store() -> None:
    jobs = read("netbox_rpc/jobs.py")
    views = read("netbox_rpc/api/views.py")
    command_handlers = read("netbox_rpc/application/command_handlers.py")
    event_store = read("netbox_rpc/event_store.py")

    assert "from .event_store import" in jobs
    assert "RPCExecutionAggregate" in command_handlers
    assert "aggregate.normalize" in command_handlers
    assert "aggregate.record_backend_response" in command_handlers
    assert "aggregate.fail" in command_handlers
    # The race-critical QUEUED transitions (start vs cancel) run under a row lock.
    assert "_transition_locked" in command_handlers
    assert "select_for_update" in command_handlers
    assert "agg.start()" in command_handlers
    assert "record_backend_response" in jobs
    assert "mark_execution_running" in jobs
    assert "mark_execution_failed" in jobs
    assert "create_execution" in views
    assert "cancel_execution" in views
    assert "def append_execution_event" in event_store
    assert "def record_backend_response" in event_store
    assert "ExecutionSucceeded" in event_store
    assert "ExecutionFailed" in event_store
    assert "record_execution_queued" in event_store
    assert "record_execution_enqueued" in event_store
    assert "record_execution_cancelled" in event_store


def test_call_backend_handles_non_dict_json() -> None:
    jobs = read("netbox_rpc/jobs.py")
    assert "not isinstance(data, dict)" in jobs


def test_install_ssh_key_procedure_is_defined_in_constants() -> None:
    constants = read("netbox_rpc/constants.py")
    assert "LINUX_INSTALL_SSH_KEY" in constants
    assert "os.linux.ubuntu.24.install_ssh_key" in constants
    assert "os.linux_ubuntu_24.install_ssh_key" in constants


def test_install_ssh_key_has_normalizer_branch() -> None:
    normalization = read("netbox_rpc/domain/normalization.py")
    assert "LINUX_INSTALL_SSH_KEY" in normalization
    assert "_normalize_ssh_install_key_execution" in normalization


def test_install_ssh_key_normalizer_strips_comment_before_forwarding() -> None:
    normalization = read("netbox_rpc/domain/normalization.py")
    # Comment is stripped by splitting on whitespace and rejoining first two fields
    assert "split(None, 2)" in normalization
    assert "key_parts[:2]" in normalization


def test_install_ssh_key_normalizer_validates_username_with_posix_regex() -> None:
    normalization = read("netbox_rpc/domain/normalization.py")
    assert "_POSIX_USERNAME_RE" in normalization
    assert "fullmatch" in normalization


def test_dell_os10_normalizer_branches_are_registered() -> None:
    normalization = read("netbox_rpc/domain/normalization.py")
    assert "DELL_OS10_S5232F_BOOTSTRAP_RESTCONF" in normalization
    assert "_normalize_dell_os10_bootstrap_execution" in normalization
    assert "_normalize_dell_os10_simple_execution" in normalization
    assert "_DELL_OS10_INTERFACE_RE" in normalization
    assert "description_sha256" in normalization


def test_install_ssh_key_migration_has_no_netbox_nms_dependency() -> None:
    migration = read("netbox_rpc/migrations/0006_seed_ssh_install_procedure.py")
    assert "netbox_nms" not in migration
    assert "0029_user_ssh_key" not in migration
    assert "from netbox_rpc" not in migration


def test_decoupling_migrations_converge_fresh_and_existing_databases() -> None:
    initial = read("netbox_rpc/migrations/0001_initial.py")
    allowlist = read("netbox_rpc/migrations/0005_allowlist_ssh_credential_override.py")
    merge = read(
        "netbox_rpc/migrations/0032_merge_payload_hash_and_pipeline_exemplars.py"
    )
    backend = read("netbox_rpc/migrations/0033_rpcbackend.py")
    drop_fks = read("netbox_rpc/migrations/0034_decouple_netbox_nms_fk_constraints.py")

    assert '"netbox_nms"' not in initial
    assert '"netbox_nms"' not in allowlist
    assert "models.PositiveBigIntegerField" in initial
    assert 'db_column="backend_id"' in initial
    assert 'db_column="ssh_credential_override_id"' in allowlist
    assert '"0031_rpcexecutionevent_payload_hash"' in merge
    assert '"0031_seed_pipeline_exemplar_procedures"' in merge
    assert "CreateModel" in backend
    assert 'name="RPCBackend"' in backend
    assert "SeparateDatabaseAndState" in drop_fks
    assert "state_operations=[]" in drop_fks
    assert "DROP CONSTRAINT IF EXISTS" in drop_fks
    assert "netbox_rpc_rpcexecution" in drop_fks
    assert "ssh_credential_override_id" in drop_fks


def test_ssh_key_procedure_seeded_targets_device_and_vm() -> None:
    migration = read("netbox_rpc/migrations/0006_seed_ssh_install_procedure.py")
    assert '"dcim.device"' in migration
    assert '"virtualization.virtualmachine"' in migration


def test_dns_host_procedure_catalog_names_are_seeded() -> None:
    constants = read("netbox_rpc/constants.py")
    migration = read("netbox_rpc/migrations/0027_seed_dns_host_procedures.py")

    assert "DNS_HOST_PROCEDURES" in constants
    for name in (
        "os.linux.dns_host.deploy_dns_stack",
        "os.linux.dns_host.status_dns_stack",
    ):
        assert name in constants
        assert name in migration
    assert "from netbox_rpc" not in migration
    assert "arbitrary_command" not in constants
    assert "shell_command" not in constants


def test_dns_host_migration_depends_on_0026() -> None:
    migration = read("netbox_rpc/migrations/0027_seed_dns_host_procedures.py")
    assert '"0026_merge_packer_and_proxmox"' in migration


def test_dns_host_procedures_have_expected_effect_and_approval() -> None:
    migration = read("netbox_rpc/migrations/0027_seed_dns_host_procedures.py")
    deploy_start = migration.index('"name": "os.linux.dns_host.deploy_dns_stack"')
    status_start = migration.index('"name": "os.linux.dns_host.status_dns_stack"')
    deploy_block = migration[deploy_start:status_start]
    status_block = migration[status_start:]

    assert '"handler_id": "os.linux.dns_host.deploy_dns_stack"' in deploy_block
    assert '"target_models": []' in deploy_block
    assert '"effect": "write"' in deploy_block
    assert '"timeout_seconds": 180' in deploy_block
    assert '"approval_required": True' in deploy_block

    assert '"handler_id": "os.linux.dns_host.status_dns_stack"' in status_block
    assert '"target_models": []' in status_block
    assert '"effect": "read"' in status_block
    assert '"timeout_seconds": 60' in status_block
    assert '"approval_required": False' in status_block


def test_dns_host_normalizer_branches_are_registered() -> None:
    normalization = read("netbox_rpc/domain/normalization.py")
    assert "DNS_HOST_DEPLOY_PROCEDURE" in normalization
    assert "DNS_HOST_STATUS_PROCEDURE" in normalization
    assert "_normalize_dns_host_deploy_execution" in normalization
    assert "_normalize_dns_host_status_execution" in normalization
    assert "rpc_ssh_known_hosts_entry" in normalization


def test_linux_agent_install_procedures_are_seeded() -> None:
    constants = read("netbox_rpc/constants.py")
    migration = read(
        "netbox_rpc/migrations/0028_seed_linux_agent_install_procedures.py"
    )

    for procedure, handler_id in (
        (
            "os.linux.ubuntu.24.install_qemu_guest_agent",
            "os.linux_ubuntu_24.install_qemu_guest_agent",
        ),
        (
            "os.linux.ubuntu.24.install_zabbix_agent2",
            "os.linux_ubuntu_24.install_zabbix_agent2",
        ),
    ):
        assert procedure in constants
        assert procedure in migration
        assert handler_id in constants
        assert handler_id in migration
    assert '"effect": "write"' in migration
    assert '"approval_required": False' in migration
    assert '"enabled": True' in migration
    assert '"version": 1' in migration
    assert '"timeout_seconds": 300' in migration
    assert '"timeout_seconds": 600' in migration
    assert '"dcim.device"' in migration
    assert '"virtualization.virtualmachine"' in migration
    assert "from netbox_rpc" not in migration
    assert "0027_seed_dns_host_procedures" in migration


def test_linux_agent_install_params_schema_is_narrow() -> None:
    migration = read(
        "netbox_rpc/migrations/0028_seed_linux_agent_install_procedures.py"
    )
    for key in (
        "rpc_ssh_credential_pk",
        "rpc_ssh_host",
        "rpc_ssh_port",
        "rpc_ssh_known_hosts_entry",
        "rpc_ssh_strict_host_key_checking",
    ):
        assert key in migration
    assert '"additionalProperties": False' in migration
    assert '"zabbix_server"' in migration
    assert '"default": "zabbix.example.com"' in migration
    assert '"maxLength": 253' in migration
    assert "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?" in migration
    assert "apt" not in migration.lower()
    assert "command" not in migration.lower()


_MINECRAFT_STACK_PROCEDURES = (
    "services.minecraft.plugin.install_url",
    "services.minecraft.viaversion.install",
    "services.minecraft.papermc.install",
    "services.pterodactyl.wings.status",
    "services.pterodactyl.wings.logs",
    "services.pterodactyl.wings.restart",
)


def test_minecraft_stack_procedure_catalog_guardrails() -> None:
    constants = load_constants()
    procedures = constants["MINECRAFT_STACK_PROCEDURES"]
    by_name = {procedure["name"]: procedure for procedure in procedures}

    assert tuple(by_name) == _MINECRAFT_STACK_PROCEDURES
    forbidden_param_names = {
        "command",
        "commands",
        "shell_command",
        "raw_command",
        "command_text",
        "script",
        "argv",
        "args",
        "destination_path",
    }

    for name, procedure in by_name.items():
        assert procedure["handler_id"] == name
        assert procedure["target_models"] == [
            "dcim.device",
            "virtualization.virtualmachine",
        ]
        schema = procedure["params_schema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert forbidden_param_names.isdisjoint(schema["properties"])

    assert by_name["services.minecraft.plugin.install_url"]["effect"] == "write"
    assert (
        by_name["services.minecraft.plugin.install_url"]["params_schema"]["properties"][
            "source_url"
        ]["pattern"]
        == "^https?://"
    )
    assert by_name["services.minecraft.viaversion.install"]["params_schema"][
        "properties"
    ]["plugins"]["items"]["enum"] == ["viaversion", "viabackwards", "viarewind"]
    assert by_name["services.minecraft.papermc.install"]["params_schema"]["properties"][
        "project"
    ]["enum"] == ["paper", "folia", "velocity"]
    assert by_name["services.pterodactyl.wings.status"]["effect"] == "read"
    assert by_name["services.pterodactyl.wings.logs"]["effect"] == "read"
    assert by_name["services.pterodactyl.wings.restart"]["effect"] == "write"
    assert by_name["services.pterodactyl.wings.restart"]["approval_required"] is True


def test_minecraft_stack_migration_matches_constants_and_stays_data_only() -> None:
    constants = read("netbox_rpc/constants.py")
    migration = read("netbox_rpc/migrations/0029_seed_minecraft_stack_procedures.py")

    for name in _MINECRAFT_STACK_PROCEDURES:
        assert name in constants
        assert name in migration
    assert "from netbox_rpc" not in migration
    assert '"additionalProperties": False' in migration
    for forbidden in (
        "shell_command",
        "raw_command",
        "command_text",
        "arbitrary_command",
        "subprocess",
        "os.system",
        "eval(",
    ):
        assert forbidden not in constants
        assert forbidden not in migration


def test_minecraft_stack_guardrail_docs_are_present() -> None:
    guide = read("docs/MINECRAFT_STACK_RPC.md")
    readme = read("README.md")
    agents = read("AGENTS.md")

    for content in (guide, readme, agents):
        assert "services.minecraft.plugin.install_url" in content
        assert "services.minecraft.viaversion.install" in content
        assert "services.minecraft.papermc.install" in content
        assert "services.pterodactyl.wings.restart" in content
    for token in (
        "additionalProperties: False",
        "source_url_sha256",
        "wings.service",
        "raw_command",
        "DeviceService",
    ):
        assert token in guide


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
    normalization = read("netbox_rpc/domain/normalization.py")
    assert "DELL_OS10_S5232F_SHOW_VLT" in normalization
    assert "DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN" in normalization
    assert "DELL_OS10_S5232F_CONFIGURE_VLT_PEER" in normalization
    assert "_DELL_OS10_IP_RE" in normalization
    assert "_DELL_OS10_MAC_RE" in normalization
    assert "backup_destination" in normalization
    assert "vlt_mac" in normalization


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
    assert (
        '"approval_required": True' in constants
        or "'approval_required': True" in constants
    )
    assert (
        '"effect": "destructive"' in constants or "'effect': 'destructive'" in constants
    )
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
    normalization = read("netbox_rpc/domain/normalization.py")
    # The import must appear inside the normalizer function (indented), not at the top
    assert (
        "from netbox_nms.proxmox_ssh import resolve_proxmox_endpoint_ssh"
        in normalization
    )
    # The comment describing the function-local rationale must be present
    assert "function-local" in normalization
    # The import must NOT appear at module top-level (no leading indent on the import)
    for line in normalization.splitlines():
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
    """normalization.py must not import netbox_packer at top level; only the function-local
    packer_normalizer dispatch may reference it."""
    normalization = read("netbox_rpc/domain/normalization.py")
    # normalization.py must reach the packer normalizer lazily (function-local import).
    assert (
        "from ..packer_normalizer import normalize_packer_vm_execution" in normalization
    )
    assert "PACKER_PROCEDURE_NAMES" in normalization
    # normalization.py must never import netbox_packer directly.
    assert "import netbox_packer" not in normalization
    assert "from netbox_packer" not in normalization
    # The packer_normalizer import must be indented (inside the dispatch function).
    for line in normalization.splitlines():
        if "from ..packer_normalizer import normalize_packer_vm_execution" in line:
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

        pytest.skip(
            "netbox-packer sibling source not available; skipping cross-repo check"
        )

    pyproject = (packer_root / "pyproject.toml").read_text(encoding="utf-8")
    assert "netbox-rpc" not in pyproject
    assert "netbox_rpc" not in pyproject

    for py_file in (packer_root / "netbox_packer").rglob("*.py"):
        src = py_file.read_text(encoding="utf-8")
        assert "netbox_rpc" not in src, f"{py_file} references netbox_rpc"
        assert "netbox-rpc" not in src, f"{py_file} references netbox-rpc"


# ---------------------------------------------------------------------------
# RPCIntent — declarative grouping of procedures (sequential/parallel modes)
# ---------------------------------------------------------------------------


def test_intent_models_are_declared() -> None:
    models = read("netbox_rpc/models.py")
    value_objects = read("netbox_rpc/domain/value_objects.py")

    assert "class RPCIntent(NetBoxModel)" in models
    assert "class RPCIntentProcedure(models.Model)" in models
    # Execution mode is single-sourced from the domain value object.
    assert "class ExecutionMode(StrEnum)" in value_objects
    assert 'SEQUENTIAL = "sequential"' in value_objects
    assert 'PARALLEL = "parallel"' in value_objects
    assert "MODE_SEQUENTIAL = ExecutionMode.SEQUENTIAL.value" in models
    assert "MODE_PARALLEL = ExecutionMode.PARALLEL.value" in models
    assert "execution_mode = models.CharField" in models
    # Grouping is an ordered M2M through the RPCIntentProcedure model.
    assert 'through="RPCIntentProcedure"' in models
    assert "sequence = models.PositiveIntegerField" in models
    assert "netbox_rpc_intent_unique_procedure" in models


def test_intent_migration_is_additive_and_standalone() -> None:
    migration = read("netbox_rpc/migrations/0039_rpcintent.py")

    assert '"0038_merge_rpc_procedure_commands"' in migration
    assert 'name="RPCIntent"' in migration
    assert 'name="RPCIntentProcedure"' in migration
    assert "ManyToManyField" in migration
    assert "netbox_rpc_intent_unique_procedure" in migration
    # Seed/data-free, no live imports, and no netbox_nms dependency (standalone).
    assert "from netbox_rpc" not in migration
    assert '"netbox_nms"' not in migration  # no netbox_nms migration dependency


def test_intent_api_route_is_registered() -> None:
    urls = read("netbox_rpc/api/urls.py")
    serializers = read("netbox_rpc/api/serializers.py")
    views = read("netbox_rpc/api/views.py")

    assert 'router.register("intents"' in urls
    assert "class RPCIntentSerializer" in serializers
    # procedure_ids is the ordered write channel; procedures is the read repr.
    assert "procedure_ids" in serializers
    assert "class RPCIntentViewSet" in views


def test_intent_is_reference_data_not_event_sourced() -> None:
    # RPCIntent is plain NetBox CRUD (like RPCProcedure/RPCBackend), so it is a
    # full read/write viewset — NOT the command-only, immutable execution model.
    views = read("netbox_rpc/api/views.py")
    intent_view_start = views.index("class RPCIntentViewSet")
    intent_view = views[intent_view_start : intent_view_start + 400]
    assert "NetBoxModelViewSet" in intent_view
    assert "http_method_names" not in intent_view


def test_intent_sequence_has_min_validator_and_check_constraint() -> None:
    models = read("netbox_rpc/models.py")
    migration = read(
        "netbox_rpc/migrations/0040_rpcintentprocedure_sequence_min.py"
    )
    assert "MinValueValidator(1)" in models
    assert "netbox_rpc_intentprocedure_sequence_gte_1" in models
    assert "condition=models.Q(sequence__gte=1)" in models
    # Migration depends on 0039, is data-safe (normalizes first), and adds the
    # DB check constraint.
    assert '"0039_rpcintent"' in migration
    assert "_normalize_sequences" in migration
    assert "CheckConstraint" in migration
    assert "sequence__gte=1" in migration


def test_intent_serialize_object_includes_ordered_membership() -> None:
    # Ordered through-row membership is part of the intent's serialized state so
    # reorders/membership changes appear in the ObjectChange diff.
    models = read("netbox_rpc/models.py")
    assert "def serialize_object" in models
    assert '"intent_procedures"' in models
    assert '"sequence": ip.sequence' in models


def test_plugin_and_migrations_support_netbox_4_5_8_through_4_6() -> None:
    init = read("netbox_rpc/__init__.py")
    gitea_workflow = read(".gitea/workflows/integration.yml")
    assert 'min_version = "4.5.8"' in init
    assert 'max_version = "4.6.99"' in init
    assert "\n  compatibility:\n" in gitea_workflow
    compatibility_job = gitea_workflow.split("\n  compatibility:\n", maxsplit=1)[1]
    assert "runs-on: mirror-host" in compatibility_job
    assert "fail-fast: false" in compatibility_job
    assert "NETBOX_VERSION: ${{ matrix.netbox-version }}" in compatibility_job
    assert "services:" in compatibility_job
    assert "v4.5.8" in compatibility_job
    assert "v4.6.5" in compatibility_job
    assert "if:" not in compatibility_job
    assert "soft-skip" not in compatibility_job

    migrations_dir = ROOT / "netbox_rpc" / "migrations"
    migration_sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in migrations_dir.glob("*.py")
    }
    extras_dependencies = [
        line.strip()
        for source in migration_sources.values()
        for line in source.splitlines()
        if line.strip().startswith(("('extras',", '("extras",'))
    ]
    assert len(extras_dependencies) == 4
    assert all("0134_owner" in dependency for dependency in extras_dependencies)

    for name in (
        "0007_rename_netbox_rpc_assigned_idx_netbox_rpc__assigne_c5b587_idx_and_more.py",
        "0033_rpcbackend.py",
        "0039_rpcintent.py",
        "0044_rpcpluginsettings.py",
    ):
        # extras.0134_owner is the final extras migration in NetBox 4.5.8 and
        # remains an ancestor of the 4.6 migration graph.
        assert "0134_owner" in migration_sources[name]
