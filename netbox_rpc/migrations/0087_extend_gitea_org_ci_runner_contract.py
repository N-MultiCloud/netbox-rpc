"""Extend both disabled Gitea runner contracts onto one durable fence epoch.

This forward migration adds the fixed ``root-python312`` trust domain, closed
operation-discriminated schemas, and the source contract shared with backend
issue #98. It also upgrades the legacy runner-registration result contract so
every participant in the canonical ``N-MultiCloud`` token fence carries the
same monotonic generation and waits the shared 1800-second safety interval.
The new lane remains activation-ineligible until
``N-MultiCloud/nmulticloud-context#411`` publishes the reviewed,
content-addressed VM416 provision-and-prove boundary. Both rows stay disabled;
the migration refuses reversal before Django could delete durable generation
history.
"""

import json

from django.db import migrations, models
from django.db.migrations.exceptions import IrreversibleError

_PROCEDURE_NAME = "service.gitea.actions_runner.provision_org_ci_runner"
_HANDLER_ID = _PROCEDURE_NAME
_LEGACY_PROCEDURE_NAME = "service.gitea.runner.register"
_TARGET_MODELS = ["virtualization.virtualmachine"]
_HOST_GENERATION_DEPENDENCY = "N-MultiCloud/nmulticloud-context#411"
_CAPABILITY_CONTRACT_SHA256 = (
    "bae186285d7e23a6bc664eb0b119e9d71ed11d5ca273f910cfef5a934420573c"
)
_SEMANTIC_CAPABILITY_SHA256 = (
    "6eec5dd6e61ada82329998e5867a2275a8e07d89340d77a89dd0a6a89a8dc41b"
)
_LEGACY_SEMANTIC_CAPABILITY_SHA256 = (
    "18f41b13f1cf6530ffb3d8f9c8cb12dc8064a3ce7aa605fac5e504e9d7c21d9f"
)
_LANES = json.loads(
    '{"root-python312":{"activation_blocker":"N-MultiCloud/nmulticloud-context#411","activation_eligible":false,"base_image_digest":"0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f","base_image_reference":"ghcr.io/astral-sh/uv:0.12.5-python3.12-trixie-slim@sha256:0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f","capacity":1,"compose_project_dir":"/opt/nmc-ci-untrusted-root-org-241","config_path":"/etc/gitea-runner/nmulticloud-org-root.yaml","container_bind_workdir":false,"container_cap_add":["CHOWN","SETUID","SETGID","FOWNER","DAC_OVERRIDE"],"container_daemon_socket_in_job":false,"container_devices":[],"container_host_ambient_capabilities":[],"container_host_effective_capabilities":[],"container_host_ipc":false,"container_host_network":false,"container_host_pid":false,"container_host_uts":false,"container_privileged":false,"container_uid0_maps_to_host_root":false,"container_valid_volumes":[],"cross_scope_state":false,"executor":"docker","fresh_container_per_job":true,"job_cap_drop_all":true,"job_network_policy":{"build":{"dns_resolvers":[],"egress":[],"network_mode":"none"},"default_action":"deny","other_egress":"deny","publisher":{"dns_required":false,"dns_resolvers":[],"host_bindings":[{"hostname":"git.nmulti.cloud","ipv4":"10.0.30.96"}],"https_origins":["https://git.nmulti.cloud:443"],"ipv4_destinations":["10.0.30.96/32"],"network_mode":"filtered","redirects":false,"tcp_ports":[443],"tls_server_names":["git.nmulti.cloud"],"tls_verify":true}},"job_no_new_privileges":true,"job_resource_limits":{"cgroup_version":2,"cpu_period_us":100000,"cpu_quota_us":200000,"cpu_weight":100,"kill_grace_seconds":10,"memory_max_bytes":4294967296,"memory_swap_max_bytes":0,"pids_max":512,"root_filesystem_read_only":true,"tmpfs":[{"options":["nodev","nosuid","noexec"],"path":"/tmp","size_bytes":1073741824},{"options":["nodev","nosuid","noexec"],"path":"/run","size_bytes":67108864}],"ulimits":{"core":{"hard":0,"soft":0},"fsize":{"hard":8589934592,"soft":8589934592},"nofile":{"hard":1024,"soft":1024},"nproc":{"hard":512,"soft":512}},"wall_clock_timeout_seconds":1800,"workspace":{"disk_quota_bytes":8589934592,"host_bind":false,"kind":"ephemeral-volume","path":"/workspace"},"writable_paths":["/workspace","/tmp","/run"]},"job_user":"0:0","jobs_mount_docker_socket":false,"management_egress_policy":"deny-except-gitea-publisher","production_egress_policy":"deny-except-gitea-publisher","prove_helper_path":null,"prove_helper_sha256":null,"provision_helper_path":null,"provision_helper_sha256":null,"python_source_sha256":"5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a","python_version":"3.12.14","rootless_user_namespace":true,"runner_cap_drop_all":true,"runner_image":null,"runner_label":"ci-untrusted-root-python312","runner_labels":["ci-untrusted-root-python312"],"runner_mounts_docker_socket":true,"runner_name":"ci-untrusted-root-nmulticloud-org-241","runner_no_new_privileges":true,"service_user":"gitea-runner-nmulticloud-org-root","service_user_login":false,"state_dir":"/var/lib/gitea-runner-nmulticloud-org-root","uv_archive_sha256":"68a509da24b06b4223a1c0175fb5eb5bc79342b76cbeff0cfe51ac3f5b17b6b2","uv_version":"0.12.5"}}'
)
_PARAMS_SCHEMA = json.loads(
    '{"additionalProperties":false,"allOf":[{"if":{"properties":{"operation":{"const":"provision"}},"required":["operation"]},"then":{"required":["registration_token_secret_ref"]}},{"if":{"properties":{"operation":{"const":"reconcile"}},"required":["operation"]},"then":{"not":{"required":["registration_token_secret_ref"]}}}],"not":{"properties":{"build_runner_image":{"const":true},"load_prebuilt_runner_image":{"const":true}},"required":["build_runner_image","load_prebuilt_runner_image"]},"properties":{"build_runner_image":{"default":true,"type":"boolean"},"force_recreate":{"default":false,"type":"boolean"},"install_docker":{"default":true,"type":"boolean"},"lane":{"description":"Selects one complete frozen runner trust domain.","enum":["root-python312"],"type":"string"},"load_prebuilt_runner_image":{"default":false,"type":"boolean"},"operation":{"enum":["provision","reconcile"],"type":"string"},"registration_token_secret_ref":{"description":"Reference to the vaulted one-time Gitea runner token.","maxLength":47,"minLength":47,"pattern":"^nms-secret:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?![\\\\s\\\\S])","type":"string"}},"required":["operation","lane"],"type":"object"}'
)
_RESULT_SCHEMA = json.loads(
    '{"additionalProperties":false,"allOf":[{"if":{"properties":{"lane":{"const":"root-python312"}},"required":["lane"]},"then":{"properties":{"activation_blocker":{"const":"N-MultiCloud/nmulticloud-context#411"},"activation_eligible":{"const":false},"base_image_digest":{"const":"0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f"},"base_image_reference":{"const":"ghcr.io/astral-sh/uv:0.12.5-python3.12-trixie-slim@sha256:0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f"},"capacity":{"const":1},"compose_project_dir":{"const":"/opt/nmc-ci-untrusted-root-org-241"},"config_path":{"const":"/etc/gitea-runner/nmulticloud-org-root.yaml"},"container_bind_workdir":{"const":false},"container_cap_add":{"const":["CHOWN","SETUID","SETGID","FOWNER","DAC_OVERRIDE"]},"container_daemon_socket_in_job":{"const":false},"container_devices":{"const":[]},"container_host_ambient_capabilities":{"const":[]},"container_host_effective_capabilities":{"const":[]},"container_host_ipc":{"const":false},"container_host_network":{"const":false},"container_host_pid":{"const":false},"container_host_uts":{"const":false},"container_privileged":{"const":false},"container_uid0_maps_to_host_root":{"const":false},"container_valid_volumes":{"const":[]},"cross_scope_state":{"const":false},"executor":{"const":"docker"},"fresh_container_per_job":{"const":true},"job_cap_drop_all":{"const":true},"job_network_policy":{"const":{"build":{"dns_resolvers":[],"egress":[],"network_mode":"none"},"default_action":"deny","other_egress":"deny","publisher":{"dns_required":false,"dns_resolvers":[],"host_bindings":[{"hostname":"git.nmulti.cloud","ipv4":"10.0.30.96"}],"https_origins":["https://git.nmulti.cloud:443"],"ipv4_destinations":["10.0.30.96/32"],"network_mode":"filtered","redirects":false,"tcp_ports":[443],"tls_server_names":["git.nmulti.cloud"],"tls_verify":true}}},"job_no_new_privileges":{"const":true},"job_resource_limits":{"const":{"cgroup_version":2,"cpu_period_us":100000,"cpu_quota_us":200000,"cpu_weight":100,"kill_grace_seconds":10,"memory_max_bytes":4294967296,"memory_swap_max_bytes":0,"pids_max":512,"root_filesystem_read_only":true,"tmpfs":[{"options":["nodev","nosuid","noexec"],"path":"/tmp","size_bytes":1073741824},{"options":["nodev","nosuid","noexec"],"path":"/run","size_bytes":67108864}],"ulimits":{"core":{"hard":0,"soft":0},"fsize":{"hard":8589934592,"soft":8589934592},"nofile":{"hard":1024,"soft":1024},"nproc":{"hard":512,"soft":512}},"wall_clock_timeout_seconds":1800,"workspace":{"disk_quota_bytes":8589934592,"host_bind":false,"kind":"ephemeral-volume","path":"/workspace"},"writable_paths":["/workspace","/tmp","/run"]}},"job_user":{"const":"0:0"},"jobs_mount_docker_socket":{"const":false},"management_egress_policy":{"const":"deny-except-gitea-publisher"},"production_egress_policy":{"const":"deny-except-gitea-publisher"},"prove_helper_path":{"const":null},"prove_helper_sha256":{"const":null},"provision_helper_path":{"const":null},"provision_helper_sha256":{"const":null},"python_source_sha256":{"const":"5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a"},"python_version":{"const":"3.12.14"},"rootless_user_namespace":{"const":true},"runner_cap_drop_all":{"const":true},"runner_image":{"const":null},"runner_label":{"const":"ci-untrusted-root-python312"},"runner_labels":{"const":["ci-untrusted-root-python312"]},"runner_mounts_docker_socket":{"const":true},"runner_name":{"const":"ci-untrusted-root-nmulticloud-org-241"},"runner_no_new_privileges":{"const":true},"scope":{"const":"nmulticloud-org-root"},"service_user":{"const":"gitea-runner-nmulticloud-org-root"},"service_user_login":{"const":false},"state_dir":{"const":"/var/lib/gitea-runner-nmulticloud-org-root"},"uv_archive_sha256":{"const":"68a509da24b06b4223a1c0175fb5eb5bc79342b76cbeff0cfe51ac3f5b17b6b2"},"uv_version":{"const":"0.12.5"}},"required":["compose_project_dir","runner_name","runner_image","runner_labels","runner_label","executor","runner_mounts_docker_socket","jobs_mount_docker_socket","runner_cap_drop_all","runner_no_new_privileges","job_user","service_user","service_user_login","state_dir","config_path","capacity","fresh_container_per_job","rootless_user_namespace","container_uid0_maps_to_host_root","container_privileged","container_host_network","container_host_pid","container_host_ipc","container_host_uts","container_bind_workdir","container_valid_volumes","container_devices","container_host_effective_capabilities","container_host_ambient_capabilities","job_cap_drop_all","job_no_new_privileges","container_cap_add","container_daemon_socket_in_job","job_network_policy","job_resource_limits","management_egress_policy","production_egress_policy","cross_scope_state","activation_eligible","activation_blocker","base_image_reference","base_image_digest","provision_helper_path","provision_helper_sha256","prove_helper_path","prove_helper_sha256","python_version","python_source_sha256","uv_version","uv_archive_sha256"]}}],"oneOf":[{"properties":{"ok":{"const":true},"operation":{"const":"provision"},"prior_token_id":{"minimum":1,"type":"integer"},"provisioned":{"const":true},"reconciled":{"const":null},"registered":{"const":true},"replacement_token_id":{"minimum":1,"type":"integer"},"reset_state":{"enum":["rotated","already_inactive"]},"stage":{"const":"complete"},"token_invalidated":{"const":true},"token_reset_required":{"const":false},"token_sha256":{"pattern":"^[0-9a-f]{64}(?![\\\\s\\\\S])","type":"string"}}},{"properties":{"ok":{"const":false},"operation":{"const":"provision"},"prior_active_sha256":{"const":null},"prior_token_id":{"const":null},"provisioned":{"const":false},"reconciled":{"const":null},"registered":{"const":false},"replacement_token_id":{"const":null},"reset_state":{"const":"not_started"},"stage":{"enum":["preconditions","docker","image","config"]},"token_invalidated":{"const":false},"token_reset_required":{"const":false},"token_sha256":{"const":null}}},{"properties":{"ok":{"const":false},"operation":{"const":"provision"},"prior_token_id":{"minimum":1,"type":"integer"},"provisioned":{"type":["boolean","null"]},"reconciled":{"const":null},"registered":{"type":["boolean","null"]},"replacement_token_id":{"minimum":1,"type":"integer"},"reset_state":{"enum":["rotated","already_inactive"]},"stage":{"enum":["register","start","verify","indeterminate"]},"token_invalidated":{"const":true},"token_reset_required":{"const":false},"token_sha256":{"pattern":"^[0-9a-f]{64}(?![\\\\s\\\\S])","type":"string"}}},{"properties":{"ok":{"const":false},"operation":{"const":"provision"},"provisioned":{"type":["boolean","null"]},"reconciled":{"const":null},"registered":{"type":["boolean","null"]},"reset_state":{"enum":["failed","indeterminate"]},"stage":{"enum":["register","start","verify","reset","indeterminate"]},"token_invalidated":{"const":false},"token_reset_required":{"const":true}}},{"properties":{"ok":{"const":true},"operation":{"const":"reconcile"},"provisioned":{"const":null},"reconciled":{"const":true},"registered":{"const":null},"replacement_token_id":{"minimum":1,"type":"integer"},"reset_state":{"enum":["reconciled_expected_active","reconciled_expected_inactive","reconciled_no_active"]},"stage":{"const":"complete"},"token_invalidated":{"const":true},"token_reset_required":{"const":false},"token_sha256":{"pattern":"^[0-9a-f]{64}(?![\\\\s\\\\S])","type":"string"}}},{"properties":{"ok":{"const":false},"operation":{"const":"reconcile"},"provisioned":{"const":null},"reconciled":{"type":["boolean","null"]},"registered":{"const":null},"replacement_token_id":{"minimum":1,"type":["integer","null"]},"reset_state":{"enum":["failed","indeterminate"]},"stage":{"enum":["reconcile","indeterminate"]},"token_invalidated":{"const":false},"token_reset_required":{"const":true},"token_sha256":{"pattern":"^[0-9a-f]{64}(?![\\\\s\\\\S])","type":"string"}}}],"properties":{"activation_blocker":{"const":"N-MultiCloud/nmulticloud-context#411"},"activation_eligible":{"const":false},"base_image_digest":{"const":"0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f"},"base_image_reference":{"const":"ghcr.io/astral-sh/uv:0.12.5-python3.12-trixie-slim@sha256:0d05436f6b7b8c88236dcaeab65c2b819df944e9af0be7f4b3a2117c38fe868f"},"capacity":{"const":1},"compose_project_dir":{"enum":["/opt/nmc-ci-untrusted-root-org-241"]},"config_path":{"const":"/etc/gitea-runner/nmulticloud-org-root.yaml"},"container_bind_workdir":{"const":false},"container_cap_add":{"const":["CHOWN","SETUID","SETGID","FOWNER","DAC_OVERRIDE"]},"container_daemon_socket_in_job":{"const":false},"container_devices":{"const":[]},"container_host_ambient_capabilities":{"const":[]},"container_host_effective_capabilities":{"const":[]},"container_host_ipc":{"const":false},"container_host_network":{"const":false},"container_host_pid":{"const":false},"container_host_uts":{"const":false},"container_privileged":{"const":false},"container_uid0_maps_to_host_root":{"const":false},"container_valid_volumes":{"const":[]},"cross_scope_state":{"const":false},"executor":{"enum":["host","docker"],"type":"string"},"fence_execution_id":{"maximum":9007199254740991,"minimum":1,"type":["integer","null"]},"fence_generation":{"maximum":9007199254740991,"minimum":1,"type":"integer"},"fresh_container_per_job":{"const":true},"gitea_instance_url":{"const":"http://10.0.30.96:3000"},"job_cap_drop_all":{"const":true},"job_network_policy":{"const":{"build":{"dns_resolvers":[],"egress":[],"network_mode":"none"},"default_action":"deny","other_egress":"deny","publisher":{"dns_required":false,"dns_resolvers":[],"host_bindings":[{"hostname":"git.nmulti.cloud","ipv4":"10.0.30.96"}],"https_origins":["https://git.nmulti.cloud:443"],"ipv4_destinations":["10.0.30.96/32"],"network_mode":"filtered","redirects":false,"tcp_ports":[443],"tls_server_names":["git.nmulti.cloud"],"tls_verify":true}}},"job_no_new_privileges":{"const":true},"job_resource_limits":{"const":{"cgroup_version":2,"cpu_period_us":100000,"cpu_quota_us":200000,"cpu_weight":100,"kill_grace_seconds":10,"memory_max_bytes":4294967296,"memory_swap_max_bytes":0,"pids_max":512,"root_filesystem_read_only":true,"tmpfs":[{"options":["nodev","nosuid","noexec"],"path":"/tmp","size_bytes":1073741824},{"options":["nodev","nosuid","noexec"],"path":"/run","size_bytes":67108864}],"ulimits":{"core":{"hard":0,"soft":0},"fsize":{"hard":8589934592,"soft":8589934592},"nofile":{"hard":1024,"soft":1024},"nproc":{"hard":512,"soft":512}},"wall_clock_timeout_seconds":1800,"workspace":{"disk_quota_bytes":8589934592,"host_bind":false,"kind":"ephemeral-volume","path":"/workspace"},"writable_paths":["/workspace","/tmp","/run"]}},"job_user":{"maxLength":64,"type":["string","null"]},"jobs_mount_docker_socket":{"type":"boolean"},"lane":{"enum":["root-python312"],"type":"string"},"management_egress_policy":{"const":"deny-except-gitea-publisher"},"ok":{"type":"boolean"},"operation":{"enum":["provision","reconcile"],"type":"string"},"organization":{"const":"N-MultiCloud"},"prior_active_sha256":{"pattern":"^[0-9a-f]{64}(?![\\\\s\\\\S])","type":["string","null"]},"prior_token_id":{"maximum":9007199254740991,"minimum":1,"type":["integer","null"]},"procedure":{"const":"service.gitea.actions_runner.provision_org_ci_runner"},"production_egress_policy":{"const":"deny-except-gitea-publisher"},"prove_helper_path":{"const":null},"prove_helper_sha256":{"const":null},"provision_helper_path":{"const":null},"provision_helper_sha256":{"const":null},"provisioned":{"type":["boolean","null"]},"python_source_sha256":{"const":"5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a"},"python_version":{"const":"3.12.14"},"reconciled":{"type":["boolean","null"]},"registered":{"type":["boolean","null"]},"replacement_token_id":{"maximum":9007199254740991,"minimum":1,"type":["integer","null"]},"reset_state":{"enum":["not_started","rotated","already_inactive","reconciled_expected_active","reconciled_expected_inactive","reconciled_no_active","failed","indeterminate"],"type":"string"},"rootless_user_namespace":{"const":true},"runner_cap_drop_all":{"type":"boolean"},"runner_image":{"enum":[null]},"runner_label":{"const":"ci-untrusted-root-python312"},"runner_labels":{"items":{"maxLength":512,"type":"string"},"maxItems":8,"minItems":1,"type":"array","uniqueItems":true},"runner_mounts_docker_socket":{"type":"boolean"},"runner_name":{"enum":["ci-untrusted-root-nmulticloud-org-241"]},"runner_no_new_privileges":{"type":"boolean"},"scope":{"enum":["nmulticloud-org-root"],"type":"string"},"service_user":{"const":"gitea-runner-nmulticloud-org-root"},"service_user_login":{"const":false},"stage":{"enum":["preconditions","docker","image","config","register","start","verify","reset","reconcile","complete","indeterminate"],"type":"string"},"state_dir":{"const":"/var/lib/gitea-runner-nmulticloud-org-root"},"target":{"const":"Gitea-Runner"},"token_invalidated":{"type":"boolean"},"token_reset_required":{"type":"boolean"},"token_sha256":{"pattern":"^[0-9a-f]{64}(?![\\\\s\\\\S])","type":["string","null"]},"uv_archive_sha256":{"const":"68a509da24b06b4223a1c0175fb5eb5bc79342b76cbeff0cfe51ac3f5b17b6b2"},"uv_version":{"const":"0.12.5"}},"required":["ok","procedure","target","operation","scope","lane","fence_execution_id","fence_generation","provisioned","registered","reconciled","stage","organization","gitea_instance_url","token_invalidated","token_reset_required","token_sha256","reset_state","prior_token_id","prior_active_sha256","replacement_token_id","runner_name","runner_labels","runner_image","compose_project_dir","executor","runner_mounts_docker_socket","jobs_mount_docker_socket","runner_cap_drop_all","runner_no_new_privileges","job_user"],"type":"object"}'
)
_LEGACY_PARAMS_SCHEMA = json.loads(
    '{"additionalProperties":false,"properties":{"operation":{"enum":["reconcile","register"],"type":"string"},"scope":{"enum":["netbox-proxbox","nmulticloud-org","nmulticloud-org-root","proxbox-api","release-netbox-proxbox-build","release-netbox-proxbox-validation","release-proxbox-api-build","release-proxbox-api-validation"],"type":"string"}},"required":["operation","scope"],"type":"object"}'
)
_LEGACY_RESULT_SCHEMA = json.loads(
    '{"additionalProperties":false,"oneOf":[{"properties":{"ok":{"const":true},"operation":{"const":"register"},"prior_active_sha256":{"const":null},"prior_token_id":{"minimum":1,"type":"integer"},"reconciled":{"const":null},"registered":{"const":true},"replacement_token_id":{"minimum":1,"type":"integer"},"reset_state":{"enum":["rotated","already_inactive"]},"stage":{"const":"complete"},"token_invalidated":{"const":true},"token_reset_required":{"const":false},"token_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"}}},{"properties":{"ok":{"const":false},"operation":{"const":"register"},"prior_active_sha256":{"const":null},"prior_token_id":{"const":null},"reconciled":{"const":null},"registered":{"const":false},"replacement_token_id":{"const":null},"reset_state":{"const":"not_started"},"stage":{"const":"generate_token"},"token_invalidated":{"const":false},"token_reset_required":{"const":false},"token_sha256":{"const":null}}},{"properties":{"ok":{"const":false},"operation":{"const":"register"},"prior_active_sha256":{"const":null},"prior_token_id":{"minimum":1,"type":"integer"},"reconciled":{"const":null},"registered":{"type":["boolean","null"]},"replacement_token_id":{"minimum":1,"type":"integer"},"reset_state":{"enum":["rotated","already_inactive"]},"stage":{"enum":["register","indeterminate"]},"token_invalidated":{"const":true},"token_reset_required":{"const":false},"token_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"}}},{"properties":{"ok":{"const":false},"operation":{"const":"register"},"prior_active_sha256":{"const":null},"prior_token_id":{"minimum":1,"type":["integer","null"]},"reconciled":{"const":null},"registered":{"type":["boolean","null"]},"replacement_token_id":{"minimum":1,"type":["integer","null"]},"reset_state":{"enum":["failed","indeterminate"]},"stage":{"enum":["register","reset","indeterminate"]},"token_invalidated":{"const":false},"token_reset_required":{"const":true},"token_sha256":{"pattern":"^[0-9a-f]{64}$","type":["string","null"]}}},{"properties":{"ok":{"const":true},"operation":{"const":"reconcile"},"prior_active_sha256":{"pattern":"^[0-9a-f]{64}$","type":["string","null"]},"prior_token_id":{"minimum":1,"type":["integer","null"]},"reconciled":{"const":true},"registered":{"const":null},"replacement_token_id":{"minimum":1,"type":"integer"},"reset_state":{"enum":["reconciled_expected_active","reconciled_expected_inactive","reconciled_no_active"]},"stage":{"const":"complete"},"token_invalidated":{"const":true},"token_reset_required":{"const":false},"token_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"}}},{"properties":{"ok":{"const":false},"operation":{"const":"reconcile"},"prior_active_sha256":{"pattern":"^[0-9a-f]{64}$","type":["string","null"]},"prior_token_id":{"minimum":1,"type":["integer","null"]},"reconciled":{"type":["boolean","null"]},"registered":{"const":null},"replacement_token_id":{"minimum":1,"type":["integer","null"]},"reset_state":{"enum":["failed","indeterminate"]},"stage":{"enum":["reconcile","indeterminate"]},"token_invalidated":{"const":false},"token_reset_required":{"const":true},"token_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"}}}],"properties":{"fence_execution_id":{"maximum":9007199254740991,"minimum":1,"type":["integer","null"]},"fence_generation":{"maximum":9007199254740991,"minimum":1,"type":"integer"},"ok":{"type":"boolean"},"operation":{"enum":["reconcile","register"],"type":"string"},"prior_active_sha256":{"pattern":"^[0-9a-f]{64}$","type":["string","null"]},"prior_token_id":{"maximum":9007199254740991,"minimum":1,"type":["integer","null"]},"procedure":{"const":"service.gitea.runner.register"},"reconciled":{"type":["boolean","null"]},"registered":{"type":["boolean","null"]},"replacement_token_id":{"maximum":9007199254740991,"minimum":1,"type":["integer","null"]},"reset_state":{"enum":["not_started","rotated","already_inactive","reconciled_expected_active","reconciled_expected_inactive","reconciled_no_active","failed","indeterminate"],"type":"string"},"scope":{"enum":["netbox-proxbox","nmulticloud-org","nmulticloud-org-root","proxbox-api","release-netbox-proxbox-build","release-netbox-proxbox-validation","release-proxbox-api-build","release-proxbox-api-validation"],"type":"string"},"stage":{"enum":["generate_token","register","reset","reconcile","complete","indeterminate"],"type":"string"},"target":{"const":"nmultifibra-ci-untrusted-01"},"token_invalidated":{"type":"boolean"},"token_reset_required":{"type":"boolean"},"token_sha256":{"pattern":"^[0-9a-f]{64}$","type":["string","null"]}},"required":["ok","procedure","target","operation","scope","fence_execution_id","fence_generation","registered","reconciled","token_invalidated","token_reset_required","token_sha256","reset_state","prior_token_id","prior_active_sha256","replacement_token_id","stage"],"type":"object"}'
)

_PROCEDURE_DEFAULTS = {
    "handler_id": _HANDLER_ID,
    "version": 1,
    "enabled": False,
    "target_models": _TARGET_MODELS,
    "effect": "write",
    "timeout_seconds": 1800,
    "approval_required": True,
    "params_schema": _PARAMS_SCHEMA,
    "result_schema": _RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_pinned": True,
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Catalog the fixed Gitea organization CI runner lanes. The isolated "
        "root-python312 candidate stays disabled and activation-ineligible "
        "until nmulticloud-context #411 supplies its reviewed host boundary."
    ),
}

_LEGACY_PROCEDURE_DEFAULTS = {
    "handler_id": _LEGACY_PROCEDURE_NAME,
    "version": 1,
    "enabled": False,
    "target_models": ["virtualization.virtualmachine"],
    "effect": "destructive",
    "timeout_seconds": 360,
    "approval_required": True,
    "params_schema": _LEGACY_PARAMS_SCHEMA,
    "result_schema": _LEGACY_RESULT_SCHEMA,
    "transport_driver": "asyncssh",
    "transport_driver_chain": [],
    "output_parser": "none",
    "output_schema": {},
    "description": (
        "Register or reconcile one fixed Gitea runner scope and invalidate the "
        "reusable token before completion without accepting, persisting, "
        "logging, or returning token material."
    ),
}

_REPRESENTATIVE_COMMAND = {
    "sequence": 1,
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "gitea-org-ci-runner-provision"],
    "description": "Backend provisions or reconciles one frozen org-runner lane and always invalidates the exact resolved registration token.",
    "condition_param": "",
    "condition_negate": False,
    "for_each_param": "",
    "continue_on_error": False,
    "render_mode": "literal",
    "produces_var": "",
    "capture_kind": "",
    "capture_expression": "",
}
_REPRESENTATIVE_COMMAND.pop("sequence")
_LEGACY_REPRESENTATIVE_COMMAND = {
    "sequence": 1,
    "step_type": "shell_argv",
    "device_cli_mode": "",
    "argv": ["backend-orchestrated", "gitea-runner-lifecycle-composite"],
    "description": "Backend registers or reconciles one fixed runner scope, always invalidating the reusable Gitea token before completion.",
    "condition_param": "",
    "condition_negate": False,
    "for_each_param": "",
    "continue_on_error": False,
    "render_mode": "literal",
    "produces_var": "",
    "capture_kind": "",
    "capture_expression": "",
}
_LEGACY_REPRESENTATIVE_COMMAND.pop("sequence")


def extend_gitea_org_ci_runner_contract(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    procedure, _created = RPCProcedure.objects.update_or_create(
        name=_PROCEDURE_NAME, defaults=_PROCEDURE_DEFAULTS
    )
    RPCProcedureCommand.objects.update_or_create(
        procedure=procedure, sequence=1, defaults=_REPRESENTATIVE_COMMAND
    )
    legacy, _legacy_created = RPCProcedure.objects.update_or_create(
        name=_LEGACY_PROCEDURE_NAME,
        defaults=_LEGACY_PROCEDURE_DEFAULTS,
    )
    RPCProcedureCommand.objects.update_or_create(
        procedure=legacy,
        sequence=1,
        defaults=_LEGACY_REPRESENTATIVE_COMMAND,
    )


def disable_gitea_org_ci_runner_contract(apps, schema_editor):
    """Keep historical rows and prevent execution after package rollback."""
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedure.objects.filter(name=_PROCEDURE_NAME).update(enabled=False)
    RPCProcedure.objects.filter(name=_LEGACY_PROCEDURE_NAME).update(enabled=False)


def preserve_takeover_generation(apps, schema_editor):
    """Document the forward-only durable epoch boundary."""


def refuse_takeover_generation_removal(apps, schema_editor):
    raise IrreversibleError(
        "Migration 0087 is intentionally irreversible because removing the "
        "durable Gitea runner takeover generation can admit late responses."
    )


class Migration(migrations.Migration):
    dependencies = [("netbox_rpc", "0086_seed_akvorado_debian13_bootstrap_procedures")]
    operations = [
        migrations.AddField(
            model_name="rpcgitearunnerscopefence",
            name="takeover_generation",
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.RunPython(
            extend_gitea_org_ci_runner_contract,
            reverse_code=disable_gitea_org_ci_runner_contract,
        ),
        migrations.RunPython(
            preserve_takeover_generation,
            reverse_code=refuse_takeover_generation_removal,
        ),
    ]
