"""Worker normalization tests for the typed Akvorado v1 procedure family."""

from __future__ import annotations

import hashlib
import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

PROCEDURE_NAMES = (
    "service.akvorado.1.config_read",
    "service.akvorado.1.config_deploy",
    "service.akvorado.1.deploy_stack",
    "service.akvorado.1.status_stack",
    "service.akvorado.1.restart_stack",
)
ENV_CONTENT_REF = "nms-secret:123e4567-e89b-42d3-a456-426614174000"


@pytest.fixture()
def jobs_module(monkeypatch: pytest.MonkeyPatch):
    _install_runtime_import_stubs(monkeypatch)
    sys.modules.pop("netbox_rpc.jobs", None)
    module = importlib.import_module("netbox_rpc.jobs")
    yield module
    sys.modules.pop("netbox_rpc.jobs", None)


@pytest.mark.parametrize(
    ("procedure_name", "params"),
    [
        ("service.akvorado.1.config_read", {}),
        (
            "service.akvorado.1.config_deploy",
            {"config_content": "inlet:\n  kafka:\n    topic: flows\n"},
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
        ),
        ("service.akvorado.1.status_stack", {}),
        ("service.akvorado.1.restart_stack", {}),
    ],
)
def test_all_akvorado_procedures_normalize_for_worker_dispatch(
    jobs_module,
    procedure_name: str,
    params: dict[str, object],
) -> None:
    normalized = jobs_module.normalize_execution_params(
        _execution(procedure_name, {"target": "127.0.0.1", **params})
    )

    assert normalized["target"] == "akvorado-01"
    assert normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 41,
    }
    assert "rpc_ssh_host" not in normalized
    assert normalized["command_fingerprint"]["handler_id"] == procedure_name
    assert normalized["command_fingerprint"]["procedure"] == procedure_name
    assert normalized["command_fingerprint"]["target_object"] == normalized[
        "target_object"
    ]

    for field_name in ("config_content", "compose_content"):
        if field_name not in params:
            assert field_name not in normalized
            continue
        content = str(params[field_name])
        assert normalized[field_name] == content
        fingerprint = normalized["command_fingerprint"]
        assert content not in str(fingerprint)
        assert fingerprint[f"{field_name}_sha256"] == hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()
        assert fingerprint[f"{field_name}_bytes"] == len(content.encode("utf-8"))

    if procedure_name.endswith("deploy_stack"):
        assert normalized["env_content"] == ENV_CONTENT_REF
        assert normalized["command_fingerprint"]["env_content_ref"] == ENV_CONTENT_REF


@pytest.mark.parametrize("procedure_name", PROCEDURE_NAMES)
def test_akvorado_normalization_requires_existing_assigned_object(
    jobs_module,
    procedure_name: str,
) -> None:
    execution = _execution(procedure_name, {})
    execution.assigned_object = None

    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(execution)

    assert exc_info.value.code == "RPC_TARGET_REQUIRED"


@pytest.mark.parametrize(
    ("procedure_name", "params", "error_code"),
    [
        (
            "service.akvorado.1.config_deploy",
            {"config_content": "inlet:\x00\n"},
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.config_deploy",
            {"config_content": "inlet:\u0001\n"},
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.config_deploy",
            {"config_content": "password: plaintext\n"},
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.config_deploy",
            {"config_content": "endpoint: https://user:pass@example.net\n"},
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": "services:\n  akvorado:\x00\n",
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": "services:\n  akvorado:\n    api_key: plaintext\n",
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    environment:\n"
                    "      PUBLIC_URL: https://akvorado.example.net\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    environment:\n"
                    "      PUBLIC_URL: ${PUBLIC_URL:-https://akvorado.example.net}\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    '    "environment":\n'
                    "      FOO: hunter2\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    " akvorado:\n"
                    "   deploy: {environment: {FOO: hunter2}}\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    env_file: [.env]\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_SECRET_FORBIDDEN",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    privileged: true\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    volumes:\n"
                    "      - root:/host\n"
                    "volumes:\n"
                    "  root:\n"
                    "    driver: local\n"
                    "    driver_opts:\n"
                    "      type: none\n"
                    "      o: bind\n"
                    '      device: "/"\n'
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": "volumes:\n  evil:\n    external: true\n",
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": "volumes:\n  'bad name!': null\n",
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    command: [akvorado, orchestrator, --clickhouse-password, hunter2]\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    healthcheck:\n"
                    '      test: ["CMD", "curl", "-u", "admin:hunter2", "http://localhost/health"]\n'
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    volumes:\n"
                    '      - "${HOST_PATH:-/}:/host"\n'
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    volumes:\n"
                    "      - type: ${MOUNT_TYPE:-bind}\n"
                    "        source: /\n"
                    "        target: /host\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    volumes:\n"
                    "      - type: bind\n"
                    "        source: ${ETC_PATH}\n"
                    "        target: /host\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    volumes:\n"
                    '      - "not a valid volume!:/data"\n'
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    network_mode: host\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    cap_add: [SYS_ADMIN]\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    '    devices: ["/dev/kvm:/dev/kvm"]\n'
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    build: .\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    volumes:\n"
                    "      - /:/host:ro\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "    volumes:\n"
                    "      - type: bind\n"
                    "        source: /var/run/docker.sock\n"
                    "        target: /var/run/docker.sock\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
        (
            "service.akvorado.1.deploy_stack",
            {
                "compose_content": (
                    "services:\n"
                    "  akvorado:\n"
                    "    image: akvorado:latest\n"
                    "secrets:\n"
                ),
                "env_content": ENV_CONTENT_REF,
            },
            "RPC_PARAM_INVALID",
        ),
    ],
)
def test_akvorado_normalization_rejects_unsafe_content(
    jobs_module,
    procedure_name: str,
    params: dict[str, object],
    error_code: str,
) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(_execution(procedure_name, params))

    assert exc_info.value.code == error_code


def test_compose_environment_allows_only_exact_external_references(jobs_module) -> None:
    compose_content = (
        "services:\n"
        "  akvorado:\n"
        '    "environment": # externally supplied\n'
        "      - PUBLIC_URL=${PUBLIC_URL}\n"
        "      - LOG_LEVEL\n"
    )

    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.akvorado.1.deploy_stack",
            {"compose_content": compose_content, "env_content": ENV_CONTENT_REF},
        )
    )

    assert normalized["compose_content"] == compose_content


def test_compose_structure_accepts_realistic_akvorado_stack(jobs_module) -> None:
    compose_content = (
        "name: akvorado\n"
        "services:\n"
        "  akvorado:\n"
        "    image: ghcr.io/akvorado/akvorado:latest\n"
        "    ports:\n"
        '      - "8080:8080"\n'
        "    volumes:\n"
        "      - /etc/akvorado/akvorado.yaml:/etc/akvorado/akvorado.yaml:ro\n"
        "      - akvorado-data:/var/lib/akvorado\n"
        "    environment:\n"
        "      KAFKA_BROKERS: ${KAFKA_BROKERS}\n"
        "      CLICKHOUSE_HOST: ${CLICKHOUSE_HOST}\n"
        "    depends_on:\n"
        "      - clickhouse\n"
        "      - redis\n"
        "    restart: unless-stopped\n"
        "  clickhouse:\n"
        "    image: clickhouse/clickhouse-server:latest\n"
        "    volumes:\n"
        "      - clickhouse-data:/var/lib/clickhouse\n"
        "    restart: unless-stopped\n"
        "  redis:\n"
        "    image: redis:latest\n"
        "    restart: unless-stopped\n"
        "volumes:\n"
        "  akvorado-data: {}\n"
        "  clickhouse-data: {}\n"
    )

    normalized = jobs_module.normalize_execution_params(
        _execution(
            "service.akvorado.1.deploy_stack",
            {"compose_content": compose_content, "env_content": ENV_CONTENT_REF},
        )
    )

    assert normalized["compose_content"] == compose_content


def test_compose_environment_rejects_invalid_yaml_cleanly(jobs_module) -> None:
    with pytest.raises(jobs_module.RPCExecutionError) as exc_info:
        jobs_module.normalize_execution_params(
            _execution(
                "service.akvorado.1.deploy_stack",
                {
                    "compose_content": "services:\n  akvorado: [\n",
                    "env_content": ENV_CONTENT_REF,
                },
            )
        )

    assert exc_info.value.code == "RPC_PARAM_INVALID"


def test_akvorado_target_identity_disambiguates_duplicate_display_names(
    jobs_module,
) -> None:
    device_execution = _execution("service.akvorado.1.config_read", {})
    device_execution.assigned_object = SimpleNamespace(name="akvorado-shared")
    device_execution.assigned_object_id = 41
    device_execution.assigned_object_type = SimpleNamespace(
        app_label="dcim",
        model="device",
    )
    vm_execution = _execution("service.akvorado.1.config_read", {})
    vm_execution.assigned_object = SimpleNamespace(name="akvorado-shared")
    vm_execution.assigned_object_id = 84
    vm_execution.assigned_object_type = SimpleNamespace(
        app_label="virtualization",
        model="virtualmachine",
    )

    device_normalized = jobs_module.normalize_execution_params(device_execution)
    vm_normalized = jobs_module.normalize_execution_params(vm_execution)

    assert device_normalized["target"] == vm_normalized["target"]
    assert device_normalized["target_object"] == {
        "content_type": "dcim.device",
        "object_id": 41,
    }
    assert vm_normalized["target_object"] == {
        "content_type": "virtualization.virtualmachine",
        "object_id": 84,
    }
    assert device_normalized["target_object"] != vm_normalized["target_object"]
    assert jobs_module._hash_json(
        device_normalized["command_fingerprint"]
    ) != jobs_module._hash_json(vm_normalized["command_fingerprint"])


def _execution(procedure_name: str, params: dict[str, object]):
    return SimpleNamespace(
        procedure=SimpleNamespace(name=procedure_name, handler_id=procedure_name),
        params=params,
        assigned_object=SimpleNamespace(name="akvorado-01"),
        assigned_object_type=SimpleNamespace(app_label="dcim", model="device"),
        assigned_object_id=41,
        target_display="caller-controlled-fallback",
        target_model_label="dcim.device",
    )


def _install_runtime_import_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = type("PluginConfig", (), {"ready": lambda self: None})

    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"
    netbox_jobs = types.ModuleType("netbox.jobs")
    netbox_jobs.JobRunner = type(
        "JobRunner",
        (),
        {"enqueue": classmethod(lambda cls, *args, **kwargs: None)},
    )

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.IntegrityError = type("IntegrityError", (Exception,), {})
    django_utils = types.ModuleType("django.utils")
    django_timezone = types.ModuleType("django.utils.timezone")
    django_timezone.now = MagicMock(return_value=None)
    django_utils.timezone = django_timezone

    models = types.ModuleType("netbox_rpc.models")
    models.RPCLinuxServiceAllowlist = type("RPCLinuxServiceAllowlist", (), {})
    models.RPCExecution = type("RPCExecution", (), {})
    models.RPCExecutionEvent = type("RPCExecutionEvent", (), {})

    requests_mod = types.ModuleType("requests")
    requests_mod.post = MagicMock()
    requests_mod.get = MagicMock()
    requests_exceptions = types.ModuleType("requests.exceptions")
    requests_exceptions.RequestException = type("RequestException", (Exception,), {})
    requests_exceptions.ConnectionError = type("ConnectionError", (Exception,), {})
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
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", models)
