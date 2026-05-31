HUAWEI_MA5800_R024_START_ONT = "network.device.huawei.olt.ma5800.r024.start_ont"
HUAWEI_MA5800_R024_START_ONT_HANDLER = "network.huawei_olt_ma5800_r024.start_ont"

# SSH key installation — appends a public key to authorized_keys on a target host
# using the device's existing privileged SSH DeviceService credential.
LINUX_INSTALL_SSH_KEY = "os.linux.ubuntu.24.install_ssh_key"
LINUX_INSTALL_SSH_KEY_HANDLER = "os.linux_ubuntu_24.install_ssh_key"

NGINX_1_CONFIG_TEST = "service.nginx.1.config_test"
NGINX_1_CONFIG_DEPLOY = "service.nginx.1.config_deploy"
NGINX_1_RELOAD = "service.nginx.1.reload"
NGINX_1_ROLLBACK = "service.nginx.1.rollback"

UBUNTU_24_RESTART_SERVICE = "os.linux.ubuntu.24.restart_service"
UBUNTU_24_RESTART_SERVICE_HANDLER = "os.linux_ubuntu_24.restart_service"

UBUNTU_24_STATUS_SERVICE = "os.linux.ubuntu.24.status_service"
UBUNTU_24_STATUS_SERVICE_HANDLER = "os.linux_ubuntu_24.status_service"

UBUNTU_24_START_SERVICE = "os.linux.ubuntu.24.start_service"
UBUNTU_24_START_SERVICE_HANDLER = "os.linux_ubuntu_24.start_service"

UBUNTU_24_STOP_SERVICE = "os.linux.ubuntu.24.stop_service"
UBUNTU_24_STOP_SERVICE_HANDLER = "os.linux_ubuntu_24.stop_service"

UBUNTU_24_RELOAD_SERVICE = "os.linux.ubuntu.24.reload_service"
UBUNTU_24_RELOAD_SERVICE_HANDLER = "os.linux_ubuntu_24.reload_service"

UBUNTU_24_ENABLE_SERVICE = "os.linux.ubuntu.24.enable_service"
UBUNTU_24_ENABLE_SERVICE_HANDLER = "os.linux_ubuntu_24.enable_service"

UBUNTU_24_DISABLE_SERVICE = "os.linux.ubuntu.24.disable_service"
UBUNTU_24_DISABLE_SERVICE_HANDLER = "os.linux_ubuntu_24.disable_service"

UBUNTU_24_DAEMON_RELOAD = "os.linux.ubuntu.24.daemon_reload"
UBUNTU_24_DAEMON_RELOAD_HANDLER = "os.linux_ubuntu_24.daemon_reload"

UBUNTU_24_JOURNAL_TAIL = "os.linux.ubuntu.24.journal_tail"
UBUNTU_24_JOURNAL_TAIL_HANDLER = "os.linux_ubuntu_24.journal_tail"

_SSH_INSTALL_KEY_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["public_key"],
    "additionalProperties": False,
    "properties": {
        "public_key": {
            "type": "string",
            "minLength": 1,
            "maxLength": 16384,
            "pattern": "^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/]+=*( .*)?$",
            "description": "Full OpenSSH public key (single line, key-type + base64 blob).",
        },
        "username": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "description": "Target user on the device; defaults to the DeviceService SSH username.",
        },
    },
}

_SSH_INSTALL_KEY_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "username": {"type": "string"},
        "fingerprint": {"type": "string"},
    },
}

LINUX_INSTALL_SSH_KEY = "os.linux.ubuntu.24.install_ssh_key"
LINUX_INSTALL_SSH_KEY_HANDLER = "os.linux_ubuntu_24.install_ssh_key"

SSH_KEY_PROCEDURES = (
    {
        "name": LINUX_INSTALL_SSH_KEY,
        "handler_id": LINUX_INSTALL_SSH_KEY_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": (
            "Append an SSH public key to the target user's authorized_keys file "
            "on the device, using the existing DeviceService SSH credential. "
            "Called automatically by nms-backend when registering a new NMS CLI key."
        ),
        "params_schema": _SSH_INSTALL_KEY_PARAMS_SCHEMA,
        "result_schema": _SSH_INSTALL_KEY_RESULT_SCHEMA,
    },
)

INITIAL_PROCEDURES = (
    {
        "name": HUAWEI_MA5800_R024_START_ONT,
        "handler_id": HUAWEI_MA5800_R024_START_ONT_HANDLER,
        "target_models": ["netbox_gpon.olt"],
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": False,
        "params_schema": {
            "type": "object",
            "required": ["frame", "slot", "port", "ont_id"],
            "additionalProperties": False,
            "properties": {
                "frame": {"type": "integer", "minimum": 0},
                "slot": {"type": "integer", "minimum": 1, "maximum": 17},
                "port": {"type": "integer", "minimum": 0, "maximum": 15},
                "ont_id": {"type": "integer", "minimum": 0, "maximum": 127},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target", "status"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "status": {"type": "string"},
            },
        },
    },
    {
        "name": UBUNTU_24_RESTART_SERVICE,
        "handler_id": UBUNTU_24_RESTART_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": False,
        "params_schema": {
            "type": "object",
            "required": ["service_slug"],
            "additionalProperties": False,
            "properties": {
                "service_slug": {"type": "string", "minLength": 1, "maxLength": 100},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target", "service", "active_state"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "service": {"type": "string"},
                "active_state": {"type": "string"},
            },
        },
    },
)

_SYSTEMD_SERVICE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["service_slug"],
    "additionalProperties": False,
    "properties": {
        "service_slug": {"type": "string", "minLength": 1, "maxLength": 100},
    },
}

_SYSTEMD_JOURNAL_TAIL_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["service_slug"],
    "additionalProperties": False,
    "properties": {
        "service_slug": {"type": "string", "minLength": 1, "maxLength": 100},
        "lines": {"type": "integer", "minimum": 1, "maximum": 500},
    },
}

_SYSTEMD_DAEMON_RELOAD_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

_SYSTEMD_SERVICE_STATE_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "service", "active_state"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "service": {"type": "string"},
        "active_state": {"type": "string"},
        "sub_state": {"type": "string"},
        "unit_file_state": {"type": "string"},
    },
}

_SYSTEMD_SERVICE_ENABLEMENT_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "service"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "service": {"type": "string"},
        "unit_file_state": {"type": "string"},
    },
}

_SYSTEMD_DAEMON_RELOAD_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "exit_code": {"type": "integer"},
    },
}

_SYSTEMD_JOURNAL_TAIL_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "service"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "service": {"type": "string"},
        "lines": {"type": "integer"},
        "output": {"type": "string"},
    },
}

SYSTEMD_PROCEDURES = (
    {
        "name": UBUNTU_24_STATUS_SERVICE,
        "handler_id": UBUNTU_24_STATUS_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read status for an allowlisted systemd service",
        "params_schema": _SYSTEMD_SERVICE_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_SERVICE_STATE_RESULT_SCHEMA,
    },
    {
        "name": UBUNTU_24_START_SERVICE,
        "handler_id": UBUNTU_24_START_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Start an allowlisted systemd service",
        "params_schema": _SYSTEMD_SERVICE_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_SERVICE_STATE_RESULT_SCHEMA,
    },
    {
        "name": UBUNTU_24_STOP_SERVICE,
        "handler_id": UBUNTU_24_STOP_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Stop an allowlisted systemd service",
        "params_schema": _SYSTEMD_SERVICE_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_SERVICE_STATE_RESULT_SCHEMA,
    },
    {
        "name": UBUNTU_24_RELOAD_SERVICE,
        "handler_id": UBUNTU_24_RELOAD_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Reload an allowlisted systemd service",
        "params_schema": _SYSTEMD_SERVICE_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_SERVICE_STATE_RESULT_SCHEMA,
    },
    {
        "name": UBUNTU_24_ENABLE_SERVICE,
        "handler_id": UBUNTU_24_ENABLE_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Enable an allowlisted systemd service",
        "params_schema": _SYSTEMD_SERVICE_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_SERVICE_ENABLEMENT_RESULT_SCHEMA,
    },
    {
        "name": UBUNTU_24_DISABLE_SERVICE,
        "handler_id": UBUNTU_24_DISABLE_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Disable an allowlisted systemd service",
        "params_schema": _SYSTEMD_SERVICE_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_SERVICE_ENABLEMENT_RESULT_SCHEMA,
    },
    {
        "name": UBUNTU_24_DAEMON_RELOAD,
        "handler_id": UBUNTU_24_DAEMON_RELOAD_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Reload the systemd manager configuration",
        "params_schema": _SYSTEMD_DAEMON_RELOAD_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_DAEMON_RELOAD_RESULT_SCHEMA,
    },
    {
        "name": UBUNTU_24_JOURNAL_TAIL,
        "handler_id": UBUNTU_24_JOURNAL_TAIL_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read recent journal output for an allowlisted systemd service",
        "params_schema": _SYSTEMD_JOURNAL_TAIL_PARAMS_SCHEMA,
        "result_schema": _SYSTEMD_JOURNAL_TAIL_RESULT_SCHEMA,
    },
)
