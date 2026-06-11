HUAWEI_MA5800_R024_START_ONT = "network.device.huawei.olt.ma5800.r024.start_ont"
HUAWEI_MA5800_R024_START_ONT_HANDLER = "network.huawei_olt_ma5800_r024.start_ont"

DELL_OS10_S5232F_BOOTSTRAP_RESTCONF = (
    "network.device.dell_os10.s5232f_on.bootstrap_restconf"
)
DELL_OS10_S5232F_BOOTSTRAP_RESTCONF_HANDLER = (
    "network.dell_os10_s5232f_on.bootstrap_restconf"
)
DELL_OS10_S5232F_SHOW_VERSION = "network.device.dell_os10.s5232f_on.show_version"
DELL_OS10_S5232F_SHOW_VERSION_HANDLER = "network.dell_os10_s5232f_on.show_version"
DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION = (
    "network.device.dell_os10.s5232f_on.set_interface_description"
)
DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION_HANDLER = (
    "network.dell_os10_s5232f_on.set_interface_description"
)
DELL_OS10_S5232F_SET_VLAN_DESCRIPTION = (
    "network.device.dell_os10.s5232f_on.set_vlan_description"
)
DELL_OS10_S5232F_SET_VLAN_DESCRIPTION_HANDLER = (
    "network.dell_os10_s5232f_on.set_vlan_description"
)
DELL_OS10_S5232F_WRITE_MEMORY = "network.device.dell_os10.s5232f_on.write_memory"
DELL_OS10_S5232F_WRITE_MEMORY_HANDLER = "network.dell_os10_s5232f_on.write_memory"
DELL_OS10_S5232F_SHOW_VLT = "network.device.dell_os10.s5232f_on.show_vlt"
DELL_OS10_S5232F_SHOW_VLT_HANDLER = "network.dell_os10_s5232f_on.show_vlt"
DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN = (
    "network.device.dell_os10.s5232f_on.configure_vlt_domain"
)
DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN_HANDLER = (
    "network.dell_os10_s5232f_on.configure_vlt_domain"
)
DELL_OS10_S5232F_CONFIGURE_VLT_PEER = (
    "network.device.dell_os10.s5232f_on.configure_vlt_peer"
)
DELL_OS10_S5232F_CONFIGURE_VLT_PEER_HANDLER = (
    "network.dell_os10_s5232f_on.configure_vlt_peer"
)
DELL_OS10_S5232F_CONFIGURE_PORT_CHANNEL = (
    "network.device.dell_os10.s5232f_on.configure_port_channel"
)
DELL_OS10_S5232F_CONFIGURE_PORT_CHANNEL_HANDLER = (
    "network.dell_os10_s5232f_on.configure_port_channel"
)
DELL_OS10_S5232F_CONFIGURE_INTERFACE_LACP = (
    "network.device.dell_os10.s5232f_on.configure_interface_lacp"
)
DELL_OS10_S5232F_CONFIGURE_INTERFACE_LACP_HANDLER = (
    "network.dell_os10_s5232f_on.configure_interface_lacp"
)
DELL_OS10_S5232F_CONFIGURE_INTERFACE_BREAKOUT = (
    "network.device.dell_os10.s5232f_on.configure_interface_breakout"
)
DELL_OS10_S5232F_CONFIGURE_INTERFACE_BREAKOUT_HANDLER = (
    "network.dell_os10_s5232f_on.configure_interface_breakout"
)
DELL_OS10_S5232F_CONFIGURE_INTERFACE_FEC = (
    "network.device.dell_os10.s5232f_on.configure_interface_fec"
)
DELL_OS10_S5232F_CONFIGURE_INTERFACE_FEC_HANDLER = (
    "network.dell_os10_s5232f_on.configure_interface_fec"
)

# SSH key installation — appends a public key to authorized_keys on a target host
# using the device's existing privileged SSH DeviceService credential.
LINUX_INSTALL_SSH_KEY = "os.linux.ubuntu.24.install_ssh_key"
LINUX_INSTALL_SSH_KEY_HANDLER = "os.linux_ubuntu_24.install_ssh_key"

# Mellanox ConnectX-3 (mlx4) InfiniBand -> Ethernet conversion on a Proxmox host.
# Targets a netbox-proxbox ProxmoxEndpoint; SSH connection details are resolved
# through the netbox-nms ProxmoxEndpointSSHBinding (see jobs.py normalizer).
LINUX_PROXMOX_CONVERT_MELLANOX_NIC = "os.linux.proxmox.convert_mellanox_nic_to_ethernet"
LINUX_PROXMOX_CONVERT_MELLANOX_NIC_HANDLER = (
    "os.linux_proxmox.convert_mellanox_nic_to_ethernet"
)

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
            # Restrict comment to safe charset (alphanumeric + common identifier chars).
            # The normalizer strips the comment before forwarding to nms-backend, so this
            # pattern is primarily a defense against malformed input at the API boundary.
            "pattern": "^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/]+=*( [A-Za-z0-9_.@:+/=-]{1,255})?$",
            "description": "OpenSSH public key (key-type base64-blob [optional-comment]).",
        },
        "username": {
            "type": "string",
            "minLength": 1,
            "maxLength": 32,
            "pattern": "^[a-z_][a-z0-9_-]{0,31}$",
            "description": "POSIX username on the device; defaults to the DeviceService SSH username.",
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

_DELL_OS10_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts it at execution time.",
}

_DELL_OS10_BOOTSTRAP_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "configure_user": {
            "type": "boolean",
            "default": False,
            "description": "Create or update the RESTCONF automation user before enabling RESTCONF.",
        },
        "restconf_credential_pk": _DELL_OS10_CREDENTIAL_REF,
        "certificate_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "description": "Optional OS10 REST HTTPS server-certificate name.",
        },
        "session_timeout": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1440,
            "default": 60,
            "description": "Optional REST HTTPS session timeout in minutes.",
        },
        "cipher_suites": {
            "type": "array",
            "minItems": 1,
            "maxItems": 12,
            "items": {"type": "string", "minLength": 1, "maxLength": 80},
            "description": "Optional TLS cipher suite names passed to rest https cipher-suite.",
        },
        "enable_ssh": {"type": "boolean", "default": True},
        "enable_restconf": {"type": "boolean", "default": True},
        "write_memory": {"type": "boolean", "default": True},
        "rpc_ssh_credential_pk": _DELL_OS10_CREDENTIAL_REF,
    },
}

_DELL_OS10_EMPTY_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "rpc_ssh_credential_pk": _DELL_OS10_CREDENTIAL_REF,
    },
}

_DELL_OS10_INTERFACE_DESCRIPTION_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["interface_name", "description"],
    "additionalProperties": False,
    "properties": {
        "interface_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z][A-Za-z0-9/._:-]{0,63}$",
        },
        "description": {"type": "string", "minLength": 0, "maxLength": 240},
        "write_memory": {"type": "boolean", "default": False},
        "rpc_ssh_credential_pk": _DELL_OS10_CREDENTIAL_REF,
    },
}

_DELL_OS10_VLAN_DESCRIPTION_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["vlan_id", "description"],
    "additionalProperties": False,
    "properties": {
        "vlan_id": {"type": "integer", "minimum": 1, "maximum": 4094},
        "description": {"type": "string", "minLength": 0, "maxLength": 240},
        "write_memory": {"type": "boolean", "default": False},
        "rpc_ssh_credential_pk": _DELL_OS10_CREDENTIAL_REF,
    },
}

_DELL_OS10_VLT_SHOW_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "domain_id": {
            "type": "integer",
            "minimum": 1,
            "maximum": 255,
            "default": 1,
            "description": "VLT domain ID (default 1).",
        },
        "rpc_ssh_credential_pk": _DELL_OS10_CREDENTIAL_REF,
    },
}

_DELL_OS10_VLT_DOMAIN_PARAMS_SCHEMA = {
    "type": "object",
    "required": [
        "domain_id",
        "unit_id",
        "discovery_port_channel",
        "backup_destination",
    ],
    "additionalProperties": False,
    "properties": {
        "domain_id": {
            "type": "integer",
            "minimum": 1,
            "maximum": 255,
            "description": "VLT domain ID (1–255).",
        },
        "unit_id": {
            "type": "integer",
            "minimum": 1,
            "maximum": 2,
            "description": "This switch's VLT unit ID (1 or 2).",
        },
        "primary_priority": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535,
            "default": 32768,
            "description": "Primary election priority (default 32768; lower wins).",
        },
        "discovery_port_channel": {
            "type": "integer",
            "minimum": 1,
            "maximum": 4096,
            "description": "Port-channel ID used as the VLT interconnect link (VLTi).",
        },
        "backup_destination": {
            "type": "string",
            "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
            "description": "IPv4 address of the VLT backup link peer.",
        },
        "vlt_mac": {
            "type": "string",
            "pattern": r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$",
            "description": "Optional shared VLT MAC address (XX:XX:XX:XX:XX:XX).",
        },
        "write_memory": {
            "type": "boolean",
            "default": True,
            "description": "Persist configuration after applying (default true).",
        },
        "rpc_ssh_credential_pk": _DELL_OS10_CREDENTIAL_REF,
    },
}

_DELL_OS10_VLT_PEER_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["port_channel_id", "vlt_port_channel_id"],
    "additionalProperties": False,
    "properties": {
        "port_channel_id": {
            "type": "integer",
            "minimum": 1,
            "maximum": 4096,
            "description": "Local port-channel ID to bind as a VLT LAG.",
        },
        "vlt_port_channel_id": {
            "type": "integer",
            "minimum": 1,
            "maximum": 4096,
            "description": "VLT port-channel ID (must match on both VLT peers).",
        },
        "remove": {
            "type": "boolean",
            "default": False,
            "description": "Remove the VLT port-channel binding instead of adding it (default false).",
        },
        "write_memory": {
            "type": "boolean",
            "default": True,
            "description": "Persist configuration after applying (default true).",
        },
        "rpc_ssh_credential_pk": _DELL_OS10_CREDENTIAL_REF,
    },
}

_DELL_OS10_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
        "output": {"type": "string"},
        "fallback": {"type": "boolean"},
    },
}

DELL_OS10_S5232F_PROCEDURES = (
    {
        "name": DELL_OS10_S5232F_BOOTSTRAP_RESTCONF,
        "handler_id": DELL_OS10_S5232F_BOOTSTRAP_RESTCONF_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": True,
        "description": "Enable Dell SmartFabric OS10 RESTCONF over HTTPS with audited SSH CLI fallback.",
        "params_schema": _DELL_OS10_BOOTSTRAP_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
    },
    {
        "name": DELL_OS10_S5232F_SHOW_VERSION,
        "handler_id": DELL_OS10_S5232F_SHOW_VERSION_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Run show version on Dell SmartFabric OS10.",
        "params_schema": _DELL_OS10_EMPTY_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
    },
    {
        "name": DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION,
        "handler_id": DELL_OS10_S5232F_SET_INTERFACE_DESCRIPTION_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": True,
        "description": "Set an OS10 interface description through an audited fixed SSH procedure.",
        "params_schema": _DELL_OS10_INTERFACE_DESCRIPTION_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
    },
    {
        "name": DELL_OS10_S5232F_SET_VLAN_DESCRIPTION,
        "handler_id": DELL_OS10_S5232F_SET_VLAN_DESCRIPTION_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": True,
        "description": "Set an OS10 VLAN interface description through an audited fixed SSH procedure.",
        "params_schema": _DELL_OS10_VLAN_DESCRIPTION_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
    },
    {
        "name": DELL_OS10_S5232F_WRITE_MEMORY,
        "handler_id": DELL_OS10_S5232F_WRITE_MEMORY_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": True,
        "description": "Persist the Dell SmartFabric OS10 running configuration.",
        "params_schema": _DELL_OS10_EMPTY_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
    },
    {
        "name": DELL_OS10_S5232F_SHOW_VLT,
        "handler_id": DELL_OS10_S5232F_SHOW_VLT_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Show VLT domain status on Dell SmartFabric OS10.",
        "params_schema": _DELL_OS10_VLT_SHOW_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
    },
    {
        "name": DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN,
        "handler_id": DELL_OS10_S5232F_CONFIGURE_VLT_DOMAIN_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": True,
        "description": (
            "Configure the VLT domain on Dell SmartFabric OS10 "
            "(unit ID, priorities, backup link)."
        ),
        "params_schema": _DELL_OS10_VLT_DOMAIN_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
    },
    {
        "name": DELL_OS10_S5232F_CONFIGURE_VLT_PEER,
        "handler_id": DELL_OS10_S5232F_CONFIGURE_VLT_PEER_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": (
            "Bind or remove a port-channel as a VLT LAG on Dell SmartFabric OS10."
        ),
        "params_schema": _DELL_OS10_VLT_PEER_PARAMS_SCHEMA,
        "result_schema": _DELL_OS10_RESULT_SCHEMA,
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

_MELLANOX_CONVERT_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["proxmox_endpoint_id"],
    "additionalProperties": False,
    "properties": {
        "proxmox_endpoint_id": {
            "type": "integer",
            "minimum": 1,
            "description": "netbox-proxbox ProxmoxEndpoint id; SSH details come from its netbox-nms binding.",
        },
        "reboot": {
            "type": "boolean",
            "description": "Reboot the host automatically after conversion (default false).",
        },
        "apply_network": {
            "type": "boolean",
            "description": "Run `ifreload -a` after touching /etc/network/interfaces (default false).",
        },
        "interfaces_content": {
            "type": "string",
            "maxLength": 65536,
            "description": "Optional full /etc/network/interfaces override; empty keeps existing config and only ensures Mellanox interfaces are declared.",
        },
        "dry_run": {
            "type": "boolean",
            "description": "Discover only; make no changes (default false).",
        },
    },
}

_MELLANOX_CONVERT_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "dry_run": {"type": "boolean"},
        "nothing_to_do": {"type": "boolean"},
        "already_ethernet": {"type": "boolean"},
        "service_enabled": {"type": "boolean"},
        "reboot_required": {"type": "boolean"},
        "rebooting": {"type": "boolean"},
    },
}

# Mellanox ConnectX-3 InfiniBand -> Ethernet conversion. Seeded by migration 0008.
# Normalizer branch lives in jobs.py (_normalize_convert_mellanox_nic_execution).
MELLANOX_PROCEDURES = (
    {
        "name": LINUX_PROXMOX_CONVERT_MELLANOX_NIC,
        "handler_id": LINUX_PROXMOX_CONVERT_MELLANOX_NIC_HANDLER,
        "target_models": ["netbox_proxbox.proxmoxendpoint"],
        "effect": "destructive",
        "timeout_seconds": 1800,
        "approval_required": True,
        # RPCProcedure.description is a CharField(max_length=255); keep this short.
        "description": (
            "Convert Mellanox ConnectX-3 (mlx4) NIC ports from InfiniBand to "
            "Ethernet on a Proxmox host, persisting via modprobe and a "
            "mlx4-force-eth systemd unit, with optional network config and reboot."
        ),
        "params_schema": _MELLANOX_CONVERT_PARAMS_SCHEMA,
        "result_schema": _MELLANOX_CONVERT_RESULT_SCHEMA,
    },
)
