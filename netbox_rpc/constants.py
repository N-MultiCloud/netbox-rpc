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
DELL_OS10_S5232F_ALLOW_THIRD_PARTY_TRANSCEIVER = (
    "network.device.dell_os10.s5232f_on.allow_third_party_transceiver"
)
DELL_OS10_S5232F_ALLOW_THIRD_PARTY_TRANSCEIVER_HANDLER = (
    "network.dell_os10_s5232f_on.allow_third_party_transceiver"
)

# Pterodactyl Panel management via docker-exec on the host. Seeded by migration 0016.
PTERODACTYL_BOOTSTRAP_API_KEY = "services.pterodactyl.bootstrap_api_key"
PTERODACTYL_BOOTSTRAP_API_KEY_HANDLER = "services.pterodactyl.bootstrap_api_key"
PTERODACTYL_ARTISAN = "services.pterodactyl.artisan"
PTERODACTYL_ARTISAN_HANDLER = "services.pterodactyl.artisan"
PTERODACTYL_CONTAINER_LOGS = "services.pterodactyl.container_logs"
PTERODACTYL_CONTAINER_LOGS_HANDLER = "services.pterodactyl.container_logs"
PTERODACTYL_WINGS_STATUS = "services.pterodactyl.wings.status"
PTERODACTYL_WINGS_STATUS_HANDLER = "services.pterodactyl.wings.status"
PTERODACTYL_WINGS_LOGS = "services.pterodactyl.wings.logs"
PTERODACTYL_WINGS_LOGS_HANDLER = "services.pterodactyl.wings.logs"
PTERODACTYL_WINGS_RESTART = "services.pterodactyl.wings.restart"
PTERODACTYL_WINGS_RESTART_HANDLER = "services.pterodactyl.wings.restart"

MINECRAFT_PLUGIN_INSTALL_URL = "services.minecraft.plugin.install_url"
MINECRAFT_PLUGIN_INSTALL_URL_HANDLER = "services.minecraft.plugin.install_url"
MINECRAFT_VIAVERSION_INSTALL = "services.minecraft.viaversion.install"
MINECRAFT_VIAVERSION_INSTALL_HANDLER = "services.minecraft.viaversion.install"
MINECRAFT_PAPERMC_INSTALL = "services.minecraft.papermc.install"
MINECRAFT_PAPERMC_INSTALL_HANDLER = "services.minecraft.papermc.install"

DNS_HOST_DEPLOY_PROCEDURE = "os.linux.dns_host.deploy_dns_stack"
DNS_HOST_STATUS_PROCEDURE = "os.linux.dns_host.status_dns_stack"

# SSH key installation — appends a public key to authorized_keys on a target host
# using the device's existing privileged SSH DeviceService credential.
LINUX_INSTALL_SSH_KEY = "os.linux.ubuntu.24.install_ssh_key"
LINUX_INSTALL_SSH_KEY_HANDLER = "os.linux_ubuntu_24.install_ssh_key"
LINUX_INSTALL_QEMU_GUEST_AGENT = "os.linux.ubuntu.24.install_qemu_guest_agent"
LINUX_INSTALL_QEMU_GUEST_AGENT_HANDLER = "os.linux_ubuntu_24.install_qemu_guest_agent"
LINUX_INSTALL_ZABBIX_AGENT2 = "os.linux.ubuntu.24.install_zabbix_agent2"
LINUX_INSTALL_ZABBIX_AGENT2_HANDLER = "os.linux_ubuntu_24.install_zabbix_agent2"

# Mellanox ConnectX-3 (mlx4) InfiniBand -> Ethernet conversion on a Proxmox host.
# Targets a netbox-proxbox ProxmoxEndpoint; SSH connection details are resolved
# through the netbox-nms ProxmoxEndpointSSHBinding (see jobs.py normalizer).
LINUX_PROXMOX_CONVERT_MELLANOX_NIC = "os.linux.proxmox.convert_mellanox_nic_to_ethernet"
LINUX_PROXMOX_CONVERT_MELLANOX_NIC_HANDLER = (
    "os.linux_proxmox.convert_mellanox_nic_to_ethernet"
)
LINUX_PROXMOX_QEMU_VM_LIFECYCLE = "os.linux.proxmox.qemu_vm_lifecycle"
LINUX_PROXMOX_QEMU_VM_LIFECYCLE_HANDLER = "os.linux_proxmox.qemu_vm_lifecycle"

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

_RPC_SSH_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "DeviceCredential primary key; nms-backend decrypts it at execution time.",
}

_RPC_SSH_OVERRIDE_PROPERTIES = {
    "rpc_ssh_credential_pk": _RPC_SSH_CREDENTIAL_REF,
    "rpc_ssh_host": {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "description": "Optional SSH host override consumed by nms-backend.",
    },
    "rpc_ssh_port": {
        "type": "integer",
        "minimum": 1,
        "maximum": 65535,
        "description": "Optional SSH port override consumed by nms-backend.",
    },
    "rpc_ssh_known_hosts_entry": {
        "type": "string",
        "description": "Optional known_hosts line consumed by nms-backend.",
    },
    "rpc_ssh_strict_host_key_checking": {
        "type": "boolean",
        "description": "Optional strict host-key checking override consumed by nms-backend.",
    },
}

_MINECRAFT_SERVER_UUID = {
    "type": "string",
    "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    "description": "Pterodactyl server UUID; used to locate the Wings volume.",
}

_MINECRAFT_JAR_FILENAME = {
    "type": "string",
    "minLength": 5,
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9._-]+\\.jar$",
    "description": "Safe JAR filename. Path separators and traversal are not allowed.",
}

_MINECRAFT_BOOLEAN_RESTART = {
    "type": "boolean",
    "default": False,
    "description": "Restart the affected server or service after the install.",
}

_MINECRAFT_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "server_uuid": {"type": "string"},
        "output": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
    },
}

_MINECRAFT_PLUGIN_INSTALL_URL_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["server_uuid", "source_url", "filename"],
    "additionalProperties": False,
    "properties": {
        "server_uuid": _MINECRAFT_SERVER_UUID,
        "source_url": {
            "type": "string",
            "minLength": 1,
            "maxLength": 2048,
            "pattern": "^https?://",
            "description": "Public http(s) URL for a plugin JAR.",
        },
        "filename": _MINECRAFT_JAR_FILENAME,
        "restart": _MINECRAFT_BOOLEAN_RESTART,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_MINECRAFT_VIAVERSION_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["server_uuid"],
    "additionalProperties": False,
    "properties": {
        "server_uuid": _MINECRAFT_SERVER_UUID,
        "preset": {
            "type": "string",
            "enum": ["minimal", "standard", "full"],
            "default": "standard",
            "description": "ViaVersion install preset.",
        },
        "plugins": {
            "type": "array",
            "minItems": 1,
            "maxItems": 3,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "enum": ["viaversion", "viabackwards", "viarewind"],
            },
            "description": "Explicit ViaVersion-family plugin set; overrides preset.",
        },
        "restart": _MINECRAFT_BOOLEAN_RESTART,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_MINECRAFT_PAPERMC_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["server_uuid", "project", "version"],
    "additionalProperties": False,
    "properties": {
        "server_uuid": _MINECRAFT_SERVER_UUID,
        "project": {
            "type": "string",
            "enum": ["paper", "folia", "velocity"],
            "description": "PaperMC Fill project.",
        },
        "version": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9._+-]+$",
            "description": "Minecraft/PaperMC version identifier.",
        },
        "build_id": {
            "type": "integer",
            "minimum": 1,
            "description": "Optional exact PaperMC build id; omitted means latest stable.",
        },
        "server_jarfile": {
            **_MINECRAFT_JAR_FILENAME,
            "default": "server.jar",
            "description": "Server root JAR filename.",
        },
        "restart": _MINECRAFT_BOOLEAN_RESTART,
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_PTERODACTYL_WINGS_SERVICE_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": _RPC_SSH_OVERRIDE_PROPERTIES,
}

_PTERODACTYL_WINGS_LOGS_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "lines": {
            "type": "integer",
            "minimum": 1,
            "maximum": 500,
            "default": 100,
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

MINECRAFT_STACK_PROCEDURES = (
    {
        "name": MINECRAFT_PLUGIN_INSTALL_URL,
        "handler_id": MINECRAFT_PLUGIN_INSTALL_URL_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 180,
        "approval_required": False,
        "description": "Install a plugin JAR into a Pterodactyl Wings server volume from a validated URL over SSH.",
        "params_schema": _MINECRAFT_PLUGIN_INSTALL_URL_PARAMS_SCHEMA,
        "result_schema": _MINECRAFT_RESULT_SCHEMA,
    },
    {
        "name": MINECRAFT_VIAVERSION_INSTALL,
        "handler_id": MINECRAFT_VIAVERSION_INSTALL_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 240,
        "approval_required": False,
        "description": "Install ViaVersion, ViaBackwards, and/or ViaRewind into a Wings server volume over SSH.",
        "params_schema": _MINECRAFT_VIAVERSION_PARAMS_SCHEMA,
        "result_schema": _MINECRAFT_RESULT_SCHEMA,
    },
    {
        "name": MINECRAFT_PAPERMC_INSTALL,
        "handler_id": MINECRAFT_PAPERMC_INSTALL_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 240,
        "approval_required": False,
        "description": "Install a PaperMC, Folia, or Velocity server JAR into a Wings server volume over SSH.",
        "params_schema": _MINECRAFT_PAPERMC_PARAMS_SCHEMA,
        "result_schema": _MINECRAFT_RESULT_SCHEMA,
    },
    {
        "name": PTERODACTYL_WINGS_STATUS,
        "handler_id": PTERODACTYL_WINGS_STATUS_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Read Pterodactyl Wings service status over SSH.",
        "params_schema": _PTERODACTYL_WINGS_SERVICE_PARAMS_SCHEMA,
        "result_schema": _MINECRAFT_RESULT_SCHEMA,
    },
    {
        "name": PTERODACTYL_WINGS_LOGS,
        "handler_id": PTERODACTYL_WINGS_LOGS_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "read",
        "timeout_seconds": 30,
        "approval_required": False,
        "description": "Fetch recent Pterodactyl Wings journal logs over SSH.",
        "params_schema": _PTERODACTYL_WINGS_LOGS_PARAMS_SCHEMA,
        "result_schema": _MINECRAFT_RESULT_SCHEMA,
    },
    {
        "name": PTERODACTYL_WINGS_RESTART,
        "handler_id": PTERODACTYL_WINGS_RESTART_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 60,
        "approval_required": True,
        "description": "Restart Pterodactyl Wings over SSH. This can interrupt game server management.",
        "params_schema": _PTERODACTYL_WINGS_SERVICE_PARAMS_SCHEMA,
        "result_schema": _MINECRAFT_RESULT_SCHEMA,
    },
)

_LINUX_AGENT_BASE_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": _RPC_SSH_OVERRIDE_PROPERTIES,
}

_ZABBIX_SERVER_PATTERN = (
    "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?$"
)

_LINUX_INSTALL_ZABBIX_AGENT2_PARAMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "zabbix_server": {
            "type": "string",
            "minLength": 1,
            "maxLength": 253,
            "pattern": _ZABBIX_SERVER_PATTERN,
            "default": "zabbix.nmulti.cloud",
            "description": "Zabbix server endpoint configured in zabbix_agent2.conf.",
        },
        **_RPC_SSH_OVERRIDE_PROPERTIES,
    },
}

_LINUX_AGENT_INSTALL_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "installed": {"type": "boolean"},
        "active": {"type": "string"},
        "enabled": {"type": "string"},
        "zabbix_server": {"type": "string"},
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

_DNS_HOST_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "netbox-nms DeviceCredential PK; nms-backend decrypts it at execution time.",
}

_DNS_HOST_TARGET = {
    "type": "string",
    "minLength": 1,
    "maxLength": 63,
    "pattern": "^[A-Za-z0-9][A-Za-z0-9-]{0,62}$",
    "description": "Short DNS host target, e.g. dns01 or dns02.",
}

_DNS_HOST_SSH_HOST_OVERRIDE = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "description": "Optional SSH host override; defaults to <target>.nmulti.cloud.",
}

_DNS_HOST_SSH_PORT_OVERRIDE = {
    "type": "integer",
    "minimum": 1,
    "maximum": 65535,
    "default": 22,
    "description": "Optional SSH port override.",
}

_DNS_HOST_KNOWN_HOSTS_ENTRY = {
    "type": "string",
    "maxLength": 8192,
    "description": "Optional OpenSSH known_hosts entry for the target host.",
}

_DNS_HOST_BASE_PARAMS_PROPERTIES = {
    "rpc_ssh_credential_pk": _DNS_HOST_CREDENTIAL_REF,
    "target": _DNS_HOST_TARGET,
    "rpc_ssh_host": _DNS_HOST_SSH_HOST_OVERRIDE,
    "rpc_ssh_port": _DNS_HOST_SSH_PORT_OVERRIDE,
    "rpc_ssh_known_hosts_entry": _DNS_HOST_KNOWN_HOSTS_ENTRY,
    "rpc_ssh_strict_host_key_checking": {
        "type": "boolean",
        "default": True,
        "description": "Require host-key verification when connecting over SSH.",
    },
}

_DNS_HOST_STATUS_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk", "target"],
    "additionalProperties": False,
    "properties": _DNS_HOST_BASE_PARAMS_PROPERTIES,
}

_DNS_HOST_DEPLOY_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk", "target"],
    "additionalProperties": False,
    "properties": {
        **_DNS_HOST_BASE_PARAMS_PROPERTIES,
        "force_recreate": {
            "type": "boolean",
            "default": False,
            "description": "Recreate containers even when Compose detects no changes.",
        },
    },
}

_DNS_HOST_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "compose_project": {"type": "string"},
        "output": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
    },
}

DNS_HOST_PROCEDURES = (
    {
        "name": DNS_HOST_DEPLOY_PROCEDURE,
        "handler_id": DNS_HOST_DEPLOY_PROCEDURE,
        "target_models": [],
        "effect": "write",
        "timeout_seconds": 180,
        "approval_required": True,
        "description": "Deploy or update the PowerDNS and dns-api Docker Compose stack on a DNS host.",
        "params_schema": _DNS_HOST_DEPLOY_PARAMS_SCHEMA,
        "result_schema": _DNS_HOST_RESULT_SCHEMA,
    },
    {
        "name": DNS_HOST_STATUS_PROCEDURE,
        "handler_id": DNS_HOST_STATUS_PROCEDURE,
        "target_models": [],
        "effect": "read",
        "timeout_seconds": 60,
        "approval_required": False,
        "description": "Read status for the PowerDNS and dns-api Docker Compose stack on a DNS host.",
        "params_schema": _DNS_HOST_STATUS_PARAMS_SCHEMA,
        "result_schema": _DNS_HOST_RESULT_SCHEMA,
    },
)

LINUX_AGENT_INSTALL_PROCEDURES = (
    {
        "name": LINUX_INSTALL_QEMU_GUEST_AGENT,
        "handler_id": LINUX_INSTALL_QEMU_GUEST_AGENT_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 300,
        "approval_required": False,
        "description": "Install and enable the QEMU Guest Agent over SSH (no rebuild).",
        "params_schema": _LINUX_AGENT_BASE_PARAMS_SCHEMA,
        "result_schema": _LINUX_AGENT_INSTALL_RESULT_SCHEMA,
    },
    {
        "name": LINUX_INSTALL_ZABBIX_AGENT2,
        "handler_id": LINUX_INSTALL_ZABBIX_AGENT2_HANDLER,
        "target_models": ["dcim.device", "virtualization.virtualmachine"],
        "effect": "write",
        "timeout_seconds": 600,
        "approval_required": False,
        "description": "Install and configure Zabbix Agent 2 (ServerActive/Server) over SSH (no rebuild).",
        "params_schema": _LINUX_INSTALL_ZABBIX_AGENT2_PARAMS_SCHEMA,
        "result_schema": _LINUX_AGENT_INSTALL_RESULT_SCHEMA,
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

# ---------------------------------------------------------------------------
# netbox-packer post-build verification procedures (read-only). Seeded by
# migration 0012. The normalizer lives in packer_normalizer.py, which
# lazy-imports netbox_packer ONLY at execution time.
#
# Dependency direction (hard constraint): netbox-rpc -> netbox-packer is a
# one-way SOFT dependency (string target_models + lazy import). netbox-packer
# MUST NOT reference netbox-rpc in any way. netbox-rpc never imports
# netbox_packer at module top level so NetBox still boots when netbox-packer is
# absent; only an actual packer.vm.* execution touches it.
# ---------------------------------------------------------------------------

# Lowercase Django content-type label (app_label.model). It must be lowercase to
# match RPCExecution.target_model_label and the /procedures/available/
# ?target_type= filter used by the nms packer UI.
PACKER_TEMPLATE_TARGET_MODEL = "netbox_packer.packertemplate"

PACKER_VM_TEST_SSH = "packer.vm.test_ssh_connectivity"
PACKER_VM_TEST_SSH_HANDLER = "packer.vm.test_ssh_connectivity"
PACKER_VM_CHECK_AGENT = "packer.vm.check_agent_running"
PACKER_VM_CHECK_AGENT_HANDLER = "packer.vm.check_agent_running"
PACKER_VM_VERIFY_SERVICES = "packer.vm.verify_services"
PACKER_VM_VERIFY_SERVICES_HANDLER = "packer.vm.verify_services"
PACKER_VM_COLLECT_INFO = "packer.vm.collect_info"
PACKER_VM_COLLECT_INFO_HANDLER = "packer.vm.collect_info"

# All packer.vm.* procedure names, used by the jobs.py dispatch and tests.
PACKER_PROCEDURE_NAMES = frozenset(
    {
        PACKER_VM_TEST_SSH,
        PACKER_VM_CHECK_AGENT,
        PACKER_VM_VERIFY_SERVICES,
        PACKER_VM_COLLECT_INFO,
    }
)

# DeviceCredential PK reference: nms-backend decrypts it at execution time and
# uses it together with rpc_ssh_host to reach the Proxmox node that holds the
# built template. A PackerTemplate has no ProxmoxEndpoint reference, so SSH is
# resolved from this explicit credential plus the template's proxmox_node
# (overridable with ssh_host), NOT via a ProxmoxEndpointSSHBinding.
_PACKER_CREDENTIAL_REF = {
    "type": "integer",
    "minimum": 1,
    "description": "netbox-nms DeviceCredential PK; nms-backend decrypts it at execution time.",
}

_PACKER_SSH_HOST_OVERRIDE = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "description": "Optional SSH host override; defaults to the template's proxmox_node.",
}

_PACKER_SSH_PORT_OVERRIDE = {
    "type": "integer",
    "minimum": 1,
    "maximum": 65535,
    "description": "Optional SSH port override (default 22).",
}

_PACKER_BASE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk"],
    "additionalProperties": False,
    "properties": {
        "rpc_ssh_credential_pk": _PACKER_CREDENTIAL_REF,
        "ssh_host": _PACKER_SSH_HOST_OVERRIDE,
        "ssh_port": _PACKER_SSH_PORT_OVERRIDE,
    },
}

_PACKER_VERIFY_SERVICES_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["rpc_ssh_credential_pk"],
    "additionalProperties": False,
    "properties": {
        "rpc_ssh_credential_pk": _PACKER_CREDENTIAL_REF,
        "ssh_host": _PACKER_SSH_HOST_OVERRIDE,
        "ssh_port": _PACKER_SSH_PORT_OVERRIDE,
        "services": {
            "type": "array",
            "maxItems": 32,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100,
                # systemd unit-name safe charset; the normalizer re-validates.
                "pattern": r"^[A-Za-z0-9_.@:-]+$",
            },
            "description": "Optional systemd unit names to check; empty checks a default set.",
        },
    },
}

_PACKER_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "command_log": {"type": "array", "items": {"type": "string"}},
        "output": {"type": "string"},
    },
}

PACKER_PROCEDURES = (
    {
        "name": PACKER_VM_TEST_SSH,
        "handler_id": PACKER_VM_TEST_SSH_HANDLER,
        "target_models": [PACKER_TEMPLATE_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Test SSH connectivity to the Proxmox node that built a packer template.",
        "params_schema": _PACKER_BASE_PARAMS_SCHEMA,
        "result_schema": _PACKER_RESULT_SCHEMA,
    },
    {
        "name": PACKER_VM_CHECK_AGENT,
        "handler_id": PACKER_VM_CHECK_AGENT_HANDLER,
        "target_models": [PACKER_TEMPLATE_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Verify the QEMU guest agent is responsive on a packer template's node.",
        "params_schema": _PACKER_BASE_PARAMS_SCHEMA,
        "result_schema": _PACKER_RESULT_SCHEMA,
    },
    {
        "name": PACKER_VM_VERIFY_SERVICES,
        "handler_id": PACKER_VM_VERIFY_SERVICES_HANDLER,
        "target_models": [PACKER_TEMPLATE_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Check that cloud-init systemd services are running for a packer template.",
        "params_schema": _PACKER_VERIFY_SERVICES_PARAMS_SCHEMA,
        "result_schema": _PACKER_RESULT_SCHEMA,
    },
    {
        "name": PACKER_VM_COLLECT_INFO,
        "handler_id": PACKER_VM_COLLECT_INFO_HANDLER,
        "target_models": [PACKER_TEMPLATE_TARGET_MODEL],
        "effect": "read",
        "timeout_seconds": 120,
        "approval_required": False,
        "description": "Collect OS information from a packer template's Proxmox node.",
        "params_schema": _PACKER_BASE_PARAMS_SCHEMA,
        "result_schema": _PACKER_RESULT_SCHEMA,
    },
)

_PROXMOX_QEMU_VM_LIFECYCLE_PARAMS_SCHEMA = {
    "type": "object",
    "required": ["proxmox_endpoint_id", "operations"],
    "additionalProperties": False,
    "properties": {
        "proxmox_endpoint_id": {
            "type": "integer",
            "minimum": 1,
            "description": "netbox-proxbox ProxmoxEndpoint id; SSH details come from its netbox-nms binding.",
        },
        "operations": {
            "type": "array",
            "minItems": 1,
            "maxItems": 10,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "enum": [
                    "clone",
                    "nextid",
                    "migrate",
                    "configure",
                    "resize",
                    "start",
                    "stop",
                    "status",
                    "agent_ping",
                    "agent_network_get_interfaces",
                    "agent_configure_debian_network",
                    "agent_set_user_password",
                    "agent_pbs_zabbix_status",
                    "agent_configure_zabbix_agent2",
                ],
            },
        },
        "vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
        "template_vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 63,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$",
        },
        "source_node": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
        },
        "node": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
        },
        "target_node": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
        },
        "storage": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
        },
        "target_storage": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
        },
        "full_clone": {"type": "boolean", "default": True},
        "agent_enabled": {"type": "boolean", "default": True},
        "memory_mb": {"type": "integer", "minimum": 128, "maximum": 1048576},
        "cores": {"type": "integer", "minimum": 1, "maximum": 512},
        "ciuser": {
            "type": "string",
            "minLength": 1,
            "maxLength": 32,
            "pattern": "^[a-z_][a-z0-9_-]{0,31}$",
        },
        "search_domain": {
            "type": "string",
            "minLength": 1,
            "maxLength": 253,
            "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?$",
            "description": "Cloud-init DNS search domain passed to Proxmox as searchdomain.",
        },
        "dns_servers": {
            "type": "array",
            "maxItems": 3,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 45,
                "pattern": "^[0-9A-Fa-f:.]+$",
            },
            "description": "Ordered DNS resolvers passed to Proxmox as nameserver.",
        },
        "networks": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "required": ["index", "bridge"],
                "additionalProperties": False,
                "properties": {
                    "index": {"type": "integer", "minimum": 0, "maximum": 31},
                    "model": {
                        "type": "string",
                        "enum": ["virtio", "e1000", "e1000e", "vmxnet3", "rtl8139"],
                        "default": "virtio",
                    },
                    "bridge": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$",
                    },
                    "tag": {"type": "integer", "minimum": 1, "maximum": 4094},
                    "firewall": {"type": "boolean"},
                },
            },
        },
        "ipconfigs": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "required": ["index", "ip"],
                "additionalProperties": False,
                "properties": {
                    "index": {"type": "integer", "minimum": 0, "maximum": 31},
                    "ip": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[^\\s,]+$",
                    },
                    "gw": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[^\\s,]+$",
                    },
                },
            },
        },
        "guest_networks": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "required": ["interface", "address"],
                "additionalProperties": False,
                "properties": {
                    "interface": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 32,
                        "pattern": "^[A-Za-z][A-Za-z0-9_.:-]{0,31}$",
                    },
                    "address": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[^\\s,]+$",
                    },
                    "gateway": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[^\\s,]+$",
                    },
                },
            },
        },
        "guest_credential_pk": {
            "type": "integer",
            "minimum": 1,
            "description": (
                "netbox-nms DeviceCredential id used by nms-backend to resolve "
                "the guest username/password server-side."
            ),
        },
        "zabbix_server": {
            "type": "string",
            "minLength": 1,
            "maxLength": 253,
            "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?$",
            "default": "zabbix.nmulti.cloud",
            "description": "Zabbix server endpoint configured in zabbix_agent2.conf.",
        },
        "resize_disk": {
            "type": "string",
            "pattern": "^(scsi|virtio|sata|ide)[0-9]+$",
            "default": "scsi0",
        },
        "disk_gb": {"type": "integer", "minimum": 1, "maximum": 262144},
    },
}

_PROXMOX_QEMU_VM_LIFECYCLE_RESULT_SCHEMA = {
    "type": "object",
    "required": ["ok", "procedure", "target", "vmid"],
    "properties": {
        "ok": {"type": "boolean"},
        "procedure": {"type": "string"},
        "target": {"type": "string"},
        "vmid": {"type": "integer"},
        "operations": {"type": "array", "items": {"type": "string"}},
        "steps": {"type": "array"},
        "nextid": {"type": "integer"},
        "status": {"type": "object"},
        "agent_network_interfaces": {"type": "array"},
        "pbs_guest_status": {"type": "object"},
    },
}

PROXMOX_QEMU_PROCEDURES = (
    {
        "name": LINUX_PROXMOX_QEMU_VM_LIFECYCLE,
        "handler_id": LINUX_PROXMOX_QEMU_VM_LIFECYCLE_HANDLER,
        "target_models": ["netbox_proxbox.proxmoxendpoint"],
        "effect": "destructive",
        "timeout_seconds": 3600,
        "approval_required": True,
        "description": (
            "Run audited Proxmox QEMU lifecycle actions, including clone, "
            "migrate, configure, resize, power, QGA checks, Debian guest "
            "network/password repair, and PBS Zabbix Agent 2 status/configure."
        ),
        "params_schema": _PROXMOX_QEMU_VM_LIFECYCLE_PARAMS_SCHEMA,
        "result_schema": _PROXMOX_QEMU_VM_LIFECYCLE_RESULT_SCHEMA,
    },
)
