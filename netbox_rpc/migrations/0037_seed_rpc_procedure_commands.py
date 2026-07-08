"""Seed structured command rows for the audited RPC procedure catalog.

Data is intentionally inline: migrations must not import netbox_rpc constants or
runtime helper modules. Handler IDs are the stable bridge to nms-backend.
"""

from django.db import migrations


def c(
    argv,
    description="",
    *,
    step_type="shell_argv",
    mode="",
    condition="",
    negate=False,
    each="",
    continue_on_error=False,
):
    return {
        "step_type": step_type,
        "device_cli_mode": mode,
        "argv": argv,
        "description": description,
        "condition_param": condition,
        "condition_negate": negate,
        "for_each_param": each,
        "continue_on_error": continue_on_error,
    }


def cli(argv, description="", *, mode="exec", condition="", negate=False, each=""):
    return c(
        argv,
        description,
        step_type="device_cli",
        mode=mode,
        condition=condition,
        negate=negate,
        each=each,
    )


def representative(slug, description):
    return [c(["backend-orchestrated", slug], description)]


COMMANDS_BY_HANDLER_ID = {
    "network.huawei_olt_ma5800_r024.start_ont": [
        cli(["config"], "Enter Huawei configuration mode"),
        cli(
            ["interface", "gpon", "{frame}", "{slot}"],
            "Select GPON interface",
            mode="config",
        ),
        cli(["ont", "activate", "{port}", "{ont_id}"], "Activate ONT", mode="config"),
        cli(
            ["display", "ont", "info", "{port}", "{ont_id}"],
            "Read ONT status",
            mode="config",
        ),
    ],
    "network.dell_os10_s5232f_on.bootstrap_restconf": representative(
        "dell-os10-bootstrap-restconf",
        "Backend-orchestrated RESTCONF bootstrap with credential resolution.",
    ),
    "network.dell_os10_s5232f_on.show_version": [
        cli(["terminal", "length", "0"], "Disable CLI pagination"),
        cli(["show", "version"], "Read Dell OS10 version"),
    ],
    "network.dell_os10_s5232f_on.set_interface_description": [
        cli(["configure", "terminal"], "Enter configuration mode"),
        cli(["interface", "{interface_name}"], "Select interface", mode="config"),
        cli(
            ["description", "{description}"], "Set interface description", mode="config"
        ),
        cli(["exit"], "Leave interface configuration", mode="config"),
        cli(["end"], "Leave configuration mode", mode="config"),
        cli(
            ["write", "memory"],
            "Persist running configuration",
            condition="write_memory",
        ),
    ],
    "network.dell_os10_s5232f_on.set_vlan_description": [
        cli(["configure", "terminal"], "Enter configuration mode"),
        cli(["interface", "vlan", "{vlan_id}"], "Select VLAN interface", mode="config"),
        cli(["description", "{description}"], "Set VLAN description", mode="config"),
        cli(["exit"], "Leave VLAN configuration", mode="config"),
        cli(["end"], "Leave configuration mode", mode="config"),
        cli(
            ["write", "memory"],
            "Persist running configuration",
            condition="write_memory",
        ),
    ],
    "network.dell_os10_s5232f_on.write_memory": [
        cli(["write", "memory"], "Persist running configuration"),
    ],
    "network.dell_os10_s5232f_on.show_vlt": [
        cli(["terminal", "length", "0"], "Disable CLI pagination"),
        cli(["show", "vlt", "{domain_id}"], "Read VLT domain"),
        cli(["show", "vlt", "{domain_id}", "vlt-port-detail"], "Read VLT port detail"),
    ],
    "network.dell_os10_s5232f_on.configure_vlt_domain": [
        cli(["terminal", "length", "0"], "Disable CLI pagination"),
        cli(["configure", "terminal"], "Enter configuration mode"),
        cli(
            ["interface", "port-channel", "{discovery_port_channel}"],
            "Select VLTi port-channel",
            mode="config",
        ),
        cli(
            ["switchport", "mode", "trunk"],
            "Set VLTi port-channel trunk mode",
            mode="config",
        ),
        cli(["no", "shutdown"], "Enable VLTi port-channel", mode="config"),
        cli(["exit"], "Leave port-channel configuration", mode="config"),
        cli(["vlt-domain", "{domain_id}"], "Enter VLT domain", mode="config"),
        cli(
            ["discovery-interface", "port-channel", "{discovery_port_channel}"],
            "Set VLT discovery interface",
            mode="config",
        ),
        cli(
            ["primary-priority", "{primary_priority}"],
            "Set VLT priority",
            mode="config",
        ),
        cli(
            ["backup", "destination", "{backup_destination}"],
            "Set backup destination",
            mode="config",
        ),
        cli(
            ["unit-id", "{unit_id}"],
            "Set VLT unit ID",
            mode="config",
            condition="unit_id",
        ),
        cli(
            ["vlt-mac", "{vlt_mac}"], "Set VLT MAC", mode="config", condition="vlt_mac"
        ),
        cli(["exit"], "Leave VLT domain", mode="config"),
        cli(["end"], "Leave configuration mode", mode="config"),
        cli(
            ["write", "memory"],
            "Persist running configuration",
            condition="write_memory",
        ),
    ],
    "network.dell_os10_s5232f_on.configure_vlt_peer": [
        cli(["configure", "terminal"], "Enter configuration mode"),
        cli(
            ["interface", "port-channel", "{port_channel_id}"],
            "Select port-channel",
            mode="config",
        ),
        cli(
            ["no", "vlt-port-channel", "{vlt_port_channel_id}"],
            "Remove VLT port-channel binding",
            mode="config",
            condition="remove",
        ),
        cli(
            ["vlt-port-channel", "{vlt_port_channel_id}"],
            "Add VLT port-channel binding",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(["exit"], "Leave port-channel configuration", mode="config"),
        cli(["end"], "Leave configuration mode", mode="config"),
        cli(
            ["write", "memory"],
            "Persist running configuration",
            condition="write_memory",
        ),
    ],
    "network.dell_os10_s5232f_on.configure_port_channel": [
        cli(["configure", "terminal"], "Enter configuration mode", condition="remove"),
        cli(
            ["no", "interface", "port-channel", "{port_channel_id}"],
            "Remove port-channel",
            mode="config",
            condition="remove",
        ),
        cli(["end"], "Leave configuration mode", mode="config", condition="remove"),
        cli(
            ["configure", "terminal"],
            "Enter configuration mode",
            condition="remove",
            negate=True,
        ),
        cli(
            ["interface", "port-channel", "{port_channel_id}"],
            "Select port-channel",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["description", "{description}"],
            "Set port-channel description",
            mode="config",
            condition="description",
        ),
        cli(
            ["switchport", "mode", "trunk"],
            "Set trunk mode",
            mode="config",
            condition="trunk_vlans",
        ),
        cli(
            ["switchport", "trunk", "allowed", "vlan", "{trunk_vlans}"],
            "Set allowed VLANs",
            mode="config",
            condition="trunk_vlans",
        ),
        cli(
            ["no", "shutdown"],
            "Enable port-channel",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["exit"],
            "Leave port-channel configuration",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["end"],
            "Leave configuration mode",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["write", "memory"],
            "Persist running configuration",
            condition="write_memory",
        ),
    ],
    "network.dell_os10_s5232f_on.configure_interface_lacp": [
        cli(["configure", "terminal"], "Enter configuration mode", condition="remove"),
        cli(
            ["interface", "{interface_name}"],
            "Select interface",
            mode="config",
            condition="remove",
        ),
        cli(
            ["no", "channel-group"],
            "Remove channel-group binding",
            mode="config",
            condition="remove",
        ),
        cli(
            ["exit"], "Leave interface configuration", mode="config", condition="remove"
        ),
        cli(["end"], "Leave configuration mode", mode="config", condition="remove"),
        cli(
            ["configure", "terminal"],
            "Enter configuration mode",
            condition="remove",
            negate=True,
        ),
        cli(
            ["interface", "{interface_name}"],
            "Select interface",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["description", "{description}"],
            "Set member interface description",
            mode="config",
            condition="description",
        ),
        cli(
            ["channel-group", "{port_channel_id}", "mode", "{lacp_mode}"],
            "Set LACP channel-group",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["no", "shutdown"],
            "Enable member interface",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["exit"],
            "Leave interface configuration",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["end"],
            "Leave configuration mode",
            mode="config",
            condition="remove",
            negate=True,
        ),
        cli(
            ["write", "memory"],
            "Persist running configuration",
            condition="write_memory",
        ),
    ],
    "network.dell_os10_s5232f_on.configure_interface_breakout": [
        cli(["configure", "terminal"], "Enter configuration mode"),
        cli(
            ["interface", "breakout", "{interface_port}", "map", "{breakout_mode}"],
            "Set breakout mode",
            mode="config",
        ),
        cli(["end"], "Leave configuration mode", mode="config"),
        cli(
            ["write", "memory"],
            "Persist running configuration",
            condition="write_memory",
        ),
    ],
    "network.dell_os10_s5232f_on.configure_interface_fec": representative(
        "dell-os10-interface-fec",
        "Backend chooses 'fec <mode>' or 'no fec' from fec_mode.",
    ),
    "network.dell_os10_s5232f_on.allow_third_party_transceiver": [
        cli(["configure", "terminal"], "Enter configuration mode"),
        cli(
            ["allow", "unsupported-transceiver"],
            "Allow unsupported transceivers",
            mode="config",
        ),
        cli(
            ["unlock", "third-party", "transceiver"],
            "Unlock third-party transceivers",
            mode="config",
        ),
        cli(["end"], "Leave configuration mode", mode="config"),
        cli(["write", "memory"], "Persist running configuration"),
    ],
    "network.dell_os10_s5232f_on.show_version_structured": [
        cli(["show", "version"], "Read Dell OS10 version for the parser pipeline"),
    ],
    "os.linux_ubuntu_24.restart_service": [
        c(
            ["sudo", "/bin/systemctl", "restart", "{service_slug}"],
            "Restart allowlisted service",
        ),
        c(["/bin/systemctl", "is-active", "{service_slug}"], "Verify active state"),
    ],
    "os.linux_ubuntu_24.status_service": [
        c(
            ["sudo", "/bin/systemctl", "status", "--no-pager", "{service_slug}"],
            "Read systemd status",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-active", "{service_slug}"],
            "Read active state",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-enabled", "{service_slug}"],
            "Read unit file state",
        ),
    ],
    "os.linux_ubuntu_24.start_service": [
        c(
            ["sudo", "/bin/systemctl", "start", "{service_slug}"],
            "Start allowlisted service",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-active", "{service_slug}"],
            "Verify active state",
        ),
    ],
    "os.linux_ubuntu_24.stop_service": [
        c(
            ["sudo", "/bin/systemctl", "stop", "{service_slug}"],
            "Stop allowlisted service",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-active", "{service_slug}"],
            "Verify inactive state",
        ),
    ],
    "os.linux_ubuntu_24.reload_service": [
        c(
            ["sudo", "/bin/systemctl", "reload", "{service_slug}"],
            "Reload allowlisted service",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-active", "{service_slug}"],
            "Verify active state",
        ),
    ],
    "os.linux_ubuntu_24.enable_service": [
        c(
            ["sudo", "/bin/systemctl", "enable", "{service_slug}"],
            "Enable allowlisted service",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-enabled", "{service_slug}"],
            "Verify unit file state",
        ),
    ],
    "os.linux_ubuntu_24.disable_service": [
        c(
            ["sudo", "/bin/systemctl", "disable", "{service_slug}"],
            "Disable allowlisted service",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-enabled", "{service_slug}"],
            "Verify unit file state",
        ),
    ],
    "os.linux_ubuntu_24.daemon_reload": [
        c(
            ["sudo", "/bin/systemctl", "daemon-reload"],
            "Reload systemd manager configuration",
        ),
    ],
    "os.linux_ubuntu_24.journal_tail": [
        c(
            [
                "sudo",
                "/bin/journalctl",
                "-u",
                "{service_slug}",
                "-n",
                "{lines}",
                "--no-pager",
            ],
            "Read recent journal output",
        ),
    ],
    "os.linux_ubuntu_24.install_ssh_key": representative(
        "install-ssh-key",
        "Backend installs sanitized SSH public key material through stdin.",
    ),
    "os.linux_ubuntu_24.install_qemu_guest_agent": [
        c(
            ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"],
            "Refresh apt metadata",
        ),
        c(
            [
                "sudo",
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                "qemu-guest-agent",
            ],
            "Install qemu-guest-agent",
        ),
        c(
            ["sudo", "/bin/systemctl", "enable", "--now", "qemu-guest-agent"],
            "Enable and start qemu-guest-agent",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-active", "qemu-guest-agent"],
            "Read active state",
        ),
        c(
            ["sudo", "/bin/systemctl", "is-enabled", "qemu-guest-agent"],
            "Read enabled state",
        ),
    ],
    "os.linux_ubuntu_24.install_zabbix_agent2": representative(
        "install-zabbix-agent2",
        "Backend runs fixed zabbix-agent2 install/configuration script through stdin.",
    ),
    "os.linux_proxmox.convert_mellanox_nic_to_ethernet": representative(
        "mellanox-conversion",
        "Backend orchestrates destructive Mellanox conversion workflow.",
    ),
    "os.linux_proxmox.qemu_vm_lifecycle": representative(
        "proxmox-qemu-lifecycle",
        "Backend orchestrates structured Proxmox QEMU lifecycle operations.",
    ),
    "service.nginx.1.config_test": [
        c(["sudo", "/usr/sbin/nginx", "-t"], "Validate nginx configuration"),
    ],
    "service.nginx.1.config_deploy": representative(
        "nginx-config-deploy",
        "Backend writes, validates, and reloads rendered nginx config.",
    ),
    "service.nginx.1.reload": [
        c(["sudo", "/bin/systemctl", "reload", "nginx"], "Reload nginx"),
    ],
    "service.nginx.1.rollback": representative(
        "nginx-rollback",
        "Backend restores a validated nginx config snapshot and reloads nginx.",
    ),
    "os.linux.dns_host.deploy_dns_stack": representative(
        "dns-stack-deploy",
        "Backend bootstraps secrets and writes the DNS Docker Compose stack.",
    ),
    "os.linux.dns_host.status_dns_stack": [
        c(
            ["docker", "compose", "-f", "/opt/dns-stack/docker-compose.yml", "ps"],
            "Read DNS stack container status",
        ),
        c(
            [
                "docker",
                "compose",
                "-f",
                "/opt/dns-stack/docker-compose.yml",
                "logs",
                "--tail",
                "50",
            ],
            "Read recent DNS stack logs",
        ),
    ],
    "services.pterodactyl.bootstrap_api_key": representative(
        "pterodactyl-bootstrap-api-key",
        "Backend runs Pterodactyl artisan connectivity checks with fallback.",
    ),
    "services.pterodactyl.artisan": [
        c(
            [
                "docker",
                "exec",
                "{container_name}",
                "php",
                "artisan",
                "{command}",
                "--no-interaction",
            ],
            "Run allowlisted artisan command",
        ),
    ],
    "services.pterodactyl.container_logs": [
        c(
            ["docker", "logs", "--tail", "{lines}", "{container_name}"],
            "Read Pterodactyl container logs",
        ),
    ],
    "services.minecraft.plugin.install_url": representative(
        "minecraft-plugin-install-url",
        "Backend downloads and atomically installs validated plugin jar URL.",
    ),
    "services.minecraft.viaversion.install": representative(
        "minecraft-viaversion-install",
        "Backend resolves ViaVersion-family release assets and installs jars.",
    ),
    "services.minecraft.papermc.install": representative(
        "minecraft-papermc-install",
        "Backend resolves PaperMC build metadata and installs the server jar.",
    ),
    "services.pterodactyl.wings.status": [
        c(
            ["/bin/systemctl", "status", "--no-pager", "--", "wings.service"],
            "Read Wings service status",
        ),
    ],
    "services.pterodactyl.wings.logs": [
        c(
            ["/bin/journalctl", "-u", "wings.service", "-n", "{lines}", "--no-pager"],
            "Read Wings journal logs",
        ),
    ],
    "services.pterodactyl.wings.restart": [
        c(
            ["/bin/systemctl", "restart", "--", "wings.service"],
            "Restart Wings service",
        ),
    ],
    "packer.vm.test_ssh_connectivity": [
        c(["printf", "packer-ssh-ok"], "Probe SSH command execution"),
    ],
    "packer.vm.check_agent_running": [
        c(
            ["qm", "config", "{proxmox_template_id}"],
            "Check template VM agent config",
            condition="proxmox_template_id",
        ),
        c(
            ["/bin/systemctl", "is-active", "--", "qemu-guest-agent"],
            "Fallback host qemu-guest-agent check",
            condition="proxmox_template_id",
            negate=True,
        ),
    ],
    "packer.vm.verify_services": [
        c(
            ["/bin/systemctl", "is-active", "--", "{item}"],
            "Verify requested service",
            each="services",
        ),
    ],
    "packer.vm.collect_info": [
        c(["cat", "/etc/os-release"], "Read OS release"),
        c(["uname", "-a"], "Read kernel and architecture"),
    ],
    "os.linux.proxmox.pvesh_json": [
        c(
            ["pvesh", "get", "{pvesh_path}", "--output-format", "json"],
            "Read validated pvesh path as JSON",
        ),
    ],
    "os.linux.collect_facts": [
        c(["uname", "-a"], "Read kernel and architecture"),
        c(["hostname", "--fqdn"], "Read FQDN"),
        c(["cat", "/etc/os-release"], "Read OS release"),
    ],
    "os.linux.ubuntu.24.ookla.diagnose": representative(
        "ookla-diagnose",
        "Backend runs service, listener, TLS, and firewall probe scripts.",
    ),
    "os.linux.ubuntu.24.ookla.check_service": representative(
        "ookla-check-service",
        "Backend runs fixed Ookla discovery and service/config parser.",
    ),
    "os.linux.ubuntu.24.ookla.check_listeners": representative(
        "ookla-check-listeners",
        "Backend runs fixed Ookla listener probe script.",
    ),
    "os.linux.ubuntu.24.ookla.check_tls": representative(
        "ookla-check-tls",
        "Backend runs fixed Ookla TLS certificate and live probe scripts.",
    ),
    "os.linux.ubuntu.24.ookla.check_firewall": representative(
        "ookla-check-firewall",
        "Backend runs fixed firewall-state probe scripts.",
    ),
}


def _seed_rpc_procedure_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")

    for handler_id, steps in COMMANDS_BY_HANDLER_ID.items():
        for procedure in RPCProcedure.objects.filter(handler_id=handler_id):
            for index, step in enumerate(steps, start=1):
                RPCProcedureCommand.objects.update_or_create(
                    procedure=procedure,
                    sequence=index,
                    defaults=step,
                )


def _remove_rpc_procedure_commands(apps, schema_editor):
    RPCProcedure = apps.get_model("netbox_rpc", "RPCProcedure")
    RPCProcedureCommand = apps.get_model("netbox_rpc", "RPCProcedureCommand")
    procedures = RPCProcedure.objects.filter(handler_id__in=COMMANDS_BY_HANDLER_ID)
    RPCProcedureCommand.objects.filter(procedure__in=procedures).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0036_rpcprocedurecommand"),
    ]

    operations = [
        migrations.RunPython(
            _seed_rpc_procedure_commands,
            reverse_code=_remove_rpc_procedure_commands,
        ),
    ]
