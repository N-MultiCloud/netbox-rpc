from netbox.choices import ButtonColorChoices
from netbox.plugins.navigation import PluginMenu, PluginMenuButton, PluginMenuItem

menu = PluginMenu(
    label="RPC",
    groups=(
        (
            "Procedures",
            (
                PluginMenuItem(
                    link="plugins:netbox_rpc:rpcbackend_list",
                    link_text="Backends",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_rpc:rpcbackend_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            color=ButtonColorChoices.GREEN,
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_rpc:rpcprocedure_list",
                    link_text="Procedures",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_rpc:rpcprocedure_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            color=ButtonColorChoices.GREEN,
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_rpc:rpclinuxserviceallowlist_list",
                    link_text="Linux Service Allowlist",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_rpc:rpclinuxserviceallowlist_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            color=ButtonColorChoices.GREEN,
                        ),
                    ),
                ),
            ),
        ),
        (
            "Operations",
            (
                PluginMenuItem(
                    link="plugins:netbox_rpc:rpcexecution_list",
                    link_text="Executions",
                ),
                PluginMenuItem(
                    link="plugins:netbox_rpc:rpcexecutionevent_list",
                    link_text="Events",
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-remote",
)
