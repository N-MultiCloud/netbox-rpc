from netbox.plugins import PluginConfig


class NetBoxRPCConfig(PluginConfig):
    name = "netbox_rpc"
    verbose_name = "NetBox RPC"
    description = "Audited RPC procedure catalog for SSH-backed NMS operations"
    version = "0.1.5"
    base_url = "rpc"
    author = "Emerson Felipe"
    author_email = "emerson.felipe@nmultifibra.com.br"
    min_version = "4.5.0"
    max_version = "4.6.99"
    required_plugins = ["netbox_nms"]
    required_settings = []
    default_settings = {}

    def ready(self) -> None:
        super().ready()
        from . import jobs  # noqa: F401


config = NetBoxRPCConfig
