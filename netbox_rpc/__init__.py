from netbox.plugins import PluginConfig


class NetBoxRPCConfig(PluginConfig):
    name = "netbox_rpc"
    verbose_name = "NetBox RPC"
    description = "Audited RPC procedure catalog & execution framework for NetBox"
    version = "0.1.5"
    base_url = "rpc"
    author = "Emerson Felipe"
    author_email = "emerson.felipe@nmultifibra.com.br"
    # Migration dependencies target anchors present in both NetBox 4.5.8 and 4.6.x.
    min_version = "4.5.8"
    max_version = "4.6.99"
    required_settings = []
    default_settings = {}

    def ready(self) -> None:
        super().ready()
        from . import jobs  # noqa: F401


config = NetBoxRPCConfig
