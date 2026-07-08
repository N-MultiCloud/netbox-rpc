from netbox.plugins import PluginConfig


class NetBoxRPCConfig(PluginConfig):
    name = "netbox_rpc"
    verbose_name = "NetBox RPC"
    description = "Audited RPC procedure catalog & execution framework for NetBox"
    version = "0.1.5"
    base_url = "rpc"
    author = "Emerson Felipe"
    author_email = "emerson.felipe@nmultifibra.com.br"
    # The migration graph depends on extras.0138 (ships with NetBox 4.6), so the
    # real floor is 4.6.0 despite earlier 4.5 compatibility claims.
    min_version = "4.6.0"
    max_version = "4.6.99"
    required_settings = []
    default_settings = {}

    def ready(self) -> None:
        super().ready()
        from . import jobs  # noqa: F401


config = NetBoxRPCConfig
