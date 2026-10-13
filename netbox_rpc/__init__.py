from netbox.plugins import PluginConfig


class NetBoxRPCConfig(PluginConfig):
    name = "netbox_rpc"
    verbose_name = "NetBox RPC"
    description = "Audited RPC procedure catalog & execution framework for NetBox"
    version = "0.1.9rc2"
    base_url = "rpc"
    author = "Emerson Felipe"
    author_email = "emerson.felipe@nmultifibra.com.br"
    min_version = "4.5.8"
    max_version = "4.7.99"
    required_settings = []
    default_settings = {}
    queues = ["control"]

    def ready(self) -> None:
        super().ready()
        from . import (  # noqa: F401
            jobs,
            system_jobs,
        )


config = NetBoxRPCConfig
