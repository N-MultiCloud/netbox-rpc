from netbox.plugins import PluginConfig

from .release_guard import validate_netbox_release


class NetBoxRPCConfig(PluginConfig):
    name = "netbox_rpc"
    verbose_name = "NetBox RPC"
    description = "Audited RPC procedure catalog & execution framework for NetBox"
    version = "0.1.7"
    base_url = "rpc"
    author = "Emerson Felipe"
    author_email = "emerson.felipe@nmultifibra.com.br"
    min_version = "4.5.8"
    max_version = "4.7.0"
    approved_netbox_version = "4.7.0"
    approved_netbox_designation = None
    required_settings = []
    default_settings = {}

    @classmethod
    def validate(cls, user_config: dict, netbox_version: str) -> None:
        """Enforce the reviewed NetBox 4.7.0 GA release identity."""
        super().validate(user_config, netbox_version)
        validate_netbox_release(cls, netbox_version)

    def ready(self) -> None:
        super().ready()
        from . import jobs  # noqa: F401


config = NetBoxRPCConfig
