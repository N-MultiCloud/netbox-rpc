from django.urls import include, path
from utilities.urls import get_model_urls

from . import views  # noqa: F401 — imports @register_model_view decorators

_MODEL_ROUTES = (
    ("rpcbackend", "backends"),
    ("rpcprocedure", "procedures"),
    ("rpcintent", "intents"),
    ("rpclinuxserviceallowlist", "linux-service-allowlist"),
    ("rpcexecution", "executions"),
    ("rpcexecutionevent", "execution-events"),
    ("rpcpluginsettings", "settings"),
)

urlpatterns = [
    # Landing/status page for /plugins/rpc/.
    path("", views.RPCHomeView.as_view(), name="home"),
    # Opt-in settings singleton: always edit the one row (create-on-first-visit).
    path(
        "settings/edit/",
        views.rpc_settings_singleton_redirect,
        name="rpcpluginsettings_singleton_edit",
    ),
    # Best-effort backend reachability probe (POST) for the Test-connection button.
    path(
        "settings/test-connection/",
        views.RpcBackendTestConnectionView.as_view(),
        name="rpcpluginsettings_test_connection",
    ),
]

for _model_name, _slug in _MODEL_ROUTES:
    urlpatterns += [
        path(
            f"{_slug}/",
            include(get_model_urls("netbox_rpc", _model_name, detail=False)),
        ),
        path(
            f"{_slug}/<int:pk>/",
            include(get_model_urls("netbox_rpc", _model_name)),
        ),
    ]
