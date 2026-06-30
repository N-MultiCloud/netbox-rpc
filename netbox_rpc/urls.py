from django.urls import include, path
from utilities.urls import get_model_urls

from . import views  # noqa: F401 — imports @register_model_view decorators

_MODEL_ROUTES = (
    ("rpcbackend", "backends"),
    ("rpcprocedure", "procedures"),
    ("rpclinuxserviceallowlist", "linux-service-allowlist"),
    ("rpcexecution", "executions"),
    ("rpcexecutionevent", "execution-events"),
)

urlpatterns = []

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
