from netbox.api.routers import NetBoxRouter

from . import views

app_name = "netbox_rpc"

router = NetBoxRouter()
router.register("backends", views.RPCBackendViewSet)
router.register("procedures", views.RPCProcedureViewSet)
router.register("procedure-commands", views.RPCProcedureCommandViewSet)
router.register("intents", views.RPCIntentViewSet)
router.register("linux-service-allowlist", views.RPCLinuxServiceAllowlistViewSet)
router.register("executions", views.RPCExecutionViewSet)
router.register("execution-events", views.RPCExecutionEventViewSet)

urlpatterns = router.urls
