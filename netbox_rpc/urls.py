from django.urls import path
from django.http import HttpResponse

app_name = "netbox_rpc"


def home(request):
    return HttpResponse("NetBox RPC")


urlpatterns = [
    path("", home, name="home"),
]
