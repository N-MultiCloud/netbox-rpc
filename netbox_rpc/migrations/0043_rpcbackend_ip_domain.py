import django.core.validators
import django.db.models.deletion
from django.db import migrations, models

_DOMAIN_HELP = "Domain name of the netbox-rpc-backend service."
_PORT_HELP = "TCP port of the netbox-rpc-backend service."
_HTTPS_HELP = "Compose the backend URL with https instead of http."
_IP_HELP = "Fallback backend address used when no domain name is set."
_BASE_URL_HELP = (
    "Optional explicit URL override. When set it wins; when empty the URL is "
    "composed from the IP address / domain, port, and HTTPS flag above."
)


class Migration(migrations.Migration):
    dependencies = [
        ("ipam", "0001_initial"),
        ("netbox_rpc", "0042_rpcprocedure_transport_driver_chain"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpcbackend",
            name="ip_address",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="+",
                to="ipam.ipaddress",
                help_text=_IP_HELP,
                verbose_name="IP address",
            ),
        ),
        migrations.AddField(
            model_name="rpcbackend",
            name="domain",
            field=models.CharField(blank=True, max_length=255, help_text=_DOMAIN_HELP),
        ),
        migrations.AddField(
            model_name="rpcbackend",
            name="port",
            field=models.PositiveIntegerField(
                default=8000,
                help_text=_PORT_HELP,
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(65535),
                ],
            ),
        ),
        migrations.AddField(
            model_name="rpcbackend",
            name="use_https",
            field=models.BooleanField(
                default=False, help_text=_HTTPS_HELP, verbose_name="Use HTTPS"
            ),
        ),
        migrations.AlterField(
            model_name="rpcbackend",
            name="base_url",
            field=models.URLField(blank=True, max_length=500, help_text=_BASE_URL_HELP),
        ),
    ]
