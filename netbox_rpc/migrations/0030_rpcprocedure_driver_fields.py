"""Add pluggable transport-driver and output-parser selection to RPCProcedure.

These additive fields let a procedure declare which nms-backend transport driver
(AsyncSSH/Scrapli/Netmiko/Paramiko/NAPALM) and output parser to use, plus an
optional parser-hint schema. Defaults preserve the legacy AsyncSSH + raw-output
behaviour, so existing procedures are unaffected.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0029_seed_minecraft_stack_procedures"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpcprocedure",
            name="transport_driver",
            field=models.CharField(
                choices=[
                    ("asyncssh", "AsyncSSH (default)"),
                    ("scrapli", "Scrapli"),
                    ("netmiko", "Netmiko"),
                    ("paramiko", "Paramiko"),
                    ("napalm", "NAPALM"),
                ],
                default="asyncssh",
                help_text=(
                    "Transport driver the nms-backend execution pipeline uses for "
                    "this procedure. AsyncSSH preserves the legacy behaviour."
                ),
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="rpcprocedure",
            name="output_parser",
            field=models.CharField(
                choices=[
                    ("none", "None (raw output)"),
                    (
                        "auto",
                        "Auto (native JSON/XML, then jc/TextFSM/TTP/Genie/regex)",
                    ),
                    ("json", "Native JSON"),
                    ("xml", "Native XML"),
                    ("jc", "jc"),
                    ("textfsm", "TextFSM"),
                    ("ttp", "TTP"),
                    ("genie", "Genie"),
                    ("regex", "Regex"),
                ],
                default="none",
                help_text=(
                    "Parser applied to raw command output when the driver returns "
                    "unstructured text. 'none' keeps raw output; 'auto' runs the "
                    "parser chain (native JSON/XML first, then jc/TextFSM/TTP/"
                    "Genie/regex)."
                ),
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="rpcprocedure",
            name="output_schema",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text=(
                    "Optional parser hints / target internal schema (e.g. a "
                    "TextFSM template reference, jc parser name, or regex field "
                    "map) consumed by the nms-backend output pipeline."
                ),
            ),
        ),
    ]
