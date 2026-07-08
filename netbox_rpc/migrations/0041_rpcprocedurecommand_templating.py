"""Add Jinja2 templating + output-capture fields to RPCProcedureCommand.

These additive fields let a command opt into Jinja2 templating of its argv
tokens (``render_mode="jinja"``) and capture a value from its output into a
named variable (``produces_var`` + ``capture_kind`` + ``capture_expression``)
that a later command can reference as ``{{ vars.<name> }}``. Defaults preserve
the historical fixed-token ``literal`` behaviour with no capture, so existing
command rows and the seeded procedure catalog are unaffected (no reseed).

Choices/help text are inlined per the migration-safety rule (no live imports of
``netbox_rpc`` modules from a migration).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0040_rpcintentprocedure_sequence_min"),
    ]

    operations = [
        migrations.AddField(
            model_name="rpcprocedurecommand",
            name="render_mode",
            field=models.CharField(
                choices=[
                    ("literal", "Literal ({param} substitution)"),
                    ("jinja", "Jinja2 template ({{ ... }})"),
                ],
                default="literal",
                help_text=(
                    "How argv tokens become a command. 'literal' keeps the "
                    "fixed-token {param} substitution; 'jinja' renders each token "
                    "as a sandboxed Jinja2 expression against params / target / "
                    "vars / runtime / item."
                ),
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="rpcprocedurecommand",
            name="produces_var",
            field=models.CharField(
                blank=True,
                help_text=(
                    "Optional snake_case name to capture this command's output "
                    "into, so a later command can reference it as {{ vars.<name> }} "
                    "(output-based variable chaining). Must be unique within the "
                    "procedure."
                ),
                max_length=64,
            ),
        ),
        migrations.AddField(
            model_name="rpcprocedurecommand",
            name="capture_kind",
            field=models.CharField(
                blank=True,
                choices=[
                    ("stdout", "Full stdout"),
                    ("stdout_stripped", "Stripped stdout"),
                    ("json", "JSON path (expression)"),
                    ("regex", "Regex (one capture group)"),
                    ("line", "Line index (expression)"),
                ],
                help_text=(
                    "How to extract the value for produces_var from this command's "
                    "output: full/stripped stdout, a JSON path, a one-group regex, "
                    "or a line index."
                ),
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="rpcprocedurecommand",
            name="capture_expression",
            field=models.CharField(
                blank=True,
                help_text=(
                    "Expression for capture_kind json/regex/line (a dotted JSON "
                    "path, a regex with exactly one capturing group, or an integer "
                    "line index). Leave blank for stdout/stdout_stripped."
                ),
                max_length=500,
            ),
        ),
    ]
