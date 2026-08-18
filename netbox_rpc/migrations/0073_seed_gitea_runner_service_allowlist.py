from django.db import migrations

# Gitea Actions runner units, one per repository runner. Controllable through the
# generic Ubuntu-24 systemd procedures (os.linux.ubuntu.24.restart_service /
# status_service / journal_tail / start_service / stop_service) once present in
# the allowlist -- the same shape as the NetBox rows seeded in 0058 and the
# InfluxDB row in 0053. No new procedure or backend handler is needed; these are
# reference data the existing restart_service normalizer and handler consume.
#
# Why these belong in the allowlist
# ---------------------------------
# An act_runner can wedge: the process keeps heartbeating, so Gitea reports the
# runner ``online`` and ``busy=false`` with correct labels, while it silently
# stops claiming jobs. Observed on 2026-08-17 with
# ``gitea-act-runner-nmc-netbox-rpc-backend``, whose unit had been active since
# 2026-08-08 while six runs -- including a ``deploy-production.yml`` for an
# already-merged promotion -- sat queued indefinitely.
#
# That failure is worse than a crash. A crashed runner is visibly down; a wedged
# one looks healthy, so a promotion merges, reports success, and never deploys.
# Production keeps serving the previous build while the repository says
# otherwise.
#
# Recovery is a restart of the unit. Before this migration there was no audited
# path to perform one: the allowlist held only ``netbox`` and ``netbox-rq``, so
# ``restart_service`` could not touch a runner, and the estate rule is to extend
# the tooling rather than SSH to the host.
#
# Operational note: restarting a runner ABORTS any job it is currently
# executing. Check ``status_service`` (and the repository's queued/running runs)
# before restarting one that may be mid-build.
RUNNER_SERVICE_ALLOWLIST = (
    {
        "slug": "gitea-act-runner-netbox-ceph",
        "systemd_unit": "gitea-act-runner-netbox-ceph.service",
        "description": "Gitea Actions runner for netbox-ceph "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-netbox-packer",
        "systemd_unit": "gitea-act-runner-netbox-packer.service",
        "description": "Gitea Actions runner for netbox-packer "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-netbox-pbs",
        "systemd_unit": "gitea-act-runner-netbox-pbs.service",
        "description": "Gitea Actions runner for netbox-pbs "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-netbox-pdm",
        "systemd_unit": "gitea-act-runner-netbox-pdm.service",
        "description": "Gitea Actions runner for netbox-pdm "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-netbox-proxbox",
        "systemd_unit": "gitea-act-runner-netbox-proxbox.service",
        "description": "Gitea Actions runner for netbox-proxbox "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-network-nms",
        "systemd_unit": "gitea-act-runner-network-nms.service",
        "description": "Gitea Actions runner for network-nms "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-billing",
        "systemd_unit": "gitea-act-runner-nmc-netbox-billing.service",
        "description": "Gitea Actions runner for nmc-netbox-billing "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-bng",
        "systemd_unit": "gitea-act-runner-nmc-netbox-bng.service",
        "description": "Gitea Actions runner for nmc-netbox-bng "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-dns",
        "systemd_unit": "gitea-act-runner-nmc-netbox-dns.service",
        "description": "Gitea Actions runner for nmc-netbox-dns "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-gpon",
        "systemd_unit": "gitea-act-runner-nmc-netbox-gpon.service",
        "description": "Gitea Actions runner for nmc-netbox-gpon "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-nms",
        "systemd_unit": "gitea-act-runner-nmc-netbox-nms.service",
        "description": "Gitea Actions runner for nmc-netbox-nms "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-opnsense",
        "systemd_unit": "gitea-act-runner-nmc-netbox-opnsense.service",
        "description": "Gitea Actions runner for nmc-netbox-opnsense "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-rpc-backend",
        "systemd_unit": "gitea-act-runner-nmc-netbox-rpc-backend.service",
        "description": "Gitea Actions runner for nmc-netbox-rpc-backend "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-netbox-rpc",
        "systemd_unit": "gitea-act-runner-nmc-netbox-rpc.service",
        "description": "Gitea Actions runner for nmc-netbox-rpc "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-nms-backend",
        "systemd_unit": "gitea-act-runner-nmc-nms-backend.service",
        "description": "Gitea Actions runner for nmc-nms-backend "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-nms-cli",
        "systemd_unit": "gitea-act-runner-nmc-nms-cli.service",
        "description": "Gitea Actions runner for nmc-nms-cli "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-nms-mcp",
        "systemd_unit": "gitea-act-runner-nmc-nms-mcp.service",
        "description": "Gitea Actions runner for nmc-nms-mcp "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmc-nms",
        "systemd_unit": "gitea-act-runner-nmc-nms.service",
        "description": "Gitea Actions runner for nmc-nms "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-nmulticloud-context",
        "systemd_unit": "gitea-act-runner-nmulticloud-context.service",
        "description": "Gitea Actions runner for nmulticloud-context "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
    {
        "slug": "gitea-act-runner-proxbox-api",
        "systemd_unit": "gitea-act-runner-proxbox-api.service",
        "description": "Gitea Actions runner for proxbox-api "
        "(restart to recover a wedged runner that reports online but claims no jobs)",
    },
)


def seed_runner_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model("netbox_rpc", "RPCLinuxServiceAllowlist")
    for item in RUNNER_SERVICE_ALLOWLIST:
        RPCLinuxServiceAllowlist.objects.update_or_create(
            slug=item["slug"],
            defaults={
                "systemd_unit": item["systemd_unit"],
                "enabled": True,
                "target_models": ["dcim.device", "virtualization.virtualmachine"],
                "description": item["description"],
            },
        )


def unseed_runner_service_allowlist(apps, schema_editor):
    RPCLinuxServiceAllowlist = apps.get_model("netbox_rpc", "RPCLinuxServiceAllowlist")
    RPCLinuxServiceAllowlist.objects.filter(
        slug__in=[item["slug"] for item in RUNNER_SERVICE_ALLOWLIST]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_rpc", "0072_seed_influxdb3_debian13_install_procedures"),
    ]

    operations = [
        migrations.RunPython(
            seed_runner_service_allowlist,
            reverse_code=unseed_runner_service_allowlist,
        ),
    ]
