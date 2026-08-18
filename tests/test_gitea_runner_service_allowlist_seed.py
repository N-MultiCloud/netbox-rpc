from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "netbox_rpc/migrations/0073_seed_gitea_runner_service_allowlist.py"


def _rows() -> tuple[dict[str, str], ...]:
    tree = ast.parse(MIGRATION.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == (
            "RUNNER_SERVICE_ALLOWLIST"
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("RUNNER_SERVICE_ALLOWLIST is missing")


def test_every_row_is_a_fixed_systemd_unit() -> None:
    """Reference data only — a row must never carry shell text.

    These rows are consumed by the existing ``restart_service`` normalizer and handler.
    A unit name is the entire payload; anything shell-shaped here would be a command
    smuggled through reference data.
    """

    rows = _rows()
    assert rows, "the allowlist seeds nothing"

    for row in rows:
        assert set(row) == {"slug", "systemd_unit", "description"}, row
        # Unit names go to systemd as an argument. Keep them boring: no spaces, no
        # separators, no path traversal, no metacharacters.
        assert re.fullmatch(r"gitea-act-runner-[a-z0-9-]+\.service", row["systemd_unit"]), row
        assert re.fullmatch(r"gitea-act-runner-[a-z0-9-]+", row["slug"]), row
        # The slug is what an operator types; it must name the unit it controls, or
        # `restart_service <slug>` restarts something other than what was asked for.
        assert f"{row['slug']}.service" == row["systemd_unit"], row

    slugs = [row["slug"] for row in rows]
    assert len(slugs) == len(set(slugs)), "duplicate slug would make the target ambiguous"


# The runner fleet as seeded. Checked in deliberately: the on-disk comparison below can
# only run where the runner definitions exist, which is not CI — so without this the
# drift check would be vacuous exactly where it runs most often. Update both together.
EXPECTED_RUNNER_UNITS = frozenset(
    {
        "gitea-act-runner-netbox-ceph.service",
        "gitea-act-runner-netbox-packer.service",
        "gitea-act-runner-netbox-pbs.service",
        "gitea-act-runner-netbox-pdm.service",
        "gitea-act-runner-netbox-proxbox.service",
        "gitea-act-runner-network-nms.service",
        "gitea-act-runner-nmc-netbox-billing.service",
        "gitea-act-runner-nmc-netbox-bng.service",
        "gitea-act-runner-nmc-netbox-dns.service",
        "gitea-act-runner-nmc-netbox-gpon.service",
        "gitea-act-runner-nmc-netbox-nms.service",
        "gitea-act-runner-nmc-netbox-opnsense.service",
        "gitea-act-runner-nmc-netbox-rpc-backend.service",
        "gitea-act-runner-nmc-netbox-rpc.service",
        "gitea-act-runner-nmc-nms-backend.service",
        "gitea-act-runner-nmc-nms-cli.service",
        "gitea-act-runner-nmc-nms-mcp.service",
        "gitea-act-runner-nmc-nms.service",
        "gitea-act-runner-nmulticloud-context.service",
        "gitea-act-runner-proxbox-api.service",
    }
)


def test_seeded_units_match_the_recorded_fleet() -> None:
    """Runs everywhere, including CI, unlike the on-disk comparison below."""

    seeded = {row["systemd_unit"] for row in _rows()}
    assert seeded == EXPECTED_RUNNER_UNITS, {
        "seeded_only": sorted(seeded - EXPECTED_RUNNER_UNITS),
        "expected_only": sorted(EXPECTED_RUNNER_UNITS - seeded),
    }


def test_rows_match_the_real_runner_units_on_disk() -> None:
    """The allowlist is only useful if the units it names actually exist.

    A row naming a unit that is not installed produces a procedure that fails at the
    guest instead of at validation, which is a worse place to discover a typo. Skips
    rather than fails when the runner definitions are not present, so the suite stays
    portable.
    """

    unit_dir = Path("/root/personal-context/gitea-act-runner/systemd")
    if not unit_dir.is_dir():  # pragma: no cover - environment-dependent
        import pytest

        pytest.skip("runner unit definitions are not available in this environment")

    on_disk = {path.name for path in unit_dir.glob("gitea-act-runner-*.service")}
    seeded = {row["systemd_unit"] for row in _rows()}

    assert not (seeded - on_disk), f"seeded units with no definition: {sorted(seeded - on_disk)}"
    assert not (on_disk - seeded), (
        "runner units exist that the allowlist does not cover, so they cannot be "
        f"recovered through the audited path: {sorted(on_disk - seeded)}"
    )


def test_covers_the_runner_whose_wedge_motivated_this() -> None:
    """Regression anchor for the incident this migration exists to make recoverable."""

    seeded = {row["systemd_unit"] for row in _rows()}
    assert "gitea-act-runner-nmc-netbox-rpc-backend.service" in seeded


def test_seed_defines_no_shell_text() -> None:
    source = MIGRATION.read_text()

    assert "subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
    assert "RPCProcedureCommand" not in source


def test_seed_is_reversible_and_scoped() -> None:
    source = MIGRATION.read_text()

    assert '"enabled": True' in source
    assert '"dcim.device"' in source
    assert '"virtualization.virtualmachine"' in source
    # Reverse deletes only the rows this migration added, never the whole allowlist.
    assert "slug__in=[item[\"slug\"] for item in RUNNER_SERVICE_ALLOWLIST]" in source
    assert "reverse_code=unseed_runner_service_allowlist" in source


def test_documents_that_a_restart_aborts_a_running_job() -> None:
    """The operator-facing warning is part of the deliverable, not commentary.

    Restarting a runner mid-build kills that build. Someone reaching for this procedure
    during a stuck-queue incident needs to know that before they run it.
    """

    source = MIGRATION.read_text()
    assert "ABORTS" in source
    assert "status_service" in source
