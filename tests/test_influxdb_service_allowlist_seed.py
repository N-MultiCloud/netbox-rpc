from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "netbox_rpc/migrations/0053_seed_influxdb_service_allowlist.py"


def test_influxdb_service_allowlist_seed_is_fixed_systemd_unit() -> None:
    source = MIGRATION.read_text()

    assert 'slug="influxdb"' in source
    assert '"systemd_unit": "influxdb.service"' in source
    assert '"enabled": True' in source
    assert '"dcim.device"' in source
    assert '"virtualization.virtualmachine"' in source


def test_influxdb_service_allowlist_seed_does_not_define_shell_text() -> None:
    source = MIGRATION.read_text()

    assert "subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
    assert "RPCProcedureCommand" not in source
