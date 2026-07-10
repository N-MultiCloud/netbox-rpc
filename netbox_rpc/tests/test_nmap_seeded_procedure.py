from __future__ import annotations

from django.test import TestCase

from netbox_rpc.models import RPCProcedure


class NmapSeededProcedureTests(TestCase):
    def test_nmap_scan_procedure_is_seeded_after_migrate(self) -> None:
        procedure = RPCProcedure.objects.get(name="nmap-scan")

        assert procedure.handler_id == "os.linux.nmap.scan"
        assert procedure.effect == "read"
        assert procedure.approval_required is False
        assert procedure.timeout_seconds == 120
        assert procedure.target_models == [
            "ipam.ipaddress",
            "dcim.device",
            "virtualization.virtualmachine",
        ]
        assert procedure.params_schema["required"] == ["target"]
        assert procedure.params_schema["additionalProperties"] is False
        assert procedure.params_schema["properties"]["scan_type"]["enum"] == [
            "connect",
            "syn",
            "os-detect",
        ]
        assert procedure.result_schema["required"] == [
            "status",
            "findings",
            "details",
        ]
        assert procedure.result_schema["properties"]["details"]["properties"][
            "open_ports"
        ]["items"]["required"] == ["port", "protocol", "service", "state"]
