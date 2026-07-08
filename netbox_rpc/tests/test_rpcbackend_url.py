"""DB-backed tests for RPCBackend structured addressing (IP / domain / port).

Mirrors the netbox-proxbox FastAPIEndpoint pattern: an operator can point the
plugin at its execution backend by IP address or domain, and `backend_url` is
composed from those fields (an explicit `base_url` override wins).
"""

from __future__ import annotations

from django.test import TestCase
from ipam.models import IPAddress

from netbox_rpc.models import RPCBackend


class RPCBackendUrlTests(TestCase):
    def test_url_composed_from_domain(self) -> None:
        backend = RPCBackend(name="rpc-a", domain="backend.rpc.example.com", port=8443, use_https=True)
        self.assertEqual(backend.url, "https://backend.rpc.example.com:8443")
        self.assertEqual(backend.backend_url, "https://backend.rpc.example.com:8443")

    def test_url_defaults_to_http_and_port_8000(self) -> None:
        backend = RPCBackend(name="rpc-b", domain="backend.rpc.example.com")
        self.assertEqual(backend.url, "http://backend.rpc.example.com:8000")

    def test_url_composed_from_ip_when_no_domain(self) -> None:
        ip = IPAddress.objects.create(address="10.0.30.207/24")
        backend = RPCBackend(name="rpc-c", ip_address=ip, port=8000)
        self.assertEqual(backend.ip, "10.0.30.207")
        self.assertEqual(backend.url, "http://10.0.30.207:8000")

    def test_domain_wins_over_ip(self) -> None:
        ip = IPAddress.objects.create(address="10.0.30.207/24")
        backend = RPCBackend(name="rpc-d", ip_address=ip, domain="backend.example.com", port=9000)
        self.assertEqual(backend.url, "http://backend.example.com:9000")

    def test_base_url_override_wins(self) -> None:
        backend = RPCBackend(
            name="rpc-e",
            base_url="http://legacy:1234",
            domain="backend.example.com",
            port=8000,
        )
        self.assertEqual(backend.backend_url, "http://legacy:1234")

    def test_backend_url_empty_when_unconfigured(self) -> None:
        backend = RPCBackend(name="rpc-f")
        self.assertEqual(backend.ip, "")
        self.assertEqual(backend.url, "")
        self.assertEqual(backend.backend_url, "")

    def test_ipv6_address_is_bracketed(self) -> None:
        ip = IPAddress.objects.create(address="2001:db8::1/64")
        backend = RPCBackend(name="rpc-v6", ip_address=ip, port=8000)
        self.assertEqual(backend.ip, "2001:db8::1")
        self.assertEqual(backend.url, "http://[2001:db8::1]:8000")

    def test_invalid_domain_is_rejected(self) -> None:
        from django.core.exceptions import ValidationError

        for i, bad in enumerate(
            ("evil.com/x", "evil.com:9999", "http://evil.com", "a b", "evil.com#")
        ):
            backend = RPCBackend(name=f"rpc-bad-{i}", domain=bad)
            with self.assertRaises(ValidationError):
                backend.full_clean()

    def test_valid_domain_passes_validation(self) -> None:
        backend = RPCBackend(name="rpc-ok", domain="backend.rpc.example.com")
        backend.full_clean()  # must not raise
