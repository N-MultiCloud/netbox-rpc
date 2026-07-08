"""DB-backed tests for local_rpcbackend_resolver.

The resolver is the seam that routes RPC dispatch to the netbox-rpc-backend
service (an RPCBackend row) instead of nms-backend, via
PLUGINS_CONFIG["netbox_rpc"]["backend_resolver"].
"""

from __future__ import annotations

from django.test import TestCase

from netbox_rpc.backends import local_rpcbackend_resolver
from netbox_rpc.models import RPCBackend


class LocalRpcBackendResolverTests(TestCase):
    def test_resolves_by_pk(self) -> None:
        backend = RPCBackend.objects.create(
            name="rpc-svc",
            domain="backend.rpc.example.com",
            use_https=True,
            port=443,
            auth_header_name="X-RPC-Service-Token",
            auth_token="secret",
        )
        target = local_rpcbackend_resolver(backend.pk)
        assert target is not None
        self.assertEqual(target.url, "https://backend.rpc.example.com:443")
        self.assertEqual(target.headers, {"X-RPC-Service-Token": "secret"})
        self.assertTrue(target.verify_ssl)

    def test_falls_back_to_single_backend_without_pk(self) -> None:
        RPCBackend.objects.create(name="only", domain="backend.rpc.example.com")
        target = local_rpcbackend_resolver(None)
        assert target is not None
        self.assertEqual(target.url, "http://backend.rpc.example.com:8000")

    def test_ambiguous_without_pk_returns_none(self) -> None:
        RPCBackend.objects.create(name="a", domain="a.example.com")
        RPCBackend.objects.create(name="b", domain="b.example.com")
        self.assertIsNone(local_rpcbackend_resolver(None))

    def test_no_backends_returns_none(self) -> None:
        self.assertIsNone(local_rpcbackend_resolver(None))

    def test_specific_missing_pk_fails_closed(self) -> None:
        # A specific backend was requested but does not exist: return None (fail
        # closed) rather than silently rerouting to the single configured backend.
        only = RPCBackend.objects.create(name="only", domain="only.example.com")
        self.assertIsNone(local_rpcbackend_resolver(only.pk + 1000))
