"""DB-backed integration tests for netbox-rpc.

These exercise the event-sourced execution lifecycle, the command/query
handlers, the append-only ledger, and the REST API against a real NetBox test
database. Run them with:

    python netbox/manage.py test netbox_rpc

They are intentionally NOT part of the fast, stub-based ``tests/`` pytest suite
(which mocks Django/NetBox and needs no database).
"""
