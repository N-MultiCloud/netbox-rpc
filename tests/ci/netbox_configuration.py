"""Minimal NetBox configuration for running the netbox-rpc integration tests
(``manage.py test netbox_rpc``) in CI.

All connection details come from environment variables so the same config works
against a CI Postgres service (GitHub Actions) or a host database (self-hosted
runner). No secrets are committed. The Django test runner only ever touches the
``test_<NAME>`` database, never ``NAME`` itself.
"""

import os

ALLOWED_HOSTS = ["*"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("NETBOX_DB_NAME", "netbox_rpc_citest"),
        "USER": os.environ.get("NETBOX_DB_USER", "netbox"),
        "PASSWORD": os.environ.get("NETBOX_DB_PASSWORD", ""),
        "HOST": os.environ.get("NETBOX_DB_HOST", "localhost"),
        "PORT": os.environ.get("NETBOX_DB_PORT", ""),
        "CONN_MAX_AGE": 0,
        # Create the test database as UTF8 from template0 so NetBox's
        # CreateCollation migration works even where the server's default
        # template is SQL_ASCII.
        "TEST": {"CHARSET": "UTF8", "TEMPLATE": "template0"},
    }
}

_REDIS_HOST = os.environ.get("NETBOX_REDIS_HOST", "localhost")
_REDIS_PORT = int(os.environ.get("NETBOX_REDIS_PORT", "6379"))
REDIS = {
    "tasks": {"HOST": _REDIS_HOST, "PORT": _REDIS_PORT, "USERNAME": "", "PASSWORD": "", "DATABASE": 10, "SSL": False},
    "caching": {"HOST": _REDIS_HOST, "PORT": _REDIS_PORT, "USERNAME": "", "PASSWORD": "", "DATABASE": 11, "SSL": False},
}

SECRET_KEY = os.environ.get("NETBOX_SECRET_KEY", "ci-" + "x" * 50)

PLUGINS = ["netbox_rpc"]
PLUGINS_CONFIG = {"netbox_rpc": {}}
