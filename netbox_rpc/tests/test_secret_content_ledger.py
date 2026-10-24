"""NetBox-backed checks that each reproduced secret form is redacted in the ledger."""

from __future__ import annotations

from django.test import TestCase

from netbox_rpc import event_store
from netbox_rpc.domain.aggregate import RPCExecutionAggregate

from ._common import make_execution

_PEM_BEGIN = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
_PEM_END = "-----END " + "OPENSSH PRIVATE KEY-----"

_FORMS = {
    "inline": "SSH failed with password=fake-inline-value",
    "quoted": 'password="fake quoted value" tail',
    "pem": f"{_PEM_BEGIN}\nAAAA-fake-body\n{_PEM_END}",
    "doubled_double_quotes": 'password="fake ""sensitive remainder" tail',
    "terminal_backslash": 'password="fake-terminal-value\\',
    "yaml_crlf_block": (
        "password: |\r\n  CRLF-SECRET\r\n\r\n  SECOND-SECRET\r\nafter: public\r\n"
    ),
    "pem_mismatched_footer": (
        "-----BEGIN RSA PRIVATE KEY-----\nLEAKED-PRIVATE-MATERIAL\n"
        "-----END EC PRIVATE KEY-----\nafter\n"
        "-----END RSA PRIVATE KEY-----"
    ),
}
_SECRETS = (
    "fake-inline-value",
    "fake quoted value",
    "AAAA-fake-body",
    "LEAKED-PRIVATE-MATERIAL",
    "sensitive remainder",
    "fake-terminal-value",
    "CRLF-SECRET",
    "SECOND-SECRET",
)


class SecretContentLedgerTests(TestCase):
    def test_event_message_and_data_hold_no_reproduced_secret(self):
        execution = make_execution()
        for text in _FORMS.values():
            event_store.append_execution_event(
                execution,
                "info",
                "BackendProgress",
                text,
                {"detail": text},
            )

        stored = list(execution.events.all())
        assert len(stored) == len(_FORMS)
        for event in stored:
            for secret in _SECRETS:
                assert secret not in event.message
                assert secret not in str(event.data)

    def test_normalized_params_and_projection_rebuild_hold_no_reproduced_secret(self):
        execution = make_execution()
        aggregate = RPCExecutionAggregate(execution)
        aggregate.queue()
        aggregate.start()
        content = "\n".join(_FORMS.values()) + "\n"
        aggregate.normalize(
            {"config_content": content, "command_fingerprint": {}},
            "hash-secret-content",
        )

        execution.refresh_from_db()
        stored = execution.events.get(event="ParametersNormalized")
        rebuilt = event_store.rebuild_projection(execution)
        for secret in _SECRETS:
            assert secret not in str(stored.data)
            assert secret not in str(execution.normalized_params)
            assert secret not in str(rebuilt.normalized_params)
        assert rebuilt.normalized_params == execution.normalized_params

    def test_terminal_backslash_is_stored_as_the_exact_placeholder(self):
        text = _FORMS["terminal_backslash"]
        execution = make_execution()
        event = event_store.append_execution_event(
            execution,
            "info",
            "BackendProgress",
            text,
            {"detail": text},
        )

        assert event.message == "[REDACTED]"
        assert event.data == {"detail": "[REDACTED]"}

    def test_terminal_backslash_normalized_value_is_stored_as_the_exact_placeholder(self):
        execution = make_execution()
        aggregate = RPCExecutionAggregate(execution)
        aggregate.queue()
        aggregate.start()
        aggregate.normalize(
            {"config_content": _FORMS["terminal_backslash"], "command_fingerprint": {}},
            "hash-terminal-backslash",
        )

        execution.refresh_from_db()
        rebuilt = event_store.rebuild_projection(execution)
        assert execution.normalized_params["config_content"] == "[REDACTED]"
        assert rebuilt.normalized_params["config_content"] == "[REDACTED]"

    def test_crlf_block_scalar_body_is_stored_without_the_secret_lines(self):
        text = _FORMS["yaml_crlf_block"]
        execution = make_execution()
        event = event_store.append_execution_event(
            execution,
            "info",
            "BackendProgress",
            text,
            {"detail": text},
        )

        # A block scalar under a sensitive key is redacted to the end of the text (issue 428).
        assert event.message == "[REDACTED]"
        assert event.data == {"detail": "[REDACTED]"}
