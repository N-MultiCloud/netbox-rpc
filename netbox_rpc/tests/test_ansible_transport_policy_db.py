"""DB-backed tests for the Ansible-first transport policy.

The pure-domain tier (``tests/test_ansible_transport_policy.py``) covers the
resolver and the platform map with stubs. These cover what only a real database
can: that migration ``0075`` actually seeded the policy and the exclusion flag,
and that the settings row rejects a capability-mismatched chain.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase

from netbox_rpc.models import RPCProcedure, RpcPluginSettings

PINNED_HANDLER_IDS = (
    "service.netbox.staging.rotate_backend_token",
    "os.linux.ubuntu.24.upgrade_26.run_upgrade",
)


class AnsibleFirstPolicySeedTests(TestCase):
    """Migration 0075 applied to a real database."""

    def test_the_estate_default_chains_are_seeded_ansible_first(self):
        settings_row = RpcPluginSettings.objects.get(singleton_key="default")

        assert settings_row.default_transport_driver_chain == ["ansible"]
        assert settings_row.default_network_driver_chain == ["ansible-network"]

    def test_the_platform_map_is_seeded_and_resolves(self):
        settings_row = RpcPluginSettings.objects.get(singleton_key="default")

        assert settings_row.ansible_platform_map, "platform map seeded nothing"
        junos = settings_row.ansible_context_for_platform("junos")
        assert junos["network_os"] == "junipernetworks.junos.junos"
        # An unmapped platform must resolve to nothing rather than a guess: the
        # backend then falls back to a raw driver instead of speaking the wrong
        # vendor's CLI dialect at a production device.
        assert settings_row.ansible_context_for_platform("no-such-platform") == {}

    def test_the_no_fallback_procedures_are_pinned(self):
        """Both disable transport fallback, so an Ansible-first chain would
        remove their required driver with nothing to catch it."""

        pinned = RPCProcedure.objects.filter(handler_id__in=PINNED_HANDLER_IDS)
        assert pinned.count() == len(PINNED_HANDLER_IDS), (
            "a pinned handler id does not match any seeded procedure"
        )
        for procedure in pinned:
            assert procedure.transport_pinned is True, procedure.handler_id

    def test_no_other_procedure_was_pinned_by_the_migration(self):
        """Mutation guard: pinning everything would silently disable the policy.

        A migration that set the flag broadly would satisfy the test above while
        making the whole feature a no-op.
        """

        pinned = set(
            RPCProcedure.objects.filter(transport_pinned=True).values_list(
                "handler_id", flat=True
            )
        )
        assert pinned == set(PINNED_HANDLER_IDS), pinned

    def test_the_migration_rewrote_no_procedure_driver(self):
        """The policy is a setting, not a per-row rewrite.

        Every seeded procedure must keep the driver it was seeded with and an
        empty chain, so rollback stays a single settings edit.
        """

        assert not RPCProcedure.objects.exclude(transport_driver_chain=[]).exists()
        staging = RPCProcedure.objects.get(
            handler_id="service.netbox.staging.rotate_backend_token"
        )
        assert staging.transport_driver == "asyncssh"


class RpcPluginSettingsValidationTests(TestCase):
    def setUp(self):
        self.settings_row = RpcPluginSettings.objects.get(singleton_key="default")

    def test_a_capability_mismatched_linux_chain_is_rejected(self):
        """The backend silently *skips* a mismatched entry, so a bad default
        would degrade to 'no policy' with no error anywhere."""

        self.settings_row.default_transport_driver_chain = ["ansible", "scrapli"]
        with self.assertRaises(ValidationError) as ctx:
            self.settings_row.full_clean()
        assert "default_transport_driver_chain" in ctx.exception.message_dict

    def test_a_capability_mismatched_network_chain_is_rejected(self):
        self.settings_row.default_network_driver_chain = ["ansible-network", "asyncssh"]
        with self.assertRaises(ValidationError) as ctx:
            self.settings_row.full_clean()
        assert "default_network_driver_chain" in ctx.exception.message_dict

    def test_the_seeded_defaults_validate(self):
        """Mutation guard: the check must accept the values we actually ship."""

        self.settings_row.full_clean()

    def test_empty_chains_validate(self):
        """Clearing the policy is the documented rollback — it must stay legal."""

        self.settings_row.default_transport_driver_chain = []
        self.settings_row.default_network_driver_chain = []
        self.settings_row.full_clean()


class PolicySeedDoesNotChangeOptInTests(TestCase):
    """Seeding transport preferences must not enable the integration.

    Migration 0075 creates the settings singleton when absent — unlike 0050,
    which deliberately leaves a fresh install alone because it was deciding the
    `enabled` opt-in gate. Recording transport preferences is a different kind of
    decision, but it shares a row with that gate, so the boundary needs a guard.
    """

    def test_seeding_the_policy_does_not_opt_the_integration_in(self):
        settings_row = RpcPluginSettings.objects.get(singleton_key="default")

        assert settings_row.enabled is False
        assert settings_row.backend_id is None
        # ...while the transport policy it *was* allowed to set is present.
        assert settings_row.default_transport_driver_chain == ["ansible"]

    def test_exactly_one_settings_row_exists(self):
        """The singleton must stay a singleton after the seed."""

        assert RpcPluginSettings.objects.count() == 1
