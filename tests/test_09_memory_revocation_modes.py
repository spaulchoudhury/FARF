"""
test_09_memory_revocation_modes.py -- v7.9.10

Thesis-supervisor-directed: "Per-record (not just per-agent) revocation
in memory_store.py: keep it as a configurable choice, with Tombstone
default but workable for soft delete where data retention is higher."

Tests the unified revoke_record()/revoke_memory_record() `mode`
dispatcher added this session, at both the MemoryStore layer (direct)
and the FederationBus layer (the wrapper operators actually call).
Also locks in backward compatibility: the pre-v7.9.10 positional call
shape (no `mode` kwarg at all) must keep behaving exactly as before.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from memory_store import MemoryStore
from federation_bus import FederationBus
from main import build_federation


@pytest.fixture
def store():
    return MemoryStore()


class TestMemoryStoreModeDispatcher:
    def test_default_mode_is_tombstone_unchanged_behaviour(self, store):
        store.write("agent1", "k", {"v": 1}, "agent1", "did:key:agent1")
        record = store.revoke_record("agent1", "k", "op", "did:key:op", reason="poisoned")
        assert record.tombstone is True
        assert store.read("agent1", "k") is None  # hidden from ordinary read
        # data retention: the PRIOR record's plaintext is still recoverable
        chain = store.get_chain("agent1")
        original = chain[0]
        assert store.decrypt(original) == {"v": 1}

    def test_backward_compatible_positional_call_without_mode_kwarg(self, store):
        # exact call shape used by tests/test_05_chaos_and_fuzzing.py --
        # must keep working with zero changes.
        store.write("agent1", "k", {"v": 1}, "agent1", "did:key:agent1")
        record = store.revoke_record("agent1", "k", "fuzz-writer", "did:key:fuzz", reason="fuzz-revoke")
        assert record is not None
        assert record.tombstone is True

    def test_crypto_shred_mode_destroys_recoverability(self, store):
        store.write("agent1", "k", {"secret": 42}, "agent1", "did:key:agent1")
        record = store.revoke_record("agent1", "k", "op", "did:key:op",
                                      reason="gdpr_request", mode="crypto_shred")
        assert record is not None
        assert store.read("agent1", "k") is None  # hidden, same as tombstone
        # UNLIKE tombstone: the prior record's plaintext is now unrecoverable
        chain = store.get_chain("agent1")
        original = chain[0]
        assert store.decrypt(original) is None

    def test_tombstone_vs_crypto_shred_recoverability_is_the_real_difference(self, store):
        # side-by-side on two independent agents, same starting value --
        # the one thing this test exists to prove.
        store.write("a", "k", {"v": "x"}, "a", "did:key:a")
        store.write("b", "k", {"v": "x"}, "b", "did:key:b")
        store.revoke_record("a", "k", "op", "did:key:op", mode="tombstone")
        store.revoke_record("b", "k", "op", "did:key:op", mode="crypto_shred")
        assert store.decrypt(store.get_chain("a")[0]) == {"v": "x"}   # retained
        assert store.decrypt(store.get_chain("b")[0]) is None          # destroyed

    def test_invalid_mode_raises(self, store):
        store.write("agent1", "k", {"v": 1}, "agent1", "did:key:agent1")
        with pytest.raises(ValueError, match="mode must be"):
            store.revoke_record("agent1", "k", "op", "did:key:op", mode="bogus")

    def test_revoking_nonexistent_key_returns_none_both_modes(self, store):
        assert store.revoke_record("agent1", "nope", "op", "did:key:op", mode="tombstone") is None
        assert store.revoke_record("agent1", "nope", "op", "did:key:op", mode="crypto_shred") is None

    def test_key_remains_writable_after_tombstone(self, store):
        store.write("agent1", "k", {"v": 1}, "agent1", "did:key:agent1")
        store.revoke_record("agent1", "k", "op", "did:key:op", mode="tombstone")
        store.write("agent1", "k", {"v": 2}, "agent1", "did:key:agent1")
        assert store.decrypt(store.read("agent1", "k")) == {"v": 2}


class TestFederationBusRevokeMemoryRecordDispatcher:
    """The operator-facing wrapper -- this is what pentest scripts and any
    real operator tooling actually calls, not MemoryStore directly."""

    @pytest.fixture
    def bus(self, tmp_path):
        b = FederationBus(db_path=str(tmp_path / "revoke_modes.db"), require_message_signatures=False)
        agents = build_federation(b, n_orgs=3)
        advisor_id = agents["OrgA"]["advisor"].agent_id
        b.sign_and_write_memory(advisor_id, "plan", {"step": 1})
        b._test_advisor_id = advisor_id
        yield b
        b.close()

    def test_default_mode_matches_pre_v7_9_10_return_shape(self, bus):
        result = bus.revoke_memory_record(bus._test_advisor_id, "plan", reason="poisoned")
        assert result["revoked"] is True
        assert "record_hash" in result
        assert result["mode"] == "tombstone"

    def test_crypto_shred_mode_delegates_to_erase_memory_record(self, bus):
        result = bus.revoke_memory_record(bus._test_advisor_id, "plan", reason="gdpr",
                                           mode="crypto_shred")
        assert result["revoked"] is True
        assert result["mode"] == "crypto_shred"
        assert result["erased"] is True               # original erase_memory_record() key, preserved
        assert result["records_shredded"] >= 1         # original key, preserved
        assert "record_hash" in result                 # normalised addition

    def test_crypto_shred_via_wrapper_equivalent_to_calling_erase_directly(self, tmp_path):
        b1 = FederationBus(db_path=str(tmp_path / "eq1.db"), require_message_signatures=False)
        b2 = FederationBus(db_path=str(tmp_path / "eq2.db"), require_message_signatures=False)
        a1 = build_federation(b1, n_orgs=3)["OrgA"]["advisor"].agent_id
        a2 = build_federation(b2, n_orgs=3)["OrgA"]["advisor"].agent_id
        b1.sign_and_write_memory(a1, "plan", {"step": 1})
        b2.sign_and_write_memory(a2, "plan", {"step": 1})
        try:
            r1 = b1.revoke_memory_record(a1, "plan", mode="crypto_shred")
            r2 = b2.erase_memory_record(a2, "plan")
            assert r1["records_shredded"] == r2["records_shredded"]
            assert r1["erased"] == r2["erased"]
            assert bus_memory_unreadable(b1, a1, "plan")
            assert bus_memory_unreadable(b2, a2, "plan")
        finally:
            b1.close()
            b2.close()

    def test_invalid_mode_raises(self, bus):
        with pytest.raises(ValueError, match="mode must be"):
            bus.revoke_memory_record(bus._test_advisor_id, "plan", mode="bogus")

    def test_default_call_with_no_mode_arg_still_works(self, bus):
        # zero-argument-change backward compatibility for any existing
        # caller (pentest scripts, prior tests) that never passes mode=.
        result = bus.revoke_memory_record(bus._test_advisor_id, "plan")
        assert result["revoked"] is True


def bus_memory_unreadable(bus, agent_id, key):
    return bus.memory.read(agent_id, key) is None
