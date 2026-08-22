"""
Chaos Engineering + Property-Based Fuzz Testing (Phase 1 item 3, v7.4)
======================================================================
Everything tested elsewhere in this codebase (all 15 pentest scripts,
all 26 pytest-suite tests) assumes a DELIBERATE ATTACKER. Nothing tests
ordinary bad luck: a mid-write database failure, a witness org that
just never responds, a process restart. This file closes that gap in
two ways:

  1. PROPERTY-BASED FUZZ TESTS on the core cryptographic/logic
     primitives (trust_protocol signing, memory_store's hash chain,
     federation_ledger's quorum arithmetic) -- many random inputs per
     property, not hand-picked examples.

     HONEST LIMITATION: this sandbox has no network access to install
     the `hypothesis` library, so these are a custom, seeded,
     deterministic fuzzer (plain `random`, many iterations per
     property) rather than true Hypothesis with its shrinking/example
     database machinery. Same spirit -- test a PROPERTY across many
     random cases rather than a single hand-picked example -- with less
     tooling around it.

  2. NON-ADVERSARIAL FAILURE INJECTION: a mid-operation database write
     failure, a witness org that silently never responds, and a bus
     "restart" (new instance, same on-disk audit DB) simulating a
     process crash and recovery. These are ordinary infrastructure
     failures, not attacks -- resilience means surviving both.
"""
import os
import random
import secrets
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from federation_bus import FederationBus
from main import build_federation
from trust_protocol import DIDKeyIdentity, did_to_public_key, decode_signature
from memory_store import MemoryStore
from federation_ledger import FederationLedger
from cryptography.exceptions import InvalidSignature

N_FUZZ_ITERATIONS = 200


# ============================================================
# Part 1: property-based fuzz tests
# ============================================================

def test_fuzz_signature_roundtrip_always_verifies_for_genuine_pairs():
    """Property: for ANY payload, signing with an identity's own key and
    verifying with that SAME identity's public key must always succeed."""
    rng = random.Random(1001)
    identity = DIDKeyIdentity("fuzz-agent")
    failures = []
    for i in range(N_FUZZ_ITERATIONS):
        payload = secrets.token_bytes(rng.randint(0, 512))
        signature = identity.sign(payload)
        try:
            did_to_public_key(identity.did).verify(decode_signature(signature), payload)
        except InvalidSignature:
            failures.append(i)
    assert failures == [], f"genuine sign/verify pairs failed on iterations {failures}"


def test_fuzz_signature_never_verifies_for_mismatched_identity():
    """Property: for ANY payload, a signature from identity A must NEVER
    verify against identity B's public key (except by cryptographic
    forgery, which should have probability ~0)."""
    rng = random.Random(1002)
    identity_a = DIDKeyIdentity("fuzz-agent-a")
    identity_b = DIDKeyIdentity("fuzz-agent-b")
    false_accepts = []
    for i in range(N_FUZZ_ITERATIONS):
        payload = secrets.token_bytes(rng.randint(0, 512))
        signature = identity_a.sign(payload)
        try:
            did_to_public_key(identity_b.did).verify(decode_signature(signature), payload)
            false_accepts.append(i)  # should never reach here
        except InvalidSignature:
            pass
    assert false_accepts == [], f"cross-identity signature falsely verified on iterations {false_accepts}"


def test_fuzz_signature_rejects_any_single_bit_flip():
    """Property: flipping ANY single byte of a valid signature or payload
    must cause verification to fail -- no partial/fuzzy acceptance."""
    rng = random.Random(1003)
    identity = DIDKeyIdentity("fuzz-agent-tamper")
    false_accepts = []
    for i in range(N_FUZZ_ITERATIONS):
        payload = secrets.token_bytes(rng.randint(8, 256))
        signature_bytes = bytearray(decode_signature(identity.sign(payload)))
        flip_index = rng.randrange(len(signature_bytes))
        signature_bytes[flip_index] ^= 0x01  # flip one bit
        try:
            did_to_public_key(identity.did).verify(bytes(signature_bytes), payload)
            false_accepts.append(i)
        except InvalidSignature:
            pass
    assert false_accepts == [], f"single-bit-flipped signature falsely verified on iterations {false_accepts}"


def test_fuzz_memory_chain_integrity_survives_random_write_sequences():
    """Property: ANY sequence of legitimate writes/revocations to a
    MemoryStore must leave verify_integrity() reporting intact=True,
    regardless of how many operations or what order."""
    rng = random.Random(2001)
    store = MemoryStore()
    agent_id = "fuzz-owner"
    keys = [f"key{i}" for i in range(5)]
    for _ in range(N_FUZZ_ITERATIONS):
        key = rng.choice(keys)
        if rng.random() < 0.2:
            store.revoke_record(agent_id, key, "fuzz-writer", "did:key:fuzz", reason="fuzz-revoke")
        else:
            value = {"n": rng.randint(0, 10_000), "s": secrets.token_hex(4)}
            store.write(agent_id, key, value, "fuzz-writer", "did:key:fuzz")
    result = store.verify_integrity(agent_id)
    assert result["intact"] is True, f"chain integrity broke under legitimate random operations: {result}"


def test_fuzz_memory_chain_detects_tampering_at_any_random_point():
    """Property: injecting a tamper (mutating the record's stored
    ciphertext in place -- v7.7: records store encrypted ciphertext,
    not a plaintext value, see memory_store.py's module docstring) at
    ANY random point in a random-length write history must be detected
    by verify_integrity(), regardless of where in history it happens."""
    rng = random.Random(2002)
    misses = []
    for trial in range(50):  # fewer iterations -- each does its own N writes
        store = MemoryStore()
        agent_id = "fuzz-owner-2"
        n_writes = rng.randint(3, 30)
        for i in range(n_writes):
            store.write(agent_id, "k", {"n": i}, "fuzz-writer", "did:key:fuzz")
        chain = store._chains[agent_id]
        tamper_index = rng.randrange(len(chain))
        record = chain[tamper_index]
        tampered = bytearray(record.ciphertext)
        tampered[-1] ^= 0xFF  # flip one byte -- direct in-place tamper, bypassing write()
        record.ciphertext = bytes(tampered)
        result = store.verify_integrity(agent_id)
        if result["intact"] is not False:
            misses.append((trial, n_writes, tamper_index))
    assert misses == [], f"tampering not detected in trials {misses}"


def test_fuzz_ledger_quorum_commits_iff_cumulative_weight_reached():
    """Property: for ANY sequence of (org, stake) witnesses, the ledger
    must report committed=True if and only if the cumulative DISTINCT-org
    weight has reached quorum_required -- never early, never missed."""
    rng = random.Random(3001)
    misses = []
    for trial in range(N_FUZZ_ITERATIONS):
        quorum = rng.uniform(1.0, 5.0)
        ledger = FederationLedger(quorum=quorum)
        pid = ledger.propose_reinstatement("AccusedOrg")
        n_orgs = rng.randint(1, 8)
        orgs = [f"Org{i}" for i in range(n_orgs)]
        for org in orgs:
            ledger.set_stake(org, rng.uniform(0.0, 2.0))

        cumulative = 0.0
        seen = set()
        committed_at_right_time = True
        for org in orgs:
            result = ledger.witness(pid, org)
            if org not in seen:
                cumulative += ledger.stake_of(org)
                seen.add(org)
            expected_committed = cumulative >= quorum
            if result["committed"] != expected_committed:
                committed_at_right_time = False
        if not committed_at_right_time:
            misses.append(trial)
    assert misses == [], f"quorum commit timing wrong in trials {misses}"


# ============================================================
# Part 2: non-adversarial failure injection
# ============================================================

def test_chaos_db_write_failure_degrades_gracefully_and_recovers(tmp_path):
    """
    A mid-operation SQLite failure (disk full, permissions, corruption --
    not an attack) should not cause a message to be treated as ALLOWED
    when it should have been blocked, or vice versa, AND (v7.6) should
    not crash the caller either. This test injects a failure into the
    audit-write path and verifies the full graceful-degradation +
    recovery story: the security decision still returns correctly, the
    failed row is buffered rather than lost, and once the DB becomes
    writable again the buffered row flushes and the hash chain is
    provably intact end to end. See THREAT_MODEL.md Section 17 (original
    finding) and pentest/pt21_audit_write_resilience.py (fuller scenario
    coverage: opportunistic flush, ordering under multiple consecutive
    failures, and the security-state-never-bypassed property).
    """
    db_path = str(tmp_path / "chaos.db")
    bus = FederationBus(db_path=db_path)
    agents = build_federation(bus, n_orgs=1)
    advisor, executor = agents["OrgA"]["advisor"], agents["OrgA"]["executor"]

    ok = bus.sign_and_send(advisor.agent_id, "OrgA", executor.agent_id, "OrgA",
                             "plan_forward", {"requested_privilege": 0.1,
                                               "attempts_system_override": False}, taint_delta=0.0)
    assert ok["decision"] == "allow"

    original_execute = bus.db.execute
    original_commit = bus.db.commit
    real_connection = bus.db
    call_count = {"n": 0}

    class _FlakyDBProxy:
        """sqlite3.Connection's methods are C-level and read-only on the
        instance -- can't monkeypatch bus.db.execute directly. Swap the
        whole connection object for a thin proxy instead."""
        def execute(self, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise sqlite3.OperationalError("simulated disk failure (chaos test)")
            return original_execute(*args, **kwargs)

        def commit(self):
            return original_commit()

    bus.db = _FlakyDBProxy()

    raised = False
    result = None
    try:
        result = bus.sign_and_send(advisor.agent_id, "OrgA", executor.agent_id, "OrgA",
                                     "plan_forward", {"requested_privilege": 0.1,
                                                       "attempts_system_override": False}, taint_delta=0.0)
    except sqlite3.OperationalError:
        raised = True

    # v7.6 FIX (was: FINDING, THREAT_MODEL.md Section 17): a DB failure
    # during the audit write no longer propagates as an unhandled
    # exception. The security decision is computed and returned exactly
    # as it would be without the failure -- no control is bypassed, and
    # now the caller doesn't crash either.
    assert raised is False, "audit-write failure should degrade gracefully, not raise"
    assert result is not None and result["decision"] == "allow"
    assert len(bus._audit_write_buffer) == 1, "the failed row should be buffered, not dropped"

    bus.db = real_connection  # DB "recovers"

    # A subsequent send() opportunistically flushes the buffer before
    # writing its own row (see _write_audit_row's opportunistic-flush
    # step) -- but call the explicit API too, so this test exercises
    # both recovery paths, not just the automatic one.
    flush_result = bus.flush_buffered_audit_rows()
    assert flush_result["flushed"] == 1
    assert flush_result["pending"] == 0

    integrity = bus.verify_audit_integrity()
    assert integrity["intact"] is True, f"hash chain must stay intact across a buffer-and-recover cycle: {integrity}"

    bus.close()


def test_chaos_silent_witness_never_crashes_or_falsely_commits(tmp_path):
    """A witness org that simply never responds (crashed, network
    partition, anything) must leave the reinstatement proposal
    indefinitely uncommitted -- no crash, no false commit, no leak."""
    db_path = str(tmp_path / "chaos_witness.db")
    bus = FederationBus(db_path=db_path, require_message_signatures=False)
    agents = build_federation(bus, n_orgs=3)
    executor = agents["OrgA"]["executor"]

    for i in range(10):
        sybil_id = f"OrgA-sybil-{i}"
        bus.register_agent(sybil_id, "OrgA", base_privilege=0.1)
        vc = bus.trust.issue_credential("OrgA", subject_did=f"did:key:agent:{sybil_id}",
                                          claims={"role": "sybil"}, ttl_seconds=300.0)
        bus.admit_agent(sybil_id, "OrgA", vc)
        bus.send(sybil_id, "OrgA", executor.agent_id, "OrgA", "memory_recall_forward",
                  {"requested_privilege": 0.2, "attempts_system_override": False}, taint_delta=0.04)
    assert "OrgA" in bus.federation_wide_quarantined

    proposal = bus.propose_federation_reinstatement("OrgA")
    bus.sign_and_witness_federation_reinstatement(proposal["proposal_id"], "OrgA")
    # OrgB and OrgC simply never witness -- simulating both being down.
    result = bus.ledger.proposals[proposal["proposal_id"]]
    assert result["committed"] is False
    assert "OrgA" in bus.federation_wide_quarantined  # still quarantined, correctly

    other_advisor, other_executor = agents["OrgB"]["advisor"], agents["OrgB"]["executor"]
    unrelated = bus.sign_and_send(other_advisor.agent_id, "OrgB", other_executor.agent_id, "OrgB",
                                    "plan_forward", {"requested_privilege": 0.1,
                                                      "attempts_system_override": False}, taint_delta=0.0)
    assert unrelated["decision"] == "allow"
    bus.close()


def test_chaos_bus_restart_loses_sessions_but_keeps_audit_history(tmp_path):
    """
    Simulates a process crash and restart: a brand-new FederationBus
    instance pointing at the SAME on-disk audit database. Correct
    behaviour: (1) audit history from before the "crash" survives,
    (2) NO admitted sessions carry over -- every agent must re-admit,
    the secure default, not a bug, (3) nothing crashes on restart even
    with pre-existing audit rows present.
    """
    db_path = str(tmp_path / "chaos_restart.db")
    bus1 = FederationBus(db_path=db_path)
    agents = build_federation(bus1, n_orgs=1)
    advisor, executor = agents["OrgA"]["advisor"], agents["OrgA"]["executor"]
    bus1.sign_and_send(advisor.agent_id, "OrgA", executor.agent_id, "OrgA",
                         "plan_forward", {"requested_privilege": 0.1,
                                           "attempts_system_override": False}, taint_delta=0.0)
    pre_crash_integrity = bus1.verify_audit_integrity()
    assert pre_crash_integrity["intact"] is True
    bus1.close()  # "crash" -- all in-memory state (bus1) is gone

    bus2 = FederationBus(db_path=db_path)  # "restart": new object, same DB file
    post_restart_integrity = bus2.verify_audit_integrity()
    assert post_restart_integrity["intact"] is True

    blocked = bus2.send(advisor.agent_id, "OrgA", executor.agent_id, "OrgA",
                          "plan_forward", {"requested_privilege": 0.1,
                                            "attempts_system_override": False}, taint_delta=0.0)
    assert blocked["decision"] == "block"
    assert blocked["reason"] == "unadmitted_identity"
    bus2.close()
