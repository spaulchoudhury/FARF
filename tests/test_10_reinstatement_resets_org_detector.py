"""
Regression test (added 21 Sep 2026): quorum reinstatement of an organisation must not leave the
organisation's volume-detector window in the tripped state.

Found during the cloud verification run: PT-08 was repeated against a persistent deployment until the
org-level SlidingWindowVolumeDetector (window 40, cap 0.35) quarantined the whole organisation. A quorum
reinstatement committed at exactly the quorum-th witness, but the organisation's very next message was
quarantined again with reason org_wide_behavioural_drift, because _restore_org() cleared the flags and the
agent-level detectors but never the org-level detector history that caused the quarantine.
"""
from federation_bus import FederationBus


def _bus(tmp_path):
    bus = FederationBus(db_path=str(tmp_path / "a.db"), require_message_signatures=True, quorum_mode="pbft_dynamic")
    for o in ["OrgA", "OrgB", "OrgC", "OrgD"]:
        bus.register_organisation(o)
    return bus


def _admit(bus, agent, org, role):
    bus.register_agent(agent, org, base_privilege=0.1)
    vc = bus.trust.issue_credential(org, subject_did=f"did:key:agent:{agent}", claims={"role": role}, ttl_seconds=300.0)
    assert bus.admit_agent(agent, org, vc)["valid"]


def test_reinstated_org_is_not_immediately_requarantined(tmp_path):
    bus = _bus(tmp_path)
    _admit(bus, "OrgA-adv", "OrgA", "advisor")
    _admit(bus, "OrgA-exe", "OrgA", "executor")
    # drive the org-level detector over its cap with ordinary low-taint traffic
    tripped = False
    for _ in range(20):
        r = bus.sign_and_send("OrgA-adv", "OrgA", "OrgA-exe", "OrgA", "memory_recall_forward",
                              {"requested_privilege": 0.1, "attempts_system_override": False}, 0.05)
        if r["decision"] == "quarantine":
            tripped = True
            break
    assert tripped and "OrgA" in bus.federation_wide_quarantined
    # quorum reinstatement (4 orgs -> quorum 3)
    pid = bus.propose_federation_reinstatement("OrgA")["proposal_id"]
    committed_at = None
    for i, org in enumerate(["OrgA", "OrgB", "OrgC", "OrgD"], start=1):
        w = bus.sign_and_witness_federation_reinstatement(pid, org)
        if w.get("committed") and committed_at is None:
            committed_at = i
    assert committed_at == 3
    assert "OrgA" not in bus.federation_wide_quarantined
    # reinstated agents need a fresh session, then must be able to send
    _admit(bus, "OrgA-adv", "OrgA", "advisor")
    r = bus.sign_and_send("OrgA-adv", "OrgA", "OrgA-exe", "OrgA", "memory_recall_forward",
                          {"requested_privilege": 0.1, "attempts_system_override": False}, 0.0)
    assert r["decision"] == "allow", r
