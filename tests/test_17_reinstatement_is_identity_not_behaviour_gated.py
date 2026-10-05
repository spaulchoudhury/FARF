"""
Negative-control test (added 26 Sep 2026, following the live reinstatement trials reported in
Chapter 5 Section 5.11.4.3): quorum-witnessed reinstatement is a vote on IDENTITY and CONSENSUS
(is this organisation who it claims to be, and do enough other organisations agree to lift the
quarantine), not a vote on the organisation's CURRENT BEHAVIOUR.

This is read directly from witness_federation_reinstatement()/`_restore_org()`'s own source: neither
function inspects the accused organisation's recent traffic, taint history, or any other behavioural
signal before restoring it. This test constructs the scenario the two live trials could not, by
design, exercise (both trials reinstated an organisation whose "hostile" traffic was entirely an
artefact of repeated benign pentest runs): an organisation that is GENUINELY, CONTINUOUSLY exhibiting
the exact behaviour that caused its quarantine, reinstated anyway, with that same behaviour resuming
immediately and without renewed scrutiny.

This is not reported as a defect: a design that required organisations to prove reformed behaviour
before a human-governed quorum could even vote would move the decision out of the quorum's hands
entirely, which may or may not be the right trade-off -- that is a design question for ADR-020, not
this test. What this test establishes is the FACT of the current design's scope, so it can be stated
in the thesis as a disclosed, evidenced limitation rather than an assumption.
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


def _send_high_taint(bus, adv, exe, org):
    return bus.sign_and_send(adv, org, exe, org, "memory_recall_forward",
                             {"requested_privilege": 0.1, "attempts_system_override": False}, 0.05)


def test_reinstatement_does_not_check_whether_hostile_behaviour_has_stopped(tmp_path):
    bus = _bus(tmp_path)
    _admit(bus, "OrgA-adv", "OrgA", "advisor")
    _admit(bus, "OrgA-exe", "OrgA", "executor")

    # Drive OrgA into quarantine with a sustained, ongoing high-taint pattern -- not a one-off.
    tripped = False
    for _ in range(20):
        r = _send_high_taint(bus, "OrgA-adv", "OrgA-exe", "OrgA")
        if r["decision"] == "quarantine":
            tripped = True
            break
    assert tripped and "OrgA" in bus.federation_wide_quarantined

    # The organisation's behaviour has NOT changed: prove it is still, right now, producing the same
    # pattern that caused the quarantine (blocked while quarantined, which is expected and correct --
    # this establishes the org is genuinely still "hostile" at the moment reinstatement is proposed,
    # not that it has gone quiet).
    still_hostile = _send_high_taint(bus, "OrgA-adv", "OrgA-exe", "OrgA")
    assert still_hostile["decision"] in ("block", "quarantine")

    # Quorum reinstatement: three OTHER organisations vote, none of them examines OrgA's traffic.
    pid = bus.propose_federation_reinstatement("OrgA")["proposal_id"]
    committed_at = None
    for i, org in enumerate(["OrgB", "OrgC", "OrgD"], start=1):
        w = bus.sign_and_witness_federation_reinstatement(pid, org)
        if w.get("committed") and committed_at is None:
            committed_at = i
    assert committed_at is not None, "reinstatement did not commit even though quorum-many independent orgs voted"
    assert "OrgA" not in bus.federation_wide_quarantined

    # The crux of this test: immediately after reinstatement, with ZERO elapsed time for OrgA to
    # "reform", the exact same high-taint pattern that caused the original quarantine is now
    # permitted again, with no additional scrutiny applied.
    _admit(bus, "OrgA-adv", "OrgA", "advisor")
    _admit(bus, "OrgA-exe", "OrgA", "executor")
    immediately_after = _send_high_taint(bus, "OrgA-adv", "OrgA-exe", "OrgA")
    assert immediately_after["decision"] == "allow", (
        "expected the reinstated org's first post-recovery message to be allowed with no added scrutiny "
        f"(this is the finding, not a bug), got {immediately_after}"
    )


def test_reinstatement_vote_is_unanimous_only_in_the_sense_of_reaching_quorum_weight():
    """A quorum vote checks accumulated stake/weight against a threshold; it has no notion of the
    voting organisations having reviewed anything, beyond each one cryptographically proving it is
    who it claims to be (tested elsewhere: PT-11, witness signature/replay checks). This test states
    that scope explicitly by inspecting the witness function's own contract rather than asserting
    behaviour that would require simulating an actual reviewing process that does not exist."""
    import inspect
    src = inspect.getsource(FederationBus.witness_federation_reinstatement)
    # The witness function must authenticate WHO is voting (signature/identity checks are present)...
    assert "signature" in src and "identities.get" in src
    # ...but must not reference the accused organisation's traffic, taint, or behaviour history at all.
    for forbidden in ("taint", "behavioural", "SlidingWindowVolumeDetector", "org_volume_detector"):
        assert forbidden not in src, (
            f"witness_federation_reinstatement() now references {forbidden!r} -- if a behavioural check "
            "was added, this test (and the thesis claim it backs) needs to be updated, not just this assertion"
        )
