"""
Test Protocol 1 -- Baseline Agentic Interaction (benign path)
==================================================================
Source diagram: Agentic_Interaction_Diagram.svg

Diagram stages under test, in order:
    Org Agents -> Federation Bus -> Trust Token (VC + DID:key attestation)
        -> Behaviour Monitor (runtime governance enforcement)
        -> Taint Propagation (origin tracking across organisations)
        -> FARS Engine -> Feedback Loop (trust recalibration + policy update)

For BENIGN traffic, the expected behaviour at every stage is "pass
through cleanly": credentials verify, no policy violation is raised,
no taint accumulates past threshold, FARS sits at the federation's
clean-topology ceiling, and the Feedback Loop is never invoked (no
agent needs trust recalibration).

This is the control/negative-case suite: every other test file proves
FARF *reacts* to attacks; this one proves it does *not* over-react to
normal collaboration.
"""
from orchestration import Decision
from tests.conftest import baseline_fars_ceiling


def test_trust_token_issuance_and_verification(fresh_bus):
    """Federation Bus stage: 'Trust Token — VC + DID:key attestation'."""
    bus, _agents = fresh_bus
    vc = bus.trust.issue_credential(
        "OrgA", subject_did="did:key:zBENIGN-SUBJECT", claims={"role": "advisor"}
    )
    result = bus.trust.verify_credential(vc, "OrgA")
    assert result["valid"] is True
    assert result["reason"] == "ok"


def test_benign_message_is_allowed_by_behaviour_monitor(fresh_bus):
    """Federation Bus stage: 'Behaviour Monitor — runtime governance enforcement'."""
    bus, agents = fresh_bus
    advisor = agents["OrgA"]["advisor"]
    executor = agents["OrgA"]["executor"]

    payload = advisor.plan("Please summarise last quarter's sales figures.")
    assert payload["attempts_system_override"] is False

    result = bus.send(advisor.agent_id, "OrgA", executor.agent_id, "OrgA",
                       action_type="benign_plan_forward", payload=payload, taint_delta=0.02)

    assert result["decision"] == Decision.ALLOW.value
    assert result["reason"] == "no_violation"
    assert bus.orchestration.quarantined_agents == set()


def test_benign_traffic_stays_below_taint_threshold(fresh_bus):
    """Federation Bus stage: 'Taint Propagation — origin tracking across organisations'."""
    bus, agents = fresh_bus
    advisor = agents["OrgB"]["advisor"]
    executor = agents["OrgB"]["executor"]
    payload = advisor.plan("Draft the weekly status report.")

    result = bus.send(advisor.agent_id, "OrgB", executor.agent_id, "OrgB",
                       action_type="benign_plan_forward", payload=payload, taint_delta=0.05)

    assert result["taint_level"] < 0.5
    assert bus.taint.is_tainted(result["message_id"]) is False


def test_fars_sits_at_clean_topology_ceiling(fresh_bus):
    """
    FARS Engine stage: with no violations and no taint, FARS should equal
    the federation's structural ceiling (trust_health = taint_containment
    = policy_compliance = 1.0; only connectivity is capped by topology).
    """
    bus, agents = fresh_bus
    advisor = agents["OrgC"]["advisor"]
    executor = agents["OrgC"]["executor"]
    payload = advisor.plan("Schedule the quarterly review meeting.")
    bus.send(advisor.agent_id, "OrgC", executor.agent_id, "OrgC",
              action_type="benign_plan_forward", payload=payload, taint_delta=0.0)

    fars = bus.current_fars()
    ceiling = baseline_fars_ceiling(bus)

    assert fars["components"]["trust_health"] == 1.0
    assert fars["components"]["taint_containment"] == 1.0
    assert fars["components"]["policy_compliance"] == 1.0
    # FARS should equal weighted sum of all-1.0 components + the topology-capped connectivity term
    expected = ceiling + 100 * (0.30 + 0.30 + 0.15)
    assert abs(fars["FARS"] - expected) < 0.5


def test_feedback_loop_not_triggered_for_benign_traffic(fresh_bus):
    """Feedback Loop stage: trust recalibration should never fire when
    there is nothing to recalibrate."""
    bus, agents = fresh_bus
    for org in ["OrgA", "OrgB", "OrgC"]:
        advisor, executor = agents[org]["advisor"], agents[org]["executor"]
        payload = advisor.plan("Routine status update, nothing unusual.")
        bus.send(advisor.agent_id, org, executor.agent_id, org,
                  action_type="benign_plan_forward", payload=payload, taint_delta=0.03)

    assert len(bus.orchestration.quarantined_agents) == 0
    violations = [e for e in bus.orchestration.audit_log if e["decision"] != "allow"]
    assert violations == []
