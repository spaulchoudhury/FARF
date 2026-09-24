"""
fars_sensitivity_sweep.py -- how much do FARS's four uncited "magic
constants" actually move the score?

This does NOT modify fars.py. It mirrors its exact formulas (connectivity
normaliser /4.0, trust_health's baseline_operational_cost=0.15, the taint
blend 0.3/0.7, and EWMA alpha=0.3) with each constant parameterised, then
sweeps each one +/-30% around its shipped value while holding the other
three fixed at their shipped value and a representative scenario's inputs
constant. This is the ablation the closure doc / Tab 7.9 doesn't yet run --
purpose is to show WHICH constants are worth calibrating before citing FARS
Correlation Coefficient numbers from real cloud-build data, not to declare
a "correct" value for any of them.

Representative scenario used: loosely modelled on E4 (Memory Manipulation)
post-quarantine state from TEST_PROTOCOL.md/THREAT_MODEL.md -- 1 org
quarantined out of 3, graph-level containment mostly successful
(structural_containment_score=0.85), moderate per-message taint
(6/40 messages tainted), 1 policy violation out of 25 events, average
node connectivity of 2.1 in a 6-agent graph. Change SCENARIO below to test
other regimes; the qualitative "which constant matters most" ranking is
what this script is actually for, not the specific numbers under one
scenario.
"""

from __future__ import annotations

import copy

SCENARIO = {
    "quarantined": 1, "total_agents": 6,
    "structural_containment_score": 0.85,
    "tainted_messages": 6, "total_messages": 40,
    "policy_violations": 1, "total_events": 25,
    "avg_connectivity": 2.1,
    "previous_ewma": 72.0,
}

# --------------------------------------------------------------------------
# v7.9.10: multi-scenario extension, thesis-supervisor-directed (Decision
# #2 -- "adjust around connectivity_divisor for multi-scenario sensitivity").
# The single SCENARIO above is kept as the original default (backward
# compatible, still what sweep()/main() use if called with no arguments),
# but "statistically untested" (PHASE1_TO_CLOUD_DECISION_BRIEF.md \u00a72 item
# 22) specifically flagged that one scenario doesn't establish robustness.
# These five span the regimes FARF's own scenario functions
# (scenario_prompt_injection/toctou/trust_boundary_violation/
# memory_manipulation in main.py) and THREAT_MODEL.md actually describe,
# not arbitrary points -- each is labelled with which real regime it
# represents so the range reported below means something.
# --------------------------------------------------------------------------
SCENARIOS = {
    "healthy_no_incident": {
        # No attack at all -- baseline federation health, all agents
        # active, full connectivity, zero taint/violations. Every FARS
        # component should sit near its ceiling here.
        "quarantined": 0, "total_agents": 6, "structural_containment_score": 1.0,
        "tainted_messages": 0, "total_messages": 40, "policy_violations": 0,
        "total_events": 25, "avg_connectivity": 5.0, "previous_ewma": 95.0,
    },
    "moderate_e1_prompt_injection": {
        # Mirrors E1 (Prompt Injection) mid-campaign: no quarantine yet,
        # partial taint, a couple of policy violations, connectivity
        # intact (injection doesn't sever graph edges).
        "quarantined": 0, "total_agents": 6, "structural_containment_score": 1.0,
        "tainted_messages": 4, "total_messages": 40, "policy_violations": 2,
        "total_events": 25, "avg_connectivity": 3.4, "previous_ewma": 85.0,
    },
    "original_e4_post_quarantine": SCENARIO,  # the original single scenario, unchanged
    "severe_multi_org_sybil": {
        # Mirrors a composite/worst-case: 2 of 6 agents' org quarantined
        # (matches pt04-style org-wide Sybil), heavier taint, connectivity
        # degraded by the quarantine itself (fewer live edges).
        "quarantined": 2, "total_agents": 6, "structural_containment_score": 0.55,
        "tainted_messages": 14, "total_messages": 40, "policy_violations": 5,
        "total_events": 25, "avg_connectivity": 1.2, "previous_ewma": 48.0,
    },
    "large_sparse_federation": {
        # A bigger, sparser federation -- tests whether the connectivity
        # normaliser's sensitivity ranking changes shape once avg
        # connectivity is naturally lower just from federation size, not
        # from an attack (matters for the N-scaling question raised
        # alongside the N>20 connectivity-sampling item).
        "quarantined": 1, "total_agents": 24, "structural_containment_score": 0.9,
        "tainted_messages": 8, "total_messages": 160, "policy_violations": 3,
        "total_events": 100, "avg_connectivity": 1.6, "previous_ewma": 78.0,
    },
}

SHIPPED = {
    "connectivity_divisor": 4.0,
    "baseline_operational_cost": 0.15,
    "taint_blend_per_message": 0.3,   # graph_level weight is (1 - this)
    "ewma_alpha": 0.3,
}

WEIGHTS = {"connectivity": 0.25, "trust_health": 0.30, "taint_containment": 0.30, "policy_compliance": 0.15}


def connectivity_score(avg_conn: float, divisor: float) -> float:
    return min(1.0, avg_conn / divisor)


def trust_health_score(quarantined: int, total_agents: int, structural_containment_score: float,
                        baseline_operational_cost: float) -> float:
    if total_agents == 0:
        return 1.0
    quarantined_fraction = quarantined / total_agents
    escape_penalty_factor = 1.0 - structural_containment_score
    penalty = quarantined_fraction * (baseline_operational_cost
                                       + (1.0 - baseline_operational_cost) * escape_penalty_factor)
    return max(0.0, 1.0 - penalty)


def taint_containment_score(tainted_messages: int, total_messages: int, max_blast_radius_fraction: float,
                             per_message_weight: float) -> float:
    per_message = 1.0 if total_messages == 0 else max(0.0, 1.0 - (tainted_messages / total_messages))
    graph_level = max(0.0, 1.0 - max_blast_radius_fraction)
    return per_message_weight * per_message + (1.0 - per_message_weight) * graph_level


def policy_compliance_score(violations: int, total_events: int) -> float:
    if total_events == 0:
        return 1.0
    return max(0.0, 1.0 - (violations / total_events))


def compute_fars(scenario: dict, constants: dict) -> float:
    c = connectivity_score(scenario["avg_connectivity"], constants["connectivity_divisor"])
    p = taint_containment_score(scenario["tainted_messages"], scenario["total_messages"],
                                 max_blast_radius_fraction=1.0 - scenario["structural_containment_score"],
                                 per_message_weight=constants["taint_blend_per_message"])
    t = trust_health_score(scenario["quarantined"], scenario["total_agents"],
                            scenario["structural_containment_score"],
                            constants["baseline_operational_cost"])
    g = policy_compliance_score(scenario["policy_violations"], scenario["total_events"])
    return 100 * (WEIGHTS["connectivity"] * c + WEIGHTS["trust_health"] * t
                   + WEIGHTS["taint_containment"] * p + WEIGHTS["policy_compliance"] * g)


def compute_ewma(current_score: float, previous_ewma: float, alpha: float) -> float:
    return alpha * current_score + (1 - alpha) * previous_ewma


def sweep(constant_name: str, scenario: dict | None = None, deltas=(-0.3, -0.15, 0.0, 0.15, 0.3)):
    scenario = scenario if scenario is not None else SCENARIO
    baseline_score = compute_fars(scenario, SHIPPED)
    rows = []
    for d in deltas:
        constants = copy.copy(SHIPPED)
        constants[constant_name] = SHIPPED[constant_name] * (1 + d)
        # keep constants in sane ranges
        if constant_name == "taint_blend_per_message":
            constants[constant_name] = min(1.0, max(0.0, constants[constant_name]))
        if constant_name == "ewma_alpha":
            constants[constant_name] = min(1.0, max(0.0, constants[constant_name]))
        score = compute_fars(scenario, constants)
        if constant_name == "ewma_alpha":
            score_display = compute_ewma(baseline_score, scenario["previous_ewma"], constants[constant_name])
            baseline_display = compute_ewma(baseline_score, scenario["previous_ewma"], SHIPPED[constant_name])
        else:
            score_display, baseline_display = score, baseline_score
        rows.append((d, constants[constant_name], score_display, score_display - baseline_display))
    return baseline_score, rows


def multi_scenario_sweep(constant_name: str = "connectivity_divisor"):
    """v7.9.10: runs `sweep()` for `constant_name` across every scenario in
    SCENARIOS and reports the range (min/mean/max of max|shift|) instead of
    a single scenario's point estimate -- this is what actually answers
    "is this constant's sensitivity a one-scenario artefact or does it hold
    up across regimes?" Defaults to connectivity_divisor per the thesis
    supervisor's specific direction, but works for any of the four."""
    print(f"=== Multi-scenario sensitivity for '{constant_name}' ({len(SCENARIOS)} scenarios) ===\n")
    max_shifts = {}
    for scenario_name, scenario in SCENARIOS.items():
        baseline, rows = sweep(constant_name, scenario=scenario)
        max_shift = max(abs(r[3]) for r in rows)
        max_shifts[scenario_name] = max_shift
        print(f"  {scenario_name:<28} baseline FARS={baseline:>6.2f}   max |shift|={max_shift:+.2f} points")
    values = list(max_shifts.values())
    print(f"\n  Across {len(SCENARIOS)} scenarios: min={min(values):.2f}, "
          f"mean={sum(values)/len(values):.2f}, max={max(values):.2f} FARS points")
    spread = max(values) - min(values)
    print(f"  Spread (max-min): {spread:.2f} points -- ", end="")
    if spread > 2.0:
        print("MATERIAL: this constant's sensitivity is scenario-dependent, not a fixed property. "
              "A single-scenario point estimate (the pre-v7.9.10 sweep) would have been misleading "
              "about how much this matters in other regimes.")
    else:
        print("the sensitivity ranking is stable across regimes -- the original single-scenario "
              "estimate was not misleading for this constant, even though it was still only one sample.")
    return max_shifts


def main():
    print(f"Scenario: {SCENARIO}\n")
    print(f"{'Constant':<28}{'delta':>8}{'value':>10}{'FARS':>10}{'shift':>10}")
    print("-" * 66)
    max_shift = {}
    for name in SHIPPED:
        _baseline, rows = sweep(name)
        for d, val, score, shift in rows:
            marker = "  <- shipped" if abs(d) < 1e-9 else ""
            print(f"{name:<28}{d:>+7.0%}{val:>10.3f}{score:>10.2f}{shift:>+10.2f}{marker}")
        max_shift[name] = max(abs(r[3]) for r in rows)
        print()
    print("Ranked by max |shift| across a +/-30% sweep (largest = most worth calibrating first):")
    for name, shift in sorted(max_shift.items(), key=lambda kv: -kv[1]):
        print(f"  {name:<28} max shift {shift:+.2f} FARS points")

    print("\n" + "=" * 78)
    print("v7.9.10 EXTENSION -- multi-scenario robustness check (supervisor-directed)")
    print("=" * 78)
    multi_scenario_sweep("connectivity_divisor")
    print()
    # honestly check whether the OTHER three constants also scenario-depend,
    # not just the one the supervisor named -- costs nothing extra to run.
    for other in ("baseline_operational_cost", "taint_blend_per_message", "ewma_alpha"):
        multi_scenario_sweep(other)
        print()


if __name__ == "__main__":
    main()
