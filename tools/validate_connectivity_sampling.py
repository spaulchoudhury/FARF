"""
validate_connectivity_sampling.py -- closes the "untested sampling path"
gap: fars.py's _connectivity_score() switches from exact
nx.node_connectivity() to a random-pair sampling estimator above
max_exact_nodes=20 agents, asserted as "an unbiased estimator" but never
compared against the exact value on anything but the toy graphs pentest
scripts happen to use.

Approach: generate topologies large enough to exceed 20 agents (via
synthetic_federation_topology.py), then call the SAME FARSEngine
._connectivity_score() twice per graph -- once with max_exact_nodes set
high enough to force the exact path even above 20, once left at the
real default (20) so it takes the sampling path -- and compare. This
isolates the estimator itself; nothing else about the score changes.
"""

from __future__ import annotations

import statistics

from synthetic_federation_topology import TopologyParams, generate_topology

from fars import FARSEngine


def compare_at_size(n_orgs: int, agents_per_org: int, n_trials: int = 15, seed_base: int = 7000):
    engine = FARSEngine()
    exact_scores = []
    sampled_scores = []
    abs_diffs = []
    n_agents = None
    for i in range(n_trials):
        params = TopologyParams(n_orgs=n_orgs, agents_per_org=agents_per_org,
                                 topology_type="gnp" if i % 2 == 0 else "barabasi_albert",
                                 p=0.35, m=2, seed=seed_base + i)
        model = generate_topology(params)
        n_agents = model.graph.number_of_nodes()
        exact = engine._connectivity_score(model.graph, max_exact_nodes=10_000)
        sampled = engine._connectivity_score(model.graph, max_exact_nodes=20, sample_pairs=200)
        exact_scores.append(exact)
        sampled_scores.append(sampled)
        abs_diffs.append(abs(exact - sampled))
    return {
        "n_agents": n_agents,
        "n_trials": n_trials,
        "mean_exact": round(statistics.mean(exact_scores), 4),
        "mean_sampled": round(statistics.mean(sampled_scores), 4),
        "mean_signed_bias(sampled-exact)": round(statistics.mean(s - e for s, e in zip(sampled_scores, exact_scores)), 4),
        "mean_abs_diff": round(statistics.mean(abs_diffs), 4),
        "max_abs_diff": round(max(abs_diffs), 4),
    }


def main():
    print("Validating fars.py's N>20 connectivity sampling estimator against the exact")
    print("nx.node_connectivity() calculation it's meant to approximate.\n")
    print(f"{'n_agents':>10}{'n_trials':>10}{'mean_exact':>14}{'mean_sampled':>14}{'signed_bias':>14}{'mean_abs_diff':>16}{'max_abs_diff':>14}")
    print("-" * 92)
    # v7.9.10: extended past the original 64-agent ceiling, per the thesis
    # supervisor's explicit direction to reach the ~200-agent case the
    # estimator's own docstring cites as its runtime-cost justification
    # (exact computation measured at ~16s for a single 200-agent graph in
    # this environment -- see CHANGELOG_v7.9.10.md). n_trials is reduced
    # as n_agents grows so the whole sweep finishes in a few minutes
    # instead of tens of minutes; still repeated, not a single draw, at
    # every size including 200.
    configs = [
        # (n_orgs, agents_per_org, n_trials) -- first 8 unchanged from the
        # original script (kept at n_trials=15, cheap up to 64 agents)
        (11, 2, 15), (13, 2, 15), (16, 2, 15), (10, 3, 15),
        (13, 3, 15), (16, 3, 15), (10, 4, 15), (13, 4, 15),
        # new: extending to the docstring's own 200-agent reference point
        (20, 4, 8),   # 80 agents
        (25, 4, 6),   # 100 agents
        (32, 4, 5),   # 128 agents
        (40, 4, 5),   # 160 agents
        (50, 4, 5),   # 200 agents -- the actual target this closes
    ]
    all_rows = []
    for n_orgs, agents_per_org, n_trials in configs:
        result = compare_at_size(n_orgs, agents_per_org, n_trials=n_trials)
        all_rows.append(result)
        print(f"{result['n_agents']:>10}{n_trials:>10}{result['mean_exact']:>14}{result['mean_sampled']:>14}"
              f"{result['mean_signed_bias(sampled-exact)']:>+14}{result['mean_abs_diff']:>16}{result['max_abs_diff']:>14}")

    print()
    overall_bias = statistics.mean(r["mean_signed_bias(sampled-exact)"] for r in all_rows)
    overall_abs = statistics.mean(r["mean_abs_diff"] for r in all_rows)
    print(f"Overall mean signed bias across all sizes tested (11-200 agents): {overall_bias:+.4f}")
    print(f"Overall mean |diff| across all sizes tested:                      {overall_abs:.4f}")

    # v7.9.10: also report the 200-agent row on its own -- an aggregate
    # across 11-200 agents could mask a bias that only appears at the
    # extreme the docstring actually worried about.
    largest = max(all_rows, key=lambda r: r["n_agents"])
    print(f"\n200-agent row specifically (the docstring's own worst case): "
          f"n_agents={largest['n_agents']}, signed_bias={largest['mean_signed_bias(sampled-exact)']:+.4f}, "
          f"mean_abs_diff={largest['mean_abs_diff']:.4f}, max_abs_diff={largest['max_abs_diff']:.4f}")

    print()
    if abs(overall_bias) < 0.01 and abs(largest["mean_signed_bias(sampled-exact)"]) < 0.01:
        print("Verdict: no material systematic bias detected from 11 up to 200 agents, INCLUDING")
        print("at the 200-agent point specifically -- this closes the 'unvalidated for scale claims'")
        print("gap (PHASE1_TO_CLOUD_DECISION_BRIEF.md \u00a72 item 23) at the scale that was actually cited.")
    elif abs(overall_bias) < 0.01:
        print("Verdict: no material bias in the AGGREGATE, but the 200-agent row specifically shows a")
        print("bias the smaller sizes did not -- do not generalise 'no bias' from small N to 200 agents.")
    else:
        print("Verdict: a systematic bias is present -- do not treat the sampling path as a")
        print("drop-in replacement for the exact calculation without further investigation.")


if __name__ == "__main__":
    main()
