"""T7 / G11: does FARS rank federations the way an INDEPENDENT outcome does, over >= 50 generated topologies?

Problem with the earlier proxy: observed_resilience = 100 * (1 - blast) * (1 - quarantined share) is read from the same taint graph
and quarantine state that FARS itself consumes, so a high correlation is partly circular.

Independent outcome used here (measured from the bus's send() DECISIONS, not from taint state):
    harm_reach    = share of the other organisations that received at least one ALLOWED hostile message (declared or relayed)
    harm_mass     = sum of effective taint delta of ALLOWED hostile messages
    benign_ok     = share of benign background messages that were allowed (service kept)
    resilience_gt = 100 * (1 - harm_reach)
Caveat that stays: both FARS and the outcome are caused by the same attack, so some correlation is expected; what is removed is
the shared MEASUREMENT path.  Report it as such.

Corpus: 3..10 organisations, alternating Erdos-Renyi and Barabasi-Albert organisation graphs (tools/synthetic_federation_topology.py),
seeded.  Each topology gets one attack: the origin sends the attack text to every neighbour; each organisation that received an allowed
hostile message relays a stealthier copy (no override flag, delta x 0.5) to its own neighbours, up to 3 hops.  All organisations also
exchange benign background traffic with their neighbours (delta 0-0.006).

Reported:  Spearman rho (with bootstrap 95% CI over topologies) of FARS vs resilience_gt, proxy vs resilience_gt, FARS vs proxy (shared
inputs), and three naive predictors (org count, mean degree, quarantined share) so FARS has something to beat.
Usage: python -m experiments.run_fars_topologies [--n 60] [--out experiments/results_fars_topologies]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random

import networkx as nx
import numpy as np
from scipy.stats import spearmanr

from experiments.common import ATTACK_TEXT, BENIGN_TEXTS, close_bus, make_bus
from main import build_federation
from tools.synthetic_federation_topology import TopologyParams, generate_topology

logging.disable(logging.CRITICAL)


def corpus(n: int, seed: int = 42):
    rng = random.Random(seed)
    for i in range(n):
        yield TopologyParams(n_orgs=3 + (i % 8), agents_per_org=2, topology_type="gnp" if i % 2 == 0 else "barabasi_albert",
                             p=rng.uniform(0.25, 0.6), m=rng.randint(1, 3), seed=seed * 1000 + i)


def org_graph_of(model) -> nx.Graph:
    g = nx.Graph()
    for node, d in model.graph.nodes(data=True):
        g.add_node(d["org"])
    for u, v in model.graph.edges():
        ou, ov = model.graph.nodes[u]["org"], model.graph.nodes[v]["org"]
        if ou != ov:
            g.add_edge(ou, ov)
    return g


def trial(i: int, params: TopologyParams) -> dict:
    rng = random.Random(params.seed + 17)
    model = generate_topology(params)
    og = org_graph_of(model)
    bus = make_bus()
    try:
        agents = build_federation(bus, n_orgs=params.n_orgs)
        orgs = list(agents)
        # replace the chain build_federation seeds with the generated cross-organisation edges
        g = bus.adversary_model.graph
        for u, v in [(u, v) for u, v in g.edges() if g.nodes[u]["org"] != g.nodes[v]["org"]]:
            g.remove_edge(u, v)
        for u, v, d in model.graph.edges(data=True):
            ou, ov = model.graph.nodes[u]["org"], model.graph.nodes[v]["org"]
            if ou != ov:
                bus.adversary_model.add_delegation(agents[ou]["executor"].agent_id, agents[ov]["advisor"].agent_id, d.get("privilege", 0.3))

        def send(src, dst, text, delta, override_plan=False, benign=False):
            adv = agents[src]["advisor"]
            payload = adv.plan(text) if override_plan else {"requested_privilege": 0.1, "attempts_system_override": False, "instruction": text}
            return bus.send(adv.agent_id, src, agents[dst]["advisor"].agent_id, dst,
                            "benign_plan_forward" if benign else "memory_recall_forward", payload, taint_delta=delta)

        origin = rng.choice(orgs)
        delta = rng.uniform(0.02, 0.4)
        reached, mass = set(), 0.0
        frontier, seen_origin = [(origin, 0)], {origin}
        hostile_sent = 0
        while frontier:
            src, hop = frontier.pop(0)
            if hop >= 3:
                continue
            for nb in sorted(og.neighbors(src)):
                first = hop == 0
                r = send(src, nb, ATTACK_TEXT, delta if first else delta * 0.5, override_plan=first)
                hostile_sent += 1
                if r["decision"] == "allow":
                    reached.add(nb)
                    mass += r.get("taint_delta_effective", delta)
                    if nb not in seen_origin:
                        seen_origin.add(nb)
                        frontier.append((nb, hop + 1))
        benign_total = benign_ok = 0
        for _ in range(30 * params.n_orgs):
            s = rng.choice(orgs)
            nbs = sorted(og.neighbors(s)) or [s]
            d = rng.choice(nbs)
            r = send(s, d, rng.choice(BENIGN_TEXTS), rng.uniform(0.0, 0.006), benign=True)
            benign_total += 1
            benign_ok += r["decision"] == "allow"

        others = [o for o in orgs if o != origin]
        harm_reach = len(reached - {origin}) / max(1, len(others))
        fars = bus.current_fars()["FARS"]
        blast = len(bus.taint.blast_radius(agents[origin]["advisor"].agent_id)) / max(1, params.n_orgs - 1)
        q_share = len(bus.orchestration.quarantined_agents) / (2 * params.n_orgs)
        proxy = 100.0 * (1 - min(1.0, blast)) * (1 - q_share)
        degs = [d for _, d in og.degree()]
        return {"i": i, "topology": params.topology_type, "n_orgs": params.n_orgs, "edges": og.number_of_edges(),
                "mean_degree": round(float(np.mean(degs)), 3) if degs else 0.0, "origin_degree": og.degree(origin),
                "hostile_sent": hostile_sent, "harm_reach": round(harm_reach, 4), "harm_mass": round(mass, 4),
                "benign_ok": round(benign_ok / benign_total, 4), "resilience_gt": round(100 * (1 - harm_reach), 2),
                "fars": fars, "proxy": round(proxy, 2), "quarantined_share": round(q_share, 4), "blast": round(blast, 4)}
    finally:
        close_bus(bus)


def rho_ci(x, y, n_boot=2000, seed=1):
    x, y = np.asarray(x, float), np.asarray(y, float)
    if np.ptp(x) == 0 or np.ptp(y) == 0:
        return {"rho": None, "ci95": [None, None], "p": None, "note": "constant input"}
    r, p = spearmanr(x, y)
    rng, boots = np.random.default_rng(seed), []
    for _ in range(n_boot):
        idx = rng.integers(0, len(x), len(x))
        if np.ptp(x[idx]) and np.ptp(y[idx]):
            boots.append(spearmanr(x[idx], y[idx])[0])
    lo, hi = np.percentile(boots, [2.5, 97.5]) if boots else (None, None)
    return {"rho": round(float(r), 3), "ci95": [round(float(lo), 3), round(float(hi), 3)] if boots else [None, None], "p": float(p)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--out", default="experiments/results_fars_topologies")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows = [trial(i, p) for i, p in enumerate(corpus(a.n))]
    with open(os.path.join(a.out, "fars_topologies.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    col = lambda k: [r[k] for r in rows]  # noqa: E731
    gt = col("resilience_gt")
    res = {
        "n_topologies": len(rows),
        "n_orgs_range": [min(col("n_orgs")), max(col("n_orgs"))],
        "gt_distribution": {"mean": round(float(np.mean(gt)), 2), "min": min(gt), "max": max(gt), "distinct_values": len(set(gt))},
        "FARS_vs_resilience_gt": rho_ci(col("fars"), gt),
        "proxy_vs_resilience_gt": rho_ci(col("proxy"), gt),
        "FARS_vs_proxy_(shared inputs)": rho_ci(col("fars"), col("proxy")),
        "FARS_vs_benign_ok": rho_ci(col("fars"), col("benign_ok")),
        "naive_org_count_vs_gt": rho_ci(col("n_orgs"), gt),
        "naive_mean_degree_vs_gt": rho_ci(col("mean_degree"), gt),
        "naive_quarantined_share_vs_gt (negated)": rho_ci([-v for v in col("quarantined_share")], gt),
    }
    with open(os.path.join(a.out, "fars_topologies.json"), "w") as f:
        json.dump(res, f, indent=2)
    print(f"FARS vs independent outcome, {len(rows)} generated topologies ({res['n_orgs_range'][0]}-{res['n_orgs_range'][1]} organisations)")
    print(f"resilience_gt: mean {res['gt_distribution']['mean']}, range {res['gt_distribution']['min']}-{res['gt_distribution']['max']}, "
          f"{res['gt_distribution']['distinct_values']} distinct values\n")
    print(f"{'comparison':44s} {'rho':>7s} {'95% CI (bootstrap)':>22s} {'p':>10s}")
    for k, v in res.items():
        if isinstance(v, dict) and "rho" in v:
            ci = "-" if v["ci95"][0] is None else f"[{v['ci95'][0]:.2f}, {v['ci95'][1]:.2f}]"
            rho_s = "-" if v["rho"] is None else f"{v['rho']:7.3f}"
            p_s = "-" if v["p"] is None else f"{v['p']:10.2e}"
            print(f"{k:44s} {rho_s:>7s} {ci:>22s} {p_s:>10s}")
    print("\nRead: FARS vs resilience_gt is the result.  FARS vs proxy shows how much of the old correlation was shared inputs.")
    print("If FARS does not beat the naive predictors, say so in Ch5/Ch6; a weak rho is a finding, not a failed run.")
    print(f"Wrote {a.out}")
    print("RESULT fars-topologies: DONE (informational)")


if __name__ == "__main__":
    main()
