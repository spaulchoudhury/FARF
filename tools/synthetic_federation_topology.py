"""
synthetic_federation_topology.py -- closes README.md's own TODO item 2
("50+ synthetic federation topologies (Tab 7.6)") and gives fars.py's
untested N>20 connectivity-sampling code path something real to run
against.

Builds populated FederatedAdversaryModel instances -- the exact same
`.graph` object FARS's connectivity scorer consumes (see
federation_bus.py's current_fars(): `graph=self.adversary_model.graph`) --
so a generated topology is immediately usable for BOTH:
  1. Tab 7.6-style adversary-model validation (simulate_privilege_escalation,
     cross_org_attack_paths), and
  2. FARS connectivity-metric validation (see validate_connectivity_sampling.py,
     which imports generate_topology from here).

Two generator families, matching README's own suggestion exactly:
  - "gnp"              -> networkx.gnp_random_graph (Erdos-Renyi: each org
                           pair independently connected w.p. p)
  - "barabasi_albert"  -> networkx.barabasi_albert_graph (scale-free,
                           preferential attachment -- a handful of "hub"
                           orgs end up with disproportionately many
                           partners, arguably closer to how real
                           multi-org consortia/supply chains actually
                           look than a flat Erdos-Renyi graph)
"""

from __future__ import annotations

import random
from dataclasses import dataclass

import networkx as nx

from adversary_model import FederatedAdversaryModel


@dataclass
class TopologyParams:
    n_orgs: int
    agents_per_org: int = 2
    topology_type: str = "gnp"          # "gnp" | "barabasi_albert"
    p: float = 0.4                       # gnp edge probability
    m: int = 2                           # barabasi_albert attachment count
    seed: int | None = None
    intra_org_privilege_range: tuple = (0.1, 0.25)   # matches main.py's 0.1/0.2 range
    cross_org_privilege_range: tuple = (0.2, 0.5)    # matches main.py's 0.3/0.4 range


def generate_topology(params: TopologyParams) -> FederatedAdversaryModel:
    rng = random.Random(params.seed)

    if params.n_orgs < 2:
        raise ValueError("n_orgs must be >= 2 to have any cross-org edges at all")

    # org-level random graph -- undirected, node-labelled 0..n_orgs-1
    if params.topology_type == "gnp":
        org_graph = nx.gnp_random_graph(params.n_orgs, params.p, seed=params.seed)
    elif params.topology_type == "barabasi_albert":
        m = min(params.m, params.n_orgs - 1)  # networkx requires m < n
        org_graph = nx.barabasi_albert_graph(params.n_orgs, m, seed=params.seed)
    else:
        raise ValueError(f"unknown topology_type {params.topology_type!r}")

    model = FederatedAdversaryModel()
    org_names = [f"Org{chr(65 + i)}" if i < 26 else f"Org{i}" for i in range(params.n_orgs)]
    org_agents = {}  # org_name -> list of agent_ids

    # --- agents + intra-org hierarchy (mirrors main.py's advisor/executor
    # pattern for agents_per_org==2; for more agents per org, a simple
    # star from agent_0 -- keeps every org internally connected without
    # inventing a second, unrelated topology model just for org-internal
    # structure) ---
    for org in org_names:
        agent_ids = [f"{org}-agent{i}" for i in range(params.agents_per_org)]
        org_agents[org] = agent_ids
        for i, aid in enumerate(agent_ids):
            priv = rng.uniform(*params.intra_org_privilege_range)
            model.add_agent(aid, org, base_privilege=priv)
        for i in range(1, len(agent_ids)):
            edge_priv = rng.uniform(*params.intra_org_privilege_range) + 0.15
            model.add_delegation(agent_ids[0], agent_ids[i], privilege=min(1.0, edge_priv))

    # --- cross-org delegation edges, one per org_graph edge, direction
    # randomised per edge (an undirected generator has no inherent
    # direction; picking one at random per edge avoids a systematic bias
    # like "always org i -> org i+1", which would understate how
    # escalation paths can run in practice) ---
    for u, v in org_graph.edges():
        org_u, org_v = org_names[u], org_names[v]
        if rng.random() < 0.5:
            org_u, org_v = org_v, org_u
        src = rng.choice(org_agents[org_u])
        dst = rng.choice(org_agents[org_v])
        model.add_delegation(src, dst, privilege=rng.uniform(*params.cross_org_privilege_range))

    return model


def generate_corpus(n_topologies: int = 50, n_orgs_range: tuple = (2, 10),
                     agents_per_org_range: tuple = (2, 3), seed: int = 42) -> list[FederatedAdversaryModel]:
    """
    Tab 7.6: "more than fifty automatically generated federation
    topologies containing between two and ten participating
    organisations." This is that generator. Alternates gnp/barabasi_albert
    and sweeps n_orgs across the full 2-10 range rather than sampling it
    uniformly at random, so small-N (where PBFT quorum math is tightest,
    per ADR-006) and large-N (where FARS's connectivity sampling kicks in
    once total agents > 20) are both guaranteed representation, not left
    to chance.
    """
    rng = random.Random(seed)
    topologies = []
    for i in range(n_topologies):
        n_orgs = n_orgs_range[0] + (i % (n_orgs_range[1] - n_orgs_range[0] + 1))
        topology_type = "gnp" if i % 2 == 0 else "barabasi_albert"
        agents_per_org = rng.randint(*agents_per_org_range)
        params = TopologyParams(
            n_orgs=n_orgs, agents_per_org=agents_per_org, topology_type=topology_type,
            p=rng.uniform(0.25, 0.6), m=rng.randint(1, 3), seed=seed * 1000 + i,
        )
        topologies.append(generate_topology(params))
    return topologies


def summarise_corpus(topologies: list[FederatedAdversaryModel]) -> dict:
    n_with_escalation = 0
    n_with_cross_org_attack = 0
    total_agents = []
    total_cross_org_paths = []
    for model in topologies:
        total_agents.append(model.graph.number_of_nodes())
        any_escalation = False
        for node in model.graph.nodes:
            if model.simulate_privilege_escalation(node, threshold=0.8):
                any_escalation = True
                break
        if any_escalation:
            n_with_escalation += 1
        cross_org = model.cross_org_attack_paths()
        total_cross_org_paths.append(len(cross_org))
        if cross_org:
            n_with_cross_org_attack += 1
    n = len(topologies)
    return {
        "n_topologies": n,
        "agents_per_topology_min_max": (min(total_agents), max(total_agents)),
        "pct_with_escalation_path_at_threshold_0.8": round(100 * n_with_escalation / n, 1),
        "pct_with_cross_org_attack_path": round(100 * n_with_cross_org_attack / n, 1),
        "avg_cross_org_paths_per_topology": round(sum(total_cross_org_paths) / n, 2),
    }


if __name__ == "__main__":
    corpus = generate_corpus(n_topologies=50)
    summary = summarise_corpus(corpus)
    print(f"Generated {len(corpus)} topologies (Tab 7.6 requirement: 50+)\n")
    for k, v in summary.items():
        print(f"  {k}: {v}")
