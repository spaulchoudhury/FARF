"""
Provenance-aware Taint Propagation Engine (FARF Artefact 4)
--------------------------------------------------------------
Tracks the organisational origin of every message as it crosses the
Federation Bus, accumulates taint as information moves through
compromised agents, and reconstructs propagation/blast-radius paths.

This is a lightweight, in-memory stand-in for the offline Soufflé
Datalog reasoning described in the proposal: graph reachability here
gives you the same "who could this have reached" answer instantly,
without needing a separate Datalog toolchain on a resource-constrained
laptop. Swap `reconstruct_privilege_path` for a Soufflé query later if
you need full first-order-logic provenance rules.
"""
from dataclasses import dataclass, field
from typing import Dict, Set, List
import networkx as nx

from farf_logging import get_logger

log = get_logger(__name__)


@dataclass
class TaintLabel:
    origin_org: str
    taint_level: float  # 0 = clean, 1 = fully compromised
    provenance_chain: List[str] = field(default_factory=list)


class TaintPropagationEngine:
    def __init__(self):
        self.flow_graph = nx.DiGraph()          # nodes = agents, edges = messages
        self.taints: Dict[str, TaintLabel] = {}  # message_id -> TaintLabel

        # PENTEST FINDING (fixed, v7.2 -- THREAT_MODEL.md 16):
        # max_blast_radius_fraction() used to recompute fresh from
        # flow_graph's CURRENT state every call. That's a real bug, not
        # just a design choice: quarantine_edges_from() (the correct,
        # WORKING containment response) physically removes the
        # quarantined agent's outgoing edges -- so successfully
        # containing an attack erased the very evidence FARS needed to
        # recognize that containment had occurred, making a correctly-
        # contained attack look identical to one that never happened.
        # _peak_reach tracks the largest reach ever observed,
        # incrementally, at propagate() time -- BEFORE any later
        # quarantine call can remove that evidence.
        self._peak_reach: int = 0

    def originate(self, message_id: str, origin_org: str, initial_taint: float = 0.0):
        self.taints[message_id] = TaintLabel(origin_org, initial_taint, [origin_org])

    def propagate(self, message_id: str, from_agent: str, to_agent: str,
                   to_org: str, taint_delta: float = 0.0):
        label = self.taints.get(message_id)
        if label is None:
            self.originate(message_id, to_org, taint_delta)
            label = self.taints[message_id]
        else:
            label.taint_level = min(1.0, label.taint_level + taint_delta * (1 - label.taint_level))
            if to_org not in label.provenance_chain:
                label.provenance_chain.append(to_org)
        self.flow_graph.add_edge(from_agent, to_agent, message_id=message_id,
                                  taint_level=label.taint_level)
        if label.taint_level > 0.5:
            # Mirrors the message-level taint threshold federation_bus.py
            # already blocks/quarantines on -- logged here too so
            # provenance-layer escalation is visible in logs/farf.log
            # even for code paths that call the taint engine directly
            # (e.g. tests/pentest scripts), not just via the bus.
            log.warning("high-taint propagation", extra={
                "event": "taint_propagation", "message_id": message_id,
                "from_agent": from_agent, "to_agent": to_agent, "to_org": to_org,
                "taint_level": label.taint_level})
        self._update_peak_reach()

    def _update_peak_reach(self, taint_threshold: float = 0.02):
        """
        Called on every propagate(), before any quarantine can remove
        edges. Uses a LOW noise threshold (0.02, down from the old
        default of 0.1) -- the old threshold silently excluded entire
        attack-severity ranges from ever registering as "tainted" at
        all (see THREAT_MODEL.md 16), which is a second,
        compounding bug beyond the evidence-erasure issue this method
        fixes. 0.02 still excludes true zero/near-zero noise, just not
        legitimate lower-intensity attack traffic.
        """
        tainted_edges = [(u, v) for u, v, d in self.flow_graph.edges(data=True)
                          if d.get("taint_level", 0.0) > taint_threshold]
        if not tainted_edges:
            return
        subgraph = nx.DiGraph()
        subgraph.add_edges_from(tainted_edges)
        for node in subgraph.nodes:
            reach = len(nx.descendants(subgraph, node))
            self._peak_reach = max(self._peak_reach, reach)

    def is_tainted(self, message_id: str, threshold: float = 0.5) -> bool:
        label = self.taints.get(message_id)
        return label is not None and label.taint_level >= threshold

    def blast_radius(self, origin_agent: str) -> Set[str]:
        """Every agent reachable from a compromised origin -- the
        containment set that must be quarantined/notified."""
        if origin_agent not in self.flow_graph:
            return set()
        return set(nx.descendants(self.flow_graph, origin_agent))

    def reconstruct_privilege_path(self, compromised_agent: str, cutoff: int = 8) -> List[List[str]]:
        paths = []
        for target in self.blast_radius(compromised_agent):
            for path in nx.all_simple_paths(self.flow_graph, compromised_agent, target, cutoff=cutoff):
                paths.append(path)
        return paths

    def quarantine_edges_from(self, agent_id: str) -> List[tuple]:
        """Simulated cross-org taint quarantine: sever outgoing propagation
        paths from a compromised/quarantined agent. Peak-reach evidence
        (see _peak_reach) was already captured at propagate() time, so
        this no longer erases what FARS needs to score the containment
        that just happened."""
        edges = list(self.flow_graph.out_edges(agent_id))
        self.flow_graph.remove_edges_from(edges)
        log.error("taint edges quarantined", extra={
            "event": "taint_quarantine", "agent_id": agent_id, "edges_severed": len(edges)})
        return edges

    def max_blast_radius_fraction(self, total_agents: int, taint_threshold: float = 0.02) -> float:
        """
        Largest fraction of the federation EVER reachable (peak, not a
        live snapshot -- see _peak_reach) via edges that actually carry
        taint above a small noise threshold -- a graph-level containment
        signal.

        This complements (and catches what) the per-message taint
        threshold misses: a low-intensity attack whose individual
        messages never cross the *message-level* taint threshold (0.5)
        can still fully propagate through the flow graph. FARS blends
        this with the per-message signal so an undetected-but-fully-
        propagated attack is not scored as perfectly contained.

        v7.2 fix: returns the PEAK ever observed (via _peak_reach,
        updated incrementally at propagate() time), not a fresh
        recompute from the current graph -- a live recompute would
        under-report exactly when containment worked, since
        quarantine_edges_from() removes the evidence a live query would
        need. `taint_threshold` here only affects the CURRENT call's
        `total_agents` normalisation, not which edges contributed to
        the peak (that was decided at propagate() time using the same
        default).
        """
        if total_agents <= 1:
            return 0.0
        return min(1.0, self._peak_reach / max(1, total_agents - 1))


if __name__ == "__main__":
    eng = TaintPropagationEngine()
    eng.propagate("m1", "OrgA-advisor", "OrgA-executor", "OrgA", taint_delta=0.6)
    eng.propagate("m1", "OrgA-executor", "OrgB-advisor", "OrgB", taint_delta=0.3)
    print("Tainted?", eng.is_tainted("m1"))
    print("Blast radius:", eng.blast_radius("OrgA-advisor"))
    print("Privilege paths:", eng.reconstruct_privilege_path("OrgA-advisor"))
