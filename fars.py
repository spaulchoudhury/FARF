"""
Federated Adversarial Resilience Score (FARS) -- FARF Artefact 5
--------------------------------------------------------------------
Combines graph-topological structure, trust health, taint containment
and policy compliance into a single, continuously-updated resilience
metric in [0, 100]. Designed to be cheap to recompute after every
Federation Bus event so it can inform adaptive recovery decisions in
near real time, using NetworkX for the topology term (as specified in
the proposal) rather than a heavier graph-learning model.
"""
from typing import Dict, List, Optional
import networkx as nx

from farf_logging import get_logger

log = get_logger(__name__)


class FARSEngine:
    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or {
            "connectivity": 0.25,
            "trust_health": 0.30,
            "taint_containment": 0.30,
            "policy_compliance": 0.15,
        }
        assert abs(sum(self.weights.values()) - 1.0) < 1e-6, "weights must sum to 1.0"
        # v7.9.11: the closed-loop bus recomputes FARS on every send; the topology term depends only
        # on the (static) agent graph, so it may be cached. Off by default -> v7.9.10 behaviour.
        self.cache_connectivity = False
        self._conn_cache: Dict = {}

    def _connectivity_score(self, graph: nx.DiGraph, max_exact_nodes: int = 20,
                             sample_pairs: int = 200) -> float:
        if not self.cache_connectivity:
            return self._connectivity_score_uncached(graph, max_exact_nodes, sample_pairs)
        key = (frozenset(graph.nodes()), frozenset(graph.edges()))
        if key not in self._conn_cache:
            self._conn_cache[key] = self._connectivity_score_uncached(graph, max_exact_nodes, sample_pairs)
        return self._conn_cache[key]

    def _connectivity_score_uncached(self, graph: nx.DiGraph, max_exact_nodes: int = 20,
                                      sample_pairs: int = 200) -> float:
        """
        v7.4 fix: exact nx.average_node_connectivity() computes a
        min-cut (max-flow) for EVERY pair of nodes -- O(N^2) pairs times
        an expensive per-pair computation. Previously flagged as an open
        concern (THREAT_MODEL.md Section 3, "FARS's connectivity-metric
        cost") but never quantified. pentest/pt17_scale_testing.py
        measured it directly: 2.7s at 100 agents, 20.3s at 200 agents --
        roughly O(N^2.9), which would be completely impractical at real
        federation scale (a naive extrapolation puts 1000 agents at
        several hours). For graphs at or under max_exact_nodes (20,
        comfortably above anything any existing pentest/main.py
        scenario uses -- all calibrated numbers are UNCHANGED), compute
        exactly as before. Above that, sample a bounded number of
        random pairs instead of all C(n,2) -- an unbiased estimator of
        the same quantity, with cost independent of N. Deterministic
        (fixed seed) so FARS stays reproducible for the same graph.
        """
        if graph.number_of_nodes() < 2:
            return 1.0
        undirected = graph.to_undirected()
        n = undirected.number_of_nodes()
        try:
            if n <= max_exact_nodes:
                avg_conn = nx.average_node_connectivity(undirected)
            else:
                import random as _random
                nodes = list(undirected.nodes())
                rng = _random.Random(42)
                pairs = set()
                attempts = 0
                target = min(sample_pairs, n * (n - 1) // 2)
                while len(pairs) < target and attempts < sample_pairs * 3:
                    a, b = rng.sample(nodes, 2)
                    pairs.add((a, b) if a < b else (b, a))
                    attempts += 1
                if not pairs:
                    avg_conn = 0.0
                else:
                    avg_conn = sum(nx.node_connectivity(undirected, s=a, t=b) for a, b in pairs) / len(pairs)
        except (nx.NetworkXException, ValueError, ZeroDivisionError):  # degenerate graph: connectivity 0 (most conservative)
            avg_conn = 0.0
        return min(1.0, avg_conn / 4.0)  # normalise against a healthy small federation

    def _trust_health_score(self, quarantined: int, total_agents: int,
                             structural_containment_score: float = 1.0) -> float:
        """
        v7.2 fix (THREAT_MODEL.md 16): previously
        `max(0.0, 1.0 - quarantined/total_agents)` penalized EVERY
        quarantined agent identically, with no way to distinguish
        "quarantined because we correctly caught an attack" (the system
        working as designed) from "quarantined for no good reason."
        That meant an attack that fully escaped WITHOUT triggering any
        quarantine scored a perfect 1.0 here, while a correctly and
        successfully contained attack scored LOWER -- a genuine
        perverse incentive, confirmed empirically (AUC=0.10 against
        observed outcomes before this fix).

        Now interactive with structural_containment_score -- deliberately
        the GRAPH-LEVEL signal (did quarantine actually stop propagation
        reaching other agents), NOT taint_containment_score's blended
        value. Coupling to the blend (which also folds in per_message:
        how many individually-risky messages got through before
        detection) double-penalized quarantine for a DIFFERENT problem
        (message-level detection speed) that taint_containment already
        accounts for on its own -- caught during calibration when a
        high-severity, fast, fully-contained attack (0 blast radius)
        still scored a near-zero trust_health because per_message
        happened to be low too. Structural containment is the more
        directly relevant question for "was this quarantine worth it."
        """
        if total_agents == 0:
            return 1.0
        quarantined_fraction = quarantined / total_agents
        escape_penalty_factor = 1.0 - structural_containment_score
        baseline_operational_cost = 0.15  # small, constant cost even for JUSTIFIED quarantine
        penalty = quarantined_fraction * (baseline_operational_cost
                                           + (1.0 - baseline_operational_cost) * escape_penalty_factor)
        return max(0.0, 1.0 - penalty)

    def _taint_containment_score(self, tainted_messages: int, total_messages: int,
                                  max_blast_radius_fraction: float = 0.0) -> Dict[str, float]:
        """
        Blends two containment signals:
          - per-message: fraction of individual messages that stayed
            under the taint threshold (catches a fully below-threshold,
            low-intensity attack that graph_level's OWN edge-taint
            threshold would also miss)
          - graph-level: largest fraction of the federation reachable
            from any one flow-graph node -- the direct, ground-truth
            containment OUTCOME.

        v7.2 fix (THREAT_MODEL.md 16): previously combined via
        min() (take the more pessimistic view). That's the wrong
        combination for this attack pattern: per_message answers "was
        any single message individually severe," which is a different
        question from "did propagation actually get contained," and a
        high-severity-but-quickly-caught attack (2 individually severe
        messages, then fully blocked, blast_radius=0) was scoring WORSE
        than a low-severity attack that fully escaped every agent
        (every message individually mild, so per_message looked
        "clean" even though nothing was ever contained). min() let the
        wrong signal veto the right one. Now a weighted blend that
        trusts the direct outcome measure (graph_level) more, while
        per_message still contributes rather than dominating.
        """
        per_message = 1.0 if total_messages == 0 else max(0.0, 1.0 - (tainted_messages / total_messages))
        graph_level = max(0.0, 1.0 - max_blast_radius_fraction)
        blended = 0.3 * per_message + 0.7 * graph_level
        return {"blended": blended, "graph_level": graph_level}

    def _policy_compliance_score(self, violations: int, total_events: int) -> float:
        if total_events == 0:
            return 1.0
        return max(0.0, 1.0 - (violations / total_events))

    def compute(self, graph: nx.DiGraph, quarantined_agents: int, total_agents: int,
                tainted_messages: int, total_messages: int,
                policy_violations: int, total_events: int,
                max_blast_radius_fraction: float = 0.0) -> Dict:
        c = self._connectivity_score(graph)
        containment = self._taint_containment_score(tainted_messages, total_messages, max_blast_radius_fraction)
        p = containment["blended"]
        t = self._trust_health_score(quarantined_agents, total_agents,
                                      structural_containment_score=containment["graph_level"])
        g = self._policy_compliance_score(policy_violations, total_events)

        score = 100 * (
            self.weights["connectivity"] * c + self.weights["trust_health"] * t
            + self.weights["taint_containment"] * p + self.weights["policy_compliance"] * g
        )
        # v7.8: FARS drops are a meaningful federation-health signal on
        # their own, independent of which individual component caused
        # them -- worth having in logs/farf.log even without a debugger
        # attached to bus.current_fars(). Threshold chosen to match the
        # "degraded" band used informally elsewhere in this codebase's
        # narration (well below a clean-federation baseline, well above
        # noise).
        log_fn = log.warning if score < 50 else log.debug
        log_fn("FARS computed", extra={
            "event": "fars_computed", "fars": round(score, 2),
            "connectivity": round(c, 3), "trust_health": round(t, 3),
            "taint_containment": round(p, 3), "policy_compliance": round(g, 3)})
        return {
            "FARS": round(score, 2),
            "components": {
                "connectivity": round(c, 3), "trust_health": round(t, 3),
                "taint_containment": round(p, 3), "policy_compliance": round(g, 3),
            },
        }

    @staticmethod
    def compute_ewma(current_score: float, previous_ewma: Optional[float], alpha: float = 0.3) -> float:
        """
        PENTEST FINDING (fixed, v7 / temporally-adaptive FARS): compute()
        above is a pure point-in-time snapshot recomputed from ALL-TIME
        cumulative totals every call -- it has no memory of trajectory,
        so a federation that was compromised for an hour and just
        recovered looks identical to one that's been healthy the whole
        time, as long as the cumulative ratios happen to match. An
        Exponentially Weighted Moving Average gives the score actual
        memory: recent snapshots count more than old ones, `alpha`
        controls how fast old history decays (higher alpha = more
        reactive/less smoothing, lower alpha = slower to move but more
        stable against single-event noise). This mirrors the "resilience
        scores should have memory" argument in NIST's cyber-resiliency
        metrics work (SP 800-160 Vol 2's adjacent literature) more
        closely than a bare snapshot does.
        """
        if previous_ewma is None:
            return current_score
        return alpha * current_score + (1 - alpha) * previous_ewma


class DetectionLatencyTracker:
    """
    Phase 1 item 2 (v7.4), deliberately combined with item 4's
    independent fan-out detector: measures HOW FAST an attack was
    caught, as its own metric -- distinct from whether it was caught at
    all (the pentest verdicts) and distinct from how long recovery took
    afterward (RecoveryTimeTracker below). Two units, since wall-clock
    time is dominated by call overhead in a synchronous prototype (not
    real attack pacing) while message count is what actually differs
    meaningfully by attack severity/detector:
      - detection_latency_messages: how many messages from this key
        were processed (including the one that tripped it) before
        detection.
      - detection_latency_seconds: wall-clock time from the first
        message involving this key to the moment of detection.
    Also records WHICH detector family caught it, so detection speed
    can be COMPARED across CUSUM, agent/org-level volume, and fan-out
    as genuinely independent families -- see stats_by_detector(). This
    is the direct payoff of having built a structurally independent
    second detector (18): "is the new detector typically
    faster or slower than CUSUM for the attacks it catches" becomes a
    measurable, reportable claim instead of a vague one.
    """
    def __init__(self):
        self._first_seen_at: Dict[str, float] = {}
        self._message_count: Dict[str, int] = {}
        self.detections: List[Dict] = []

    def mark_message(self, key: str, now: float):
        """Call on every message attributed to `key`, BEFORE checking
        whether it trips a detector."""
        if key not in self._first_seen_at:
            self._first_seen_at[key] = now
            self._message_count[key] = 0
        self._message_count[key] += 1

    def mark_detected(self, key: str, now: float, detector: str) -> Optional[Dict]:
        """Call the moment a detector trips for `key`. Deletes this
        key's tracking state afterward, so a FUTURE episode (after
        reinstatement) starts a fresh count rather than an inflated
        cumulative one."""
        if key not in self._first_seen_at:
            return None  # detected without prior mark_message -- defensive, shouldn't happen
        record = {
            "key": key, "detector": detector,
            "detection_latency_messages": self._message_count[key],
            "detection_latency_seconds": round(now - self._first_seen_at[key], 4),
            "detected_at": now,
        }
        self.detections.append(record)
        del self._first_seen_at[key]
        del self._message_count[key]
        return record

    def stats_by_detector(self) -> Dict[str, Dict]:
        by_detector: Dict[str, List[Dict]] = {}
        for d in self.detections:
            by_detector.setdefault(d["detector"], []).append(d)
        result = {}
        for detector, records in by_detector.items():
            msgs = sorted(r["detection_latency_messages"] for r in records)
            secs = [r["detection_latency_seconds"] for r in records]
            n = len(msgs)
            result[detector] = {
                "count": n,
                "mean_messages": round(sum(msgs) / n, 2),
                "median_messages": msgs[n // 2],
                "mean_seconds": round(sum(secs) / n, 4),
            }
        return result


class RecoveryTimeTracker:
    """
    PENTEST FINDING (fixed, v7): FARS previously only reported a
    steady-state score -- nothing measured HOW LONG it took to recover
    after a quarantine event, which is itself a distinct and arguably
    more decision-relevant resilience metric (two federations with the
    same steady-state FARS can have very different recovery speeds).
    Tracks wall-clock time from "a key first entered quarantine" to
    "that key was reinstated", per key (agent_id or org), independent
    of the FARS score itself.
    """
    def __init__(self):
        self._started_at: Dict[str, float] = {}
        self.completed: List[Dict] = []

    def mark_quarantined(self, key: str, now: float):
        if key not in self._started_at:
            self._started_at[key] = now

    def mark_recovered(self, key: str, now: float) -> Optional[Dict]:
        started = self._started_at.pop(key, None)
        if started is None:
            return None
        record = {"key": key, "duration_seconds": round(now - started, 4), "recovered_at": now}
        self.completed.append(record)
        return record

    def stats(self) -> Dict:
        # `completed` (the raw per-key records) is included alongside the aggregate so a caller can report
        # the duration for ONE specific key (e.g. "how long did THIS org's reinstatement take") as well as
        # the aggregate across every quarantine/reinstatement pair the bus has seen this revision.
        if not self.completed:
            return {"count": 0, "mean_seconds": None, "min_seconds": None, "max_seconds": None, "completed": []}
        durations = [r["duration_seconds"] for r in self.completed]
        return {"count": len(durations), "mean_seconds": round(sum(durations) / len(durations), 4),
                "min_seconds": round(min(durations), 4), "max_seconds": round(max(durations), 4),
                "completed": self.completed}


if __name__ == "__main__":
    import networkx as nx
    g = nx.DiGraph()
    g.add_edges_from([("A", "B"), ("B", "C"), ("A", "C")])
    engine = FARSEngine()
    print(engine.compute(g, quarantined_agents=1, total_agents=3,
                          tainted_messages=2, total_messages=10,
                          policy_violations=1, total_events=10))
