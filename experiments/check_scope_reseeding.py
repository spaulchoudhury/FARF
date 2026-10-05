"""Deterministic (FakeClock) check of one behaviour of the scoped-cold FARS loop: does a collateral-quarantined neighbour that keeps
retrying AFTER the incident's boost has decayed re-seed a fresh scope that reaches the next org along a chain?
    python -m experiments.check_scope_reseeding
Chain O0 - O1 - O2 - O3 (+ isolated O4). Incident at O1. O2 (1 hop) is collaterally quarantined by the boost.
  A) O2's retries finish while O1's boost is active          -> O3 untouched (max hop 1, O3 sensitivity 1.0)
  B) O2 retries after decay_s: O2 is 'cold' again, becomes a ROOT (hop 0) and boosts O3 (sensitivity up to max_multiplier)
closed_loop.py / federation_bus._mark_incident_scope describe B as 'genuinely cold re-detection'; this makes the consequence explicit."""
import logging

from closed_loop import FarsFeedback
from experiments.common import BENIGN_TEXTS, FakeClock, close_bus, make_bus
from main import build_federation

logging.disable(logging.CRITICAL)


def scenario(retry_after_decay, require_cold=True, hop_cap=None):
    clk = FakeClock()
    fb = FarsFeedback(enabled=True, scope="scoped", require_cold=require_cold, hop_cap=hop_cap, beta=20.0, max_multiplier=3.0)
    bus = make_bus(fars_feedback=fb, clock=clk)
    try:
        ag = build_federation(bus, n_orgs=5)
        o = list(ag)
        for a, b in ((0, 1), (1, 2), (2, 3)):
            bus.adversary_model.add_delegation(ag[o[a]]["advisor"].agent_id, ag[o[b]]["advisor"].agent_id, 0.3)

        def send(f, t, text, delta):
            return bus.send(ag[o[f]]["advisor"].agent_id, o[f], ag[o[t]]["advisor"].agent_id, o[t], "memory_recall_forward",
                            {"requested_privilege": 0.1, "attempts_system_override": False, "instruction": text}, taint_delta=delta)

        for _ in range(12):
            if send(1, 0, "x", 0.1)["decision"] == "quarantine":
                break
        dests = [0, 2, 4, 1]
        for i in range(8):
            send(2, dests[i % 4], BENIGN_TEXTS[i % 5], 0.02)
        if retry_after_decay:
            clk.advance(31.0)
            for i in range(4):
                send(2, dests[i % 4], BENIGN_TEXTS[i % 5], 0.02)
        sens3 = 1.0
        for i in range(8):
            sens3 = max(sens3, send(3, dests[i % 4], BENIGN_TEXTS[i % 5], 0.02).get("sensitivity", 1.0))
        hops = {f"O{o.index(k)}": v for k, v in bus.incident_hop_snapshot().items()}
        return sens3, hops
    finally:
        close_bus(bus)


ARMS = (("", dict(require_cold=True, hop_cap=None)),                    # the original check: scoped-cold (output format unchanged)
        ("[scoped-hop-cap] ", dict(require_cold=True, hop_cap=1)),      # does a hop cap stop the re-seeded scope?
        ("[scoped-naive] ", dict(require_cold=False, hop_cap=None)))    # reference: no cold gate at all


if __name__ == "__main__":
    for prefix, kw in ARMS:
        for label, retry in (("A) retries within decay_s", False), ("B) retries after decay_s ", True)):
            s3, hops = scenario(retry, **kw)
            print(f"{prefix}{label}: O3 max sensitivity={s3:.3f}  incident hops={dict(sorted(hops.items()))}  "
                  f"-> {'O3 BOOSTED (scope re-seeded from O2)' if s3 > 1.0 else 'O3 untouched'}")
