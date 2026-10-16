"""T3 / G9 follow-up: can an organisation that was quarantined as COLLATERAL of someone else's incident
evade the opt-in re-seed guard by waiting, and what does the guard cost when it does?

Chain OrgA - OrgB - OrgC - OrgD - OrgE (OrgE has no delegation edge).  FakeClock, decay_s = 30 s
(the cooling-off default), guard memory = 6 x decay_s = 180 s.

  1. OrgB is the real incident (blatant burst, quarantined).  OrgC is 1 hop away and is caught as collateral.
  2. The attacker sits in OrgC and keeps its second agent (the executor) clean.  It waits `gap` decay
     periods, then sends a stealthy stream (declared delta 0.02-0.05, benign-looking text) to OrgA/OrgC/OrgE/OrgB.
  3. Outcome: messages the attacker's executor gets DELIVERED before it is quarantined, and how far the
     resulting scope spread (OrgD, OrgE quarantined).

Arms (same seeds): off (no loop) / scoped-cold (guard off) / scoped-cold+guard.
gap = 1, 3, 5 decay periods (inside the guard memory) and 7 (outside it: the guard should then behave like scoped-cold).

Reading the result
  * Cost of the guard   = delivered(guard) - delivered(scoped-cold) at gaps inside the memory.
  * Evasion by waiting  = the guard's advantage disappears at gap 7.
  * Benefit of the guard = spread to OrgD/OrgE that scoped-cold produces and the guard does not.

Local and deterministic given the seeds.  Usage:
    python -m experiments.run_guard_evasion [--n 20] [--gaps 1,3,5,7] [--msgs 40] [--out experiments/guard_evasion_<stamp>]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random

from closed_loop import FarsFeedback
from experiments.common import BENIGN_TEXTS, FakeClock, close_bus, make_bus
from experiments.run_fars_loop_sweep_v2 import BETA, ci_and_sig
from main import build_federation

logging.disable(logging.CRITICAL)

DECAY_S = 30.0
ARMS = ("off", "scoped-cold", "scoped-cold+guard")


def feedback(arm: str):
    if arm == "off":
        return None
    return FarsFeedback(enabled=True, scope="scoped", beta=BETA, max_multiplier=3.0, require_cold=True,
                        reseed_guard=(arm == "scoped-cold+guard"))


def trial(seed: int, arm: str, gap_periods: float, n_msgs: int, probes: int = 4, band=(0.008, 0.03)) -> dict:
    rng = random.Random(seed)
    clk = FakeClock()
    bus = make_bus(fars_feedback=feedback(arm), clock=clk)
    try:
        ag = build_federation(bus, n_orgs=5)
        o = list(ag)                                                   # OrgA..OrgE
        for a, b in ((0, 1), (1, 2), (2, 3)):
            bus.adversary_model.add_delegation(ag[o[a]]["advisor"].agent_id, ag[o[b]]["advisor"].agent_id, 0.3)

        def send(f, t, text, delta, role="advisor"):
            return bus.send(ag[o[f]][role].agent_id, o[f], ag[o[t]]["advisor"].agent_id, o[t], "memory_recall_forward",
                            {"requested_privilege": 0.1, "attempts_system_override": False, "instruction": text},
                            taint_delta=delta)

        dests = [0, 2, 4, 1]
        for _ in range(12):                                            # 1. the real incident at OrgB
            if send(1, 0, "x", 0.1)["decision"] == "quarantine":
                break
        for i in range(8):                                             # OrgC retries and is caught as collateral
            send(2, dests[i % 4], BENIGN_TEXTS[i % 5], 0.02)
        collateral = o[2] in bus.federation_wide_quarantined or ag[o[2]]["advisor"].agent_id in bus.orchestration.quarantined_agents

        clk.advance(gap_periods * DECAY_S + 1.0)                       # 2. wait
        delta = rng.uniform(*band)
        for i in range(probes):                                        # the quarantined identity retries (blocked, but seen)
            send(2, dests[i % 4], BENIGN_TEXTS[i % 5], 0.02)
        delivered, first_stop = 0, None
        for i in range(n_msgs):                                        # 3. second wave from the clean executor
            r = send(2, dests[i % 4], BENIGN_TEXTS[(i + seed) % 5], delta, role="executor")
            if r["decision"] == "allow":
                delivered += 1
            elif first_stop is None:
                first_stop = i

        def org_quarantined(k):
            return any(ag[o[k]][r].agent_id in bus.orchestration.quarantined_agents for r in ("advisor", "executor"))

        hops = bus.incident_hop_snapshot()
        return {"seed": seed, "arm": arm, "gap_periods": gap_periods, "collateral_at_setup": collateral,
                "delta": round(delta, 4), "probes": probes, "w2_delivered": delivered, "w2_stopped_after": first_stop,
                "attacker_requarantined": first_stop is not None, "orgD_quarantined": org_quarantined(3),
                "orgE_quarantined": org_quarantined(4), "max_hop": max(hops.values()) if hops else 0}
    finally:
        close_bus(bus)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--gaps", default="1,3,5,7")
    ap.add_argument("--probes", default="0,4", help="blocked retries by the quarantined identity before the executor starts")
    ap.add_argument("--msgs", type=int, default=40)
    ap.add_argument("--out", default="experiments/results_guard_evasion")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    gaps = [float(x) for x in a.gaps.split(",")]
    probes_list = [int(x) for x in a.probes.split(",")]
    rows, report = [], {}
    print(f"guard-evasion, n={a.n} seeds per cell, {a.msgs} second-wave messages, decay_s={DECAY_S:.0f}, guard memory={6 * DECAY_S:.0f}s")
    print(f"{'gap':>4s} {'probes':>6s} {'arm':18s} {'collat':>6s} {'w2_deliv':>9s} {'requar':>7s} {'D_q':>5s} {'E_q':>5s}  vs off")
    for g in gaps:
        for pr in probes_list:
            cell = {arm: [trial(s, arm, g, a.msgs, probes=pr) for s in range(a.n)] for arm in ARMS}
            rows += [r for arm in ARMS for r in cell[arm]]
            off = [r["w2_delivered"] for r in cell["off"]]
            key = f"gap{g:.0f}_probes{pr}"
            report[key] = {}
            for arm in ARMS:
                rs = cell[arm]
                sig = ci_and_sig([r["w2_delivered"] for r in rs], off)
                s = {"w2_delivered": sig,
                     "collateral_at_setup": sum(r["collateral_at_setup"] for r in rs) / a.n,
                     "attacker_requarantined": sum(r["attacker_requarantined"] for r in rs) / a.n,
                     "orgD_quarantined": sum(r["orgD_quarantined"] for r in rs) / a.n,
                     "orgE_quarantined": sum(r["orgE_quarantined"] for r in rs) / a.n}
                report[key][arm] = s
                p = sig["sig_vs_off"]["p_value"]
                print(f"{g:4.0f} {pr:6d} {arm:18s} {s['collateral_at_setup']:6.2f} {sig['mean']:9.2f} {s['attacker_requarantined']:7.2f} "
                      f"{s['orgD_quarantined']:5.2f} {s['orgE_quarantined']:5.2f}  {'-' if p is None else f'p={p:.2e}'}")
    with open(os.path.join(a.out, "guard_evasion.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("\nCost of the guard = mean second-wave messages delivered, guard minus scoped-cold (positive = attacker gets more through):")
    verdict = {}
    for g in gaps:
        for pr in probes_list:
            key = f"gap{g:.0f}_probes{pr}"
            d = report[key]["scoped-cold+guard"]["w2_delivered"]["mean"] - report[key]["scoped-cold"]["w2_delivered"]["mean"]
            inside = g < 6
            verdict[key] = {"guard_minus_scoped_cold": d, "inside_guard_memory": inside}
            print(f"  gap {g:.0f} periods ({'inside' if inside else 'outside'} guard memory), probes {pr}: {d:+.2f} messages")
    report["_verdict"] = verdict
    with open(os.path.join(a.out, "guard_evasion.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nWrote {a.out}")
    print("NOTE: compare the guard with scoped-cold, not with off. Only the loop arms had a collateral quarantine at setup, "
          "which resets OrgC's detector window, so 'off' starts from a fuller window.")
    print("RESULT guard-evasion: DONE (informational; read the cost lines above)")


if __name__ == "__main__":
    main()
