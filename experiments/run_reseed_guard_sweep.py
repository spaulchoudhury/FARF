"""G9 / L15 / F16: does the opt-in incident-root re-seed guard change anything it should not?

Compares three arms on the same seeds as the v2 loop sweep (same trials, same metrics):
  off                  no feedback loop
  scoped-cold          the v7.9.11 design (re-seeds after decay_s)
  scoped-cold+guard    scoped-cold plus FarsFeedback(reseed_guard=True)

A pass means the guard (a) keeps collateral beyond one hop at the scoped-cold level (<= 0.05),
(b) does not make second-wave detection worse than scoped-cold, and (c) leaves scoped-cold itself unchanged.
The deterministic re-seed check is `python -m experiments.check_scope_reseeding`.

Usage: python -m experiments.run_reseed_guard_sweep [--n 20] [--out experiments/results_reseed_guard]
"""
from __future__ import annotations

import argparse
import json
import logging
import os

from closed_loop import FarsFeedback
from experiments import run_fars_loop_sweep_v2 as v2

logging.disable(logging.CRITICAL)


def arms(multiplier: float) -> dict:
    return {
        "off": None,
        "scoped-cold": FarsFeedback(enabled=True, scope="scoped", beta=v2.BETA, max_multiplier=multiplier,
                                    require_cold=True),
        "scoped-cold+guard": FarsFeedback(enabled=True, scope="scoped", beta=v2.BETA, max_multiplier=multiplier,
                                          require_cold=True, reseed_guard=True),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--out", default="experiments/results_reseed_guard")
    ap.add_argument("--chains", default="5,12", help="chain lengths, comma separated")
    ap.add_argument("--mults", default="1.5,3.0,30.0", help="multipliers, comma separated")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    v2.arm_configs = arms                                   # same trials, three arms
    report = {}
    print(f"re-seed guard sweep, n={args.n} seeds per cell")
    print(f"{'chain':>5s} {'mult':>5s} {'arm':18s} {'camp_coll':>9s} {'grief_coll':>10s} {'e4b_coll':>9s} "
          f"{'w2_deliv':>9s} {'max_hop':>7s}  verdict")
    all_ok = True
    chains = [int(x) for x in args.chains.split(',')]
    mults = [float(x) for x in args.mults.split(',')]
    for n_orgs in chains:
        for mult in mults:
            res = v2.run_chain_scenarios(args.n, n_orgs, mult, {})
            summ = v2.summarise_collateral(res)
            off_w2 = summ["off"]["w2_delivered"]["mean"]
            cold_w2 = summ["scoped-cold"]["w2_delivered"]["mean"]
            for arm in ("off", "scoped-cold", "scoped-cold+guard"):
                r = summ[arm]
                row = dict(r, _off_w2_mean=off_w2)
                ev = v2.evaluate(row)
                extra = ""
                if arm == "scoped-cold+guard":
                    worse = r["w2_delivered"]["mean"] > cold_w2 + 1e-9
                    extra = " (second wave worse than scoped-cold!)" if worse else ""
                    all_ok = all_ok and ev["pass"] and not worse
                print(f"{n_orgs:5d} {mult:5.1f} {arm:18s} {r['campaign_collateral']['mean']:9.3f} "
                      f"{r['griefing_distant_collateral']['mean']:10.3f} {r['e4_bystander_collateral']['mean']:9.3f} "
                      f"{r['w2_delivered']['mean']:9.2f} {r['max_incident_hop']:7d}  "
                      f"{'PASS' if ev['pass'] else 'FAIL ' + ','.join(ev['reasons'])}{extra}")
            report[f"{n_orgs}_{mult}"] = {a: summ[a] for a in summ}
    with open(os.path.join(args.out, "reseed_guard_sweep.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("\nOVERALL:", "PASS - guard adds no collateral and no second-wave regression" if all_ok
          else "FAIL - see rows above")


if __name__ == "__main__":
    main()
