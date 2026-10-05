"""
Rank-3 runner: close the FARS loop.

Two separate questions, because "the loop is closed" and "closing it helps" are different claims:

  (A) MECHANISM CHECK (campaign_trial, two waves). Does a degraded federation actually get more
      sensitive? Wave 1 (blatant) drives FARS-derived health down; wave 2 (stealthy, same magnitude
      either way) should then be caught EARLIER / more often when fars_feedback is enabled than when
      it is not, because health_ewma is feeding back into detector sensitivity for the SAME
      detectors used in wave 2. This is the direct answer to "no code path reads FARS back into
      send(), admission, quorum or thresholds" -- with fars_feedback enabled, one now does.

  (B) CONTINUITY WITH THE EXISTING CHAPTER-6 SHAPE (e4_trial, same convention as
      tests/test_04_statistical_validation.py: observed_resilience = 100*(1-blast)*(1-quarantined),
      contained = blast_fraction==0). Reports descriptive stats, FARS predictive validity (Pearson/
      MAE/RMSE) and FARS discriminative validity (ROC AUC) with the loop off vs on, so the existing
      Tab 7.8-style numbers have a direct "before/after closing the loop" companion instead of being
      silently replaced.

Note on what "closing the loop" is NOT claimed to do here: it does not change E4's single-shot
outcome much, because E4 is one federation with no prior incident to degrade its health -- the loop
has nothing upstream to react to. (A) is deliberately a two-wave scenario for exactly that reason.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os

from closed_loop import FarsFeedback
from experiments.common import campaign_trial, e4_trial
from tests.stats_utils import (
    descriptive_statistics,
    effect_size_cohens_d,
    fars_discriminative_validity,
    fars_predictive_validity,
    normality_test,
    paired_significance_test,
)

logging.disable(logging.CRITICAL)


def run_campaign_mechanism_check(n: int) -> dict:
    rows = {"off": [], "on": []}
    # NOTE: this script is the ORIGINAL (checkpoint-2) naive-global demonstration, kept as the
    # historical record of the finding that led to the TS ruling. scope is pinned explicitly to
    # "global" here so it keeps reproducing that finding even though FarsFeedback's default scope
    # changed to "scoped" afterward (closed_loop.py). See run_fars_loop_sweep.py for the current,
    # TS-mandated three-arm/multiplier-swept evaluation -- that script, not this one, is the one
    # whose numbers belong in the thesis.
    for label, fb in (("off", None), ("on", FarsFeedback(enabled=True, scope="global", beta=1.5, max_multiplier=3.0))):
        for seed in range(n):
            rows[label].append(campaign_trial(seed, fars_feedback=fb))
    def agg(rs):
        detect_rate = sum(r["w2_detected"] for r in rs) / len(rs)
        w2_deliv = descriptive_statistics([r["w2_delivered"] for r in rs])
        collateral = descriptive_statistics([r["benign_agents_quarantined_frac"] for r in rs])
        benign_blocked = descriptive_statistics([r["benign_blocked_frac"] for r in rs])
        return {"n": len(rs), "w2_detect_rate": detect_rate, "w2_delivered_mean": w2_deliv["mean"],
                "w2_delivered_ci95": w2_deliv["ci_95"], "benign_collateral_mean": collateral["mean"],
                "benign_blocked_frac_mean": benign_blocked["mean"]}
    return {"fars_feedback_off": agg(rows["off"]), "fars_feedback_on": agg(rows["on"]),
            "raw": rows}


def run_e4_before_after(n: int) -> dict:
    out = {}
    for label, fb in (("loop_off", None), ("loop_on", FarsFeedback(enabled=True, scope="global"))):
        trials = [e4_trial(i, fars_feedback=fb) for i in range(n)]
        blast = [t["blast_fraction"] for t in trials]
        fars = [t["fars"] for t in trials]
        quarantined = [t["quarantined_fraction"] for t in trials]
        observed_resilience = [100 * (1 - b) * (1 - q) for b, q in zip(blast, quarantined)]
        contained = [b == 0.0 for b in blast]
        desc = descriptive_statistics(blast)
        pred = fars_predictive_validity(fars, observed_resilience)
        disc = fars_discriminative_validity(fars, contained)
        out[label] = {"n": n, "blast_fraction_desc": desc, "predictive_validity": pred,
                     "discriminative_validity": disc,
                     "contained_rate": sum(contained) / n}
    a, b = out["loop_off"]["blast_fraction_desc"], out["loop_on"]["blast_fraction_desc"]
    if a["sd"] > 0 or b["sd"] > 0:
        off_vals = [t["blast_fraction"] for t in [e4_trial(i, fars_feedback=None) for i in range(n)]]
        on_vals = [t["blast_fraction"] for t in [e4_trial(i, fars_feedback=FarsFeedback(enabled=True, scope="global")) for i in range(n)]]
        is_normal = normality_test(off_vals)["is_normal"] and normality_test(on_vals)["is_normal"]
        sig = paired_significance_test(on_vals, off_vals, is_normal)
        out["paired_blast_fraction_on_vs_off"] = {**sig, "cohens_d": effect_size_cohens_d(on_vals, off_vals)}
    else:
        out["paired_blast_fraction_on_vs_off"] = {"note": "degenerate: no variance in either arm"}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--out", default="experiments/results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    print(f"[1/2] Campaign mechanism check (does health feedback change wave-2 detection?), n={args.n} ...")
    mech = run_campaign_mechanism_check(args.n)
    print(f"  FARS feedback OFF: detect_rate={mech['fars_feedback_off']['w2_detect_rate']:.3f} "
          f"w2_delivered_mean={mech['fars_feedback_off']['w2_delivered_mean']:.2f} "
          f"collateral={mech['fars_feedback_off']['benign_collateral_mean']:.3f}")
    print(f"  FARS feedback ON : detect_rate={mech['fars_feedback_on']['w2_detect_rate']:.3f} "
          f"w2_delivered_mean={mech['fars_feedback_on']['w2_delivered_mean']:.2f} "
          f"collateral={mech['fars_feedback_on']['benign_collateral_mean']:.3f}")
    with open(os.path.join(args.out, "fars_loop_campaign_mechanism.json"), "w") as f:
        json.dump({k: v for k, v in mech.items() if k != "raw"}, f, indent=2)
    with open(os.path.join(args.out, "fars_loop_campaign_raw.csv"), "w", newline="") as f:
        allrows = [{**r, "fars_feedback": lab} for lab, rs in mech["raw"].items() for r in rs]
        w = csv.DictWriter(f, fieldnames=sorted({k for r in allrows for k in r}))
        w.writeheader(); w.writerows(allrows)

    print(f"\n[2/2] E4 before/after (Chapter-6-style predictive/discriminative validity), n={args.n} ...")
    e4 = run_e4_before_after(args.n)
    for label in ("loop_off", "loop_on"):
        d, p, di = e4[label]["blast_fraction_desc"], e4[label]["predictive_validity"], e4[label]["discriminative_validity"]
        print(f"  {label:9s} blast_mean={d['mean']:.3f} contained_rate={e4[label]['contained_rate']:.3f} "
              f"pearson_r={p['pearson_r']:.3f} mae={p['mae']:.2f} rmse={p['rmse']:.2f} auc={di['auc']:.3f}")
    print(f"  paired (on vs off): {e4['paired_blast_fraction_on_vs_off']}")
    with open(os.path.join(args.out, "fars_loop_e4_before_after.json"), "w") as f:
        json.dump(e4, f, indent=2)

    print(f"\nWrote fars_loop_* files to {args.out}/")


if __name__ == "__main__":
    main()
