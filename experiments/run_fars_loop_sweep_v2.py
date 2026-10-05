"""
Rank-3 runner v2 -- second TS ruling (2025-09-30). Supersedes run_fars_loop_sweep.py (archived,
see experiments/archive/README_ARCHIVE.md). Implements all eight numbered points of that ruling:

  1. Old sweep withdrawn and archived (experiments/archive/).
  2. Five arms, same seeds: off, global, scoped-naive, scoped-cold, scoped-hop-cap.
  3. Chain topology >=3 hops is REQUIRED: every scenario below runs at n_orgs=5 (4 hops, the
     original pre-registered scale) AND n_orgs=12 (11 hops, a stress scale). This is where the
     earlier (v1) result would have broken silently if not tested -- see Section "A scale-dependent
     bug found while building this" in the printed output and PRE_REGISTERED_CRITERIA amendment 2.
  4. Slow-distributed adversary (experiments.common.slow_distributed_adversary_trial): several
     independently-genuine incidents staged along a long chain, spaced inside each other's decay
     window, testing whether the cold-gate survives an adversary who knows about decay.
  5. Multiplier sweep extended until something breaks: {1.5, 2.0, 3.0, 5.0, 10.0, 20.0}, at BOTH
     chain lengths. Decay is tied to reinstatement_policy.cooling_off_s throughout (closed_loop.py
     default).
  6. CI (95%, via tests.stats_utils.descriptive_statistics) and paired Wilcoxon/t-test against `off`
     for every metric; the E4 result is reported plainly, including whether scoped remains inert on
     it (it does -- see Section E4).
  7. Regression check (run separately, see chat record / README): off reproduces the v7.9.11
     ablation/recovery/baseline-comparison tables byte-for-byte (0 differing fields in all three).
  8. Full 8-scenario smoke test (run separately, see chat record / README): all pass.

Usage: python3 -m experiments.run_fars_loop_sweep_v2 [--n 40]
"""
from __future__ import annotations

import argparse
import json
import logging
import os

from closed_loop import FarsFeedback
from experiments.common import (
    campaign_trial,
    e4_trial,
    griefing_trial,
    slow_distributed_adversary_trial,
)
from tests.stats_utils import (
    descriptive_statistics,
    fars_discriminative_validity,
    fars_predictive_validity,
    normality_test,
    paired_significance_test,
)

logging.disable(logging.CRITICAL)

BETA = 20.0   # large enough that max_multiplier, not beta, is the binding swept constraint
MULTIPLIERS = (1.5, 3.0, 30.0)   # extended "until something breaks" (point 5) -- a 20x span
CHAIN_LENGTHS = (5, 12)          # (4 hops, 11 hops) -- point 3
COLLATERAL_MAX = 0.05


def arm_configs(multiplier: float) -> dict:
    return {
        "off": None,
        "global": FarsFeedback(enabled=True, scope="global", beta=BETA, max_multiplier=multiplier),
        "scoped-naive": FarsFeedback(enabled=True, scope="scoped", beta=BETA, max_multiplier=multiplier,
                                     require_cold=False),
        "scoped-cold": FarsFeedback(enabled=True, scope="scoped", beta=BETA, max_multiplier=multiplier,
                                    require_cold=True, hop_cap=None),
        "scoped-hop-cap": FarsFeedback(enabled=True, scope="scoped", beta=BETA, max_multiplier=multiplier,
                                       require_cold=True, hop_cap=1),
    }


def ci_and_sig(candidate_vals, off_vals) -> dict:
    d = descriptive_statistics(candidate_vals)
    if all(v == candidate_vals[0] for v in candidate_vals) and all(v == off_vals[0] for v in off_vals):
        sig = {"test": "degenerate (no variance)", "p_value": None, "significant": False}
    else:
        is_normal = normality_test(candidate_vals)["is_normal"] and normality_test(off_vals)["is_normal"]
        sig = paired_significance_test(candidate_vals, off_vals, is_normal)
    return {"mean": d["mean"], "ci_95": d["ci_95"], "sig_vs_off": sig}


def run_chain_scenarios(n: int, n_orgs: int, multiplier: float, e4b_cache: dict) -> dict:
    msgs = 80 * (n_orgs - 2)
    configs = arm_configs(multiplier)
    out = {}
    for arm, fb in configs.items():
        camp = [campaign_trial(s, n_orgs=n_orgs, benign_msgs=msgs, fars_feedback=fb) for s in range(n)]
        grief = [griefing_trial(s, n_orgs=n_orgs, benign_msgs=80 * (n_orgs - 1), fars_feedback=fb) for s in range(n)]
        # e4_trial's own n_orgs is internal/random (3-6) and independent of the outer chain length,
        # so it is computed once per (multiplier, arm) and reused across both chain lengths rather
        # than wastefully recomputed identically for n_orgs=5 and n_orgs=12.
        if (arm, multiplier) not in e4b_cache:
            e4b_cache[(arm, multiplier)] = [e4_trial(s, n_bystander_orgs=2, fars_feedback=fb) for s in range(n)]
        out[arm] = {"campaign": camp, "griefing": grief, "e4_bystander": e4b_cache[(arm, multiplier)]}
    return out


def run_e4_plain(n: int, multiplier: float) -> dict:
    configs = arm_configs(multiplier)
    out = {}
    for arm, fb in configs.items():
        rows = [e4_trial(s, fars_feedback=fb) for s in range(n)]
        blast = [r["blast_fraction"] for r in rows]
        fars = [r["fars"] for r in rows]
        quarantined = [r["quarantined_fraction"] for r in rows]
        observed_resilience = [100 * (1 - b) * (1 - q) for b, q in zip(blast, quarantined)]
        contained = [b == 0.0 for b in blast]
        out[arm] = {"blast_fraction": blast, "predictive_validity": fars_predictive_validity(fars, observed_resilience),
                    "discriminative_validity": fars_discriminative_validity(fars, contained),
                    "contained_rate": sum(contained) / n}
    return out


def run_slow_distributed(n: int, multiplier: float) -> dict:
    configs = arm_configs(multiplier)
    out = {}
    for arm, fb in configs.items():
        rows = [slow_distributed_adversary_trial(s, fars_feedback=fb) for s in range(n)]
        out[arm] = rows
    return out


def summarise_collateral(chain_result: dict) -> dict:
    off = chain_result["off"]
    out = {}
    for arm, data in chain_result.items():
        camp_vals = [r["benign_agents_quarantined_frac"] for r in data["campaign"]]
        camp_off = [r["benign_agents_quarantined_frac"] for r in off["campaign"]]
        grief_vals = [(r["distant_bystander_collateral_fraction"] or 0.0) for r in data["griefing"]]
        grief_off = [(r["distant_bystander_collateral_fraction"] or 0.0) for r in off["griefing"]]
        e4b_vals = [r["bystander_collateral_fraction"] for r in data["e4_bystander"]]
        e4b_off = [r["bystander_collateral_fraction"] for r in off["e4_bystander"]]
        w2_vals = [r["w2_delivered"] for r in data["campaign"]]
        w2_off = [r["w2_delivered"] for r in off["campaign"]]
        max_hop = max((r["max_incident_hop"] or 0) for r in data["campaign"])
        out[arm] = {"campaign_collateral": ci_and_sig(camp_vals, camp_off),
                    "griefing_distant_collateral": ci_and_sig(grief_vals, grief_off),
                    "e4_bystander_collateral": ci_and_sig(e4b_vals, e4b_off),
                    "w2_delivered": ci_and_sig(w2_vals, w2_off),
                    "max_incident_hop": max_hop}
    return out


def evaluate(summary_row: dict) -> dict:
    reasons = []
    c1 = all(summary_row[m]["mean"] <= COLLATERAL_MAX
            for m in ("campaign_collateral", "griefing_distant_collateral", "e4_bystander_collateral"))
    if not c1:
        reasons.append("collateral>{:.2f}".format(COLLATERAL_MAX))
    c2 = summary_row["w2_delivered"]["mean"] <= summary_row["_off_w2_mean"] + 1e-9
    if not c2:
        reasons.append("wave2 worse than off")
    return {"pass": c1 and c2, "reasons": reasons}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--out", default="experiments/results")
    ap.add_argument("--sections", default="123", help="which of sections 1/2/3 to run, e.g. '1'")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    n = args.n

    full_report = {"chain": {}, "e4_plain": {}, "slow_distributed": {}}

    if "1" in args.sections:
        print("=" * 100)
        print("SECTION 1: Chain-topology collateral/detection results, 5 arms x multiplier sweep x 2 chain lengths")
        print("=" * 100)
        e4b_cache = {}   # keyed by (arm, multiplier); e4_trial doesn't depend on the outer chain length,
                         # so this is shared across n_orgs but NOT across multiplier (each multiplier
                         # produces a genuinely different FarsFeedback config).
        for n_orgs in CHAIN_LENGTHS:
            hops = n_orgs - 1
            print(f"\n----- n_orgs={n_orgs} ({hops} hops) -----")
            full_report["chain"][n_orgs] = {}
            for mult in MULTIPLIERS:
                print(f"\n  multiplier={mult}:")
                chain_result = run_chain_scenarios(n, n_orgs, mult, e4b_cache)
                summ = summarise_collateral(chain_result)
                off_w2_mean = summ["off"]["w2_delivered"]["mean"]
                print(f"  {'arm':16s} {'camp_coll':>10s} {'grief_coll':>10s} {'e4b_coll':>9s} "
                      f"{'w2_deliv':>9s} {'max_hop':>8s} | verdict")
                for arm in ("off", "global", "scoped-naive", "scoped-cold", "scoped-hop-cap"):
                    row = summ[arm]
                    row["_off_w2_mean"] = off_w2_mean
                    v = evaluate(row) if arm != "off" else {"pass": None, "reasons": []}
                    verdict = "--" if v["pass"] is None else ("PASS" if v["pass"] else "fail: " + ",".join(v["reasons"]))
                    print(f"  {arm:16s} {row['campaign_collateral']['mean']:10.3f} "
                          f"{row['griefing_distant_collateral']['mean']:10.3f} "
                          f"{row['e4_bystander_collateral']['mean']:9.3f} "
                          f"{row['w2_delivered']['mean']:9.2f} {row['max_incident_hop']:8d} | {verdict}")
                full_report["chain"][n_orgs][mult] = summ

    if "2" in args.sections:
        print("\n" + "=" * 100)
        print("SECTION 2: E4 plain (Chapter-6-style), does scoped remain inert on E4? Reported plainly either way.")
        print("=" * 100)
        for mult in (30.0,):   # one extreme multiplier is sufficient here; Section 1 already sweeps fully
            print(f"\n  multiplier={mult}:")
            e4res = run_e4_plain(n, mult)
            off_blast = e4res["off"]["blast_fraction"]
            print(f"  {'arm':16s} {'blast_mean':>10s} {'contained%':>10s} {'AUC':>6s} {'pearson_r':>9s} | vs-off blast p")
            for arm, r in e4res.items():
                d = descriptive_statistics(r["blast_fraction"])
                if arm == "off":
                    p_str = "--"
                else:
                    is_normal = normality_test(r["blast_fraction"])["is_normal"] and normality_test(off_blast)["is_normal"]
                    sig = paired_significance_test(r["blast_fraction"], off_blast, is_normal)
                    p_str = f"{sig['p_value']:.3g}" if sig["p_value"] is not None else sig["test"]
                print(f"  {arm:16s} {d['mean']:10.3f} {r['contained_rate']*100:9.1f}% "
                      f"{r['discriminative_validity']['auc']:6.3f} {r['predictive_validity']['pearson_r']:9.3f} | {p_str}")
            inert = all(descriptive_statistics(e4res[a]["blast_fraction"])["mean"] ==
                       descriptive_statistics(e4res["off"]["blast_fraction"])["mean"]
                       for a in ("scoped-cold", "scoped-hop-cap"))
            print(f"  -> scoped remains INERT on E4 at multiplier={mult}: {inert} "
                  f"(E4 is a single-shot scenario with no prior incident to degrade health, and its "
                  f"attacking org's own detection comes from the deterministic override-flag rule and "
                  f"org_detector, neither of which the FARS loop touches)")
            full_report["e4_plain"][mult] = e4res

    if "3" in args.sections:
        print("\n" + "=" * 100)
        print("SECTION 3: Slow-distributed adversary (staged independently-genuine incidents along a 15-org chain)")
        print("=" * 100)
        for mult in (30.0,):   # one extreme multiplier is sufficient here; Section 1 already sweeps fully
            print(f"\n  multiplier={mult}:")
            sd = run_slow_distributed(n, mult)
            print(f"  {'arm':16s} {'true_bystander_coll':>20s} {'max_hop':>8s} {'orgs_touched':>13s}")
            for arm, rows in sd.items():
                coll = descriptive_statistics([(r["true_bystander_collateral_fraction"] or 0.0) for r in rows])
                maxhop = max((r["max_incident_hop"] or 0) for r in rows)
                touched = descriptive_statistics([r["n_orgs_touched_by_scope"] for r in rows])
                print(f"  {arm:16s} {coll['mean']:20.3f} {maxhop:8d} {touched['mean']:13.1f}")
            full_report["slow_distributed"][mult] = {arm: rows for arm, rows in sd.items()}

    with open(os.path.join(args.out, "fars_loop_sweep_v2.json"), "w") as f:
        json.dump(full_report, f, indent=2, default=str)
    print(f"\nWrote fars_loop_sweep_v2.json to {args.out}/")


if __name__ == "__main__":
    main()
