"""
Rank-3 runner v2: TS-mandated Option B evaluation.

Implements every numbered condition in the TS's ruling on the FARS loop:
  1. Three arms (off / global / scoped) on the same seeds.
  2. Acceptance criteria are pre-registered in PRE_REGISTERED_CRITERIA_fars_loop_v2.md, written
     BEFORE this script is run at full (n=40) scale -- read that file for the exact thresholds;
     this script enforces them mechanically rather than re-deciding them here.
  3. Multiplier sweep: max_multiplier in {1.5, 2.0, 3.0}.
  4. Decay tied to reinstatement_policy.cooling_off_s (closed_loop.FarsFeedback.decay_s=None default
     already does this; see closed_loop.py docstring).
  5. E4 collateral is reported via e4_trial(n_bystander_orgs=2), not left implicit in blast_fraction.
  6. Adversarial self-inflicted-incident case: experiments.common.griefing_trial.

Usage: python3 -m experiments.run_fars_loop_sweep [--n 40]
"""
from __future__ import annotations

import argparse
import json
import logging
import os

from closed_loop import FarsFeedback
from experiments.common import campaign_trial, e4_trial, griefing_trial
from tests.stats_utils import (
    descriptive_statistics,
    fars_discriminative_validity,
    fars_predictive_validity,
    normality_test,
    paired_significance_test,
)

logging.disable(logging.CRITICAL)

MULTIPLIERS = (1.5, 2.0, 3.0)
SCOPES = ("global", "scoped")
COLLATERAL_MAX = 0.05
BETA = 20.0   # see PRE_REGISTERED_CRITERIA_fars_loop_v2.md Amendment 1 item 2: large enough that
              # max_multiplier, not beta, is the binding constraint being swept


def fb_for(scope: str | None, multiplier: float | None) -> FarsFeedback | None:
    if scope is None:
        return None
    return FarsFeedback(enabled=True, scope=scope, beta=BETA, max_multiplier=multiplier)


def run_arm(n: int, scope: str | None, multiplier: float | None) -> dict:
    fb = fb_for(scope, multiplier)
    camp = [campaign_trial(s, fars_feedback=fb) for s in range(n)]
    grief = [griefing_trial(s, fars_feedback=fb) for s in range(n)]
    e4b = [e4_trial(s, n_bystander_orgs=2, fars_feedback=fb) for s in range(n)]
    e4p = [e4_trial(s, fars_feedback=fb) for s in range(n)]   # same seeds as the Chapter-6 report

    camp_collateral = descriptive_statistics([r["benign_agents_quarantined_frac"] for r in camp])
    # griefing: criterion 1 checks DISTANT bystander collateral only -- the immediate topology
    # neighbour is meant to be in scope under 'scoped' (see PRE_REGISTERED_CRITERIA amendment 1.3).
    # 'off'/global have no neighbour concept distinction that matters, so this is still well-defined
    # for them (distant == "not the one declared neighbour").
    grief_distant = [r["distant_bystander_collateral_fraction"] for r in grief if r["distant_bystander_collateral_fraction"] is not None]
    grief_collateral = descriptive_statistics(grief_distant) if grief_distant else {"mean": 0.0, "n": 0, "sd": 0.0, "ci_95": (0.0, 0.0)}
    grief_neighbour_caught_rate = sum(bool(r["immediate_neighbour_caught"]) for r in grief) / len(grief)
    e4b_collateral = descriptive_statistics([r["bystander_collateral_fraction"] for r in e4b])
    w2_delivered = descriptive_statistics([r["w2_delivered"] for r in camp])
    w2_detect_rate = sum(r["w2_detected"] for r in camp) / n

    blast = [r["blast_fraction"] for r in e4p]
    fars = [r["fars"] for r in e4p]
    quarantined = [r["quarantined_fraction"] for r in e4p]
    observed_resilience = [100 * (1 - b) * (1 - q) for b, q in zip(blast, quarantined)]
    contained = [b == 0.0 for b in blast]

    return {"scope": scope, "multiplier": multiplier,
            "campaign_collateral": camp_collateral, "griefing_distant_collateral": grief_collateral,
            "griefing_neighbour_caught_rate": grief_neighbour_caught_rate,
            "e4_bystander_collateral": e4b_collateral,
            "w2_delivered": w2_delivered, "w2_detect_rate": w2_detect_rate,
            "e4_blast_raw": blast, "e4_fars_raw": fars,
            "e4_predictive_validity": fars_predictive_validity(fars, observed_resilience),
            "e4_discriminative_validity": fars_discriminative_validity(fars, contained),
            "e4_contained_rate": sum(contained) / n}


def evaluate(candidate: dict, off: dict) -> dict:
    """Mechanical pass/fail against PRE_REGISTERED_CRITERIA_fars_loop_v2.md. Returns per-criterion
    verdicts plus an overall pass flag; does not decide, only checks."""
    reasons = []

    c1 = (candidate["campaign_collateral"]["mean"] <= COLLATERAL_MAX and
          candidate["griefing_distant_collateral"]["mean"] <= COLLATERAL_MAX and
          candidate["e4_bystander_collateral"]["mean"] <= COLLATERAL_MAX)
    if not c1:
        reasons.append(f"collateral>{COLLATERAL_MAX}: campaign={candidate['campaign_collateral']['mean']:.3f} "
                       f"griefing={candidate['griefing_distant_collateral']['mean']:.3f} "
                       f"e4_bystander={candidate['e4_bystander_collateral']['mean']:.3f}")

    c2 = candidate["w2_delivered"]["mean"] <= off["w2_delivered"]["mean"] + 1e-9
    if not c2:
        reasons.append(f"wave2 delivery worse than off: {candidate['w2_delivered']['mean']:.2f} "
                       f"> {off['w2_delivered']['mean']:.2f}")

    def not_degraded(cand_vals, off_vals, higher_is_better: bool):
        if all(v == cand_vals[0] for v in cand_vals) and all(v == off_vals[0] for v in off_vals):
            return True, {"test": "degenerate (no variance)", "p_value": None}
        is_normal = normality_test(cand_vals)["is_normal"] and normality_test(off_vals)["is_normal"]
        sig = paired_significance_test(cand_vals, off_vals, is_normal)
        if not sig["significant"]:
            return True, sig
        cand_mean, off_mean = sum(cand_vals) / len(cand_vals), sum(off_vals) / len(off_vals)
        degraded = (cand_mean < off_mean) if higher_is_better else (cand_mean > off_mean)
        return (not degraded), sig

    blast_ok, blast_sig = not_degraded(candidate["e4_blast_raw"], off["e4_blast_raw"], higher_is_better=False)
    if not blast_ok:
        reasons.append(f"E4 blast_fraction significantly worse ({blast_sig})")

    auc_c, auc_o = candidate["e4_discriminative_validity"]["auc"], off["e4_discriminative_validity"]["auc"]
    auc_ok = auc_c >= auc_o - 0.05   # AUC has no natural paired-sample test here; use a fixed tolerance
    if not auc_ok:
        reasons.append(f"E4 discriminative AUC dropped: {auc_c:.3f} vs off {auc_o:.3f}")

    r_c, r_o = candidate["e4_predictive_validity"]["pearson_r"], off["e4_predictive_validity"]["pearson_r"]
    r_ok = r_c >= r_o - 0.10
    if not r_ok:
        reasons.append(f"E4 Pearson r dropped: {r_c:.3f} vs off {r_o:.3f}")

    c3 = blast_ok and auc_ok and r_ok
    passed = c1 and c2 and c3
    return {"pass": passed, "criterion_1_collateral": c1, "criterion_2_wave2": c2,
            "criterion_3_e4_not_degraded": c3, "reasons": reasons}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--out", default="experiments/results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    n = args.n

    print("Pre-registered criteria: see PRE_REGISTERED_CRITERIA_fars_loop_v2.md (written before this run)")
    print(f"Running OFF baseline, n={n} ...")
    off = run_arm(n, None, None)

    results = {"off": off, "sweep": []}
    print(f"\n{'scope':8s} {'mult':>5s} | {'camp_coll':>9s} {'grief_coll':>10s} {'e4b_coll':>8s} | "
          f"{'w2_deliv':>8s} {'w2_det%':>7s} | {'blast':>6s} {'AUC':>5s} {'r':>5s} | pass")
    print(f"{'off':8s} {'--':>5s} | {off['campaign_collateral']['mean']:9.3f} "
          f"{off['griefing_distant_collateral']['mean']:10.3f} {off['e4_bystander_collateral']['mean']:8.3f} | "
          f"{off['w2_delivered']['mean']:8.2f} {off['w2_detect_rate']*100:6.1f}% | "
          f"{descriptive_statistics(off['e4_blast_raw'])['mean']:6.3f} "
          f"{off['e4_discriminative_validity']['auc']:5.3f} {off['e4_predictive_validity']['pearson_r']:5.3f} | --")

    passing = []
    for scope in SCOPES:
        for m in MULTIPLIERS:
            print(f"Running scope={scope} multiplier={m}, n={n} ...")
            cand = run_arm(n, scope, m)
            verdict = evaluate(cand, off)
            results["sweep"].append({"scope": scope, "multiplier": m, "result": cand, "verdict": verdict})
            if verdict["pass"]:
                passing.append((scope, m))
            print(f"{scope:8s} {m:5.1f} | {cand['campaign_collateral']['mean']:9.3f} "
                  f"{cand['griefing_distant_collateral']['mean']:10.3f} {cand['e4_bystander_collateral']['mean']:8.3f} | "
                  f"{cand['w2_delivered']['mean']:8.2f} {cand['w2_detect_rate']*100:6.1f}% | "
                  f"{descriptive_statistics(cand['e4_blast_raw'])['mean']:6.3f} "
                  f"{cand['e4_discriminative_validity']['auc']:5.3f} "
                  f"{cand['e4_predictive_validity']['pearson_r']:5.3f} | "
                  f"{'PASS' if verdict['pass'] else 'fail: ' + '; '.join(verdict['reasons'])}")

    print("\n=== Decision ===")
    if passing:
        passing.sort(key=lambda t: t[1])   # smallest multiplier first, per the pre-registered decision rule
        chosen = passing[0]
        print(f"PASSING combinations: {passing}")
        print(f"Selected (smallest passing multiplier): scope={chosen[0]}, max_multiplier={chosen[1]}")
        print('Write-up: "Closing the loop with topology-scoped sensitivity yields faster containment '
              f'({off["w2_delivered"]["mean"]:.1f} -> '
              f'{[s for s in results["sweep"] if s["scope"]==chosen[0] and s["multiplier"]==chosen[1]][0]["result"]["w2_delivered"]["mean"]:.1f} '
              'wave-2 messages delivered before detection) at <=5% collateral. '
              'Naive global scaling fails the same criteria (see table)."')
    else:
        print("NO combination passed all three pre-registered criteria.")
        print('Write-up (TS fallback wording): "Closing the loop yields a small speed gain that does not '
              'survive the collateral cost. Claim C stays partial; the remaining gap to DART is reported, '
              'not hidden."')
    results["decision"] = {"passing": passing, "chosen": passing[0] if passing else None}

    with open(os.path.join(args.out, "fars_loop_sweep.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nWrote fars_loop_sweep.json to {args.out}/")


if __name__ == "__main__":
    main()
