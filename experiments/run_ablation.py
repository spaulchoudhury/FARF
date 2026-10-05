"""
Rank-1 runner: composition ablation.

For each coupling the TS named, disable ONLY that coupling (all else = full FARF) and re-run a
paired trial set (same seeds across arms). Primary outcome is ground-truth `delivered_fraction`
(what the bus actually let through to another organisation / agent), not the post-hoc taint-graph
`blast_fraction` -- see experiments/common.py module docstring for why the latter alone would be
circular for the edge-severing ablation.

Each coupling is tested on the scenario that actually stresses it:
  - E4 (memory-manipulation replay, the Chapter-6 scenario): run under ALL ablations, because the
    TS asked for E4 specifically. E4's payload trips the deterministic
    attempts_system_override policy rule regardless of taint coupling, so E4 alone under-states
    the value of taint_to_orchestration / org_detector / fanout_detector -- it is not a full
    ablation story on its own, only the mandated one.
  - Sybil fragmentation (PT-04 pattern, benign-looking payload, no override flag): isolates
    org_detector, because this attack is invisible to per-agent CUSUM by construction.
  - Low-magnitude fan-out (PT-16 pattern): isolates fanout_detector, same reasoning.
  - Two-wave campaign, wave 2 only (stealthy, no override flag): isolates taint_to_orchestration,
    because wave 2's detection depends on taint level reaching the per-agent CUSUM/window, and
    reports the FARS/health side-effect too since campaign_trial already tracks it.

Usage:
    python3 -m experiments.run_ablation [--n 40] [--out experiments/results]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import statistics as stat

from closed_loop import CompositionFlags
from experiments.common import campaign_trial, e4_trial, fanout_trial, sybil_trial
from tests.stats_utils import descriptive_statistics, normality_test, paired_significance_test

logging.disable(logging.CRITICAL)  # the FARF logger is intentionally verbose; silence it for batch runs

E4_ARMS = [
    ("full", CompositionFlags()),
    ("-taint_to_orchestration", CompositionFlags(taint_to_orchestration=False)),
    ("-quarantine_to_edge_severing", CompositionFlags(quarantine_to_edge_severing=False)),
    ("-org_detector", CompositionFlags(org_detector=False)),
    ("-fanout_detector", CompositionFlags(fanout_detector=False)),
    ("reinstatement=self_attest", CompositionFlags(reinstatement="self_attest")),
    ("reinstatement=none", CompositionFlags(reinstatement="none")),
]


def run_e4_matrix(n: int, outdir: str) -> list[dict]:
    rows = []
    for label, flags in E4_ARMS:
        for seed in range(n):
            r = e4_trial(seed, composition=flags)
            r["arm"] = label
            rows.append(r)
    _write_csv(os.path.join(outdir, "ablation_e4_raw.csv"), rows)
    return rows


def run_org_detector_arm(n: int) -> list[dict]:
    rows = []
    for on in (True, False):
        flags = CompositionFlags(org_detector=on)
        for seed in range(n):
            r = sybil_trial(seed, composition=flags)
            r["arm"] = "full" if on else "-org_detector"
            rows.append(r)
    return rows


def run_fanout_detector_arm(n: int) -> list[dict]:
    rows = []
    for on in (True, False):
        flags = CompositionFlags(fanout_detector=on)
        for seed in range(n):
            r = fanout_trial(seed, composition=flags)
            r["arm"] = "full" if on else "-fanout_detector"
            rows.append(r)
    return rows


def run_taint_to_orch_arm(n: int) -> list[dict]:
    """Isolating taint_to_orchestration requires holding org_detector/fanout_detector OFF in both
    arms: campaign wave 2's repeated cross-org sends from one agent otherwise get caught by the
    org-level rolling-volume detector regardless of this flag (confirmed empirically -- the first
    version of this runner had both arms off org_detector left on and got p=1, identical sequences,
    because org_detector was doing 100% of the catching before taint_to_orchestration was ever
    exercised). With both bus-level detectors off, the only route left to catch wave 2 is the
    per-agent CUSUM/sliding-window inside SecureOrchestrationLayer.evaluate(), which IS gated by
    this flag (it consumes event.taint_score, and taint_for_orchestration = 0.0 when the flag is
    off -- see federation_bus.send())."""
    rows = []
    for on in (True, False):
        flags = CompositionFlags(taint_to_orchestration=on, org_detector=False, fanout_detector=False)
        for seed in range(n):
            r = campaign_trial(seed, composition=flags)
            r["arm"] = "full" if on else "-taint_to_orchestration"
            rows.append(r)
    return rows


def _write_csv(path: str, rows: list[dict]):
    if not rows:
        return
    keys = sorted({k for r in rows for k in r})
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def _paired_summary(rows: list[dict], arm_key: str, metric: str, baseline_label: str,
                    seed_key: str = "seed") -> list[dict]:
    """Group by arm, align by seed against baseline_label, report descriptive + paired stats."""
    by_arm: dict[str, dict] = {}
    for r in rows:
        by_arm.setdefault(r[arm_key], {})[r[seed_key]] = r[metric]
    base = by_arm.get(baseline_label, {})
    out = []
    for arm, seed_to_val in by_arm.items():
        vals = [seed_to_val[s] for s in sorted(seed_to_val)]
        desc = descriptive_statistics(vals)
        row = {"arm": arm, "metric": metric, "n": desc["n"], "mean": desc["mean"], "sd": desc["sd"],
               "ci_95_lo": desc["ci_95"][0], "ci_95_hi": desc["ci_95"][1]}
        if arm != baseline_label and base:
            common = sorted(set(seed_to_val) & set(base))
            a = [seed_to_val[s] for s in common]
            b = [base[s] for s in common]
            if len(common) >= 2 and (stat.pstdev(a) > 0 or stat.pstdev(b) > 0):
                is_normal = normality_test(a)["is_normal"] and normality_test(b)["is_normal"]
                sig = paired_significance_test(a, b, is_normal)
                row.update({"vs_baseline": baseline_label, "test": sig["test"], "p_value": sig["p_value"]})
            else:
                row.update({"vs_baseline": baseline_label, "test": "degenerate (no variance)", "p_value": None})
        out.append(row)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--out", default="experiments/results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    print(f"[1/4] E4 ablation matrix, n={args.n} seeds x {len(E4_ARMS)} arms ...")
    e4_rows = run_e4_matrix(args.n, args.out)
    e4_summary = (_paired_summary(e4_rows, "arm", "delivered_fraction", "full")
                  + _paired_summary(e4_rows, "arm", "blast_fraction", "full"))

    print(f"[2/4] Sybil / org_detector, n={args.n} seeds x 2 arms ...")
    sybil_rows = run_org_detector_arm(args.n)
    sybil_summary = _paired_summary(sybil_rows, "arm", "delivered_fraction", "full")

    print(f"[3/4] Fan-out / fanout_detector, n={args.n} seeds x 2 arms ...")
    fanout_rows = run_fanout_detector_arm(args.n)
    fanout_summary = _paired_summary(fanout_rows, "arm", "delivered_fraction", "full")

    print(f"[4/4] Campaign wave-2 / taint_to_orchestration, n={args.n} seeds x 2 arms ...")
    camp_rows = run_taint_to_orch_arm(args.n)
    camp_summary_delivered = _paired_summary(camp_rows, "arm", "w2_delivered", "full")
    camp_detect_rate = {}
    for r in camp_rows:
        d = camp_detect_rate.setdefault(r["arm"], [0, 0])
        d[0] += int(r["w2_detected"]); d[1] += 1
    camp_detect_summary = [{"arm": a, "w2_detected_rate": c[0] / c[1], "n": c[1]}
                           for a, c in camp_detect_rate.items()]

    _write_csv(os.path.join(args.out, "ablation_sybil_raw.csv"), sybil_rows)
    _write_csv(os.path.join(args.out, "ablation_fanout_raw.csv"), fanout_rows)
    _write_csv(os.path.join(args.out, "ablation_campaign_raw.csv"), camp_rows)

    report = {"n_per_arm": args.n,
              "e4_summary": e4_summary, "sybil_summary": sybil_summary,
              "fanout_summary": fanout_summary,
              "campaign_w2_delivered_summary": camp_summary_delivered,
              "campaign_w2_detect_rate": camp_detect_summary}
    with open(os.path.join(args.out, "ablation_summary.json"), "w") as f:
        json.dump(report, f, indent=2)

    print("\n=== E4 (all ablations) -- delivered_fraction & blast_fraction ===")
    for row in e4_summary:
        p = f"p={row['p_value']:.4g}" if row.get("p_value") is not None else ""
        print(f"  {row['metric']:20s} {row['arm']:28s} mean={row['mean']:.3f}"
              f" ci95=({row['ci_95_lo']:.3f},{row['ci_95_hi']:.3f}) {p}")
    print("\n=== Sybil -- org_detector ablation, delivered_fraction ===")
    for row in sybil_summary:
        p = f"p={row['p_value']:.4g}" if row.get("p_value") is not None else ""
        print(f"  {row['arm']:20s} mean={row['mean']:.3f} ci95=({row['ci_95_lo']:.3f},{row['ci_95_hi']:.3f}) {p}")
    print("\n=== Fan-out -- fanout_detector ablation, delivered_fraction ===")
    for row in fanout_summary:
        p = f"p={row['p_value']:.4g}" if row.get("p_value") is not None else ""
        print(f"  {row['arm']:20s} mean={row['mean']:.3f} ci95=({row['ci_95_lo']:.3f},{row['ci_95_hi']:.3f}) {p}")
    print("\n=== Campaign wave 2 -- taint_to_orchestration ablation ===")
    for row in camp_summary_delivered:
        p = f"p={row['p_value']:.4g}" if row.get("p_value") is not None else ""
        print(f"  delivered {row['arm']:28s} mean={row['mean']:.3f} ci95=({row['ci_95_lo']:.3f},{row['ci_95_hi']:.3f}) {p}")
    for row in camp_detect_summary:
        print(f"  detect_rate {row['arm']:26s} {row['w2_detected_rate']:.3f}  (n={row['n']})")

    print(f"\nWrote raw CSVs + ablation_summary.json to {args.out}/")


if __name__ == "__main__":
    main()
