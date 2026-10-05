"""
Rank-4 runner: independent baseline comparison (DART-style reputation gate vs full FARF).

experiments/baselines/dart_style.py adapts DART's (arXiv:2609.05529) reputation/quarantine
equations to a message bus, fed exactly the same per-message information FARF's per-agent layer
sees (see that file's docstring for the full disclosure of what is and is not faithfully mapped).
This runner is what turns that adaptation into a result: same scenarios, same seeds, FARF's full
orchestration.evaluate() vs DartStyleOrchestrationLayer.evaluate() as a drop-in replacement.

Scenarios (ground-truth delivered_fraction as the primary outcome, consistent with the rest of the
v7.9.11/12 harness):
  - E4 (mandated memory-manipulation scenario)
  - Sybil fragmentation (PT-04 pattern) -- DART has no org-level analogue at all, so this is expected
    to be the sharpest contrast: DART's reputation is purely per-agent (Eq.6/Eq.8 in dart_style.py),
    so N identities each staying under DART's own per-agent flag threshold is exactly the same class
    of gap FARF's org_detector exists to close.
  - Fan-out (PT-16 pattern) -- same reasoning: DART's B/Psi has no topology term.
  - Recovery (persistent_hostile persona only): DART defines quarantine as PERMANENT (no
    reinstatement equation exists in the paper), so this reports what "recovery" means for DART
    (system continues operating around the isolated agent) rather than pretending it has an MTTR.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os

from experiments.baselines.dart_style import DartStyleOrchestrationLayer
from experiments.common import close_bus, e4_trial, fanout_trial, make_bus, sybil_trial
from main import build_federation
from tests.stats_utils import descriptive_statistics, normality_test, paired_significance_test

logging.disable(logging.CRITICAL)


def run_scenario(fn, n: int, farf_kwargs: dict, dart_kwargs: dict) -> dict:
    farf_rows = [fn(s, **farf_kwargs) for s in range(n)]
    dart_rows = [fn(s, orchestration=DartStyleOrchestrationLayer(), **dart_kwargs) for s in range(n)]
    return {"farf": farf_rows, "dart": dart_rows}


def summarise(pair: dict, metric: str) -> dict:
    farf_vals = [r[metric] for r in pair["farf"]]
    dart_vals = [r[metric] for r in pair["dart"]]
    farf_d, dart_d = descriptive_statistics(farf_vals), descriptive_statistics(dart_vals)
    if any(v != farf_vals[0] for v in farf_vals) or any(v != dart_vals[0] for v in dart_vals):
        is_normal = normality_test(farf_vals)["is_normal"] and normality_test(dart_vals)["is_normal"]
        sig = paired_significance_test(dart_vals, farf_vals, is_normal)
    else:
        sig = {"test": "degenerate (no variance)", "p_value": None, "significant": False}
    return {"metric": metric, "farf_mean": farf_d["mean"], "farf_ci95": farf_d["ci_95"],
            "dart_mean": dart_d["mean"], "dart_ci95": dart_d["ci_95"], "significance": sig}


def run_recovery_comparison(n: int) -> dict:
    """DART has no reinstatement equation -- quarantine is permanent (dart_style.py docstring).
    So the comparable question isn't MTTR (undefined for DART) but: does the system correctly
    isolate a persistent attacker and STAY isolated, without an examiner-visible failure mode.
    Uses the same persistent_hostile traffic pattern as experiments.common.recovery_trial's setup
    phase, but does not attempt reinstatement for the DART arm."""
    from experiments.common import BENIGN_TEXTS
    import random
    rows = {"farf": [], "dart": []}
    for label, orch in (("farf", None), ("dart", DartStyleOrchestrationLayer())):
        for seed in range(n):
            rng = random.Random(seed)
            bus = make_bus(orchestration=orch)
            try:
                agents = build_federation(bus, n_orgs=4)
                adv, exe = agents["OrgA"]["advisor"], agents["OrgA"]["executor"]
                n_sent, quarantined_at = 0, None
                for i in range(60):
                    r = bus.send(adv.agent_id, "OrgA", exe.agent_id, "OrgA", "memory_recall_forward",
                                {"requested_privilege": 0.1, "attempts_system_override": False,
                                 "instruction": rng.choice(BENIGN_TEXTS)}, taint_delta=0.05)
                    n_sent += 1
                    if r["decision"] == "quarantine" and quarantined_at is None:
                        quarantined_at = i + 1
                        break
                rows[label].append({"seed": seed, "quarantined": quarantined_at is not None,
                                    "messages_to_quarantine": quarantined_at})
            finally:
                close_bus(bus)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--out", default="experiments/results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    n = args.n

    print(f"[1/4] E4, n={n} ...")
    e4 = run_scenario(e4_trial, n, {}, {})
    print(f"[2/4] Sybil fragmentation, n={n} ...")
    sybil = run_scenario(sybil_trial, n, {}, {})
    print(f"[3/4] Fan-out, n={n} ...")
    fanout = run_scenario(fanout_trial, n, {}, {})
    print(f"[4/4] Persistent-hostile isolation, n={n} ...")
    recovery = run_recovery_comparison(n)

    report = {
        "e4_delivered_fraction": summarise(e4, "delivered_fraction"),
        "e4_blast_fraction": summarise(e4, "blast_fraction"),
        "sybil_delivered_fraction": summarise(sybil, "delivered_fraction"),
        "fanout_delivered_fraction": summarise(fanout, "delivered_fraction"),
        "recovery_farf_quarantine_rate": sum(r["quarantined"] for r in recovery["farf"]) / n,
        "recovery_dart_quarantine_rate": sum(r["quarantined"] for r in recovery["dart"]) / n,
        "recovery_farf_messages_to_quarantine": descriptive_statistics(
            [r["messages_to_quarantine"] for r in recovery["farf"] if r["messages_to_quarantine"]])
            if any(r["messages_to_quarantine"] for r in recovery["farf"]) else None,
        "recovery_dart_messages_to_quarantine": descriptive_statistics(
            [r["messages_to_quarantine"] for r in recovery["dart"] if r["messages_to_quarantine"]])
            if any(r["messages_to_quarantine"] for r in recovery["dart"]) else None,
    }

    for key in ("e4_delivered_fraction", "e4_blast_fraction", "sybil_delivered_fraction", "fanout_delivered_fraction"):
        r = report[key]
        p = f"p={r['significance']['p_value']:.4g}" if r['significance'].get('p_value') is not None else r['significance']['test']
        print(f"{key:28s} FARF={r['farf_mean']:.3f} {r['farf_ci95']}  DART={r['dart_mean']:.3f} {r['dart_ci95']}  {p}")
    print(f"\npersistent-hostile isolation: FARF quarantine-rate={report['recovery_farf_quarantine_rate']:.3f} "
          f"(mean {report['recovery_farf_messages_to_quarantine']['mean']:.1f} msgs to quarantine)"
          if report['recovery_farf_messages_to_quarantine'] else
          f"\npersistent-hostile isolation: FARF quarantine-rate={report['recovery_farf_quarantine_rate']:.3f} (never)")
    print(f"                              DART quarantine-rate={report['recovery_dart_quarantine_rate']:.3f} "
          f"(mean {report['recovery_dart_messages_to_quarantine']['mean']:.1f} msgs to quarantine)"
          if report['recovery_dart_messages_to_quarantine'] else
          f"                              DART quarantine-rate={report['recovery_dart_quarantine_rate']:.3f} (never)")

    for name, pair in (("e4", e4), ("sybil", sybil), ("fanout", fanout)):
        rows = [{**r, "system": sysname} for sysname, rs in pair.items() for r in rs]
        with open(os.path.join(args.out, f"baseline_comparison_{name}_raw.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r}))
            w.writeheader(); w.writerows(rows)
    with open(os.path.join(args.out, "baseline_comparison_summary.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nWrote baseline_comparison_* files to {args.out}/")


if __name__ == "__main__":
    main()
