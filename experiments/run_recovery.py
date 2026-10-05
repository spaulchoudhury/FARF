"""
Rank-2 runner: behaviour-gated reinstatement.

tests/test_17_reinstatement_is_identity_not_behaviour_gated.py documents the v7.9.10 gap directly
in its name: the quorum vote authenticates WHO is voting (identity) and counts votes, but nothing
inspects the accused organisation's behaviour before or after the vote commits. This runner
re-plays that gap against three personas under two policies:

  policy=identity        (ReinstatementPolicy(), the v7.9.10 default -- ports test_17's finding
                          into a quantified MTTR/relapse table instead of a single yes/no test)
  policy=behaviour_gated (cooling-off + monitored probation + strike back-off, new in v7.9.11)

Personas (same three the TS's framing implies -- a defensible reinstatement policy has to handle
all three, not just the attacker):
  persistent_hostile      keeps transmitting through quarantine and resumes immediately after
                          reinstatement -- the literal test_17 scenario.
  dormant_attacker        goes quiet for a seeded 25-70s (long enough to look clean under a short
                          identity-only wait), then resumes hostile behaviour post-reinstatement --
                          this is what a cooling-off ALONE cannot catch; only the probation window
                          can, because it inspects post-reinstatement behaviour rather than pre-vote
                          silence.
  benign_false_positive   was quarantined by noise (e.g. a burst of legitimate traffic), goes quiet
                          immediately, behaves normally after reinstatement -- the point of also
                          reporting this persona is that a policy which merely stays stricter for
                          longer has a false-positive cost (delayed legitimate recovery), which the
                          thesis chapter must disclose, not just the true-positive win against the
                          other two personas.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os

from closed_loop import FarsFeedback, ReinstatementPolicy
from experiments.common import PERSONAS, recovery_trial
from tests.stats_utils import descriptive_statistics

logging.disable(logging.CRITICAL)

POLICIES = {
    "identity": ReinstatementPolicy(mode="identity"),
    "behaviour_gated": ReinstatementPolicy(mode="behaviour_gated", cooling_off_s=30.0,
                                           probation_messages=10, probation_sensitivity=2.0,
                                           strike_backoff=2.0),
}


def run(n: int, with_fars_feedback: bool = False) -> list[dict]:
    fb = FarsFeedback(enabled=True, scope="scoped") if with_fars_feedback else None   # explicit: the TS-accepted design
    rows = []
    for policy_name, policy in POLICIES.items():
        for persona in PERSONAS:
            for seed in range(n):
                r = recovery_trial(seed, persona, policy=policy, fars_feedback=fb)
                r["policy"] = policy_name
                rows.append(r)
    return rows


def summarise(rows: list[dict]) -> list[dict]:
    out = []
    for policy in POLICIES:
        for persona in PERSONAS:
            sub = [r for r in rows if r["policy"] == policy and r["persona"] == persona]
            n = len(sub)
            reinstated = [r for r in sub if r["reinstated"]]
            mttr = [r["mttr_s"] for r in reinstated]
            # "caught" = attacker personas that were re-quarantined before exhausting post_msgs;
            # for benign_false_positive, "caught" (a relapse flag on a clean agent) is the harm metric.
            caught = sum(r["requarantined"] for r in sub)
            post_delivered = [r["post_delivered"] for r in sub]
            row = {"policy": policy, "persona": persona, "n": n,
                  "reinstated_rate": len(reinstated) / n,
                  "requarantined_rate": caught / n,
                  "mean_post_delivered": descriptive_statistics(post_delivered)["mean"]}
            if mttr:
                d = descriptive_statistics(mttr)
                row.update({"mttr_mean_s": d["mean"], "mttr_ci95": d["ci_95"]})
            else:
                row.update({"mttr_mean_s": None, "mttr_ci95": None})
            out.append(row)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", default="experiments/results")
    ap.add_argument("--with-fars-feedback", action="store_true",
                    help="also scale cooling-off by FARS-derived federation health (rank-3 interaction)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    print(f"[1/1] Recovery trials, n={args.n} seeds x {len(POLICIES)} policies x {len(PERSONAS)} personas ...")
    rows = run(args.n, args.with_fars_feedback)
    keys = sorted({k for r in rows for k in r})
    with open(os.path.join(args.out, "recovery_raw.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader(); w.writerows(rows)

    summary = summarise(rows)
    with open(os.path.join(args.out, "recovery_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'policy':16s} {'persona':22s} {'n':>3s} {'reinst%':>8s} {'requar%':>8s} "
          f"{'mttr_s':>8s} {'post_deliv':>10s}")
    for row in summary:
        mttr = f"{row['mttr_mean_s']:.1f}" if row['mttr_mean_s'] is not None else "n/a"
        print(f"{row['policy']:16s} {row['persona']:22s} {row['n']:3d} "
              f"{row['reinstated_rate']*100:7.1f}% {row['requarantined_rate']*100:7.1f}% "
              f"{mttr:>8s} {row['mean_post_delivered']:10.2f}")
    print(f"\nWrote recovery_raw.csv + recovery_summary.json to {args.out}/")


if __name__ == "__main__":
    main()
