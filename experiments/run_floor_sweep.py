"""CLASSIFIER_FLOOR operating curve for content-derived taint: what each floor costs a BENIGN sender versus what it buys against a
LYING sender, so the floor is chosen from data and then frozen (Chapter 4, Section 4.10.5).
    python -m experiments.run_floor_sweep [--n 60] [--out experiments/results]
For each floor it reports
  * benign_max_delta     largest content delta over the benign development sets fixture sentences (0.0 = no benign taint),
  * repeat_first_refusal message index at which a sender repeating ONLY the benign sentence closest to the floor is first refused
                         (None = never in 120 messages) -- the worst case for benign collateral,
  * E4 / classic delivered and blast fraction for a lying sender (n paired seeds), as in experiments.run_content_taint.
In-sample caveat: the floor is tuned against benign development sets; an out-of-sample split is future work (F12)."""
import argparse
import csv
import json
import logging
import os

import content_taint as ct
from content_taint_classifier import classifier_score
from experiments.common import ATTACK_TEXT, BENIGN_TEXTS, close_bus, make_bus
from experiments.run_content_taint import CLASSIC_OVERRIDE_TEXT, lying_sender_trial
from main import build_federation

logging.disable(logging.CRITICAL)
FLOORS = (0.49, 0.505, 0.513, 0.52, 0.54, 0.58)    # old values: (0.49, 0.50, 0.501, 0.502, 0.503, 0.505)


def require_classifier_score(text):
    score = classifier_score(text)
    if score is None:
        raise RuntimeError("content-taint classifier unavailable; install requirements.txt before sweeping floors")
    return score


def repeat_first_refusal(text, n_msgs=120):
    bus = make_bus(taint_source="content")
    try:
        agents = build_federation(bus, n_orgs=5)
        orgs = list(agents)
        sender = agents[orgs[0]]["advisor"]
        for i in range(n_msgs):
            dest = orgs[1 + i % 4]
            r = bus.send(sender.agent_id, orgs[0], agents[dest]["advisor"].agent_id, dest, "memory_recall_forward",
                         {"requested_privilege": 0.1, "attempts_system_override": False, "instruction": text}, taint_delta=0.0)
            if r["decision"] != "allow":
                return i + 1
        return None
    finally:
        close_bus(bus)


def mean(xs):
    return sum(xs) / len(xs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--out", default="experiments/results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    original = ct.CLASSIFIER_FLOOR
    worst = max(BENIGN_TEXTS, key=require_classifier_score)
    print("benign classifier scores:", [round(require_classifier_score(t), 3) for t in BENIGN_TEXTS], f"(max {require_classifier_score(worst):.3f})")
    print(f"{'floor':>7} {'benign_max_delta':>17} {'repeat_first_refusal':>21} {'E4 deliv':>9} {'E4 blast':>9} {'classic deliv':>14}")
    rows = []
    try:
        for floor in FLOORS:
            ct.CLASSIFIER_FLOOR = floor
            bmax = max(ct.analyse_payload({"instruction": t})["delta"] for t in BENIGN_TEXTS)
            rfr = repeat_first_refusal(worst)
            e4 = [lying_sender_trial(s, attack_text=ATTACK_TEXT, taint_source="content") for s in range(args.n)]
            cl = [lying_sender_trial(s, attack_text=CLASSIC_OVERRIDE_TEXT, taint_source="content") for s in range(args.n)]
            row = {"floor": floor, "benign_max_delta": bmax, "repeat_first_refusal": rfr if rfr is not None else "",
                   "e4_delivered": round(mean([r["delivered_fraction"] for r in e4]), 3),
                   "e4_blast": round(mean([r["blast_fraction"] for r in e4]), 3),
                   "classic_delivered": round(mean([r["delivered_fraction"] for r in cl]), 3),
                   "classic_blast": round(mean([r["blast_fraction"] for r in cl]), 3), "n": args.n}
            rows.append(row)
            print(f"{floor:>7.3f} {bmax:>17.4f} {str(rfr if rfr is not None else 'never'):>21} {row['e4_delivered']:>9.3f} "
                  f"{row['e4_blast']:>9.3f} {row['classic_delivered']:>14.3f}")
    finally:
        ct.CLASSIFIER_FLOOR = original
    with open(os.path.join(args.out, "floor_sweep_raw.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out, "floor_sweep_summary.json"), "w") as fh:
        json.dump({"configured_floor_at_start": original, "benign_scores": [round(require_classifier_score(t), 4) for t in BENIGN_TEXTS],
                   "rows": rows}, fh, indent=1)
    print(f"configured floor in this tree: {original}.  Wrote floor_sweep_raw.csv + floor_sweep_summary.json")


if __name__ == "__main__":
    main()
