"""Benign-collateral check for content-derived taint (missing from v7.9.11's run_content_taint.py).
run_content_taint.py only tests a LYING sender. This measures the other side: a fully benign sender with declared
delta 0.0 and ordinary text, under taint_source = declared | content | max.
Finding at time of writing (30 Sep 2026, 30 trials x 40 msgs): declared -> 0/30 senders refused; content -> 30/30
refused (median first refusal at message 4). Cause: content_taint.CLASSIFIER_FLOOR=0.3 is below the classifier's
score range for ordinary text (0.35-0.49), so benign text gets delta 0.04-0.16 against an org cap of 0.35/40 msgs.
Run:  python -m experiments.check_content_taint_benign [--n 30] [--out experiments/results]
"""
import argparse
import csv
import json
import logging
import os
import random

from experiments.common import BENIGN_TEXTS, close_bus, make_bus
from main import build_federation

logging.disable(logging.CRITICAL)


def trial(seed, src, n_msgs=40):
    rng = random.Random(seed)
    bus = make_bus(taint_source=src)
    try:
        ag = build_federation(bus, n_orgs=5)
        orgs = list(ag)
        s = ag[orgs[0]]["advisor"]
        first = None
        refused = 0
        for i in range(n_msgs):
            o = orgs[1 + i % 4]
            r = bus.send(s.agent_id, orgs[0], ag[o]["advisor"].agent_id, o, "memory_recall_forward",
                         {"requested_privilege": 0.1, "attempts_system_override": False,
                          "instruction": rng.choice(BENIGN_TEXTS)}, taint_delta=0.0)
            if r["decision"] != "allow":
                refused += 1
                first = first or i + 1
        return {"seed": seed, "taint_source": src, "refused": refused, "of": n_msgs, "first_refusal": first or ""}
    finally:
        close_bus(bus)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", default="experiments/results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows = [trial(s, src) for src in ("declared", "content", "max") for s in range(a.n)]
    with open(os.path.join(a.out, "content_taint_benign_raw.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summ = {}
    for src in ("declared", "content", "max"):
        rs = [r for r in rows if r["taint_source"] == src]
        firsts = sorted(r["first_refusal"] for r in rs if r["first_refusal"] != "")
        summ[src] = {"trials": len(rs), "senders_refused": sum(1 for r in rs if r["refused"] > 0),
                     "msgs_refused": sum(r["refused"] for r in rs), "msgs_total": sum(r["of"] for r in rs),
                     "median_first_refusal": firsts[len(firsts) // 2] if firsts else None}
        print(f"{src:9s} senders refused {summ[src]['senders_refused']}/{summ[src]['trials']}  "
              f"msgs refused {summ[src]['msgs_refused']}/{summ[src]['msgs_total']}  median first refusal={summ[src]['median_first_refusal']}")
    with open(os.path.join(a.out, "content_taint_benign_summary.json"), "w") as fh:
        json.dump(summ, fh, indent=1)
    print("Wrote content_taint_benign_raw.csv + content_taint_benign_summary.json")


if __name__ == "__main__":
    main()
