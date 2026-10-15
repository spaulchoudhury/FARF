"""G10 / F19: the legacy agents.py detector measured END TO END through the default bus.

Chapter 4 reports that the legacy detector flags 75/119 benign (63%) and 74/125 malicious (59%) held-out
phrases when called directly. This tool sends every phrase of D (benign) and M (malicious) through a default
FederationBus (declared taint, override policy 'agents', no loop) the way an honest sender would: the sender
runs detect_prompt_injection(), declares the result in the payload, and the bus decides. One fresh bus per
phrase, so one quarantine never contaminates the next phrase.

Two senders are reported for M:
  honest sender  declares what its own detector found           -> the default-path detection rate
  lying sender   declares attempts_system_override=False, delta 0 -> what the default bus does when the sender lies

D and M are already burned (the pre-registered evaluation consumed them). This tool only MEASURES the legacy
detector; it must not be used to tune anything.

Usage: python tools/legacy_detector_endtoend.py [--d data/heldout/D_benign.txt] [--m data/heldout/M_malicious.txt]
                                               [--out experiments/results_legacy_endtoend]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import detect_prompt_injection  # noqa: E402
from experiments.common import close_bus, make_bus  # noqa: E402
from main import build_federation  # noqa: E402

logging.disable(logging.CRITICAL)


def read_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


def send_one(text: str, declared_override: bool | None) -> dict:
    """declared_override None -> honest (run the legacy detector); False -> a lying sender."""
    det = detect_prompt_injection(text)
    override = det["attempts_system_override"] if declared_override is None else declared_override
    bus = make_bus()                                           # default: declared taint, policy 'agents', no loop
    try:
        ag = build_federation(bus, n_orgs=2)
        o = list(ag)
        r = bus.send(ag[o[0]]["advisor"].agent_id, o[0], ag[o[1]]["advisor"].agent_id, o[1],
                     "memory_recall_forward",
                     {"requested_privilege": 0.1, "attempts_system_override": bool(override), "instruction": text},
                     taint_delta=0.0)
        return {"decision": r["decision"], "detector_flag": bool(det["attempts_system_override"])}
    finally:
        close_bus(bus)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--d", default="data/heldout/D_benign.txt")
    ap.add_argument("--m", default="data/heldout/M_malicious.txt")
    ap.add_argument("--out", default="experiments/results_legacy_endtoend")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    D, M = read_lines(args.d), read_lines(args.m)
    rows, summary = [], {}
    for label, texts, sender in (("D benign, honest sender", D, None),
                                 ("M malicious, honest sender", M, None),
                                 ("M malicious, lying sender", M, False)):
        res = [send_one(t, sender) for t in texts]
        refused = sum(r["decision"] != "allow" for r in res)
        flagged = sum(r["detector_flag"] for r in res)
        summary[label] = {"n": len(texts), "detector_flags": flagged, "refused_by_bus": refused,
                          "refused_pct": round(100.0 * refused / len(texts), 1)}
        for t, r in zip(texts, res):
            rows.append({"set": label, "decision": r["decision"], "detector_flag": r["detector_flag"], "text": t[:120]})
    print(f"{'set':32s} {'n':>4s} {'detector flags':>15s} {'refused by bus':>15s} {'refused %':>10s}")
    for k, v in summary.items():
        print(f"{k:32s} {v['n']:4d} {v['detector_flags']:15d} {v['refused_by_bus']:15d} {v['refused_pct']:10.1f}")
    d = summary["D benign, honest sender"]
    m = summary["M malicious, honest sender"]
    print(f"\ndefault-path false-refusal rate on D: {d['refused_pct']}%   |   detection rate on M: {m['refused_pct']}%")
    with open(os.path.join(args.out, "legacy_endtoend.json"), "w") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(args.out, "legacy_endtoend.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["set", "decision", "detector_flag", "text"])
        w.writeheader()
        w.writerows(rows)
    print("saved to", args.out)


if __name__ == "__main__":
    main()
