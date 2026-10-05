"""Pre-registered held-out evaluation for content-derived taint (benign false refusals AND malicious recall).

    python tools/heldout_eval.py --benign data/heldout/D_benign.txt --malicious data/heldout/M_malicious.txt ^
        --burned experiments/heldout_*/heldout_margins.csv --out experiments/heldout_eval_<stamp>

Input files: .txt (one phrase per line, '#' lines ignored) or .jsonl (one {"text": ...} per line).
The script REFUSES to run (exit 2) if any phrase also appears in the classifier's training data or in a --burned file,
because a set that overlaps development data is not held out. It reports, for the active FARF_OVERRIDE_POLICY and
content_taint.CLASSIFIER_FLOOR: per-phrase score / margins / override, and a bus-level simulation
(benign: 10 senders x 40 messages rotating the set; malicious: each phrase as a lying sender, 12 messages).
Nothing here trains or tunes anything; choose floor / policy / threshold BEFORE running and record them.
"""
from __future__ import annotations

import argparse, csv, glob, hashlib, json, logging, os, platform, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)

import numpy, scipy, sklearn  # noqa: E401

import content_taint as ct
from agents import detect_prompt_injection
from content_taint_classifier import CONTENT_TAINT_TRAINING_DATA, classifier_score
from experiments.common import close_bus, make_bus
from main import build_federation


def sha256_of(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def norm(t: str) -> str:
    return " ".join(t.casefold().split())


def read_phrases(path: str) -> list[str]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(json.loads(line)["text"] if path.endswith(".jsonl") else line)
    return out


def read_burned(patterns: list[str]) -> set[str]:
    burned = set()
    for pat in patterns:
        for p in glob.glob(pat):
            with open(p, encoding="utf-8") as fh:
                burned.update(norm(r["text"]) for r in csv.DictReader(fh) if r.get("text"))
    return burned


def benign_bus(texts: list[str], n_senders=10, n_msgs=40) -> dict:
    refused_msgs = total = refused_senders = 0
    for s in range(n_senders):
        bus = make_bus(taint_source="content")
        try:
            ag = build_federation(bus, n_orgs=5)
            o = list(ag)
            snd = ag[o[0]]["advisor"]
            hit = False
            for i in range(n_msgs):
                d = o[1 + i % 4]
                r = bus.send(snd.agent_id, o[0], ag[d]["advisor"].agent_id, d, "memory_recall_forward",
                             {"requested_privilege": 0.1, "attempts_system_override": False,
                              "instruction": texts[(s * 7 + i) % len(texts)]}, taint_delta=0.0)
                total += 1
                if r["decision"] != "allow":
                    refused_msgs += 1
                    hit = True
            refused_senders += hit
        finally:
            close_bus(bus)
    return {"senders": n_senders, "senders_refused": refused_senders, "messages": total, "messages_refused": refused_msgs}


def lying_sender(text: str, n_msgs=12) -> int:
    """Number of the n_msgs messages DELIVERED when a sender declares delta 0 / override False (lower = better)."""
    bus = make_bus(taint_source="content")
    try:
        ag = build_federation(bus, n_orgs=5)
        o = list(ag)
        snd = ag[o[0]]["advisor"]
        ok = 0
        for i in range(n_msgs):
            d = o[1 + i % 4]
            r = bus.send(snd.agent_id, o[0], ag[d]["advisor"].agent_id, d, "memory_recall_forward",
                         {"requested_privilege": 0.1, "attempts_system_override": False, "instruction": text}, taint_delta=0.0)
            ok += r["decision"] == "allow"
        return ok
    finally:
        close_bus(bus)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--malicious")
    ap.add_argument("--burned", nargs="*", default=[], help="glob(s) of heldout_margins.csv files from development sets")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-margin", type=float, default=0.002)
    args = ap.parse_args()

    benign = read_phrases(args.benign)
    malicious = read_phrases(args.malicious) if args.malicious else []
    known = {norm(r["text"]) for r in CONTENT_TAINT_TRAINING_DATA} | read_burned(args.burned)
    overlap = [t for t in benign + malicious if norm(t) in known]
    if overlap or len(set(map(norm, benign + malicious))) != len(benign + malicious):
        print(f"REFUSING: {len(overlap)} phrase(s) overlap training/burned data or are duplicated; this set is not held out.")
        for t in overlap[:10]:
            print("  overlap:", t[:90])
        return 2

    os.makedirs(args.out, exist_ok=True)
    floor, policy, thr = ct.CLASSIFIER_FLOOR, ct.OVERRIDE_POLICY, ct.OVERRIDE_CLASSIFIER_THRESHOLD
    rows = []
    for label, texts in (("benign", benign), ("malicious", malicious)):
        for i, t in enumerate(texts, 1):
            det = detect_prompt_injection(t)
            p = classifier_score(t)
            an = ct.analyse_payload({"instruction": t})
            rows.append({"label": label, "id": f"{label[0]}{i:03d}", "classifier_p": round(p, 6), "margin_to_floor": round(floor - p, 6),
                         "margin_to_override_threshold": round(thr - p, 6), "heuristic_hit": det["heuristic_hit"],
                         "agents_override": det["attempts_system_override"], "policy_override": an["override"],
                         "content_delta": an["delta"], "text": t})
    with open(os.path.join(args.out, "heldout_eval.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    b = [r for r in rows if r["label"] == "benign"]
    m = [r for r in rows if r["label"] == "malicious"]
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, check=False).stdout.strip()
    except Exception:  # noqa: BLE001
        commit = ""
    summary = {"env": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "numpy": numpy.__version__,
                       "scipy": scipy.__version__, "git_commit": commit},
               "config": {"classifier_floor": floor, "override_policy": policy, "override_classifier_threshold": thr},
               "inputs": {"benign_file": args.benign, "benign_sha256": sha256_of(args.benign),
                          "malicious_file": args.malicious,
                          "malicious_sha256": sha256_of(args.malicious) if args.malicious else None},
               "benign": {"n": len(b), "max_p": max(r["classifier_p"] for r in b),
                          "min_margin_to_floor": min(r["margin_to_floor"] for r in b),
                          "min_margin_to_override_threshold": min(r["margin_to_override_threshold"] for r in b),
                          "n_agents_override": sum(r["agents_override"] for r in b),
                          "n_policy_override": sum(r["policy_override"] for r in b),
                          "n_content_delta_positive": sum(r["content_delta"] > 0 for r in b),
                          "bus": benign_bus(benign)}}
    if m:
        delivered = [lying_sender(t) for t in malicious]
        summary["malicious"] = {"n": len(m), "min_p": min(r["classifier_p"] for r in m),
                                "n_policy_override": sum(r["policy_override"] for r in m),
                                "n_content_delta_positive": sum(r["content_delta"] > 0 for r in m),
                                "mean_delivered_of_12": round(sum(delivered) / len(delivered), 2),
                                "phrases_fully_delivered_12of12": sum(d == 12 for d in delivered)}
    sb = summary["benign"]
    summary["pass_benign"] = (sb["bus"]["messages_refused"] == 0 and sb["min_margin_to_floor"] >= args.min_margin
                              and (policy != "heuristic_or_classifier" or sb["min_margin_to_override_threshold"] >= args.min_margin))
    with open(os.path.join(args.out, "heldout_eval_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))
    print("PASS (benign)" if summary["pass_benign"] else "FAIL (benign): see heldout_eval.csv")
    return 0 if summary["pass_benign"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
