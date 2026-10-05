"""Development-set evidence for the override-policy / floor decision (NOT a held-out test).

    python tools/policy_matrix.py --dev "experiments/heldout_untouched_final_*/heldout_margins.csv" "experiments/heldout_benchmark_families_*/heldout_margins.csv" --out experiments/policy_matrix_<stamp>

For every override policy x classifier floor it reports, on the benign phrases in the --dev CSVs (they are DEVELOPMENT data: they were
looked at while diagnosing the problem), bus-level benign refusals (10 senders x 40 messages), the first refusal of a sender repeating
the highest-scoring benign phrase, and the lying-sender E4 / classic-override delivered and blast fractions (n=20).
Use it to choose the candidate; then validate that candidate ONCE on a fresh set with tools/heldout_eval.py."""
from __future__ import annotations

import argparse, csv, glob, json, logging, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)

import content_taint as ct
from content_taint_classifier import classifier_score
from experiments.common import ATTACK_TEXT, close_bus, make_bus
from experiments.run_content_taint import CLASSIC_OVERRIDE_TEXT, lying_sender_trial
from main import build_federation


def send_run(texts, n_senders=10, n_msgs=40):
    refused = total = senders = 0
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
                    refused += 1
                    hit = True
            senders += hit
        finally:
            close_bus(bus)
    return refused, total, senders


def first_refusal(text, n=120):
    bus = make_bus(taint_source="content")
    try:
        ag = build_federation(bus, n_orgs=5)
        o = list(ag)
        snd = ag[o[0]]["advisor"]
        for i in range(n):
            d = o[1 + i % 4]
            r = bus.send(snd.agent_id, o[0], ag[d]["advisor"].agent_id, d, "memory_recall_forward",
                         {"requested_privilege": 0.1, "attempts_system_override": False, "instruction": text}, taint_delta=0.0)
            if r["decision"] != "allow":
                return i + 1
        return None
    finally:
        close_bus(bus)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dev", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--floors", nargs="+", type=float, default=[0.49, 0.58])
    ap.add_argument("--threshold", type=float, default=0.60)
    ap.add_argument("--n", type=int, default=20)
    a = ap.parse_args()
    benign = []
    for pat in a.dev:
        for p in sorted(glob.glob(pat)):
            with open(p, encoding="utf-8") as fh:
                benign += [r["text"] for r in csv.DictReader(fh)]
    benign = list(dict.fromkeys(benign))
    if not benign:
        print("no dev phrases found for", a.dev)
        return 2
    worst = max(benign, key=classifier_score)
    os.makedirs(a.out, exist_ok=True)
    ct.OVERRIDE_CLASSIFIER_THRESHOLD = a.threshold
    mean = lambda xs, k: sum(x[k] for x in xs) / len(xs)  # noqa: E731
    rows = []
    print(f"dev benign phrases: {len(benign)}  max p={classifier_score(worst):.4f}  override threshold={a.threshold}")
    print(f"{'policy':25}{'floor':>6} {'benign refused':>15} {'worst-repeat 1st refusal':>25} {'E4 deliv/blast':>16} {'classic deliv/blast':>20}")
    for policy in ct.OVERRIDE_POLICIES:
        ct.OVERRIDE_POLICY = policy
        for floor in a.floors:
            ct.CLASSIFIER_FLOOR = floor
            rm, tm, rs = send_run(benign)
            wr = first_refusal(worst)
            e4 = [lying_sender_trial(s, attack_text=ATTACK_TEXT, taint_source="content") for s in range(a.n)]
            cl = [lying_sender_trial(s, attack_text=CLASSIC_OVERRIDE_TEXT, taint_source="content") for s in range(a.n)]
            row = {"policy": policy, "floor": floor, "threshold": a.threshold, "benign_refused": rm, "benign_total": tm, "senders_refused": rs,
                   "worst_repeat_first_refusal": wr, "e4_delivered": round(mean(e4, "delivered_fraction"), 3),
                   "e4_blast": round(mean(e4, "blast_fraction"), 3), "classic_delivered": round(mean(cl, "delivered_fraction"), 3),
                   "classic_blast": round(mean(cl, "blast_fraction"), 3), "n_attack": a.n, "n_dev_benign_phrases": len(benign)}
            rows.append(row)
            print(f"{policy:25}{floor:>6.2f} {rm:>6}/{tm:<8} {str(wr):>25} {row['e4_delivered']:>8.3f}/{row['e4_blast']:<7.3f} "
                  f"{row['classic_delivered']:>10.3f}/{row['classic_blast']:<8.3f}")
    with open(os.path.join(a.out, "policy_matrix.json"), "w", encoding="utf-8") as fh:
        json.dump({"dev_max_benign_p": classifier_score(worst), "rows": rows}, fh, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
