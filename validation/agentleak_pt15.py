"""External validation of FARF's prompt-injection signal (agents.detect_prompt_injection, PT-15)
against the AgentLeak scenario set (El Yagoubi et al., arXiv:2602.11510, MIT licence).

WHAT THIS TESTS (and what it does not)
  Tests : does the content-level signal FARF already has flag AgentLeak's labelled attack payloads
          (positives) and stay quiet on its benign task requests (negatives)?
  Does NOT test: PII-leak detection. The FARF bus performs no payload-content inspection; taint_delta is
          caller-supplied. Do not report these numbers as "FARF prevents AgentLeak leakage", and do not
          compare them with the paper's leakage rates (different quantity, different unit).

PRE-REGISTERED EXPECTATIONS (written before the first run, 24 Sep 2026)
  E1  Recall is high for direct_prompt_injection / indirect_prompt_injection (override phrasing).
  E2  Recall is LOW for role_confusion, cross_agent_collusion, memory_write_exfiltration and
      tool_output_poisoning: these contain no override vocabulary, so heuristic + TF-IDF should miss them.
  E3  False-positive rate on benign requests is low (< 5%).
  If E2 holds, that is a scope finding (content detector covers override-style injection only; the other
  classes rely on identity, signature, memory-integrity and taint controls), not a defect to hide.

UNIT OF ANALYSIS: unique payload TEMPLATES. The 496 attack scenarios reuse a handful of payload texts, and
many embed a random CANARY_<FIELD>_<RANDOM> token that makes otherwise identical strings look unique.
Canary tokens are collapsed to <CANARY> before de-duplication; counting scenarios or raw strings would
inflate N by 5x to 30x (pseudo-replication).
"""
import argparse
import collections
import hashlib
import json
import logging
import math
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
logging.disable(logging.CRITICAL)  # FARF logs every detection; silence for batch runs
from agents import detect_prompt_injection


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(c - h, 4), round(c + h, 4))


_CANARY = re.compile(r"CANARY_[A-Z_]*[A-Z0-9]{6,}")


def template(t):
    return _CANARY.sub("<CANARY>", t)


def skeleton(t):
    """Collapse person and case names so benign strings differing only by name count once."""
    t = re.sub(r"CASE-\d+", "CASE-N", t)
    t = re.sub(r"\b[A-Z][a-z]+ [A-Z][a-z']+(?:'s)?", "<NAME>", t)
    return re.sub(r"\d+", "N", t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", required=True, help="path to scenarios_full_1000.jsonl")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "results", "agentleak_pt15.json"))
    ap.add_argument("--dataset-commit", default="unknown", help="AgentLeak git commit the file came from")
    a = ap.parse_args()

    with open(a.scenarios, "rb") as fh:
        raw = fh.read()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]

    pos = {}  # payload -> attack_class (first seen)
    neg = set()
    skel_neg = {}
    for s in rows:
        if s["attack"]["enabled"] and s["attack"]["payload"]:
            pos.setdefault(template(s["attack"]["payload"]), s["attack"]["attack_class"])
        elif not s["attack"]["enabled"]:
            neg.add(template(s["objective"]["user_request"]))
            skel_neg.setdefault(skeleton(s["objective"]["user_request"]), []).append(s["objective"]["user_request"])

    def sig(t):
        d = detect_prompt_injection(t)
        return {"combined": bool(d["attempts_system_override"]), "heuristic": bool(d["heuristic_hit"]),
                "classifier": bool(d["classifier_hit"])}

    def flag(t):
        return sig(t)["combined"]

    per_class = collections.defaultdict(lambda: [0, 0])
    misses = collections.defaultdict(list)
    for text, cls in pos.items():
        hit = flag(text)
        per_class[cls][1] += 1
        per_class[cls][0] += hit
        if not hit:
            misses[cls].append(text)
    fp = sorted(t for t in neg if flag(t))
    ablation = {}
    for name in ("combined", "heuristic", "classifier"):
        r_k = sum(sig(t)[name] for t in pos)
        f_k = sum(sig(t)[name] for t in neg)
        sk_k = sum(1 for v in skel_neg.values() if sum(sig(x)[name] for x in v) / len(v) >= 0.5)
        ablation[name] = {"attack_recall": f"{r_k}/{len(pos)}", "benign_flagged_strings": f"{f_k}/{len(neg)}",
                          "benign_skeletons_mostly_flagged": f"{sk_k}/{len(skel_neg)}"}
    tp = sum(v[0] for v in per_class.values())
    npos = sum(v[1] for v in per_class.values())

    res = {
        "dataset": {"file_sha256": hashlib.sha256(raw).hexdigest(), "commit": a.dataset_commit,
                    "scenarios": len(rows), "unique_attack_templates": npos, "unique_benign_templates": len(neg), "benign_skeletons": len(skel_neg),
                    "attack_scenarios": sum(1 for r in rows if r["attack"]["enabled"])},
        "overall_recall": {"k": tp, "n": npos, "rate": round(tp / npos, 4), "wilson95": wilson(tp, npos)},
        "false_positive_rate": {"k": len(fp), "n": len(neg), "rate": round(len(fp) / len(neg), 4),
                                "wilson95": wilson(len(fp), len(neg))},
        "per_class_recall": {c: {"k": k, "n": n, "rate": round(k / n, 4), "wilson95": wilson(k, n)}
                             for c, (k, n) in sorted(per_class.items())},
        "per_signal_ablation": ablation,
        "example_misses": {c: v[:3] for c, v in misses.items()},
        "example_false_positives": fp[:5],
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps({k: res[k] for k in ("dataset", "overall_recall", "false_positive_rate", "per_signal_ablation")}, indent=1))


if __name__ == "__main__":
    main()
