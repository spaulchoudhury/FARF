"""External validation of FARF's prompt-injection signal (PT-15) against AgentHarm (Andriushchenko et al.,
arXiv:2410.09024; Gray Swan AI + UK AISI; HF: ai-safety-institute/AgentHarm).

STATUS: written against the published file layout but NOT yet run against the real files. The author's
build environment could not reach huggingface.co. Run it on your laptop and inspect the loader error message
if the schema differs.

WHAT THIS TESTS
  AgentHarm measures whether an LLM agent REFUSES or COMPLIES with explicitly harmful multi-step requests.
  FARF's PT-15 signal detects instruction-OVERRIDE / injection phrasing, not harmful intent. So this is a
  scope-boundary measurement: how often does the content signal fire on direct harmful requests (harmful set)
  versus on the matched benign set? It is NOT an AgentHarm score (no agent runs, no refusal or harm-score
  metric) and must not be reported as one.

PRE-REGISTERED EXPECTATIONS (written before any run)
  H1  Flag rate on the harmful set is low (< 30%): harmful requests are direct, not override-style.
  H2  Flag rate on the benign set is NOT lower than on harmful, i.e. the signal does not separate the two sets,
      and any flags come from the TF-IDF classifier (per-signal split reported), as seen on AgentLeak.
  If H1/H2 hold, the correct thesis statement is a scope limit: harmful-intent screening is out of FARF's
  detector; it needs a content-safety layer or an LLM judge (llm_judge.py, opt-in).

DATA HANDLING: the files carry an anti-training-contamination canary and a non-standard licence. They live in
validation/data/ (git-ignored, docker-ignored). Never commit them; never paste their prompts into documents.

USAGE
  python validation/agentharm_pt15.py --harmful validation/data/harmful_behaviors_test_public.json \\
                                      --benign  validation/data/benign_behaviors_test_public.json
"""
import argparse
import hashlib
import json
import logging
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
logging.disable(logging.CRITICAL)
from agents import detect_prompt_injection


def load_behaviors(path):
    """Return (list of (category, prompt), sha256). Accepts {"behaviors": [...]} or a bare list."""
    with open(path, "rb") as fh:
        raw = fh.read()
    obj = json.loads(raw.decode("utf-8"))
    items = obj.get("behaviors") if isinstance(obj, dict) else obj
    if not isinstance(items, list) or not items:
        raise ValueError(f"{path}: expected a non-empty list under 'behaviors' (got {type(items).__name__}); "
                         f"top-level keys: {list(obj)[:8] if isinstance(obj, dict) else 'n/a'}")
    out = []
    for i, it in enumerate(items):
        if not isinstance(it, dict) or not isinstance(it.get("prompt"), str):
            raise ValueError(f"{path}: item {i} has no string 'prompt' field; keys: {list(it)[:10] if isinstance(it, dict) else type(it)}")
        out.append((str(it.get("category", "unknown")), it["prompt"]))
    return out, hashlib.sha256(raw).hexdigest()


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(c - h, 4), round(c + h, 4))


def score(items):
    per_cat, tot = {}, {"combined": 0, "heuristic": 0, "classifier": 0}
    for cat, text in items:
        d = detect_prompt_injection(text)
        hit = {"combined": bool(d["attempts_system_override"]), "heuristic": bool(d["heuristic_hit"]),
               "classifier": bool(d["classifier_hit"])}
        c = per_cat.setdefault(cat, [0, 0])
        c[1] += 1
        c[0] += hit["combined"]
        for k, v in hit.items():
            tot[k] += v
    n = len(items)
    return {"n": n,
            "flag_rate": {k: {"k": v, "rate": round(v / n, 4), "wilson95": wilson(v, n)} for k, v in tot.items()},
            "per_category_combined": {c: f"{k}/{m}" for c, (k, m) in sorted(per_cat.items())}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harmful", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "results", "agentharm_pt15.json"))
    a = ap.parse_args()
    harmful, h_sha = load_behaviors(a.harmful)
    benign, b_sha = load_behaviors(a.benign)
    res = {"files_sha256": {"harmful": h_sha, "benign": b_sha}, "harmful": score(harmful), "benign": score(benign)}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)  # aggregate counts only: no prompt text is written
    print(json.dumps({k: res[k]["flag_rate"] if isinstance(res[k], dict) and "flag_rate" in res[k] else res[k]
                      for k in ("files_sha256", "harmful", "benign")}, indent=1)[:2500])


if __name__ == "__main__":
    main()
