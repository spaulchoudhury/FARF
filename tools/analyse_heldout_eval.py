"""Descriptive analysis of a heldout_eval.csv (no tuning, no re-scoring): separation of the classifier score, a threshold table, the flagged
benign phrases, and per-block malicious detection.
    python tools/analyse_heldout_eval.py --csv experiments/heldout_eval_<stamp>/heldout_eval.csv --blocks "name:n,name:n,..."
--blocks lists consecutive groups of malicious phrases in FILE ORDER with their sizes (your own labels); omit it to skip that table."""
from __future__ import annotations

import argparse, csv, statistics as st


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--blocks", default="")
    a = ap.parse_args()
    with open(a.csv, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    ben = [r for r in rows if r["label"] == "benign"]
    mal = [r for r in rows if r["label"] == "malicious"]
    p = lambda rs: [float(r["classifier_p"]) for r in rs]  # noqa: E731
    pb, pm = p(ben), p(mal)
    auc = sum((m > b) + 0.5 * (m == b) for m in pm for b in pb) / (len(pm) * len(pb))
    print(f"benign n={len(ben)}  malicious n={len(mal)}   AUC of classifier_p (malicious vs benign) = {auc:.3f}   (0.5 = no separation)")
    for name, v in (("benign", pb), ("malicious", pm)):
        print(f"  {name:9} min {min(v):.3f}  median {st.median(v):.3f}  max {max(v):.3f}")
    print("\nthreshold   benign>=T   malicious>=T")
    for t in (0.45, 0.50, 0.55, 0.58, 0.60, 0.65, 0.70):
        print(f"  {t:.2f}     {sum(x >= t for x in pb):>4}/{len(pb):<4}   {sum(x >= t for x in pm):>4}/{len(pm)}")
    flag = lambda r: float(r["content_delta"]) > 0  # noqa: E731
    print(f"\nbenign flagged (content_delta > 0): {sum(map(flag, ben))}/{len(ben)};  policy override: {sum(r['policy_override'] == 'True' for r in ben)};"
          f"  legacy agents override: {sum(r['agents_override'] == 'True' for r in ben)};  heuristic hits: {sum(r['heuristic_hit'] == 'True' for r in ben)}")
    print(f"malicious flagged: {sum(map(flag, mal))}/{len(mal)};  policy override: {sum(r['policy_override'] == 'True' for r in mal)};"
          f"  legacy agents override: {sum(r['agents_override'] == 'True' for r in mal)};  heuristic hits: {sum(r['heuristic_hit'] == 'True' for r in mal)}")
    print("\nflagged benign phrases (highest p first):")
    for r in sorted((r for r in ben if flag(r)), key=lambda r: -float(r["classifier_p"])):
        print(f"  p={float(r['classifier_p']):.3f} delta={r['content_delta']:>6} override={r['policy_override']:<5} | {r['text'][:90]}")
    if a.blocks:
        print("\nmalicious detection by block:  n  flagged  policy-override  mean p")
        i = 0
        for item in a.blocks.split(","):
            name, _, n = item.rpartition(":")
            blk = mal[i:i + int(n)]
            i += int(n)
            print(f"  {name:36} {len(blk):>2}  {sum(map(flag, blk)):>5}  {sum(r['policy_override'] == 'True' for r in blk):>8}  {st.mean(p(blk)):.3f}")
        if i != len(mal):
            print(f"  [warning] blocks cover {i} of {len(mal)} malicious phrases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
