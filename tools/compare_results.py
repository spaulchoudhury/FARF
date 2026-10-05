"""Compare freshly generated experiment CSVs against the shipped ones, row by row on the same seed keys.
Usage: python tools/compare_results.py <fresh_dir> [shipped_dir=experiments/results]
Exit 0 = every overlapping row identical. Reports which columns differ if not."""
import csv
import glob
import os
import sys

KEYS = ("policy", "system", "arm", "fars_feedback", "persona", "attack_style", "taint_source", "seed")


def main():
    fresh = sys.argv[1]
    ship = sys.argv[2] if len(sys.argv) > 2 else "experiments/results"
    bad = 0
    files = sorted(glob.glob(os.path.join(fresh, "*_raw.csv")))
    if not files:
        print(f"ERROR: no *_raw.csv files in {fresh!r} (wrong folder?)")
        sys.exit(2)
    for f in files:
        b = os.path.basename(f)
        sp = os.path.join(ship, b)
        if not os.path.exists(sp):
            print(f"  SKIP  {b}: no shipped counterpart")
            continue
        with open(f, newline="") as fa, open(sp, newline="") as fb:
            A = list(csv.DictReader(fa))
            B = list(csv.DictReader(fb))
        kc = [k for k in KEYS if k in A[0] and k in B[0]]
        idx = {tuple(r[k] for k in kc): r for r in B}
        m = d = 0
        cols = set()
        for r in A:
            o = idx.get(tuple(r[k] for k in kc))
            if o is None:
                continue
            m += 1
            diff = [c for c in r if c in o and c not in kc and r[c] != o[c]]
            if diff:
                d += 1
                cols.update(diff)
        extra = sorted(set(A[0]) ^ set(B[0]))
        status = "OK  " if d == 0 and m > 0 else "DIFF"
        bad += status == "DIFF"
        print(f"  {status}  {b}: matched={m} differing={d} cols={sorted(cols)} schema_diff={extra}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
