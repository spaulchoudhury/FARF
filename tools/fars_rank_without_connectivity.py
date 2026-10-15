"""Does the near-zero FARS connectivity term change how the cloud profiles rank?

On the sparse federation graphs of the cloud runs the connectivity term stayed between about 0.003 and 0.054,
so a quarter of the FARS weight (0.25) carried almost no information. This tool re-scores every recorded
`/fars` snapshot WITHOUT that term (the remaining weights 0.30/0.30/0.15 renormalised to sum to 1) and compares
the two orderings of the profiles. Pure analysis of existing evidence files: nothing is run or deployed.

Profiles are read from the `<HHMMSS>_deploy_config_<profile>.txt` files; each `/fars` snapshot belongs to the most
recent deploy before it. Use --until to stop at the last file of the run you want (default: the 7 Oct run).

Usage: python tools/fars_rank_without_connectivity.py [--dir evidence_v7911_cloud_20261007] [--until 073338]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re

W = {"connectivity": 0.25, "trust_health": 0.30, "taint_containment": 0.30, "policy_compliance": 0.15}


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def fars_full(c):
    return 100.0 * sum(W[k] * c[k] for k in W)


def fars_no_conn(c):
    w3 = {k: v for k, v in W.items() if k != "connectivity"}
    tot = sum(w3.values())
    return 100.0 * sum(w3[k] * c[k] for k in w3) / tot


def ranks(values):
    order = sorted(range(len(values)), key=lambda i: -values[i])
    r = [0] * len(values)
    for pos, i in enumerate(order):
        r[i] = pos + 1
    return r


def spearman(a, b):
    n = len(a)
    ra, rb = ranks(a), ranks(b)
    d2 = sum((x - y) ** 2 for x, y in zip(ra, rb))
    return 1 - 6 * d2 / (n * (n * n - 1)) if n > 2 else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="evidence_v7911_cloud_20261007")
    ap.add_argument("--until", default="073338", help="last HHMMSS to include (end of the 7 Oct run)")
    args = ap.parse_args()
    cfgs = sorted((os.path.basename(p)[:6], re.search(r"deploy_config_(.+)\.txt$", p).group(1))
                  for p in glob.glob(os.path.join(args.dir, "*_deploy_config_*.txt")))
    snaps = sorted(os.path.basename(p) for p in glob.glob(os.path.join(args.dir, "*ep_fars.txt")))
    prof_rows: dict[str, list] = {}
    for s in snaps:
        t = s[:6]
        if t > args.until:
            continue
        owner = [name for ts, name in cfgs if ts <= t]
        if not owner:
            continue
        j = load(os.path.join(args.dir, s))
        c = j["components"]
        prof_rows.setdefault(owner[-1], []).append((s, j["FARS"], c, fars_full(c), fars_no_conn(c)))
    print(f"{'profile':12s} {'snapshot':26s} {'FARS':>6s} {'conn':>6s} {'trust':>6s} {'taint':>6s} {'policy':>6s} {'FARS-no-conn':>13s}")
    final = []
    for prof, rows in prof_rows.items():
        for s, fars, c, ff, f3 in rows:
            print(f"{prof:12s} {s:26s} {fars:6.2f} {c['connectivity']:6.3f} {c['trust_health']:6.3f} "
                  f"{c['taint_containment']:6.3f} {c['policy_compliance']:6.3f} {f3:13.2f}")
        final.append((prof, sum(r[1] for r in rows) / len(rows), sum(r[4] for r in rows) / len(rows)))
    names = [f[0] for f in final]
    a, b = [f[1] for f in final], [f[2] for f in final]
    ra, rb = ranks(a), ranks(b)
    print("\nprofile means and ranks (1 = highest score)")
    print(f"{'profile':12s} {'FARS':>7s} {'rank':>5s} {'no-conn':>9s} {'rank':>5s}")
    for n, x, y, p, q in zip(names, a, b, ra, rb):
        print(f"{n:12s} {x:7.2f} {p:5d} {y:9.2f} {q:5d}")
    all_conn = [r[2]["connectivity"] for rows in prof_rows.values() for r in rows]
    print(f"\nconnectivity term range {min(all_conn):.3f}-{max(all_conn):.3f}: it moves FARS by at most "
          f"{25.0 * (max(all_conn) - min(all_conn)):.2f} points")
    rho = spearman(a, b)
    same = ra == rb
    print(f"Spearman rank correlation between FARS and FARS-without-connectivity: {rho:.2f}; "
          f"{'identical ordering' if same else 'ordering differs'}")
    print("VERDICT:", "profile ordering does not depend on the connectivity term" if same
          else "ordering depends on the connectivity term for at least one pair; report components beside FARS")


if __name__ == "__main__":
    main()
