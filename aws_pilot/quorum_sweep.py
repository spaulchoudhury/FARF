"""
aws_pilot/quorum_sweep.py
=========================
Quorum-threshold sweep over a live deployment (Cloud Run), N = 4 .. 8 organisations.

WHY: the first cloud quorum test (cloud_run_final_checks.py PART 1) ran at N = 3, where the
pbft_dynamic rule degenerates to unanimity (f = 0  ->  quorum = N). That confirms the threshold
is computed and enforced, but cannot show the 2f+1 behaviour that is the point of a
Byzantine-tolerant quorum. This script registers additional organisations up to each requested
stage, reads the quorum the bus reports, checks it against the rule
    f = max(0, (N-1)//3);  quorum = N if f == 0 else 2f+1
and then runs a reinstatement proposal, witnessing in the bus's own (alphabetical) order and
asserting that the proposal commits at exactly the quorum-th witness and not before.

HONEST SCOPE: /witness takes the witnessing org's name from the request body and the bus signs
the vote with a key the bus itself holds (disclosed bus-side-signing boundary, bus_service.py).
So this shows threshold arithmetic and enforcement over real hosting; it does NOT show that
independent hosts hold independent keys or that a "faulty org" could not vote on another's behalf.

There is no org-removal path in the bus: run this on a FRESH revision (-Step warm) if you want
the whole curve from N = 3. Organisations already present above a stage are reported and skipped.

Usage:
  python aws_pilot/quorum_sweep.py --url https://BUS --stages 4,7,8
Exit code 0 = every stage passed.
"""
import argparse
import sys

import requests

FILLERS = ["PilotOrgA", "PilotOrgB", "PilotOrgC", "PilotOrgD", "PilotOrgE",
           "PilotOrgF", "PilotOrgG", "PilotOrgH", "PilotOrgI", "PilotOrgJ"]


def expected_quorum(n):
    f = max(0, (n - 1) // 3)
    return n if f == 0 else 2 * f + 1


def status(base):
    return requests.get(f"{base}/status", timeout=20).json()


def ensure_orgs(base, n):
    """Register filler orgs until exactly n are registered. Returns list of (count, quorum) steps."""
    steps = []
    orgs = status(base)["registered_orgs"]
    if len(orgs) > n:
        return None, len(orgs)
    for name in FILLERS:
        if len(orgs) >= n:
            break
        if name in orgs:
            continue
        r = requests.post(f"{base}/register_org", json={"org": name}, timeout=20)
        r.raise_for_status()
        orgs = status(base)["registered_orgs"]
        steps.append((len(orgs), r.json().get("quorum_required")))
    return steps, len(orgs)


def test_stage(base, n):
    st = status(base)
    orgs = st["registered_orgs"]
    quorum = int(st["quorum_required"])
    exp = expected_quorum(len(orgs))
    rec = {"N": len(orgs), "quorum_reported": quorum, "quorum_expected": exp,
           "commit_at": None, "ok": True, "note": ""}
    if quorum != exp:
        rec["ok"] = False
        rec["note"] = f"reported quorum {quorum} != rule {exp}"
    accused = orgs[0]
    prop = requests.post(f"{base}/propose_reinstatement", json={"org": accused}, timeout=20).json()
    pid = prop["proposal_id"]
    for i, org in enumerate(orgs, start=1):
        w = requests.post(f"{base}/witness", json={"proposal_id": pid, "witnessing_org": org}, timeout=20).json()
        expected_committed = i >= quorum
        if w.get("committed") is not expected_committed:
            rec["ok"] = False
            rec["note"] += f" witness {i}/{len(orgs)}: committed={w.get('committed')} expected {expected_committed};"
        if w.get("committed") and rec["commit_at"] is None:
            rec["commit_at"] = i
    if rec["commit_at"] != quorum:
        rec["ok"] = False
        rec["note"] += f" committed at {rec['commit_at']} not {quorum};"
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--stages", default="4,7,8", help="comma-separated organisation counts to test, ascending")
    a = ap.parse_args()
    base = a.url.rstrip("/")
    print(f"=== Quorum sweep over {base} (stages {a.stages}) ===")
    curve, results = [], []
    for n in [int(x) for x in a.stages.split(",")]:
        steps, have = ensure_orgs(base, n)
        if steps is None:
            print(f"stage N={n}: SKIPPED, deployment already has {have} orgs (> {n}); use a fresh revision for the full curve")
            continue
        for cnt, q in steps:
            print(f"  registered org #{cnt}: bus reports quorum_required={q}   (rule says {expected_quorum(cnt)})")
            curve.append((cnt, q, expected_quorum(cnt)))
        rec = test_stage(base, n)
        results.append(rec)
        print(f"stage N={rec['N']}: quorum {rec['quorum_reported']} (rule {rec['quorum_expected']}); "
              f"committed at witness {rec['commit_at']} of {rec['N']}; {'PASS' if rec['ok'] else 'FAIL ' + rec['note']}")
    print("\nSummary (N, quorum, commit at witness, result):")
    for r in results:
        print(f"  N={r['N']:<2} quorum={r['quorum_reported']:<3} commit_at={r['commit_at']}  {'PASS' if r['ok'] else 'FAIL'}")
    bad = [c for c in curve if c[1] is None or int(c[1]) != c[2]]
    print(f"registration curve mismatches vs rule: {len(bad)}")
    ok = bool(results) and all(r["ok"] for r in results) and not bad
    print("QUORUM SWEEP: " + ("PASSED" if ok else "FAILED or nothing tested"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
