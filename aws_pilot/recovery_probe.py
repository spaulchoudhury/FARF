"""
aws_pilot/recovery_probe.py
===========================
Quorum-witnessed recovery on a LIVE bus, after a genuine (detector-driven) organisation quarantine.

1. Reads /status and /fars, and lists the quarantined agents of the organisation.
2. Opens a reinstatement proposal and witnesses it, organisation by organisation in the bus's own
   (alphabetical) order, recording the witness at which it COMMITS. Expected: exactly the quorum-th.
3. Checks that the organisation's agents are no longer quarantined and reads /fars again.
4. Re-admits a fresh agent pair (reinstated agents need a new session by design) and sends three
   messages with taint_delta 0.0, recording each decision. This tests whether the recovery is DURABLE:
   on code that does not reset the org-level detector window, the first message is quarantined again
   with reason org_wide_behavioural_drift.

Exit code: 0 = reinstatement committed at exactly the quorum-th witness and the quarantine was lifted;
           4 = it did not; 5 = nothing to reinstate (the organisation has no quarantined agents).
Durability is reported on its own line (it is a finding, not a pass/fail of the mechanism).

HONEST SCOPE: the bus signs /witness votes with keys it holds itself, so this shows threshold enforcement
and state recovery over real hosting, not independent key custody.
"""
import argparse
import sys
import uuid

import requests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--org", default="PT08Org")
    a = ap.parse_args()
    b = a.url.rstrip("/")
    get = lambda p: requests.get(b + p, timeout=20).json()
    post = lambda p, j: requests.post(b + p, json=j, timeout=20).json()

    st = get("/status")
    orgs = st["registered_orgs"]
    q = int(st["quorum_required"])
    mine = [x for x in st["quarantined_agents"] if x.startswith(a.org + "-")]
    f0 = get("/fars")
    print(f"=== Recovery probe on {b} ===")
    print(f"organisations: {len(orgs)}   quorum_required: {q}   quarantined agents of {a.org}: {len(mine)}")
    print(f"FARS before: {f0['FARS']}   trust_health: {f0['components']['trust_health']}")
    if not mine:
        print(f"NOTHING TO REINSTATE: {a.org} has no quarantined agents.")
        sys.exit(5)

    pid = post("/propose_reinstatement", {"org": a.org})["proposal_id"]
    commit_at, _early = None, False
    for i, o in enumerate(orgs, start=1):
        w = post("/witness", {"proposal_id": pid, "witnessing_org": o})
        if w.get("committed"):
            commit_at = i
            break
    print(f"reinstatement committed at witness {commit_at} of {len(orgs)} (quorum {q})")
    ok_commit = commit_at == q

    st2 = get("/status")
    left = [x for x in st2["quarantined_agents"] if x.startswith(a.org + "-")]
    f1 = get("/fars")
    lifted = len(left) == 0
    print(f"quarantined agents of {a.org} after the commit: {len(left)}   (lifted: {'yes' if lifted else 'no'})")
    print(f"FARS after:  {f1['FARS']}   trust_health: {f1['components']['trust_health']}")

    try:
        timing = get("/resilience_timing")["recovery_time"]
        this_org_recovery_seconds = None
        for record in timing.get("completed", []) if isinstance(timing.get("completed"), list) else []:
            if record.get("key") == a.org:
                this_org_recovery_seconds = record["duration_seconds"]
        if this_org_recovery_seconds is not None:
            print(f"recovery time (quarantine -> reinstatement) for {a.org}: {this_org_recovery_seconds}s")
        print(f"recovery-time stats, all orgs/agents this bus revision: {timing}")
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        # /resilience_timing is new instrumentation, added after the reinstatement logic above. A problem
        # fetching it (endpoint missing on this image, transient network issue, unexpected shape) must never
        # turn a SUCCESSFUL reinstatement -- already confirmed and printed above -- into a reported failure.
        print(f"[warn] /resilience_timing unavailable on this deployment ({exc}); MTTR not recorded for this run, "
              f"but the reinstatement result above is unaffected.")

    tag = uuid.uuid4().hex[:6]
    adv, exe = f"{a.org}-rec{tag}-advisor", f"{a.org}-rec{tag}-executor"
    for ag, role in ((adv, "advisor"), (exe, "executor")):
        requests.post(b + "/admit_agent", json={"agent_id": ag, "org": a.org, "role": role, "base_privilege": 0.1}, timeout=20)
    decisions = []
    for k in range(1, 4):
        r = post("/send", {"from_agent": adv, "from_org": a.org, "to_agent": exe, "to_org": a.org,
                           "action_type": "memory_recall_forward",
                           "payload": {"requested_privilege": 0.1, "attempts_system_override": False},
                           "taint_delta": 0.0})
        decisions.append((r.get("decision"), r.get("reason")))
        print(f"message {k} after re-admission (taint_delta 0.0): {r.get('decision')} / {r.get('reason')}")
    durable = decisions[0][0] == "allow"
    print("\nRESULT")
    print(f"  quorum reinstatement: {'PASS' if ok_commit else 'FAIL'} (committed at witness {commit_at}, quorum {q})")
    print(f"  quarantine lifted:    {'PASS' if lifted else 'FAIL'}")
    if durable:
        print("  durability:           DURABLE (the reinstated organisation can send again)")
    else:
        print("  durability:           NOT DURABLE (the first message after re-admission was "
              f"{decisions[0][0]} / {decisions[0][1]}; the org-level detector window was not reset by the reinstatement)")
    sys.exit(0 if (ok_commit and lifted) else 4)


if __name__ == "__main__":
    main()
