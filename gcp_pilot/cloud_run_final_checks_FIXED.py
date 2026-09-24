"""
gcp_pilot/cloud_run_final_checks.py
=====================================
Two quick, genuinely HTTP-compatible checks against the live Cloud Run
pilot before teardown -- both reuse routes already baked into the
deployed image (docker/bus_service.py's /propose_reinstatement, /witness,
/send), unlike the pentest suite or Tab 7.8 metrics harness, which are
in-process test harnesses with no HTTP layer at all and cannot run
against this deployment without a much larger rewrite.

PART 1 -- Re-runs the quorum correctness check as test_adr004_partition.py
Part 1, but against the real Cloud Run URL instead of local Docker. The
expected commit point is read from the deployed service because
pbft_dynamic uses 3 votes for six organizations, rather than unanimity.

PART 2 -- Real WAN /send round-trip latency, same methodology as
test_adr004_latency.py, but hitting the internet instead of a local
Docker bridge -- a fourth latency data point for
CLOUD_PROVIDER_COMPARISON.md, alongside in-process (~0.158ms), Docker
bridge (~11.7ms), and Cloud KMS AsymmetricSign (~549.5ms).

ADR-019 FIX (this version): PART 2 previously derived from_agent/to_agent
by guessing a naming convention off status["registered_orgs"][0:2].
That field (docker/bus_service.py's /status route) is
`sorted(bus.trust.identities.keys())` -- ALPHABETICALLY sorted, not in
registration order. Against a persistent deployment that has also been
used for other pilot/pentest runs in the same session (whose org names,
e.g. "PT01Org...", "PT08Org<uuid>", sort ahead of or interleave with
"PilotOrgA"/"PilotOrgB" alphabetically), orgs[0]/orgs[1] silently picked
the wrong two orgs, whose agents were never admitted under the guessed
executor/advisor naming pattern at all -- producing "No successful
requests" with no indication of why. This version (a) accepts explicit
--from-agent/--from-org/--to-agent/--to-org so the operator can name the
exact identities a concurrently-run egress_load_test.py actually
admitted, (b) falls back to the previous guess only if not supplied, and
(c) queries /status up front and prints the full registered_orgs list
plus a same-request admission probe result, so a naming mismatch is
reported explicitly rather than surfacing only as a bare zero-successes
message.

Usage:
  python gcp_pilot/cloud_run_final_checks.py --url https://YOUR-SERVICE-URL --n-latency-trials 100
  # or, to be explicit about which identities to use (recommended when
  # other pilot/pentest scripts have run against the same deployment):
  python gcp_pilot/cloud_run_final_checks.py --url https://YOUR-SERVICE-URL \
      --from-agent PilotOrgA-executor --from-org PilotOrgA \
      --to-agent PilotOrgB-advisor --to-org PilotOrgB
"""
import argparse
import statistics
import time

import requests


def part1_quorum_over_cloud_run(base):
    print("\n=== PART 1: Quorum correctness over Cloud Run (real WAN, not local Docker) ===")
    status = requests.get(f"{base}/status", timeout=15).json()
    orgs = status["registered_orgs"]
    print("Currently registered:", orgs)

    # Top up to 3 orgs if the egress test only registered 2.
    if len(orgs) < 3:
        r = requests.post(f"{base}/register_org", json={"org": "PilotOrgC"}, timeout=15)
        print("Registered PilotOrgC:", r.json())
        status = requests.get(f"{base}/status", timeout=15).json()
        orgs = status["registered_orgs"]

    print(f"quorum_required: {status['quorum_required']} for {len(orgs)} orgs")
    accused = orgs[0]
    prop = requests.post(f"{base}/propose_reinstatement", json={"org": accused}, timeout=15).json()
    print("Proposal:", prop)
    proposal_id = prop["proposal_id"]

    quorum_required = int(status["quorum_required"])
    for i, org in enumerate(orgs, start=1):
        w = requests.post(f"{base}/witness",
                           json={"proposal_id": proposal_id, "witnessing_org": org},
                           timeout=15).json()
        print(f"Witness {i}/{len(orgs)} ({org}): {w}")
        expected_committed = i >= quorum_required
        assert w["committed"] is expected_committed, (
            f"FAIL: expected committed={expected_committed} at witness "
            f"{i}/{len(orgs)} with quorum={quorum_required}, got {w['committed']}."
        )
    print("Confirmed: dynamic quorum committed exactly at the configured threshold "
          "over real Cloud Run hosting, not just local Docker. PART 1 PASSED.")


def part2_real_wan_latency(base, n_trials, from_agent=None, from_org=None,
                            to_agent=None, to_org=None):
    print(f"\n=== PART 2: Real WAN /send latency over Cloud Run (N={n_trials}) ===")
    session = requests.Session()   # NEW -- reuse one TCP/TLS connection for the whole run
    status = session.get(f"{base}/status", timeout=15).json()
    orgs = status["registered_orgs"]
    print(f"Currently registered (alphabetically sorted by /status -- NOT "
          f"registration order): {orgs}")

    if from_agent and from_org and to_agent and to_org:
        fa, fo, ta, to = from_agent, from_org, to_agent, to_org
        print(f"Using explicitly supplied identities: {fa}@{fo} -> {ta}@{to}")
    else:
        # Previous fallback guess, kept for backward compatibility when the
        # caller hasn't supplied explicit identities -- but now labelled as
        # a guess, not treated as reliable.
        if len(orgs) < 2:
            print(f"FAIL (setup error): only {len(orgs)} org(s) registered, need at "
                  f"least 2 and no explicit --from-agent/--to-agent given.")
            return
        fo, to = orgs[0], orgs[1]
        fa = f"{fo}-executor" if "executor" not in fo.lower() else fo
        ta = f"{to}-advisor" if "advisor" not in to.lower() else to
        print(f"No explicit identities given -- GUESSING from alphabetically-sorted "
              f"registered_orgs[0:2]: {fa}@{fo} -> {ta}@{to}. This guess is unreliable "
              f"on a deployment shared with other pilot/pentest runs (see module "
              f"docstring, ADR-019). Pass --from-agent/--from-org/--to-agent/--to-org "
              f"explicitly to avoid it.")

    # Explicit admission probe before the timed loop, so a naming mismatch
    # is reported as a clear setup failure, not a silent zero-successes result.
    probe = session.post(f"{base}/send", json={
        "from_agent": fa, "from_org": fo, "to_agent": ta, "to_org": to,
        "action_type": "wan_latency_probe", "payload": {"trial": "admission_probe"},
        "taint_delta": 0.0,
    }, timeout=15)
    probe_json = probe.json() if probe.headers.get("content-type", "").startswith("application/json") else {}
    if probe.status_code != 200 or probe_json.get("decision") == "block":
        print(f"FAIL (setup error): admission probe for {fa}@{fo} -> {ta}@{to} did not "
              f"succeed (status={probe.status_code}, body={probe_json}). These "
              f"identities are not both admitted on this deployment -- re-check which "
              f"agents the concurrently-run load/pentest scripts actually admitted, or "
              f"pass --from-agent/--from-org/--to-agent/--to-org explicitly.")
        return

    latencies_ms = []
    errors = 0
    timeouts = 0
    for i in range(n_trials):
        t0 = time.perf_counter()
        try:
            r = session.post(f"{base}/send", json={
                "from_agent": fa, "from_org": fo, "to_agent": ta, "to_org": to,
                "action_type": "wan_latency_probe", "payload": {"trial": i}, "taint_delta": 0.0,
            }, timeout=20)  # bumped from 15s -- a just-deployed revision needs more margin
        except requests.exceptions.RequestException as e:
            errors += 1
            timeouts += 1
            print(f"  trial {i}: network error ({type(e).__name__}), counted as error, continuing")
            continue
        t1 = time.perf_counter()
        if r.status_code != 200:
            errors += 1
            continue
        latencies_ms.append((t1 - t0) * 1000.0)

    if not latencies_ms:
        print("No successful requests in the timed loop, despite the admission probe "
              "above succeeding -- this indicates a different, intermittent failure "
              "(e.g. rate limiting, or the load generator's traffic itself causing "
              "5xx responses under concurrency), not the identity-mismatch class of "
              "bug this version's admission probe already rules out.")
        return

    mean = statistics.mean(latencies_ms)
    sd = statistics.pstdev(latencies_ms)
    p50 = statistics.median(latencies_ms)
    p95 = sorted(latencies_ms)[int(0.95 * len(latencies_ms)) - 1]
    print(f"\n=== Real WAN /send latency, Cloud Run (N={len(latencies_ms)}, errors={errors}) ===")
    print(f"Network-level failures (not HTTP errors): {timeouts}/{n_trials}")
    print(f"  mean = {mean:.3f} ms   sd = {sd:.3f} ms   p50 = {p50:.3f} ms   p95 = {p95:.3f} ms")
    print("\nFour-point latency comparison for documentation (ONLY the Cloud Run line is measured by this run):")
    print("  in-process (trust_protocol.py):            ~0.150-0.166 ms   [historical constant, not measured here]")
    print("  Docker bridge network (/send):               ~11.69-11.71 ms   [historical constant, not measured here]")
    print(f"  Real Cloud Run WAN (/send, this script):     {mean:.3f} ms   [measured now; new TCP+TLS connection per request]")
    print("  Real Cloud KMS AsymmetricSign:                549.515 ms   [HISTORICAL constant from the us-central1 deployment; "
          "NOT measured here. Use gcp_pilot/kms_latency_probe.py for a current figure]")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--n-latency-trials", type=int, default=100)
    p.add_argument("--from-agent", default=None)
    p.add_argument("--from-org", default=None)
    p.add_argument("--to-agent", default=None)
    p.add_argument("--to-org", default=None)
    p.add_argument("--skip-quorum", action="store_true",
                   help="Run PART 2 (latency) only. Use when measuring latency UNDER LOAD alongside "
                        "the pentest scripts, so PART 1's org/quorum state changes cannot interfere.")
    args = p.parse_args()
    base = args.url.rstrip("/")

    if not args.skip_quorum:
        part1_quorum_over_cloud_run(base)
    part2_real_wan_latency(base, args.n_latency_trials,
                            from_agent=args.from_agent, from_org=args.from_org,
                            to_agent=args.to_agent, to_org=args.to_org)
