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

Usage:
  python gcp_pilot/cloud_run_final_checks.py --url https://YOUR-SERVICE-URL --n-latency-trials 100
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


def part2_real_wan_latency(base, n_trials):
    print(f"\n=== PART 2: Real WAN /send latency over Cloud Run (N={n_trials}) ===")
    status = requests.get(f"{base}/status", timeout=15).json()
    orgs = status["registered_orgs"]
    from_org, to_org = orgs[0], orgs[1]
    from_agent = f"{from_org}-executor" if "executor" not in from_org.lower() else from_org
    to_agent = f"{to_org}-advisor" if "advisor" not in to_org.lower() else to_org
    # Fall back to the exact agent names the egress test admitted, if present
    candidates = [(f"{orgs[0]}-executor", orgs[0], f"{orgs[1]}-advisor", orgs[1])]

    latencies_ms = []
    errors = 0
    for i in range(n_trials):
        fa, fo, ta, to = candidates[0]
        t0 = time.perf_counter()
        r = requests.post(f"{base}/send", json={
            "from_agent": fa, "from_org": fo, "to_agent": ta, "to_org": to,
            "action_type": "wan_latency_probe", "payload": {"trial": i}, "taint_delta": 0.0,
        }, timeout=15)
        t1 = time.perf_counter()
        if r.status_code != 200:
            errors += 1
            continue
        latencies_ms.append((t1 - t0) * 1000.0)

    if not latencies_ms:
        print("No successful requests -- check agent names match what was admitted "
              "(the egress_load_test.py run admits PilotOrgA-executor / PilotOrgB-advisor).")
        return

    mean = statistics.mean(latencies_ms)
    sd = statistics.pstdev(latencies_ms)
    p50 = statistics.median(latencies_ms)
    p95 = sorted(latencies_ms)[int(0.95 * len(latencies_ms)) - 1]
    print(f"\n=== Real WAN /send latency, Cloud Run (N={len(latencies_ms)}, errors={errors}) ===")
    print(f"  mean = {mean:.3f} ms   sd = {sd:.3f} ms   p50 = {p50:.3f} ms   p95 = {p95:.3f} ms")
    print("\nFour-point latency comparison for documentation:")
    print("  in-process (trust_protocol.py):            ~0.150-0.166 ms")
    print("  Docker bridge network (/send):               ~11.69-11.71 ms")
    print(f"  Real Cloud Run WAN (/send, this script):     {mean:.3f} ms")
    print("  Real Cloud KMS AsymmetricSign:                549.515 ms")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--n-latency-trials", type=int, default=100)
    args = p.parse_args()
    base = args.url.rstrip("/")

    part1_quorum_over_cloud_run(base)
    part2_real_wan_latency(base, args.n_latency_trials)
    print("\n=== ALL CLOUD RUN FINAL CHECKS COMPLETE ===")
    print("Now safe to tear down: gcloud run services delete <farf-prototype>-bus --region=us-central1 --quiet")
