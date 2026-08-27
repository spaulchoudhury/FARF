"""
aws_pilot/cross_cloud_timing_wrapper.py
=========================================
Wraps docker/org_client.py's registration+send flow with explicit timing,
designed to run AS the AWS Fargate task's command -- meaning the timing
happens FROM AWS COMPUTE TO THE GCP-HOSTED BUS, not from a laptop to
either cloud. This is the one number none of the previous pilots could
produce: real inter-cloud (not client-to-cloud) network latency.

Deliberately does NOT modify docker/org_client.py itself -- that file's
evidence chain (used identically in the Docker Compose and Cloud Run
pilots) stays untouched. This is a separate, additive script that
reimplements just enough of org_client.py's registration flow to add
timing instrumentation, reusing the same env vars (FARF_BUS_URL,
FARF_ORG, FARF_PEER_ORG) so it drops into the same container image and
task definition pattern with a one-line command override.

Output goes to stdout, which Fargate's awslogs driver automatically
sends to CloudWatch Logs -- no extra plumbing needed, just fetch the log
group after the task finishes (see AWS_CROSS_CLOUD_STEPS.md Step 5).
"""
import os
import time

import requests

BUS_URL = os.environ.get("FARF_BUS_URL", "http://federation-bus:8000")
ORG = os.environ.get("FARF_ORG", "OrgB")
PEER_ORG = os.environ.get("FARF_PEER_ORG", "OrgA")
N_LATENCY_TRIALS = int(os.environ.get("FARF_N_LATENCY_TRIALS", "50"))


def wait_for_bus(timeout=60):
    print(f"[{ORG}] waiting for federation-bus at {BUS_URL} (cross-cloud, from AWS)...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{BUS_URL}/health", timeout=5)
            if r.status_code == 200:
                print(f"[{ORG}] federation-bus reachable: {r.json()}")
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f"[{ORG}] federation-bus not reachable after {timeout}s "
                        "(cross-cloud from AWS to GCP)")


def main():
    wait_for_bus()

    t0 = time.perf_counter()
    r = requests.post(f"{BUS_URL}/register_org", json={"org": ORG}, timeout=15)
    register_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[{ORG}] registered: {r.json()}  ({register_ms:.3f} ms, AWS->GCP)")

    agent_id = f"{ORG}-executor"
    t0 = time.perf_counter()
    r = requests.post(f"{BUS_URL}/admit_agent",
                       json={"agent_id": agent_id, "org": ORG, "role": "executor"},
                       timeout=15)
    admit_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[{ORG}] admitted {agent_id}: {r.status_code}  ({admit_ms:.3f} ms, AWS->GCP)")

    if PEER_ORG:
        peer_agent = f"{PEER_ORG}-advisor" if not PEER_ORG.endswith("-advisor") else PEER_ORG
        print(f"\n[{ORG}] timing {N_LATENCY_TRIALS} real cross-cloud /send calls "
              f"(AWS compute -> GCP Cloud Run, not laptop -> either cloud)...")
        latencies_ms = []
        errors = 0
        for i in range(N_LATENCY_TRIALS):
            t0 = time.perf_counter()
            r = requests.post(f"{BUS_URL}/send", json={
                "from_agent": agent_id, "from_org": ORG,
                "to_agent": peer_agent, "to_org": PEER_ORG,
                "action_type": "cross_cloud_latency_probe",
                "payload": {"trial": i}, "taint_delta": 0.0,
            }, timeout=15)
            t1 = time.perf_counter()
            if r.status_code != 200:
                errors += 1
                continue
            latencies_ms.append((t1 - t0) * 1000.0)

        if latencies_ms:
            import statistics
            mean = statistics.mean(latencies_ms)
            sd = statistics.pstdev(latencies_ms)
            p50 = statistics.median(latencies_ms)
            p95 = sorted(latencies_ms)[int(0.95 * len(latencies_ms)) - 1]
            print(f"\n=== Real cross-cloud /send latency, AWS->GCP "
                  f"(N={len(latencies_ms)}, errors={errors}) ===")
            print(f"  mean = {mean:.3f} ms   sd = {sd:.3f} ms   "
                  f"p50 = {p50:.3f} ms   p95 = {p95:.3f} ms")
            print("\nCompare against the earlier laptop-origin measurements:")
            print("  Docker bridge (laptop, local):              ~11.69-11.71 ms")
            print("  Cloud Run WAN (laptop -> GCP):                337.839 ms")
            print(f"  Cross-cloud compute (AWS -> GCP, this run):   {mean:.3f} ms")
            print("This is the first number in this project measuring cloud-to-")
            print("cloud latency directly, rather than laptop-to-cloud -- the two")
            print("won't be identical since AWS and GCP regions sit at different")
            print("physical distances from each other than either does from the")
            print("pilot laptop.")
        else:
            print("No successful cross-cloud /send calls -- check FARF_PEER_ORG "
                  "matches an org already registered on the GCP side.")

    print(f"\n[{ORG}] done.")


if __name__ == "__main__":
    main()
