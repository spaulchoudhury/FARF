"""
docker/test_adr004_latency.py
===============================
Measures REAL cross-container HTTP round-trip latency for /send over the
Docker bridge network, and compares it against the in-process baseline
(trust_establishment_latency_ms_mean, ~0.15-0.17ms, from
tests/evaluation_metrics_tab78.py / the N_REPEATS robustness check).

This is a genuinely different measurement, not a re-run of the same
thing: the in-process figure times FederatedTrustProtocol credential
issuance/verification with no network involved at all. This script
times the full HTTP request/response round trip (client -> Docker bridge
-> Flask -> FederationBus.sign_and_send() -> Flask -> Docker bridge ->
client) for an already-admitted agent sending a message, which is the
number that actually matters for "what does crossing an organisational
boundary cost once it's a real network hop instead of a function call."

Run from the HOST after `docker compose -f docker/docker-compose.yml up -d --build`
and after org-a/org-b/org-c have finished their one-shot startup script
(wait ~15s after `up`, or check `docker compose ps` shows them Exited(0)).
"""
import statistics
import time

import requests

BUS = "http://localhost:8000"
N_TRIALS = 200


def main():
    status = requests.get(f"{BUS}/status", timeout=5).json()
    orgs = status["registered_orgs"]
    print("Registered orgs:", orgs)
    if len(orgs) < 2:
        print("Need at least 2 registered orgs (run the normal `docker "
              "compose up` first, which registers OrgA/OrgB/OrgC and "
              "admits their agents).")
        return

    from_org, to_org = orgs[0], orgs[1]
    from_agent = f"{from_org}-executor"
    to_agent = f"{to_org}-advisor"

    print(f"Timing {N_TRIALS} real HTTP /send round trips: "
          f"{from_agent} -> {to_agent} over the Docker bridge network...")

    latencies_ms = []
    errors = 0
    for i in range(N_TRIALS):
        t0 = time.perf_counter()
        r = requests.post(f"{BUS}/send", json={
            "from_agent": from_agent, "from_org": from_org,
            "to_agent": to_agent, "to_org": to_org,
            "action_type": "latency_probe",
            "payload": {"trial": i}, "taint_delta": 0.0,
        }, timeout=5)
        t1 = time.perf_counter()
        if r.status_code != 200:
            errors += 1
            continue
        latencies_ms.append((t1 - t0) * 1000.0)

    if not latencies_ms:
        print("FAIL: no successful requests -- check the bus is up and "
              "the agent names above match a real admitted agent.")
        return

    mean = statistics.mean(latencies_ms)
    sd = statistics.pstdev(latencies_ms) if len(latencies_ms) > 1 else 0.0
    p50 = statistics.median(latencies_ms)
    p95 = sorted(latencies_ms)[int(0.95 * len(latencies_ms)) - 1]

    print(f"\n=== Docker-network /send round-trip latency (N={len(latencies_ms)}, "
          f"errors={errors}) ===")
    print(f"  mean = {mean:.3f} ms")
    print(f"  sd   = {sd:.3f} ms")
    print(f"  p50  = {p50:.3f} ms")
    print(f"  p95  = {p95:.3f} ms")
    print("\nCompare against the in-process baseline "
          "(trust_establishment_latency_ms_mean, ~0.150-0.166ms across "
          "N=20..400 in TAB78_ROBUSTNESS_CHECK_N20_TO_400.md): the ratio "
          "between the two numbers is the real, measured cost of crossing "
          "an actual Docker network socket instead of a same-process "
          "function call -- expect roughly 1-3ms here on a typical "
          "laptop's default bridge network, i.e. one to two orders of "
          "magnitude slower than the in-process figure. That gap is the "
          "genuinely new evidence this test produces; the in-process "
          "number alone couldn't speak to it.")


if __name__ == "__main__":
    main()
