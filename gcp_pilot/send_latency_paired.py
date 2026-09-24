"""
gcp_pilot/send_latency_paired.py
================================
Paired /send latency: FRESH connection per request versus a KEPT-ALIVE connection, interleaved
request by request so slow drift in the network path affects both equally.

WHY (audit finding): Chapter 6 Section 6.5.1 compares /send (measured with requests.post, i.e. a
new TCP+TLS handshake on every call) with Cloud KMS AsymmetricSign (measured through the Google
client library, i.e. one long-lived gRPC channel). Those two figures differ in connection
handling as well as in what they measure, so their ORDER (which is larger) is confounded. The
keep-alive column here is the like-for-like counterpart of the KMS probe. Run
gcp_pilot/kms_latency_probe.py from the same machine straight afterwards.

Usage:
  python gcp_pilot/send_latency_paired.py --url https://BUS --n 200 \
     --from-agent PilotOrgA-executor --from-org PilotOrgA --to-agent PilotOrgB-advisor --to-org PilotOrgB
"""
import argparse
import statistics
import time

import requests


def stats(v):
    v = sorted(v)
    n = len(v)
    pc = lambda q: v[min(n - 1, max(0, round(q * n + 0.5) - 1))]
    return (f"n={n} mean={statistics.mean(v):.1f} ms sd={statistics.pstdev(v):.1f} "
            f"p50={pc(0.5):.1f} p95={pc(0.95):.1f} min={v[0]:.1f} max={v[-1]:.1f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--from-agent", default="PilotOrgA-executor")
    ap.add_argument("--from-org", default="PilotOrgA")
    ap.add_argument("--to-agent", default="PilotOrgB-advisor")
    ap.add_argument("--to-org", default="PilotOrgB")
    a = ap.parse_args()
    base = a.url.rstrip("/")

    # (Re)admit the two identities: the bus's admission credential lasts 300 s.
    for org in sorted({a.from_org, a.to_org}):
        requests.post(f"{base}/register_org", json={"org": org}, timeout=20).raise_for_status()
    for agent, org, role in [(a.from_agent, a.from_org, "executor"), (a.to_agent, a.to_org, "advisor")]:
        requests.post(f"{base}/admit_agent", json={"agent_id": agent, "org": org, "role": role,
                                                    "base_privilege": 0.1}, timeout=20).raise_for_status()
    body = {"from_agent": a.from_agent, "from_org": a.from_org, "to_agent": a.to_agent, "to_org": a.to_org,
            "action_type": "latency_paired_probe", "payload": {"probe": True}, "taint_delta": 0.0}

    sess = requests.Session()
    for _ in range(3):                                   # establish + warm the kept-alive connection
        sess.post(f"{base}/send", json=body, timeout=20)
    requests.post(f"{base}/send", json=body, timeout=20)  # one discarded fresh call

    def one(kind):
        t0 = time.perf_counter()
        r = (sess if kind == "keep" else requests).post(f"{base}/send", json=body, timeout=20)
        ms = (time.perf_counter() - t0) * 1000.0
        ok = r.status_code == 200 and r.json().get("decision") == "allow"
        return ms, ok

    fresh, keep, err = [], [], 0
    for i in range(a.n):
        order = ("fresh", "keep") if i % 2 == 0 else ("keep", "fresh")
        for kind in order:
            ms, ok = one(kind)
            if not ok:
                err += 1
                continue
            (fresh if kind == "fresh" else keep).append(ms)

    print(f"\n=== Paired /send latency (N={a.n} pairs, errors={err}) ===")
    print(f"  fresh connection per request : {stats(fresh)}")
    print(f"  kept-alive connection        : {stats(keep)}")
    d = statistics.mean(fresh) - statistics.mean(keep)
    print(f"  mean connection-setup cost   : {d:.1f} ms  (fresh minus kept-alive)")
    print("Compare the kept-alive line with the Cloud KMS AsymmetricSign figure measured from the SAME machine.")


if __name__ == "__main__":
    main()
