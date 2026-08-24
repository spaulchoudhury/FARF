"""
gcp_pilot/kms_latency_probe.py
================================
ADR-006 Option 3 pilot: measures REAL Google Cloud KMS asymmetric-sign
latency using an Ed25519 key (EC_SIGN_ED25519 / `ec-sign-ed25519`) -- the
same algorithm FARF's own DID identities already use in-process
(trust_protocol.py's Ed25519PrivateKey), so this is a like-for-like
latency comparison, not a different-algorithm approximation.

This does NOT wire Cloud KMS into FederationBus/trust_protocol.py itself
-- that would be a much larger, riskier change for a pilot whose whole
point is to de-risk unknowns cheaply first. This script calls the KMS
`AsymmetricSign` API directly and times it, exactly the same methodology
already used for the Docker-network latency test
(test_adr004_latency.py) and the in-process baseline
(TAB78_ROBUSTNESS_CHECK_N20_TO_400.md) -- three comparable numbers by the
end: in-process (~0.15ms) -> Docker bridge (~11.7ms) -> real Cloud KMS
API call (this script).

PREREQUISITES (see gcp_pilot/PILOT_STEPS.md for the full walkthrough):
  1. A GCP project with billing enabled and a budget alert set.
  2. `gcloud auth application-default login` run once on your machine.
  3. A KMS keyring + Ed25519 signing key already created (PILOT_STEPS.md
     Step 2 has the exact `gcloud kms` commands).
  4. `pip install google-cloud-kms`

Usage:
  python gcp_pilot/kms_latency_probe.py \
      --project YOUR_PROJECT_ID \
      --location us-central1 \
      --keyring <farf-prototype>-keyring \
      --key <farf-prototype>-org-a-key \
      --n-trials 100
"""
import argparse
import statistics
import time

from google.cloud import kms


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--project", required=True)
    p.add_argument("--location", default="us-central1")
    p.add_argument("--keyring", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--key-version", default="1")
    p.add_argument("--n-trials", type=int, default=100)
    args = p.parse_args()

    client = kms.KeyManagementServiceClient()
    key_version_name = client.crypto_key_version_path(
        args.project, args.location, args.keyring, args.key, args.key_version
    )
    print(f"Signing against: {key_version_name}")

    # Confirm the key is actually EC_SIGN_ED25519 before timing -- fail
    # loudly rather than silently timing the wrong algorithm.
    key_version = client.get_crypto_key_version(name=key_version_name)
    algo = key_version.algorithm.name
    print(f"Key algorithm: {algo}")
    if algo != "EC_SIGN_ED25519":
        print(f"WARNING: expected EC_SIGN_ED25519, got {algo}. "
              "Latency numbers below are still real, but not the "
              "same-algorithm comparison this script is meant to produce.")

    # Warm-up call (excluded from timing) -- the first call to a KMS key
    # version can include additional cold-path latency (regional routing,
    # first-use checks); excluding it gives a fairer steady-state number,
    # and this is disclosed rather than silently discarded.
    warm_payload = b"warmup"
    t0 = time.perf_counter()
    client.asymmetric_sign(request={"name": key_version_name, "data": warm_payload})
    warmup_ms = (time.perf_counter() - t0) * 1000.0
    print(f"Warm-up call: {warmup_ms:.3f} ms (excluded from stats below)")

    print(f"\nTiming {args.n_trials} real AsymmetricSign API calls...")
    latencies_ms = []
    for i in range(args.n_trials):
        payload = f"<farf-prototype>-trial-{i}".encode()
        t0 = time.perf_counter()
        resp = client.asymmetric_sign(
            request={"name": key_version_name, "data": payload}
        )
        t1 = time.perf_counter()
        assert resp.signature, f"trial {i}: empty signature returned"
        latencies_ms.append((t1 - t0) * 1000.0)

    mean = statistics.mean(latencies_ms)
    sd = statistics.pstdev(latencies_ms)
    p50 = statistics.median(latencies_ms)
    p95 = sorted(latencies_ms)[int(0.95 * len(latencies_ms)) - 1]

    print(f"\n=== Cloud KMS AsymmetricSign latency (Ed25519, N={len(latencies_ms)}) ===")
    print(f"  mean = {mean:.3f} ms")
    print(f"  sd   = {sd:.3f} ms")
    print(f"  p50  = {p50:.3f} ms")
    print(f"  p95  = {p95:.3f} ms")
    print("\nThree-point comparison for documentation purposes:")
    print("  in-process (trust_protocol.py, no network):        ~0.150-0.166 ms")
    print("  Docker bridge network (/send round trip):          ~11.69-11.71 ms")
    print(f"  Real Cloud KMS AsymmetricSign (this script):        {mean:.3f} ms")
    print("\nNote: the KMS number above is API-call latency only (client "
          "machine -> KMS regional endpoint -> back). It does NOT include "
          "the Docker-network hop -- a real signing operation inside a "
          "Cloud-Run-hosted federation-bus would pay both costs (Cloud Run "
          "request latency AND the KMS call latency), roughly additive, "
          "not a replacement for either number above.")


if __name__ == "__main__":
    main()
