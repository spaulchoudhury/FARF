"""
aws_pilot/aws_kms_latency_probe.py
=====================================
ADR-003/ADR-006 cross-cloud pilot: measures REAL AWS KMS signing latency
using an Ed25519 key (key spec ECC_NIST_EDWARDS25519, signing algorithm
ED25519_SHA_512, MessageType=RAW) -- same algorithm as
gcp_pilot/kms_latency_probe.py's GCP key and FARF's own in-process
Ed25519PrivateKey, so all three numbers are a genuine like-for-like
comparison, not different-algorithm approximations.

AWS KMS added native EdDSA/Ed25519 support in November 2025 (previously
only NIST curves were available), which is why this pilot is possible now
and wasn't when ADR-003 was first written.

PREREQUISITES (see aws_pilot/AWS_CROSS_CLOUD_STEPS.md for the full
walkthrough):
  1. AWS CLI installed and configured (`aws configure`) with a user/role
     that has kms:CreateKey, kms:Sign, kms:DescribeKey permissions.
  2. An Ed25519 KMS key already created (AWS_CROSS_CLOUD_STEPS.md Step 2
     has the exact `aws kms create-key` command).
  3. `pip install boto3`

Usage:
  python aws_pilot/aws_kms_latency_probe.py --key-id alias/<farf-prototype>-org-b-key --region us-east-1 --n-trials 100
"""
import argparse
import statistics
import time

import boto3


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--key-id", required=True, help="Key ID, ARN, or alias (alias/...)")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--n-trials", type=int, default=100)
    args = p.parse_args()

    client = boto3.client("kms", region_name=args.region)

    key_desc = client.describe_key(KeyId=args.key_id)
    key_spec = key_desc["KeyMetadata"]["KeySpec"]
    print(f"Key: {args.key_id}  Region: {args.region}  KeySpec: {key_spec}")
    if key_spec != "ECC_NIST_EDWARDS25519":
        print(f"WARNING: expected ECC_NIST_EDWARDS25519, got {key_spec}. "
              "Latency numbers below are still real, but not the "
              "same-algorithm comparison this script is meant to produce.")

    # Warm-up call, excluded from timing -- same rationale as the GCP
    # probe: first call to a key can carry extra cold-path latency.
    t0 = time.perf_counter()
    client.sign(KeyId=args.key_id, Message=b"warmup",
                MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
    warmup_ms = (time.perf_counter() - t0) * 1000.0
    print(f"Warm-up call: {warmup_ms:.3f} ms (excluded from stats below)")

    print(f"\nTiming {args.n_trials} real KMS Sign API calls...")
    latencies_ms = []
    for i in range(args.n_trials):
        payload = f"farf-aws-pilot-trial-{i}".encode()
        t0 = time.perf_counter()
        resp = client.sign(KeyId=args.key_id, Message=payload,
                            MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
        t1 = time.perf_counter()
        assert resp["Signature"], f"trial {i}: empty signature returned"
        latencies_ms.append((t1 - t0) * 1000.0)

    mean = statistics.mean(latencies_ms)
    sd = statistics.pstdev(latencies_ms)
    p50 = statistics.median(latencies_ms)
    p95 = sorted(latencies_ms)[int(0.95 * len(latencies_ms)) - 1]

    print(f"\n=== AWS KMS Sign latency (Ed25519, N={len(latencies_ms)}) ===")
    print(f"  mean = {mean:.3f} ms")
    print(f"  sd   = {sd:.3f} ms")
    print(f"  p50  = {p50:.3f} ms")
    print(f"  p95  = {p95:.3f} ms")
    print("\nFive-point latency comparison for documentation purposes:")
    print("  in-process (trust_protocol.py, no network):        ~0.150-0.166 ms")
    print("  Docker bridge network (/send round trip):          ~11.69-11.71 ms")
    print("  Real Cloud Run WAN (/send, client->us-central1):    337.839 ms")
    print("  Real Google Cloud KMS AsymmetricSign:                549.515 ms")
    print(f"  Real AWS KMS Sign (this script):                     {mean:.3f} ms")
    print("\nNote: this measures client-machine -> AWS KMS regional endpoint")
    print("round trip, same methodology as the GCP KMS probe -- both were run")
    print("from the same laptop, so the comparison between the two KMS numbers")
    print("is apples-to-apples for 'signing latency as experienced by a client")
    print("this geographically distant from both providers' nearest region',")
    print("not a claim about which KMS is inherently faster in general.")


if __name__ == "__main__":
    main()
