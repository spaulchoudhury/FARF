"""
gcp_pilot/egress_load_test.py
================================
ADR-006 Option 3 pilot: generates real, measurable egress traffic against
the Cloud-Run-hosted federation-bus so the pilot produces an actual GCP
billing line item to compare against CLOUD_PROVIDER_COMPARISON.md's
published-rate-card estimates ($0.12/GB Premium Tier -- see that
document's §2.2), rather than staying purely theoretical.

IMPORTANT: GCP egress billing is not real-time -- costs typically appear
in the Billing Console's cost table with a delay of several hours to a
day, not immediately after this script finishes. Run this script, note
the client-side byte count it reports, then check the Billing Console
the *next day* and compare the two.

Usage:
  python gcp_pilot/egress_load_test.py --url https://YOUR-CLOUD-RUN-URL --n-messages 500
"""
import argparse
import json
import time

import requests


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="Cloud Run service URL, no trailing slash")
    p.add_argument("--n-messages", type=int, default=500)
    args = p.parse_args()

    base = args.url.rstrip("/")

    print("Registering 2 pilot orgs...")
    for org in ["PilotOrgA", "PilotOrgB"]:
        r = requests.post(f"{base}/register_org", json={"org": org}, timeout=10)
        print(f"  {org}: {r.status_code} {r.json()}")

    for agent, org in [("PilotOrgA-executor", "PilotOrgA"), ("PilotOrgB-advisor", "PilotOrgB")]:
        r = requests.post(f"{base}/admit_agent",
                           json={"agent_id": agent, "org": org, "role": "executor"},
                           timeout=10)
        print(f"  admit {agent}: {r.status_code}")

    print(f"\nSending {args.n_messages} messages to generate measurable egress "
          "(each response includes the full federation status payload, "
          "which is the realistic traffic shape for this endpoint)...")

    total_request_bytes = 0
    total_response_bytes = 0
    t_start = time.time()
    errors = 0

    for i in range(args.n_messages):
        payload = {
            "from_agent": "PilotOrgA-executor", "from_org": "PilotOrgA",
            "to_agent": "PilotOrgB-advisor", "to_org": "PilotOrgB",
            "action_type": "pilot_load_test",
            "payload": {"trial": i, "note": "ADR-006 Option 3 egress pilot"},
            "taint_delta": 0.0,
        }
        body = json.dumps(payload).encode()
        r = requests.post(f"{base}/send", data=body,
                           headers={"Content-Type": "application/json"}, timeout=10)
        total_request_bytes += len(body)
        total_response_bytes += len(r.content)
        if r.status_code != 200:
            errors += 1

    elapsed = time.time() - t_start
    total_bytes = total_request_bytes + total_response_bytes

    print(f"\n=== Done in {elapsed:.1f}s, {errors} errors ===")
    print(f"  Client-observed request bytes:  {total_request_bytes:,}")
    print(f"  Client-observed response bytes: {total_response_bytes:,}")
    print(f"  Total (client-side estimate):   {total_bytes:,} bytes "
          f"({total_bytes / 1024 / 1024:.4f} MiB)")
    print("\nThis is a CLIENT-SIDE estimate of traffic volume, not the "
          "actual billed egress figure -- GCP bills egress from Cloud Run's "
          "side (response bytes leaving Google's network to you), and only "
          "the response direction is typically billable egress, not the "
          "request direction. Check the Billing Console tomorrow, filter to "
          "'Cloud Run Network Egress', and compare against "
          f"{total_response_bytes / 1024 / 1024:.4f} MiB response bytes as "
          "the rough expected order of magnitude -- at $0.12/GB (Premium "
          "Tier, CLOUD_PROVIDER_COMPARISON.md §2.2) this predicts a charge "
          f"of roughly ${(total_response_bytes / 1024**3) * 0.12:.6f}, i.e. "
          "likely still inside the free tier for a pilot at this volume. "
          "The point of running this isn't to spend money -- it's to "
          "confirm the actual billed number matches this prediction at "
          "all, which validates (or corrects) the rate-card assumption for "
          "future, larger-scale planning.")


if __name__ == "__main__":
    main()
