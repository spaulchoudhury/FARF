$cold = Get-Content .\lambda-out-cold.json -Raw | ConvertFrom-Json
$cold.body | ConvertFrom-Json | ConvertTo-Json -Depth 10"""
aws_pilot/lambda_agent_worker.py
====================================
ADR-011 gap fix: the pilot's OrgB ran on AWS Fargate, but ADR-011's
service-mapping table names AWS Lambda for "stateless agent workers
(Advisor/Executor)" specifically -- Fargate is ADR-011's row for
"relay/orchestration," a different service for a different workload
shape. This handler exercises the actual row ADR-011 names, so that
row's cost/cold-start numbers stop being unverified-by-substitution.

Deliberately reuses the exact same three HTTP calls docker/org_client.py
already makes (register_org -> admit_agent -> send) against the
GCP-hosted federation-bus, so the comparison against the Fargate/Docker
numbers already measured is apples-to-apples: same bus, same payload
shape, same three-call sequence, only the AWS-side compute primitive
changes (Lambda invocation vs. a long-lived Fargate task).

Deploy as a Lambda function (see AWS_CROSS_CLOUD_STEPS.md Step 12) with
environment variables:
  FARF_BUS_URL   - the GCP Cloud Run federation-bus URL
  FARF_ORG       - e.g. "PilotOrgB-Lambda"
  FARF_PEER_ORG  - e.g. "PilotOrgA" (must already be registered)

The `requests` library isn't in the default Lambda Python runtime --
package it in the deployment zip (see Step 12's `pip install -t`
command) or use a Lambda Layer.
"""
import json
import os
import time

import requests

BUS_URL = os.environ.get("FARF_BUS_URL", "")
ORG = os.environ.get("FARF_ORG", "PilotOrgB-Lambda")
PEER_ORG = os.environ.get("FARF_PEER_ORG", "PilotOrgA")


def handler(event, context):
    """
    Lambda entry point. Runs the same register -> admit -> send sequence
    as docker/org_client.py's main(), timing each HTTP call separately
    so cold-start overhead (visible only on the first invocation after a
    deploy or a scale-to-zero gap) is distinguishable from steady-state
    per-call latency in the returned JSON.
    """
    if not BUS_URL:
        return {"statusCode": 500, "body": json.dumps({"error": "FARF_BUS_URL not set"})}

    timings = {}
    t_start = time.time()

    t0 = time.time()
    r = requests.post(f"{BUS_URL}/register_org", json={"org": ORG}, timeout=10)
    timings["register_org_ms"] = (time.time() - t0) * 1000
    register_result = r.json()

    agent_id = f"{ORG}-executor"
    t0 = time.time()
    r = requests.post(f"{BUS_URL}/admit_agent", json={
        "agent_id": agent_id, "org": ORG, "role": "executor", "base_privilege": 0.1,
    }, timeout=10)
    timings["admit_agent_ms"] = (time.time() - t0) * 1000
    admit_result = r.json()

    t0 = time.time()
    r = requests.post(f"{BUS_URL}/send", json={
        "from_agent": agent_id, "from_org": ORG,
        "to_agent": f"{PEER_ORG}-advisor", "to_org": PEER_ORG,
        "action_type": "cross_org_status_check",
        "payload": {"note": f"Lambda invocation from {ORG} to {PEER_ORG}"},
        "taint_delta": 0.0,
    }, timeout=10)
    timings["send_ms"] = (time.time() - t0) * 1000
    send_result = r.json()

    timings["total_wall_clock_ms"] = (time.time() - t_start) * 1000

    # Lambda's own /proc/uptime-based cold-start heuristic: if this
    # container's uptime is close to the total execution time so far,
    # this is very likely a cold start (fresh execution environment).
    # Not authoritative (Lambda doesn't expose a direct cold-start flag
    # to handler code) but a reasonable, disclosed proxy -- report it as
    # a heuristic, not a certainty.
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
        likely_cold_start = uptime_seconds < 5.0
    except Exception:
        uptime_seconds = None
        likely_cold_start = None

    return {
        "statusCode": 200,
        "body": json.dumps({
            "org": ORG, "peer_org": PEER_ORG,
            "timings_ms": timings,
            "register_result": register_result,
            "admit_result": admit_result,
            "send_result": send_result,
            "container_uptime_seconds": uptime_seconds,
            "likely_cold_start": likely_cold_start,
        }),
    }
