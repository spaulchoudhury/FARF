"""
aws_pilot/adr004_partition_client.py
========================================
ADR-004 gap fix: the ADR-004 "Live Docker Verification" only tested a
single-host Docker network partition (`docker network disconnect`).
That's real evidence, but not the case ADR-004 actually names: "cross-
cloud network partition is its own explicit failure mode" -- a genuine
AWS<->GCP internet-path partition, not a container bridge.

docker/org_client.py (and the AWS Fargate variant that reused it) is
one-shot: register, send once, exit. That's not useful for a mid-task
partition test, since there's no "mid" to interrupt. This script is the
same registration flow, but then LOOPS a /send call every
FARF_LOOP_INTERVAL_SECONDS for FARF_LOOP_ITERATIONS iterations, logging
every attempt's outcome (success / timeout / connection error) with a
timestamp -- so a real partition, introduced mid-loop by revoking this
task's security group's outbound rule (from the operator's laptop, via
the AWS CLI -- see AWS_CROSS_CLOUD_STEPS.md Step 13), shows up as a
clean, timestamped block-then-recover window in CloudWatch Logs.

Every line is also a legitimate log-format check for ADR-007's JSON
logging fix -- if FARF_LOG_FORMAT=json was set on the redeployed bus,
these client-side lines (which use plain print(), not farf_logging.py,
since org_client.py never imported it either) are still human-readable
text; only the BUS's own log lines are affected by that env var, which
is the correct scope for that fix.

Deploy env vars (same names as docker/org_client.py, plus two new ones):
  FARF_BUS_URL              - the GCP Cloud Run federation-bus URL
  FARF_ORG                  - e.g. "PilotOrgB-Partition"
  FARF_PEER_ORG              - e.g. "PilotOrgA"
  FARF_LOOP_INTERVAL_SECONDS - default 5
  FARF_LOOP_ITERATIONS       - default 24 (2 minutes at the default interval --
                                long enough to comfortably fit a manual
                                revoke/wait/restore sequence in the middle)
"""
import json
import os
import sys
import time

import requests

BUS_URL = os.environ.get("FARF_BUS_URL", "http://federation-bus:8000")
ORG = os.environ.get("FARF_ORG", "PilotOrgB-Partition")
PEER_ORG = os.environ.get("FARF_PEER_ORG", "PilotOrgA")
LOOP_INTERVAL = float(os.environ.get("FARF_LOOP_INTERVAL_SECONDS", "5"))
LOOP_ITERATIONS = int(os.environ.get("FARF_LOOP_ITERATIONS", "24"))


def log_line(payload: dict):
    """One JSON object per line to stdout -- CloudWatch's awslogs driver
    captures this as-is, and the timestamp field is what lets you line
    up 'send started failing' / 'send started succeeding again' against
    exactly when you ran the revoke/restore commands."""
    payload["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(json.dumps(payload), flush=True)


def wait_for_bus(timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{BUS_URL}/health", timeout=3)
            if r.status_code == 200:
                log_line({"event": "bus_reachable", "org": ORG, "health": r.json()})
                return True
        except requests.exceptions.RequestException as e:
            log_line({"event": "bus_not_yet_reachable", "org": ORG, "error": str(e)})
        time.sleep(2)
    raise RuntimeError(f"[{ORG}] federation-bus not reachable after {timeout}s")


def register_and_admit():
    requests.post(f"{BUS_URL}/register_org", json={"org": ORG}, timeout=10).raise_for_status()
    agent_id = f"{ORG}-executor"
    r = requests.post(f"{BUS_URL}/admit_agent", json={
        "agent_id": agent_id, "org": ORG, "role": "executor", "base_privilege": 0.1,
    }, timeout=10)
    r.raise_for_status()
    result = r.json()
    assert result["valid"], f"[{ORG}] admission failed: {result}"
    log_line({"event": "registered_and_admitted", "org": ORG, "agent_id": agent_id})
    return agent_id


def main():
    wait_for_bus()
    agent_id = register_and_admit()

    log_line({"event": "loop_start", "org": ORG, "iterations": LOOP_ITERATIONS,
               "interval_seconds": LOOP_INTERVAL,
               "instructions": "Revoke this task's security group's outbound rule "
                                "partway through this loop, wait a few iterations, "
                                "then restore it -- see AWS_CROSS_CLOUD_STEPS.md Step 13."})

    outcomes = {"success": 0, "timeout": 0, "connection_error": 0, "other_error": 0}

    for i in range(LOOP_ITERATIONS):
        t0 = time.time()
        try:
            r = requests.post(f"{BUS_URL}/send", json={
                "from_agent": agent_id, "from_org": ORG,
                "to_agent": f"{PEER_ORG}-advisor", "to_org": PEER_ORG,
                "action_type": "cross_org_status_check",
                "payload": {"note": f"partition-test iteration {i}"},
                "taint_delta": 0.0,
            }, timeout=8)
            elapsed_ms = (time.time() - t0) * 1000
            result = r.json()
            outcomes["success"] += 1
            log_line({"event": "send_attempt", "iteration": i, "outcome": "success",
                       "elapsed_ms": round(elapsed_ms, 1), "decision": result.get("decision"),
                       "org": ORG})
        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - t0) * 1000
            outcomes["timeout"] += 1
            log_line({"event": "send_attempt", "iteration": i, "outcome": "timeout",
                       "elapsed_ms": round(elapsed_ms, 1), "org": ORG,
                       "note": "fail-closed: no message reached the bus, nothing to roll back"})
        except requests.exceptions.ConnectionError as e:
            elapsed_ms = (time.time() - t0) * 1000
            outcomes["connection_error"] += 1
            log_line({"event": "send_attempt", "iteration": i, "outcome": "connection_error",
                       "elapsed_ms": round(elapsed_ms, 1), "org": ORG, "error": str(e)[:200],
                       "note": "fail-closed: no message reached the bus, nothing to roll back"})
        except Exception as e:
            outcomes["other_error"] += 1
            log_line({"event": "send_attempt", "iteration": i, "outcome": "other_error",
                       "org": ORG, "error": str(e)[:200]})

        time.sleep(LOOP_INTERVAL)

    log_line({"event": "loop_complete", "org": ORG, "outcomes": outcomes,
               "summary": (
                   f"{outcomes['success']} succeeded, "
                   f"{outcomes['timeout'] + outcomes['connection_error']} failed closed "
                   f"(timeout/connection_error -- expected during the revoked window), "
                   f"{outcomes['other_error']} other errors (should be 0)"
               )})

    if outcomes["other_error"] > 0:
        log_line({"event": "unexpected_error_present", "org": ORG,
                   "note": "other_error should be 0 -- any non-network exception here is "
                            "a genuine bug, not expected partition behaviour"})
        sys.exit(1)


if __name__ == "__main__":
    main()
