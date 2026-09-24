"""
aws_pilot/adr010_boundary_probe_v2.py
========================================
Extends adr010_boundary_probe.py with the adversarial mismatch case
(TEST_PROTOCOL.md Section 6.4 / 6.2 "Not yet covered by this script").

The original script only sent resource_hash_at_check == resource_hash_at_use
("h1"/"h1") and confirmed decision=allow. That proves the re-verification
mechanism instruments and logs correctly across the AWS<->GCP boundary,
but not that it actually catches a real cross-provider tampering attempt
-- the more consequential claim.

v2 sends BOTH cases in one run:
  Case 1 (non-tampered): resource_hash_at_check == resource_hash_at_use
    -> expected decision=allow, reason=no_violation
  Case 2 (adversarial):  resource_hash_at_check != resource_hash_at_use
    -> expected decision=block,
       reason=toctou_resource_mismatch   <-- NOT "toctou_violation"; that
       name was an error in an earlier draft of this thesis's own
       documentation, corrected here after actually reading
       orchestration.py's PolicyOrchestrator.rules list, where the rule
       is registered as PolicyRule(name="toctou_resource_mismatch", ...).

Both cases also cross the org boundary (from_org != to_org) and use
action_type="execute_action", so both should independently trigger
orchestration.py's cross_boundary_toctou_reverification log line
(logged unconditionally for any TOCTOU-relevant action_type crossing an
org boundary, regardless of whether the rule below blocks it) --
confirm this by checking BOTH requests' timestamps appear as separate
cross_boundary_toctou_reverification entries in GCP's own log stream
(PS step below), not just one.
"""
import os
import sys

import requests

bus_url = os.environ["FARF_BUS_URL"]
org = os.environ["FARF_ORG"]
agent_id = f"{org}-executor"

print(f"=== ADR-010 boundary probe v2 (org={org}) ===")

requests.post(f"{bus_url}/register_org", json={"org": org}, timeout=15).raise_for_status()
requests.post(f"{bus_url}/admit_agent", json={
    "agent_id": agent_id, "org": org, "role": "executor", "base_privilege": 0.1,
}, timeout=15).raise_for_status()

results = {}

print("\n--- Case 1: non-tampered (resource_hash_at_check == resource_hash_at_use) ---")
r1 = requests.post(f"{bus_url}/send", json={
    "from_agent": agent_id, "from_org": org,
    "to_agent": "PilotOrgA-advisor", "to_org": "PilotOrgA",
    "action_type": "execute_action",
    "payload": {"resource_hash_at_check": "h1", "resource_hash_at_use": "h1"},
    "taint_delta": 0.0,
}, timeout=15)
print(r1.status_code, r1.text)
results["case1_no_tamper"] = r1.json()

print("\n--- Case 2: adversarial mismatch (resource_hash_at_check != resource_hash_at_use) ---")
r2 = requests.post(f"{bus_url}/send", json={
    "from_agent": agent_id, "from_org": org,
    "to_agent": "PilotOrgA-advisor", "to_org": "PilotOrgA",
    "action_type": "execute_action",
    "payload": {"resource_hash_at_check": "h1_original", "resource_hash_at_use": "h2_tampered"},
    "taint_delta": 0.0,
}, timeout=15)
print(r2.status_code, r2.text)
results["case2_adversarial_mismatch"] = r2.json()

case1_ok = (results["case1_no_tamper"].get("decision") == "allow"
            and results["case1_no_tamper"].get("reason") == "no_violation")
case2_ok = (results["case2_adversarial_mismatch"].get("decision") == "block"
            and results["case2_adversarial_mismatch"].get("reason") == "toctou_resource_mismatch")

print("\n=== Verdict ===")
print(f"Case 1 (no tamper -> allow/no_violation):            {'PASS' if case1_ok else 'FAIL'}  {results['case1_no_tamper']}")
print(f"Case 2 (tamper -> block/toctou_resource_mismatch):   {'PASS' if case2_ok else 'FAIL'}  {results['case2_adversarial_mismatch']}")

if case1_ok and case2_ok:
    print("\nCROSS-CLOUD TOCTOU RE-VERIFICATION: CONFIRMED for both the "
          "non-tampered and the adversarial-mismatch path. Next: confirm "
          "via 'gcloud logging read' that TWO separate "
          "cross_boundary_toctou_reverification entries appear in GCP's "
          "own log stream (one per case above), not just one.")
    sys.exit(0)
else:
    print("\nINCOMPLETE: at least one case did not match the expected "
          "decision/reason -- do not report cross-boundary adversarial "
          "detection as confirmed.")
    sys.exit(1)
