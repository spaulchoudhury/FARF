"""
docker/org_client.py
======================
Runs inside each per-organisation container (org-a, org-b, org-c in
docker-compose.yml). Talks to the `federation-bus` container exclusively
over HTTP -- this container never imports FederationBus or any other
FARF artefact directly, and has no in-process access to another
organisation's agents or credentials. This is the property that makes
this a genuine multi-container deployment rather than the in-process
namespace simplification disclosed in Chapter 4 Section 4.6: crossing an
organisational boundary here means crossing a real Docker network
socket, not a Python function call within one process.
"""
import os
import time
import sys
import requests

BUS_URL = os.environ.get("FARF_BUS_URL", "http://federation-bus:8000")
ORG = os.environ.get("FARF_ORG", "OrgA")
PEER_ORG = os.environ.get("FARF_PEER_ORG", "")
ROLE_SUFFIX = {"advisor": 0.2, "executor": 0.1}


def wait_for_bus(timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{BUS_URL}/health", timeout=2)
            if r.status_code == 200:
                print(f"[{ORG}] federation-bus reachable: {r.json()}", flush=True)
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError(f"[{ORG}] federation-bus not reachable after {timeout}s")


def register_and_admit():
    requests.post(f"{BUS_URL}/register_org", json={"org": ORG}, timeout=5).raise_for_status()
    agents = {}
    for role, priv in ROLE_SUFFIX.items():
        agent_id = f"{ORG}-{role}"
        r = requests.post(f"{BUS_URL}/admit_agent",
                           json={"agent_id": agent_id, "org": ORG, "role": role, "base_privilege": priv},
                           timeout=5)
        r.raise_for_status()
        result = r.json()
        assert result["valid"], f"[{ORG}] admission failed for {agent_id}: {result}"
        agents[role] = agent_id
        print(f"[{ORG}] admitted {agent_id}: {result}", flush=True)

    requests.post(f"{BUS_URL}/delegate",
                  json={"from_agent": agents["advisor"], "to_agent": agents["executor"], "privilege": 0.4},
                  timeout=5).raise_for_status()
    return agents


def send_signed_message(agents, to_org):
    r = requests.post(f"{BUS_URL}/send", json={
        "from_agent": agents["executor"], "from_org": ORG,
        "to_agent": f"{to_org}-advisor", "to_org": to_org,
        "action_type": "cross_org_status_check",
        "payload": {"note": f"container-to-container message from {ORG} to {to_org}"},
        "taint_delta": 0.0,
    }, timeout=5)
    r.raise_for_status()
    print(f"[{ORG}] -> {to_org}: {r.json()}", flush=True)
    return r.json()


def main():
    wait_for_bus()
    agents = register_and_admit()
    if PEER_ORG:
        # give the peer org's container a moment to register/admit too
        time.sleep(3)
        send_signed_message(agents, PEER_ORG)
    fars = requests.get(f"{BUS_URL}/fars", timeout=5).json()
    status = requests.get(f"{BUS_URL}/status", timeout=5).json()
    print(f"[{ORG}] federation FARS after this container's actions: {fars}", flush=True)
    print(f"[{ORG}] federation status: {status}", flush=True)


if __name__ == "__main__":
    main()
    # keep the container alive briefly so `docker compose logs` is easy to read
    time.sleep(5)
    sys.exit(0)
