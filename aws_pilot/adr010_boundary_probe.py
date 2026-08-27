import os
import requests

bus_url = os.environ["FARF_BUS_URL"]
org = os.environ["FARF_ORG"]
agent_id = f"{org}-executor"

requests.post(
    f"{bus_url}/register_org",
    json={"org": org},
    timeout=15,
).raise_for_status()

admitted = requests.post(
    f"{bus_url}/admit_agent",
    json={
        "agent_id": agent_id,
        "org": org,
        "role": "executor",
        "base_privilege": 0.1,
    },
    timeout=15,
)
admitted.raise_for_status()

response = requests.post(
    f"{bus_url}/send",
    json={
        "from_agent": agent_id,
        "from_org": org,
        "to_agent": "PilotOrgA-advisor",
        "to_org": "PilotOrgA",
        "action_type": "execute_action",
        "payload": {
            "resource_hash_at_check": "h1",
            "resource_hash_at_use": "h1",
        },
        "taint_delta": 0.0,
    },
    timeout=15,
)

print(response.status_code)
print(response.text)
response.raise_for_status()
