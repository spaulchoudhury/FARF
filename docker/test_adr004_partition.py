"""
docker/test_adr004_partition.py
================================
ADR-004 (fail-safe defaults, network-partition-aware) live Docker test.

Run from the HOST machine (not inside a container) against the published
port (docker-compose.yml already publishes federation-bus on localhost:8000).
Requires the stack to be up first: `docker compose -f docker/docker-compose.yml up -d --build`
and the two new routes (/propose_reinstatement, /witness) from
docker/bus_service.py (this session's addition -- see PR notes) to be in
the image you build.

Two things are tested, both genuinely over the Docker network, not mocked:

  PART 1 -- Quorum-witnessed recovery correctly refuses at 2-of-3 and
            only commits at genuine 3-of-3 unanimity (ADR-006's PBFT
            behaviour), driven entirely by real HTTP calls to the running
            federation-bus container.

  PART 2 -- A GENUINELY network-partitioned 4th org (started with
            `--network none`, i.e. no network access at all, not just an
            unreachable hostname) can never register, never gets counted
            in quorum, and fails closed (crashes with a clear error)
            rather than silently corrupting the federation's state.
"""
import subprocess
import sys

import requests

BUS = "http://localhost:8000"


def part1_quorum_witness():
    print("\n=== PART 1: Quorum-witnessed recovery (2-of-3 vs 3-of-3) ===")
    status = requests.get(f"{BUS}/status", timeout=5).json()
    print("Current status:", status)
    orgs = status["registered_orgs"]
    if len(orgs) < 3:
        print("FAIL: expected 3 registered orgs (OrgA, OrgB, OrgC) from the "
              "normal `docker compose up` run -- run that first.")
        sys.exit(1)
    assert status["quorum_required"] == 3.0, \
        f"expected quorum_required=3.0 for 3 orgs (unanimity), got {status['quorum_required']}"
    print(f"Confirmed: quorum_required = 3.0 for {len(orgs)} orgs (PBFT unanimity).")

    accused = orgs[0]
    prop = requests.post(f"{BUS}/propose_reinstatement",
                          json={"org": accused}, timeout=5).json()
    print("Proposal:", prop)
    proposal_id = prop["proposal_id"]

    # Self-witness (accused org attesting for itself) -- must NOT be enough alone
    w1 = requests.post(f"{BUS}/witness",
                        json={"proposal_id": proposal_id, "witnessing_org": accused},
                        timeout=5).json()
    print(f"Witness 1/3 ({accused}, self):", w1)
    assert w1["committed"] is False, "FAIL: committed after only 1 witness -- quorum bypassed!"

    other_orgs = [o for o in orgs if o != accused]
    w2 = requests.post(f"{BUS}/witness",
                        json={"proposal_id": proposal_id, "witnessing_org": other_orgs[0]},
                        timeout=5).json()
    print(f"Witness 2/3 ({other_orgs[0]}):", w2)
    assert w2["committed"] is False, (
        "FAIL: committed at 2-of-3 -- this is exactly the gap the item-1 "
        "quorum swap (legacy static quorum=2) was meant to close. If this "
        "assertion fails, the deployed image is running the OLD quorum "
        "logic, not pbft_dynamic."
    )
    print("Confirmed: 2-of-3 correctly refused (fails closed) -- this is the "
          "live Docker-network proof of the property Table in the changelog "
          "only demonstrated in-process before.")

    w3 = requests.post(f"{BUS}/witness",
                        json={"proposal_id": proposal_id, "witnessing_org": other_orgs[1]},
                        timeout=5).json()
    print(f"Witness 3/3 ({other_orgs[1]}):", w3)
    assert w3["committed"] is True, "FAIL: did not commit at genuine 3-of-3 unanimity"
    print("Confirmed: genuine 3-of-3 unanimity commits. PART 1 PASSED.")


def part2_genuine_partition():
    print("\n=== PART 2: Genuinely network-partitioned 4th org ===")
    before = requests.get(f"{BUS}/status", timeout=5).json()
    print("Status before partition attempt:", before)
    n_before = len(before["registered_orgs"])

    print("Starting a 4th org container with --network none "
          "(no network access at all -- a stronger, more literal partition "
          "than an unreachable hostname)...")
    # Build tag matches docker-compose.yml's default project-name image tag;
    # adjust the image name below if `docker compose images` shows a
    # different tag on your machine.
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "--name", "farf-org-partitioned-test",
         "-e", "FARF_ORG=OrgPartitioned", "-e", "FARF_BUS_URL=http://federation-bus:8000",
         "docker-org-a", "python", "docker/org_client.py"],
        capture_output=True, text=True, timeout=75, check=False,
    )
    print("Container exit code:", result.returncode)
    print("Container stdout (tail):", result.stdout[-500:])
    print("Container stderr (tail):", result.stderr[-500:])

    assert result.returncode != 0, (
        "FAIL: a container with NO network access exited 0 -- it should "
        "have crashed with 'federation-bus not reachable after 60s'."
    )
    assert "not reachable" in (result.stdout + result.stderr), (
        "Exit was non-zero as expected, but the expected timeout message "
        "wasn't seen -- check output above for what actually happened."
    )
    print("Confirmed: the partitioned container could not reach the bus, "
          "crashed with a clear error, and never got to call /register_org.")

    after = requests.get(f"{BUS}/status", timeout=5).json()
    print("Status after partition attempt:", after)
    assert len(after["registered_orgs"]) == n_before, (
        "FAIL: registered_orgs count changed -- the partitioned org "
        "should never have been counted."
    )
    assert "OrgPartitioned" not in after["registered_orgs"]
    print("Confirmed: OrgPartitioned was never registered, quorum_required "
          f"is unchanged at {after['quorum_required']}. PART 2 PASSED.")


if __name__ == "__main__":
    part1_quorum_witness()
    part2_genuine_partition()
    print("\n=== ALL ADR-004 PARTITION TESTS PASSED ===")
