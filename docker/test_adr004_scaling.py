"""
docker/test_adr004_scaling.py
==============================
Tests whether PBFT-dynamic's quorum math (federation_ledger.py's
recommended_quorum_for_pbft) behaves as designed once the federation
scales past N=3, over a REAL 5-container Docker network (federation-bus +
org-a..org-e via docker-compose.scale-test.yml), not just the analytical
table in tools/quorum_policy_comparison.py.

THE KEY QUESTION this answers: ARCHITECTURE_DECISIONS_1_3.md and the
changelog both flag "N=3 unanimity has no compensating control for
network partitions" as an open concern. recommended_quorum_for_pbft()'s
own formula says quorum stays at 3 (not N) once N>=4 -- i.e. a federation
with 5 orgs should tolerate ONE org being offline/malicious and still
reach quorum with the remaining 4 (or even 3). This test proves that
live, not just by reading the formula.

Run from the HOST after bringing up the 5-org stack:
  docker compose -f docker/docker-compose.yml -f docker/docker-compose.scale-test.yml up -d --build
"""
import time
from typing import TypedDict

import requests

BUS = "http://localhost:8000"

EXPECTED_QUORUM = {3: 3.0, 4: 3.0, 5: 3.0}  # from recommended_quorum_for_pbft()


class RegistrationStatus(TypedDict):
    registered_orgs: list[str]
    quorum_required: float


class WitnessResult(TypedDict):
    committed: bool


def wait_for_orgs(n: int, timeout: int = 90) -> RegistrationStatus:
    status: RegistrationStatus = {"registered_orgs": [], "quorum_required": 0.0}
    start = time.time()
    while time.time() - start < timeout:
        status = requests.get(f"{BUS}/status", timeout=5).json()
        if len(status["registered_orgs"]) >= n:
            return status
        time.sleep(2)
    raise TimeoutError(f"only {len(status['registered_orgs'])}/{n} orgs registered after {timeout}s")


def main():
    print("Waiting for all 5 orgs (OrgA..OrgE) to register via their containers...")
    status = wait_for_orgs(5)
    orgs = status["registered_orgs"]
    print("Registered orgs:", orgs)
    print("quorum_required:", status["quorum_required"])

    expected = EXPECTED_QUORUM[len(orgs)]
    assert status["quorum_required"] == expected, (
        f"FAIL: expected quorum_required={expected} for {len(orgs)} orgs "
        f"per recommended_quorum_for_pbft(), got {status['quorum_required']}"
    )
    print(f"Confirmed: quorum_required = {expected} for N={len(orgs)} "
          f"(matches recommended_quorum_for_pbft({len(orgs)}) computed live "
          "over the 5-container Docker network, not just in-process).")

    print("\n=== Partition-tolerance test: can 3-of-5 orgs reach quorum "
          "while 2 orgs never witness at all (simulating them being "
          "offline/partitioned)? ===")
    accused = orgs[0]
    prop = requests.post(f"{BUS}/propose_reinstatement",
                          json={"org": accused}, timeout=5).json()
    proposal_id = prop["proposal_id"]
    print("Proposal:", prop)

    # Only 3 of the 5 orgs witness -- the other 2 are treated as
    # unreachable/absent and simply never called.
    witnessing = orgs[:3]
    result: WitnessResult | None = None
    for org in witnessing:
        result = requests.post(f"{BUS}/witness",
                                json={"proposal_id": proposal_id, "witnessing_org": org},
                                timeout=5).json()
        print(f"Witness ({org}):", result)

    if result is None:
        raise RuntimeError("No witness result was returned")

    assert result["committed"] is True, (
        f"FAIL: expected commit at 3-of-5 (quorum={expected}), but "
        f"committed={result['committed']} -- either the quorum value is "
        "wrong or the witness weighting isn't summing as expected."
    )
    print(f"\nConfirmed: quorum reached and committed with only "
          f"{len(witnessing)} of {len(orgs)} orgs witnessing -- "
          f"{len(orgs) - len(witnessing)} orgs' absence (simulating "
          "partition/downtime) did NOT block recovery. This is the "
          "concrete, live answer to the 'N=3 has no compensating control "
          "for partitions' concern: scaling to N=5 buys exactly this "
          "tolerance, without changing any code.")


if __name__ == "__main__":
    main()
