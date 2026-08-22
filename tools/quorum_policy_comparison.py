"""
tools/quorum_policy_comparison.py -- v7.9.10

Supervisor-directed comparison (Decision #1, Option B: "Fix + re-run as
a comparison"): legacy static quorum default (quorum_required=2,
frozen regardless of federation size) vs. the new pbft_dynamic mode
(quorum_required = FederationLedger.recommended_quorum_for_pbft(n),
recomputed on every org join -- see federation_bus.py's
_recompute_quorum()).

WHY THIS IS NOT A MONTE-CARLO / REPEATED-TRIALS COMPARISON (unlike the
Tab 7.8 statistics or the FARS sensitivity sweep): both dimensions
measured below are DETERMINISTIC, closed-form functions of N (org
count) and stake weights, not stochastic outcomes. Running 20 seeded
repeats of a quantity that's the same every time would be statistical
theater, not rigor -- descriptive_statistics() from stats_utils.py is
deliberately NOT used here. What replaces it: (1) the closed-form
result is derived analytically for N=2..10, AND (2) that formula is
cross-checked against the REAL FederationLedger/FederationBus code
actually running the witness/reinstatement flow for N=3 and N=4, so
the comparison isn't just arithmetic on paper -- see
`empirical_cross_check()`.

TWO DIMENSIONS MEASURED, DELIBERATELY BOTH -- NOT JUST THE ONE THAT
FAVOURS THE SWAP:

  1. SECURITY: minimum number of colluding orgs (including the accused
     itself) needed to falsely clear a federation-wide quarantine when
     the OTHER orgs are honest and refuse to witness. Higher = better
     (harder for a dishonest minority to force a false clear).

  2. AVAILABILITY: minimum number of orgs that must be online and
     willing to witness for a LEGITIMATE clear to succeed when every
     org is honest and cooperating, i.e. how many can be down/
     partitioned before recovery is blocked. Lower quorum = more
     availability headroom under partition; this is exactly the
     "N=3 unanimity has no compensating control for real-world network
     partitions" concern already flagged in ARCHITECTURE_DECISIONS_1.md
     and PHASE1_TO_CLOUD_DECISION_BRIEF.md \u00a72 item 21 -- this script
     turns that qualitative concern into a quantified number instead of
     leaving it as a general worry.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from federation_bus import FederationBus
from federation_ledger import FederationLedger
from main import build_federation


def legacy_quorum(n_orgs: int) -> float:
    return 2.0  # today's fixed FederationBus default, independent of n_orgs


def pbft_quorum(n_orgs: int) -> float:
    return float(FederationLedger.recommended_quorum_for_pbft(n_orgs))


def min_colluding_orgs_to_falsely_clear(quorum_required: float, n_orgs: int, stake: float = 1.0) -> int:
    """
    The accused org's own self-witness always counts (weight=stake).
    Additional COLLUDING orgs (dishonest, agreeing to falsely clear)
    each add `stake` more weight. Returns the total number of orgs
    (accused + colluders) whose combined weight first reaches
    quorum_required -- i.e. the smallest coalition size that can force
    a false clear with zero honest cooperation. Capped at n_orgs (can't
    collude with orgs that don't exist).
    """
    import math
    orgs_needed = math.ceil(quorum_required / stake)
    return min(orgs_needed, n_orgs)


def min_orgs_that_must_be_online_for_legitimate_clear(quorum_required: float, stake: float = 1.0) -> int:
    """Same arithmetic, different framing: with everyone honest and
    willing, how many orgs (including the accused) must actually be
    online/responsive to reach quorum_required? Below this many online,
    even a fully legitimate, fully-agreed recovery is blocked."""
    import math
    return math.ceil(quorum_required / stake)


def analytical_table(n_range=range(2, 11)):
    print(f"{'N':>3} | {'legacy quorum':>13} | {'pbft quorum':>11} | "
          f"{'legacy: orgs to collude':>24} | {'pbft: orgs to collude':>22} | "
          f"{'legacy: orgs must be online':>28} | {'pbft: orgs must be online':>26}")
    print("-" * 130)
    rows = []
    for n in n_range:
        lq, pq = legacy_quorum(n), pbft_quorum(n)
        l_collude = min_colluding_orgs_to_falsely_clear(lq, n)
        p_collude = min_colluding_orgs_to_falsely_clear(pq, n)
        l_online = min_orgs_that_must_be_online_for_legitimate_clear(lq)
        p_online = min_orgs_that_must_be_online_for_legitimate_clear(pq)
        rows.append((n, lq, pq, l_collude, p_collude, l_online, p_online))
        print(f"{n:>3} | {lq:>13.1f} | {pq:>11.1f} | {l_collude:>24} | {p_collude:>22} | "
              f"{l_online:>28} | {p_online:>26}")
    return rows


def empirical_cross_check():
    """Runs the REAL FederationBus/FederationLedger witness flow (not
    just the formula above) for N=3 and N=4, confirming the analytical
    table matches actual code behaviour."""
    print("\n=== Empirical cross-check against real code (not just arithmetic) ===")
    for n_orgs, mode, label in [
        (3, "static", "N=3, legacy static (quorum stays 2)"),
        (3, "pbft_dynamic", "N=3, pbft_dynamic (quorum -> 3, unanimity)"),
        (4, "pbft_dynamic", "N=4, pbft_dynamic (quorum -> 3, f=1 tolerated)"),
    ]:
        bus = FederationBus(db_path=":memory:", require_message_signatures=False, quorum_mode=mode)
        build_federation(bus, n_orgs=n_orgs)
        orgs = [f"Org{chr(65+i)}" for i in range(n_orgs)]
        accused = orgs[0]
        others = orgs[1:]

        # Case A: only the accused self-witnesses, nobody else cooperates
        # (simulates every other org being honest and refusing, OR being
        # offline/partitioned -- ledger can't distinguish "refused" from
        # "down", which is exactly the availability trade-off).
        proposal = bus.propose_federation_reinstatement(accused)
        bus.sign_and_witness_federation_reinstatement(proposal["proposal_id"], accused)
        committed_self_only = bus.ledger.proposals[proposal["proposal_id"]]["committed"]

        # Case B: accused + exactly ONE other org witnesses (the classic
        # "one colluding/available independent org" scenario)
        bus2 = FederationBus(db_path=":memory:", require_message_signatures=False, quorum_mode=mode)
        build_federation(bus2, n_orgs=n_orgs)
        proposal2 = bus2.propose_federation_reinstatement(accused)
        bus2.sign_and_witness_federation_reinstatement(proposal2["proposal_id"], accused)
        bus2.sign_and_witness_federation_reinstatement(proposal2["proposal_id"], others[0])
        committed_one_other = bus2.ledger.proposals[proposal2["proposal_id"]]["committed"]

        # Case C: accused + ALL other orgs witness (full cooperation)
        bus3 = FederationBus(db_path=":memory:", require_message_signatures=False, quorum_mode=mode)
        build_federation(bus3, n_orgs=n_orgs)
        proposal3 = bus3.propose_federation_reinstatement(accused)
        bus3.sign_and_witness_federation_reinstatement(proposal3["proposal_id"], accused)
        for org in others:
            bus3.sign_and_witness_federation_reinstatement(proposal3["proposal_id"], org)
        committed_all = bus3.ledger.proposals[proposal3["proposal_id"]]["committed"]

        print(f"\n{label} (quorum_required={bus.ledger.quorum_required}):")
        print(f"  accused self-witness only  -> committed={committed_self_only} (must be False, always)")
        print(f"  accused + 1 other org      -> committed={committed_one_other}")
        print(f"  accused + ALL other orgs   -> committed={committed_all} (must be True, always)")

        for b in (bus, bus2, bus3):
            b.close()


def main():
    print("=== Analytical table: legacy static (quorum=2) vs. pbft_dynamic ===")
    print("(deterministic given N and uniform stake=1.0 -- see module docstring for why no")
    print(" repeated-trial statistics are used here)\n")
    rows = analytical_table()

    empirical_cross_check()

    print("\n=== Verdict, for the N=3 case that matters today ===")
    lq, pq = legacy_quorum(3), pbft_quorum(3)
    l_collude = min_colluding_orgs_to_falsely_clear(lq, 3)
    p_collude = min_colluding_orgs_to_falsely_clear(pq, 3)
    print(f"SECURITY: legacy needs only {l_collude} colluding org(s) (out of 3) to force a false "
          f"clear; pbft_dynamic needs {p_collude} -- i.e. ALL of them (unanimity). "
          f"A single honest hold-out org can block a false clear under pbft_dynamic; it cannot "
          f"under legacy, where one dishonest independent org colluding with the accused suffices.")
    print(f"AVAILABILITY COST: legacy tolerates 1 org being down/partitioned during a LEGITIMATE "
          f"recovery (needs {min_orgs_that_must_be_online_for_legitimate_clear(lq)} of 3 online); "
          f"pbft_dynamic tolerates 0 (needs {min_orgs_that_must_be_online_for_legitimate_clear(pq)} of 3 "
          f"online -- everyone). This is the real, quantified trade-off, not a free win.")


if __name__ == "__main__":
    main()
