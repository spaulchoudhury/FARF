"""
Federation Ledger (FARF hardening -- v3 Step 2, hardened further v7)
------------------------------------------------------------------------
Blockchain-style quorum consensus ensuring no single organisation can
unilaterally clear a FEDERATION-WIDE quarantine on itself.

Context: `FederationBus.reinstate_with_reattestation()` already gates
per-agent recovery on a fresh, valid credential from that agent's own
org -- correct for an ordinary single-agent quarantine. But when an
org-wide (Sybil) attack trips the aggregate defence (`_quarantine_org()`,
see THREAT_MODEL.md Section 5 / pentest/pt04), the ACCUSED org is
exactly the org whose credential-issuing key would be used to
self-attest its way back in. A single dishonest or compromised org
could clear its own federation-wide quarantine with zero independent
verification -- see pentest/pt07_unilateral_federation_clearing.py.

v7 hardening (was previously documented as open limitations, now
closed at the ledger's own layer -- cryptographic accountability is
enforced by FederationBus.witness_federation_reinstatement(), see that
method's docstring for the signature/nonce machinery; this module only
deals with weighted votes and the tamper-evident chain):

  - **Stake/reputation-weighted voting**, not one-org-one-vote. Each
    org has a `stake` (default 1.0); `quorum_required` is now a WEIGHT
    THRESHOLD, not a headcount. `witness()` sums the distinct weighted
    votes so far and commits once the total reaches the threshold.
  - **Idempotent re-witnessing**: an org re-witnessing the same
    proposal updates (not duplicates) its recorded vote -- prevents a
    single org's repeated calls from being double-counted toward
    quorum.

Documented limitation (see THREAT_MODEL.md 12 for the full PBFT
comparison): `quorum_required` is a fixed constant chosen at
construction time, not automatically proportional to federation size.
Classic PBFT-style tolerance requires N >= 3f+1 total participants to
survive f Byzantine/colluding participants, with a quorum of 2f+1 --
`recommended_quorum_for_pbft(n_orgs)` below computes that value, but
callers must opt in to using it (see FederationBus / THREAT_MODEL.md
for why the default is left alone: changing it changes every existing
pentest's calibrated behaviour and the thesis's documented numbers).
"""
import hashlib
import secrets

from farf_logging import get_logger

log = get_logger(__name__)

GENESIS_HASH = "0" * 64


class FederationLedger:
    def __init__(self, quorum: float = 2.0):
        self.quorum_required = quorum
        self.proposals: dict[str, dict] = {}  # proposal_id -> {org, witnesses: {org: weight}, committed, reason}
        self.chain: list[dict] = []
        self._last_hash = GENESIS_HASH
        self.org_stake: dict[str, float] = {}  # org -> stake weight; default 1.0 if absent

    def set_stake(self, org: str, weight: float):
        self.org_stake[org] = weight

    def stake_of(self, org: str) -> float:
        return self.org_stake.get(org, 1.0)

    @staticmethod
    def recommended_quorum_for_pbft(n_orgs: int) -> int:
        """
        Classic PBFT: with N total participants, N = 3f+1 tolerates f
        Byzantine/colluding participants, and a quorum of 2f+1 is
        required to commit. Solving for the largest tolerable f given
        N: f = floor((N-1)/3).

        IMPORTANT correction (caught during v7.1 hardening): naively
        applying quorum=2f+1 when f=0 (N<4) gives quorum=1 -- which is
        WRONG. Tolerating zero Byzantine participants means you need
        EVERY participant to agree (unanimity = N), not just one. The
        naive formula only holds once f>=1; below that it must fall
        back to requiring all N votes. Getting this wrong would have
        been a real vulnerability: for a 2-org federation, quorum=1
        would let the accused org's own self-witness alone reach
        quorum, silently defeating PT-07's entire premise.
        """
        f = max(0, (n_orgs - 1) // 3)
        if f == 0:
            return n_orgs
        return 2 * f + 1

    def propose_reinstatement(self, org: str, reason: str = "federation_wide_quarantine_clear") -> str:
        proposal_id = secrets.token_hex(8)
        self.proposals[proposal_id] = {
            "org": org, "witnesses": {}, "committed": False, "reason": reason,
        }
        return proposal_id

    def witness(self, proposal_id: str, witnessing_org: str, weight: float | None = None) -> dict:
        """
        Records `witnessing_org`'s weighted vote for `proposal_id`. The
        accused org witnessing its OWN proposal counts (an org must be
        able to initiate its own recovery) but its stake alone must not
        be enough to reach quorum -- only additional, INDEPENDENT
        orgs' weighted votes can supply what's needed to commit.
        Re-witnessing the same proposal from the same org UPDATES that
        org's recorded weight rather than adding a second vote.
        """
        p = self.proposals.get(proposal_id)
        if p is None:
            return {"accepted": False, "reason": "unknown_proposal"}
        if p["committed"]:
            return {"accepted": True, "witness_count": len(p["witnesses"]),
                     "total_weight": sum(p["witnesses"].values()),
                     "quorum_required": self.quorum_required, "committed": True}

        w = weight if weight is not None else self.stake_of(witnessing_org)
        p["witnesses"][witnessing_org] = w
        total_weight = sum(p["witnesses"].values())
        newly_committed = total_weight >= self.quorum_required
        if newly_committed:
            p["committed"] = True
            self._commit_block(proposal_id, p)
            log.error("federation-wide quarantine cleared by quorum", extra={
                "event": "federation_reinstatement_committed", "proposal_id": proposal_id,
                "accused_org": p["org"], "witness_orgs": list(p["witnesses"].keys()),
                "total_weight": round(total_weight, 4), "quorum_required": self.quorum_required})
        else:
            log.info("witness recorded, quorum not yet reached", extra={
                "event": "federation_reinstatement_witness", "proposal_id": proposal_id,
                "accused_org": p["org"], "witnessing_org": witnessing_org,
                "total_weight": round(total_weight, 4), "quorum_required": self.quorum_required})
        return {"accepted": True, "witness_count": len(p["witnesses"]), "total_weight": round(total_weight, 4),
                 "quorum_required": self.quorum_required, "committed": p["committed"]}

    def _commit_block(self, proposal_id: str, p: dict):
        witnesses_repr = sorted(f"{org}:{w}" for org, w in p["witnesses"].items())
        block_repr = f"{proposal_id}|{p['org']}|{witnesses_repr}|{p['reason']}|{self._last_hash}"
        block_hash = hashlib.sha256(block_repr.encode()).hexdigest()
        self.chain.append({
            "proposal_id": proposal_id, "org": p["org"], "witnesses": dict(p["witnesses"]),
            "reason": p["reason"], "prev_hash": self._last_hash, "block_hash": block_hash,
        })
        self._last_hash = block_hash

    def verify_chain_integrity(self) -> dict:
        expected_prev = GENESIS_HASH
        for i, block in enumerate(self.chain):
            if block["prev_hash"] != expected_prev:
                return {"intact": False, "first_broken_block": i, "reason": "prev_hash_mismatch"}
            witnesses_repr = sorted(f"{org}:{w}" for org, w in block["witnesses"].items())
            recomputed = hashlib.sha256(
                f"{block['proposal_id']}|{block['org']}|{witnesses_repr}|{block['reason']}|{block['prev_hash']}".encode()
            ).hexdigest()
            if recomputed != block["block_hash"]:
                return {"intact": False, "first_broken_block": i, "reason": "block_hash_mismatch"}
            expected_prev = block["block_hash"]
        return {"intact": True, "blocks_checked": len(self.chain)}


if __name__ == "__main__":
    ledger = FederationLedger(quorum=2.0)
    pid = ledger.propose_reinstatement("OrgA")
    print("Proposal created:", pid)

    r1 = ledger.witness(pid, "OrgA")  # the accused org self-witnessing, weight 1.0
    print("Committed after only the accused org self-witnesses:", r1["committed"], "(should be False)")

    r2 = ledger.witness(pid, "OrgB")  # an independent org, weight 1.0
    print("Committed after an independent org also witnesses:", r2["committed"],
          "(should be True -- total weight 2.0 reaches quorum 2.0)")

    print("Chain integrity:", ledger.verify_chain_integrity())

    print("\nPBFT-style recommended quorum by federation size:")
    for n in [2, 3, 4, 7, 10, 100]:
        print(f"  N={n:>3} orgs -> quorum={ledger.recommended_quorum_for_pbft(n)} "
              f"(tolerates f={max(0,(n-1)//3)} Byzantine/colluding orgs)")
