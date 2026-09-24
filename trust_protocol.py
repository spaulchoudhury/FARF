"""
Federated Trust Protocol (FARF Artefact 2)
--------------------------------------------
Decentralised trust establishment using short-lived, W3C-VC-style
credentials anchored to did:key identities (Ed25519). No central
certificate authority or blockchain registry is required, matching the
proposal's design goal. Includes:

  - DID:key identity generation per organisation
  - Verifiable Credential issuance/verification with signature checks
  - Replay-attack resistance (nonce cache + TTL window)
  - A lightweight commitment-based "Zero-Knowledge Attestation" standing
    in for the session-scoped ZK proofs described in the proposal
    (cheap enough to run on a laptop; swap for a real zk-SNARK library
    later if you need formal ZK guarantees).
"""
import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from farf_logging import get_logger

log = get_logger(__name__)
from cryptography.exceptions import InvalidSignature


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# Public alias -- used by federation_bus.py to decode a message signature
# without reaching into this module's "private" helper.
decode_signature = _unb64


def did_to_public_key(did: str) -> Ed25519PublicKey:
    """
    Reconstructs an Ed25519 public key from a did:key string of the form
    'did:key:z<base64url-encoded-raw-public-key>', with no need for the
    verifier to hold a live handle to the original DIDKeyIdentity object
    -- exactly the situation a real remote verifier is in (it only ever
    sees the did:key string on the wire, not the in-process object).
    """
    encoded = did.rsplit(":", 1)[-1]
    encoded = encoded.removeprefix("z")
    return Ed25519PublicKey.from_public_bytes(_unb64(encoded))


class DIDKeyIdentity:
    """A minimal did:key identity backed by an Ed25519 keypair."""

    def __init__(self, org: str):
        self.org = org
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        raw_pub = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.did = f"did:key:z{_b64(raw_pub)}"

    def sign(self, payload: bytes) -> str:
        return _b64(self._private_key.sign(payload))

    def public_key(self) -> Ed25519PublicKey:
        return self._public_key


@dataclass
class VerifiableCredential:
    issuer_did: str
    subject_did: str
    claims: dict
    issued_at: float
    ttl_seconds: float
    nonce: str
    signature: str | None = None

    def payload_bytes(self) -> bytes:
        payload = {
            "issuer": self.issuer_did, "subject": self.subject_did,
            "claims": self.claims, "issued_at": self.issued_at,
            "ttl": self.ttl_seconds, "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True).encode()

    def is_expired(self) -> bool:
        return time.time() > (self.issued_at + self.ttl_seconds)


class FederatedTrustProtocol:
    def __init__(self):
        self.identities: dict[str, DIDKeyIdentity] = {}
        self._nonce_expiry: dict[str, float] = {}   # nonce -> expiry timestamp (self-pruning, bounded)
        self._zk_salts: dict[str, str] = {}          # attestation_id -> salt (server-side only, never returned to caller)

        # Zero-Trust per-message signing (Step 3 hardening): each AGENT
        # (not just each org) gets its own Ed25519 keypair, distinct from
        # the org's credential-issuing key, so a message can be verified
        # as having actually come from that specific agent's process --
        # see FederationBus.send()'s require_message_signatures path.
        self.agent_identities: dict[str, DIDKeyIdentity] = {}

        # PENTEST FINDING (fixed, PT-09 / revocation registry): before
        # this, a leaked or compromised agent credential/key remained
        # fully trusted for its entire TTL with no way to kill it early
        # -- documented as an open MEDIUM finding in THREAT_MODEL.md
        # Section 3/8. revoke_agent() gives an immediate, permanent
        # override that admission and message verification both consult,
        # independent of whether the credential or signature would
        # otherwise still validate.
        self.revoked_agents: set[str] = set()

        # LINDDUN fix (v7.5, Linkability/Identifiability -- THREAT_MODEL.md
        # Section 14/RISK_APPENDIX.md Part A): every agent's did:key was
        # previously a single, permanent identifier used in every signed
        # message and, more importantly, in every PERSISTED audit row --
        # trivially linkable across the entire federation's history by
        # anyone with access to an audit export. This registry gives each
        # agent a ROTATING pseudonym used specifically for anything
        # written to disk/exported (see FederationBus._write_audit_row,
        # which pseudonymizes before persisting) -- unlinkable across
        # rotations by anyone without resolve_pseudonym()'s mapping,
        # which is bus-internal only and NEVER itself persisted to disk.
        # Honest scope: this does NOT anonymize from the bus operator
        # (who, by design, needs a stable identifier for CUSUM/
        # revocation/accountability -- that's a legitimate security
        # requirement, not an oversight), and linkability WITHIN one
        # pseudonym's lifetime (between rotations) is not prevented --
        # rotate more often for stronger protection, at the cost of
        # losing continuity in exported audit views across rotations.
        self.pseudonym_to_agent: dict[str, str] = {}
        self.agent_current_pseudonym: dict[str, str] = {}

    def save_pseudonym_registry(self, path: str):
        """Persists the pseudonym mapping to a file SEPARATE from the
        audit DB -- raw theft of the DB alone still reveals nothing
        (an attacker needs BOTH files), while a legitimate bus restart
        doesn't permanently destroy the operator's accountability
        capability the way losing this mapping entirely would. In a
        real cloud deployment this file should itself be encrypted/
        KMS-protected, not plain JSON with OS permissions as the only
        guard -- same caveat as every other in-process secret here.

        v7.6: writes to a temp file in the same directory, then
        os.replace()s it over the real path. A direct `open(path, "w")`
        followed by `json.dump()` (the old approach) leaves a
        half-written, invalid-JSON file on disk if the process is
        killed mid-write -- which then fails load_pseudonym_registry()
        on the NEXT startup, well after the write that actually caused
        it. os.replace() is atomic on both POSIX and Windows, so the
        file on disk is always either the old complete version or the
        new complete version, never a partial one."""
        import tempfile
        directory = os.path.dirname(os.path.abspath(path)) or "."
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".pseudonyms_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"pseudonym_to_agent": self.pseudonym_to_agent,
                           "agent_current_pseudonym": self.agent_current_pseudonym}, f)
            os.replace(tmp_path, path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def load_pseudonym_registry(self, path: str):
        if os.path.exists(path):
            # v7.6: same reasoning as the audit-encryption-key load above
            # -- a corrupted file here (pre-existing damage from before
            # the atomic-write fix, a manually-edited file, truncated
            # copy, etc.) should fail loudly with an actionable message
            # at startup, not raise a raw json.JSONDecodeError from deep
            # inside a constructor, and not silently proceed with an
            # empty registry (which would orphan every existing audit
            # row's pseudonym -- unable to resolve any of them back to
            # a real identity again).
            try:
                with open(path) as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"FARF pseudonym registry file '{path}' exists but could not be read as "
                    f"valid JSON ({exc}). Refusing to silently continue with an empty registry, "
                    f"since that would permanently orphan every existing audit row's pseudonym "
                    f"-- none of them could be resolved back to a real agent identity again. "
                    f"If you have a backup of this file, restore it. If you accept losing that "
                    f"resolution capability, remove '{path}' and retry."
                ) from exc
            self.pseudonym_to_agent = data.get("pseudonym_to_agent", {})
            self.agent_current_pseudonym = data.get("agent_current_pseudonym", {})

    def rotate_pseudonym(self, agent_id: str) -> str:
        pseudonym = f"pseudo-{secrets.token_hex(8)}"
        self.pseudonym_to_agent[pseudonym] = agent_id
        self.agent_current_pseudonym[agent_id] = pseudonym
        return pseudonym

    def pseudonym_for(self, agent_id: str) -> str:
        if agent_id not in self.agent_current_pseudonym:
            return self.rotate_pseudonym(agent_id)
        return self.agent_current_pseudonym[agent_id]

    def resolve_pseudonym(self, pseudonym: str) -> str | None:
        """De-anonymization -- bus-operator-only capability (never
        exposed to other agents or external audit consumers), for
        legitimate accountability/investigation needs. The mapping this
        reads from is held ONLY in this process's memory, never written
        to disk -- someone who steals the audit DB file gets pseudonyms
        with no way to resolve them back to real identities."""
        return self.pseudonym_to_agent.get(pseudonym)

    def revoke_agent(self, agent_id: str):
        self.revoked_agents.add(agent_id)

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self.revoked_agents

    def register_organisation(self, org: str) -> DIDKeyIdentity:
        identity = DIDKeyIdentity(org)
        self.identities[org] = identity
        return identity

    def register_agent_identity(self, agent_id: str) -> DIDKeyIdentity:
        identity = DIDKeyIdentity(agent_id)
        self.agent_identities[agent_id] = identity
        return identity

    def sign_message(self, agent_id: str, payload_bytes: bytes) -> str:
        return self.agent_identities[agent_id].sign(payload_bytes)

    def issue_credential(self, issuer_org: str, subject_did: str, claims: dict,
                          ttl_seconds: float = 60.0) -> VerifiableCredential:
        issuer = self.identities[issuer_org]
        vc = VerifiableCredential(
            issuer_did=issuer.did, subject_did=subject_did, claims=claims,
            issued_at=time.time(), ttl_seconds=ttl_seconds, nonce=secrets.token_hex(8),
        )
        vc.signature = issuer.sign(vc.payload_bytes())
        return vc

    def _prune_expired_nonces(self):
        """
        Bounds memory to 'nonces issued within their TTL window' instead
        of growing forever (PENTEST FINDING: unbounded _seen_nonces set
        was a slow memory-exhaustion leak on any long-running, high-
        credential-throughput federation).
        """
        now = time.time()
        expired = [n for n, exp in self._nonce_expiry.items() if exp < now]
        for n in expired:
            del self._nonce_expiry[n]

    def verify_credential(self, vc: VerifiableCredential, issuer_org: str) -> dict:
        self._prune_expired_nonces()
        if vc.nonce in self._nonce_expiry:
            log.warning("credential replay detected", extra={
                "event": "credential_verification_failed", "reason": "replay_detected",
                "issuer_org": issuer_org, "subject_did": vc.subject_did})
            return {"valid": False, "reason": "replay_detected"}
        if vc.is_expired():
            log.info("credential expired", extra={
                "event": "credential_verification_failed", "reason": "expired",
                "issuer_org": issuer_org, "subject_did": vc.subject_did})
            return {"valid": False, "reason": "expired"}
        issuer = self.identities.get(issuer_org)
        if issuer is None or issuer.did != vc.issuer_did:
            log.error("spoofed or unknown credential issuer", extra={
                "event": "credential_verification_failed", "reason": "unknown_or_spoofed_issuer",
                "issuer_org": issuer_org, "subject_did": vc.subject_did})
            return {"valid": False, "reason": "unknown_or_spoofed_issuer"}
        try:
            issuer.public_key().verify(_unb64(vc.signature), vc.payload_bytes())
        except InvalidSignature:
            log.error("credential signature verification failed", extra={
                "event": "credential_verification_failed", "reason": "bad_signature",
                "issuer_org": issuer_org, "subject_did": vc.subject_did})
            return {"valid": False, "reason": "bad_signature"}
        # retain the nonce only until the credential itself would have
        # expired anyway -- no need to remember it forever
        self._nonce_expiry[vc.nonce] = vc.issued_at + vc.ttl_seconds
        log.debug("credential verified", extra={
            "event": "credential_verified", "issuer_org": issuer_org, "subject_did": vc.subject_did})
        return {"valid": True, "reason": "ok"}

    # ---- session-scoped ZK-style attestation ---------------------------
    def issue_zk_attestation(self, org: str, secret_attribute: str) -> dict:
        """
        PENTEST FINDING (fixed): the salt used to be returned in the same
        object as the commitment, so anyone who intercepted an
        attestation could mount an offline dictionary attack against the
        underlying secret with zero interaction with the issuer. The
        salt is now retained server-side, keyed by an opaque
        attestation_id, and never leaves this object.

        This is still NOT a true zero-knowledge proof (no interactive
        challenge-response, no zk-SNARK) -- see README limitations --
        but the concrete salt-exposure vulnerability is closed: a party
        who only has the returned {"commitment", "attestation_id"} pair
        cannot reconstruct the secret offline.
        """
        attestation_id = secrets.token_hex(8)
        salt = secrets.token_hex(16)
        commitment = hashlib.sha256((secret_attribute + salt).encode()).hexdigest()
        self._zk_salts[attestation_id] = salt
        return {"org": org, "attestation_id": attestation_id, "commitment": commitment}

    def verify_zk_attestation(self, attestation: dict, revealed_attribute: str) -> bool:
        salt = self._zk_salts.get(attestation.get("attestation_id"))
        if salt is None:
            return False
        check = hashlib.sha256((revealed_attribute + salt).encode()).hexdigest()
        return check == attestation["commitment"]


if __name__ == "__main__":
    proto = FederatedTrustProtocol()
    proto.register_organisation("OrgA")
    proto.register_organisation("OrgB")

    vc = proto.issue_credential("OrgA", subject_did="did:key:zSUBJECT", claims={"role": "advisor"})
    print("legit:", proto.verify_credential(vc, "OrgA"))
    print("replay (same credential replayed):", proto.verify_credential(vc, "OrgA"))

    vc2 = proto.issue_credential("OrgA", subject_did="did:key:zSUBJECT", claims={"role": "advisor"})
    print("spoofed issuer (claims to be OrgB):", proto.verify_credential(vc2, "OrgB"))

    att = proto.issue_zk_attestation("OrgA", "clearance:level-3")
    print("zk correct reveal:", proto.verify_zk_attestation(att, "clearance:level-3"))
    print("zk wrong reveal:", proto.verify_zk_attestation(att, "clearance:level-9"))
