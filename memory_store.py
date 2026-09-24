"""
Memory / Context Integrity (FARF hardening -- v6, OWASP ASI06)
--------------------------------------------------------------------
Nothing in the prototype prior to this module gave any agent a real
persistent memory store at all -- the "memory manipulation" scenario
(E4 in main.py) simulated compromise purely through instruction TEXT
passed straight into Agent.plan(), with no actual write/read surface
to attack or defend. taint_engine.py tracks provenance on MESSAGES in
transit; nothing tracked provenance on what an agent WRITES to memory,
so a poisoned memory entry looked identical to a legitimate one, and a
value read at "check" time could silently differ from the same key's
value at "use" time with no way to notice.

This module gives every agent its own hash-chained, per-writer-signed
memory namespace:

  - Every write is bound to the writer's did:key (verified the same
    way FederationBus.send()'s Zero-Trust signing verifies a message --
    see FederationBus.write_memory()), so a poisoned entry is
    attributable to whoever's key actually signed it.
  - Every write is chained (prev_hash/record_hash, same tamper-evidence
    pattern as the audit log and the Federation Ledger), so datastore-
    level tampering (bypassing the signed-write API entirely, e.g. a
    compromised DB) is detectable via verify_integrity().
  - verify_integrity() recomputes BOTH the content hash (from the
    record's actual stored value) and the chain hash on every record --
    recomputing only the chain hash would miss an attacker who edits
    `value` in place but leaves the stored `content_hash` field alone.
  - A companion TOCTOU pattern for memory READS is wired into
    orchestration.py's policy rules (see `memory_toctou_mismatch`),
    exactly mirroring the existing resource_hash_at_check/at_use rule
    already used for the execute_action TOCTOU defence.

Documented limitations (consistent with the rest of this prototype):
  - In-memory, single-process. A real deployment persists this the
    same way the audit trail is persisted (SQLite here; something
    durable and access-controlled in production).
  - No revocation of a specific memory RECORD once written -- only the
    writer's whole identity can be revoked (FederationBus.revoke_agent),
    which stops further writes but does not retroactively invalidate
    an already-written poisoned entry. Detecting and purging a
    specific bad record is left as future work.
  - Only self-writes are supported (an agent can only write to its own
    namespace) -- there is no delegated-write model yet for e.g. an
    advisor legitimately writing into an executor's memory. Adding that
    would need an explicit capability/delegation grant, analogous to
    the delegation edges already modelled in adversary_model.py.

v7.7 addition -- crypto-shredding for GDPR Art. 17 erasure
(THREAT_MODEL.md's LINDDUN "Non-compliance" finding /
PHASE1_GAP_REPORT_v7.6.md structural gap #1, "Append-only chains vs.
'right to erasure'"): a tamper-evident, append-only hash chain and
true deletion are fundamentally incompatible -- you cannot both prove
nothing was silently altered AND make a specific value unreadable by
walking the chain, if the chain stores the value itself. The fix is
NOT to make the chain mutable (that would reintroduce the exact
in-place-tampering risk verify_integrity() exists to catch). Instead:

  - Every write's `value` is encrypted with a fresh, per-record
    AES-256-GCM key BEFORE it ever enters the chain. Only the
    ciphertext is stored in the record.
  - `content_hash` is now defined as the hash of the CIPHERTEXT, not
    the plaintext -- this is what makes tamper-evidence independent of
    whether the plaintext is still recoverable: verify_integrity() can
    always detect an in-place edit to the stored ciphertext, whether
    or not the decryption key still exists.
  - `erase_record_for_subject()` performs the actual "erasure": it
    discards the per-record key(s) for every record ever written at a
    given key (not just the latest) from the in-memory keystore. Once
    discarded, the ciphertext is permanently unrecoverable -- the data
    is gone -- while the hash-chained ciphertext blob remains in place,
    so the chain's structural integrity, ordering, and the fact that
    "a record existed here and was later erased" all remain fully
    auditable. This is the standard crypto-shredding pattern; it
    satisfies "right to erasure" for the DATA while preserving
    tamper-evidence of the AUDIT TRAIL, which are different assets.
  - Documented limitation (consistent with the rest of this
    prototype): the per-record key keystore is itself in-memory,
    single-process, same as everything else here -- a real deployment
    needs the keys in a KMS with per-record-key wrapping (envelope
    encryption), not a Python dict. This module's job is to prove the
    DESIGN closes the structural tension; Phase 2/cloud swaps the
    keystore for a managed KMS without changing anything above it.
"""
import hashlib
import json
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from farf_logging import get_logger

log = get_logger(__name__)

GENESIS_HASH = "0" * 64


@dataclass
class MemoryRecord:
    key: str
    ciphertext: bytes           # AES-256-GCM(nonce || ciphertext) of the canonical value bytes
    writer_agent_id: str
    writer_did: str
    timestamp: float
    content_hash: str           # sha256 of `ciphertext` -- see module docstring for why
    prev_hash: str
    record_hash: str
    tombstone: bool = False        # v7.1: True means this record REVOKES the key
    tombstone_reason: str | None = None
    crypto_shredded: bool = False  # v7.7: True means the write was itself an erasure marker


class MemoryStore:
    def __init__(self):
        self._chains: dict[str, list[MemoryRecord]] = {}          # agent_id -> hash-chained history
        self._current: dict[str, dict[str, MemoryRecord]] = {}    # agent_id -> {key: latest record}
        # record_hash -> per-record AES-256-GCM key. Deleting an entry
        # here is what "erasure" actually IS -- the ciphertext in the
        # chain becomes permanently unrecoverable the moment its key is
        # gone, with no need to touch the chain itself.
        self._record_keys: dict[str, bytes] = {}

    @staticmethod
    def _ciphertext_hash(ciphertext: bytes) -> str:
        return hashlib.sha256(ciphertext).hexdigest()

    @staticmethod
    def _encrypt(value: dict) -> "tuple[bytes, bytes]":
        """Returns (nonce || ciphertext, key). A fresh key per record
        is the whole point -- it's what lets one record be shredded
        without affecting any other record's recoverability."""
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        plaintext = json.dumps(value, sort_keys=True).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext, key

    def decrypt(self, record: MemoryRecord) -> dict | None:
        """Public: decrypts `record` if its per-record key is still
        present. Returns None if the record was crypto-shredded (or is
        a tombstone/erasure marker that was never issued a key) -- the
        caller (FederationBus.read_memory) is responsible for
        distinguishing "no current value" (tombstone) from "value
        existed but was erased" (crypto-shredded) using the record's
        `tombstone`/`crypto_shredded` flags, since both return None
        here but mean different things for an audit/compliance
        reviewer."""
        key = self._record_keys.get(record.record_hash)
        if key is None:
            return None
        aesgcm = AESGCM(key)
        nonce, ciphertext = record.ciphertext[:12], record.ciphertext[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())

    def write(self, agent_id: str, key: str, value: dict,
              writer_agent_id: str, writer_did: str) -> MemoryRecord:
        chain = self._chains.setdefault(agent_id, [])
        prev_hash = chain[-1].record_hash if chain else GENESIS_HASH
        ciphertext, record_key = self._encrypt(value)
        content_hash = self._ciphertext_hash(ciphertext)
        ts = time.time()
        record_repr = f"{key}|{content_hash}|{writer_agent_id}|{writer_did}|{ts}|{prev_hash}"
        record_hash = hashlib.sha256(record_repr.encode()).hexdigest()
        record = MemoryRecord(key=key, ciphertext=ciphertext, writer_agent_id=writer_agent_id,
                               writer_did=writer_did, timestamp=ts, content_hash=content_hash,
                               prev_hash=prev_hash, record_hash=record_hash)
        self._record_keys[record_hash] = record_key
        chain.append(record)
        self._current.setdefault(agent_id, {})[key] = record
        return record

    def revoke_record(self, agent_id: str, key: str, revoker_agent_id: str,
                       revoker_did: str, reason: str = "revoked",
                       mode: str = "tombstone") -> MemoryRecord | None:
        """
        v7.1: tombstone-only. v7.9.10: unified into a single, configurable
        entry point per the thesis supervisor's explicit direction ("keep
        it as a configurable choice, with tombstone default but workable
        for soft delete where data retention is higher").

        CORRECTION, disclosed rather than silently fixed: an audit earlier
        this session (PHASE1_TO_CLOUD_DECISION_BRIEF.md \u00a72 item 8) claimed
        per-record revocation "genuinely doesn't exist yet, only whole-agent
        revocation does." That was WRONG -- per-record revocation already
        existed, as two separately-named methods (this one, tombstone-only
        at the time, and erase_record_for_subject() below for crypto-
        shredding). An incomplete grep pattern during that audit
        (`grep -n "def write\\|def verify\\|signature\\|sign("`) simply
        didn't match either method's name and erase_record_for_subject()
        was never actually read. What THIS change adds is the genuinely
        missing piece: previously a caller had to already know both method
        names existed and pick the right one by hand; there was no single
        configurable choice-point. Now there is one.

        mode="tombstone" (default -- identical behaviour to the pre-v7.9.10
          version of this method): appends a tombstone record. Non-
          destructive -- read() hides `key` from ordinary use from this
          point on, but every PRIOR record's per-record AES key is
          RETAINED, so the plaintext remains recoverable via
          get_chain() + decrypt() for a compliance/legal-hold reviewer.
          The right default for "soft delete where data retention is
          higher": logically deleted, not destroyed.
        mode="crypto_shred": destructive. Delegates to
          erase_record_for_subject() -- discards the per-record keys for
          EVERY record ever written at `key`, permanently destroying
          plaintext recoverability while leaving the ciphertext + hash
          chain in place for tamper-evidence (GDPR Art. 17-style actual
          erasure, not routine revocation).

        erase_record_for_subject() also remains directly callable on its
        own (existing callers, e.g. federation_bus.py's
        erase_memory_record(), are unaffected by this change).
        """
        if mode not in ("tombstone", "crypto_shred"):
            raise ValueError(f"mode must be 'tombstone' or 'crypto_shred', got {mode!r}")
        if mode == "crypto_shred":
            # Same "nothing to do" contract as tombstone mode below --
            # without this check, erase_record_for_subject() would still
            # write a "0 records shredded" marker for a key that was
            # never written, which is a confusing, misleading audit
            # trail entry, not a real erasure event.
            if self.read(agent_id, key) is None:
                return None
            self.erase_record_for_subject(agent_id, key, eraser_agent_id=revoker_agent_id,
                                           eraser_did=revoker_did, reason=reason)
            return self._current.get(agent_id, {}).get(key)  # the marker record just written
        return self._tombstone_record(agent_id, key, revoker_agent_id, revoker_did, reason)

    def _tombstone_record(self, agent_id: str, key: str, revoker_agent_id: str,
                           revoker_did: str, reason: str) -> MemoryRecord | None:
        """The original v7.1 tombstone logic, unchanged, moved here so
        revoke_record() above can be a mode dispatcher without duplicating
        it. Implemented as an APPEND (a tombstone record), not an in-place
        edit of history -- mutating a past record directly would be
        indistinguishable from the exact in-place-tampering attack
        verify_integrity() exists to catch (see its docstring). The chain
        stays append-only and fully auditable: read() treats the latest
        record at a key being a tombstone as "no current value", but the
        full history including what was revoked and why remains inspectable
        via the chain itself."""
        if self.read(agent_id, key) is None:
            return None
        chain = self._chains.setdefault(agent_id, [])
        prev_hash = chain[-1].record_hash if chain else GENESIS_HASH
        tombstone_value = {"tombstone": True, "reason": reason}
        ciphertext, record_key = self._encrypt(tombstone_value)
        content_hash = self._ciphertext_hash(ciphertext)
        ts = time.time()
        record_repr = f"{key}|{content_hash}|{revoker_agent_id}|{revoker_did}|{ts}|{prev_hash}"
        record_hash = hashlib.sha256(record_repr.encode()).hexdigest()
        record = MemoryRecord(key=key, ciphertext=ciphertext, writer_agent_id=revoker_agent_id,
                               writer_did=revoker_did, timestamp=ts, content_hash=content_hash,
                               prev_hash=prev_hash, record_hash=record_hash,
                               tombstone=True, tombstone_reason=reason)
        self._record_keys[record_hash] = record_key
        chain.append(record)
        self._current.setdefault(agent_id, {})[key] = record
        return record

    def erase_record_for_subject(self, agent_id: str, key: str, eraser_agent_id: str,
                                  eraser_did: str, reason: str = "gdpr_article_17") -> dict:
        """
        v7.7 -- crypto-shredding (GDPR Art. 17 "right to erasure"; see
        module docstring for the full design rationale). Unlike
        revoke_record() (which just marks a key as "no current value"
        while leaving every past record's plaintext forensically
        recoverable via the chain), this DESTROYS the ability to
        recover the plaintext of every record ever written at `key`,
        by discarding their per-record AES keys -- while leaving the
        ciphertext blobs and the hash chain itself completely intact,
        so the chain's tamper-evidence and "something existed here and
        was erased on <date> for <reason>" remain fully auditable.

        This is an OPERATOR action (like revoke_agent()/
        revoke_memory_record()) -- called out-of-band by whoever runs
        the bus in response to an erasure request, not signed by an
        in-federation agent.

        Returns a summary, not the erased data (there is nothing left
        to return once this completes).
        """
        chain = self._chains.get(agent_id, [])
        shredded_hashes = [r.record_hash for r in chain
                            if r.key == key and r.record_hash in self._record_keys]
        for record_hash in shredded_hashes:
            del self._record_keys[record_hash]

        prev_hash = chain[-1].record_hash if chain else GENESIS_HASH
        marker_value = {"crypto_shredded": True, "reason": reason,
                         "records_shredded": len(shredded_hashes)}
        ciphertext, record_key = self._encrypt(marker_value)
        content_hash = self._ciphertext_hash(ciphertext)
        ts = time.time()
        record_repr = f"{key}|{content_hash}|{eraser_agent_id}|{eraser_did}|{ts}|{prev_hash}"
        record_hash = hashlib.sha256(record_repr.encode()).hexdigest()
        marker = MemoryRecord(key=key, ciphertext=ciphertext, writer_agent_id=eraser_agent_id,
                               writer_did=eraser_did, timestamp=ts, content_hash=content_hash,
                               prev_hash=prev_hash, record_hash=record_hash,
                               tombstone=True, tombstone_reason=reason, crypto_shredded=True)
        # The marker record's OWN key is deliberately kept (not
        # shredded) -- it only records metadata about the erasure
        # event itself (reason, count), which is exactly the audit
        # trail GDPR expects an erasure to leave behind.
        self._record_keys[record_hash] = record_key
        self._chains.setdefault(agent_id, []).append(marker)
        self._current.setdefault(agent_id, {})[key] = marker
        log.warning("memory record crypto-shredded", extra={
            "event": "memory_crypto_shredded", "agent_id": agent_id, "key": key,
            "records_shredded": len(shredded_hashes), "reason": reason})
        return {"erased": True, "key": key, "records_shredded": len(shredded_hashes),
                "marker_record_hash": record_hash}

    def get_chain(self, agent_id: str) -> list[MemoryRecord]:
        """Public accessor for the full history (not just the current
        record) -- used by compliance-review tooling (see
        FederationBus.inspect_memory_history()) that needs to
        distinguish 'revoked' from 'crypto-shredded' for a specific
        key across its whole write history, not just the latest write."""
        return list(self._chains.get(agent_id, []))

    def read(self, agent_id: str, key: str) -> MemoryRecord | None:
        record = self._current.get(agent_id, {}).get(key)
        if record is not None and record.tombstone:
            return None
        return record

    def verify_integrity(self, agent_id: str) -> dict:
        """
        Recomputes BOTH the ciphertext hash and the chain hash for
        every record belonging to `agent_id` -- and does so WHETHER OR
        NOT that record's plaintext is still recoverable (crypto-
        shredded records included), which is exactly the point: an
        attacker with direct datastore access who edits a record's
        stored `ciphertext` in place while leaving `content_hash`
        untouched is still caught, even for a record whose encryption
        key has since been discarded. Recomputing only the chain hash
        would miss that same attacker if they also happened to update
        content_hash to match -- catching that requires comparing
        against an independent value (the ciphertext itself), same
        principle as the pre-v7.7 design, just re-anchored on
        ciphertext instead of plaintext.
        """
        chain = self._chains.get(agent_id, [])
        expected_prev = GENESIS_HASH
        for i, r in enumerate(chain):
            recomputed_content_hash = self._ciphertext_hash(r.ciphertext)
            if recomputed_content_hash != r.content_hash:
                return {"intact": False, "first_broken_record": i, "reason": "ciphertext_tampered_in_place"}
            if r.prev_hash != expected_prev:
                return {"intact": False, "first_broken_record": i, "reason": "prev_hash_mismatch"}
            record_repr = f"{r.key}|{r.content_hash}|{r.writer_agent_id}|{r.writer_did}|{r.timestamp}|{r.prev_hash}"
            recomputed_record_hash = hashlib.sha256(record_repr.encode()).hexdigest()
            if recomputed_record_hash != r.record_hash:
                return {"intact": False, "first_broken_record": i, "reason": "record_hash_mismatch"}
            expected_prev = r.record_hash
        return {"intact": True, "records_checked": len(chain)}
