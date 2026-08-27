"""
Federation Bus (integration layer)
--------------------------------------
Every cross-boundary agent interaction is routed through a single
choke point that mirrors the FARF architecture's Federation Bus:

    Identity admission check --> Taint Propagation
        --> Orchestration & Behavioural Governance (agent- and org-level)
        --> (containment on quarantine) --> Audit persistence (SQLite, hash-chained)
        --> FARS resilience recomputation

This module was hardened following the threat model / pen-test in
THREAT_MODEL.md. Everything tagged "PENTEST FINDING (fixed)" below
closes a specific exploit in pentest/*.py; see that file for the
runnable proof and THREAT_MODEL.md Section 4 for the write-up.
"""
import hashlib
import functools
import json
import os
import base64
import sqlite3
import threading
import time
import uuid
from typing import Dict, Optional, Set, List

from trust_protocol import FederatedTrustProtocol, did_to_public_key, decode_signature
from orchestration import (SecureOrchestrationLayer, ActionEvent, Decision,
                            SlidingWindowVolumeDetector, FanOutAnomalyDetector)
from taint_engine import TaintPropagationEngine
from fars import FARSEngine, RecoveryTimeTracker, DetectionLatencyTracker
from adversary_model import FederatedAdversaryModel
from federation_ledger import FederationLedger
from memory_store import MemoryStore
from adaptive_detection import AdaptiveOrgVolumeDetector
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from farf_logging import get_logger

log = get_logger(__name__)

GENESIS_HASH = "0" * 64


def _locked(method):
    """
    v7.1: serializes a state-mutating FederationBus method behind
    self._lock (a threading.RLock) -- see FederationBus.__init__'s
    docstring for why. RLock means a locked method calling another
    locked method on the same bus, in the same thread (e.g.
    sign_and_send() -> send(), witness_federation_reinstatement() ->
    _restore_org()), does not deadlock.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class FederationBus:
    VALID_QUORUM_MODES = ("static", "pbft_dynamic")
    VALID_RECOMPUTE_STRATEGIES = ("immediate", "batched")

    def __init__(self, db_path: str = "farf_audit.db", require_message_signatures: bool = True,
                 message_nonce_ttl_seconds: float = 300.0, adaptive_org_volume: bool = False,
                 quorum_mode: str = "static", quorum_recompute_strategy: str = "immediate"):
        """
        `quorum_mode` (v7.9.10 -- closes "dynamic PBFT quorum adoption",
        confirmed absent in `PHASE1_TO_CLOUD_DECISION_BRIEF.md` \u00a72
        item 9, per the thesis supervisor's explicit decision on that
        finding):
          - "static" (default -- unchanged from every prior version):
            `quorum_required` never changes on its own. Starts at the
            legacy fixed value (2.0) unless `enable_pbft_quorum()` is
            called explicitly, exactly as before.
          - "pbft_dynamic": `quorum_required` is recomputed from
            `FederationLedger.recommended_quorum_for_pbft(n_orgs)` every
            time `register_organisation()` runs, so quorum tracks
            federation membership instead of being frozen at whatever
            it was when last set. See `_recompute_quorum()` below for
            exactly what "every time" means and why.

        `quorum_recompute_strategy` -- only consulted when
        `quorum_mode="pbft_dynamic"`:
          - "immediate" (default, implemented): recompute synchronously
            on every `register_organisation()` call. Correct at today's
            scale (a handful of orgs joining rarely); see
            `_recompute_quorum()`.
          - "batched": explicit provision for a future high-join-
            throughput federation to debounce/batch the recompute
            instead of paying the cost on every single join. NOT
            implemented -- raises `NotImplementedError` here, at
            construction time (fail fast, not on first org join), so a
            caller who selects it gets an immediate, unambiguous signal
            rather than an untested behaviour silently standing in for
            "immediate."
        """
        if quorum_mode not in self.VALID_QUORUM_MODES:
            raise ValueError(f"quorum_mode must be one of {self.VALID_QUORUM_MODES}, got {quorum_mode!r}")
        if quorum_recompute_strategy not in self.VALID_RECOMPUTE_STRATEGIES:
            raise ValueError(f"quorum_recompute_strategy must be one of "
                              f"{self.VALID_RECOMPUTE_STRATEGIES}, got {quorum_recompute_strategy!r}")
        if quorum_mode == "pbft_dynamic" and quorum_recompute_strategy == "batched":
            raise NotImplementedError(
                "quorum_recompute_strategy='batched' is a reserved provision for a future "
                "high-join-throughput federation -- see FederationBus._recompute_quorum()'s "
                "docstring -- but has no implementation yet. Use 'immediate' (the default) "
                "for now, or quorum_mode='static' if you don't need dynamic recompute at all."
            )
        self.quorum_mode = quorum_mode
        self.quorum_recompute_strategy = quorum_recompute_strategy

        self.trust = FederatedTrustProtocol()
        self.orchestration = SecureOrchestrationLayer()
        self.taint = TaintPropagationEngine()
        self.fars_engine = FARSEngine()
        # v7 -- temporally-adaptive FARS (was a pure point-in-time
        # snapshot before this): EWMA gives the score memory of recent
        # trajectory, and RecoveryTimeTracker measures how long
        # quarantine episodes actually last as its own metric, distinct
        # from the steady-state score. See fars.py and THREAT_MODEL.md
        # 14.
        self._fars_ewma: Optional[float] = None
        self.fars_ewma_alpha = 0.3
        self.fars_history: List[Dict] = []
        self._fars_history_cap = 500
        self.recovery_tracker = RecoveryTimeTracker()
        self.detection_latency_tracker = DetectionLatencyTracker()

        # PENTEST FINDING (fixed, v7.1 / latent async TOCTOU): every
        # check-then-act sequence in this class (nonce check -> insert,
        # admission check -> session mutation, org-volume check ->
        # quarantine trigger, delegation check -> write) was previously
        # unguarded -- safe only because this prototype has always been
        # called synchronously, single-threaded. THREAT_MODEL.md Section
        # 3 flagged this as latent/not-currently-exploitable and said to
        # revisit before any concurrency work; this is that revisit. A
        # single reentrant lock (RLock -- several public methods call
        # other public methods on the same bus, e.g. sign_and_send()
        # calls send()) serializes every state-mutating bus operation
        # into an atomic critical section. See
        # pentest/pt14_concurrent_replay_race.py for a real multi-thread
        # stress test proving this actually matters, not just a
        # theoretical concern.
        self._lock = threading.RLock()
        self.adversary_model = FederatedAdversaryModel()

        # PENTEST FINDING (fixed, PT-07): reinstate_with_reattestation()
        # lets an org clear its OWN federation-wide (Sybil) quarantine
        # with a credential issued by that same org -- self-attestation,
        # not independent verification. Org-wide recoveries are now
        # instead gated on quorum witness via FederationLedger; see
        # propose_federation_reinstatement()/witness_federation_reinstatement()
        # below and THREAT_MODEL.md Section 6.
        self.ledger = FederationLedger(quorum=2)
        self.federation_wide_quarantined: Set[str] = set()

        # PENTEST FINDING (fixed, PT-08 / Zero-Trust per-message signing):
        # admission previously only checked that a session TOKEN was
        # currently valid -- once admitted, `send()` trusted the
        # caller-supplied `from_agent` string for every subsequent
        # message with no further proof of possession of that agent's

        # private key. An attacker who merely learns an admitted
        # agent_id/org pair (e.g. from a log, or by observing traffic)
        # could inject messages for the rest of that session. When
        # `require_message_signatures=True` by default (v4 -- Zero-Trust
        # rollout complete, see THREAT_MODEL.md Section 7): every message
        # must carry a per-message Ed25519 signature verified against the
        # sender's did:key, plus a single-use, TTL-bounded nonce (replay
        # protection scoped to the message layer, independent of the
        # credential-layer nonce in trust_protocol.py). Overridable to
        # False for callers with a specific reason not to enforce it (see
        # tests/conftest.py, which does this deliberately to keep unit
        # tests focused on the layer under test -- PT-08 is what actually
        # exercises this enforcement path end to end).
        self.require_message_signatures = require_message_signatures
        self._message_nonce_expiry: Dict[str, float] = {}
        self.message_nonce_ttl_seconds = message_nonce_ttl_seconds

        # PENTEST FINDING (fixed, PT-10 / Memory & Context Integrity,
        # OWASP ASI06): nothing previously tracked provenance or
        # tamper-evidence on what an agent writes to persistent memory
        # -- taint_engine.py only covers messages in transit. See
        # memory_store.py's module docstring for the full design and
        # documented limitations.
        self.memory = MemoryStore()
        self.memory_delegations: Dict[str, List[Dict]] = {}  # owner_agent_id -> [{delegate, keys, expires_at}]

        # PENTEST FINDING (fixed, PT-04): per-organisation rolling taint
        # volume, independent of any single agent's detectors, so an
        # attack fragmented across many Sybil identities within one org
        # still accumulates and trips containment. Cap chosen empirically
        # (see pentest/pt04_distributed_sybil_attack.py and
        # THREAT_MODEL.md Section 5): 0.8 required ~21 low-intensity
        # Sybil agents to trip; 0.35 catches a 10-agent swarm at the
        # same per-agent intensity while still tolerating ordinary
        # multi-agent benign traffic in the existing test suite.
        # KNOWN LIMITATION: this is a fixed threshold, not adaptive to
        # organisation size -- see THREAT_MODEL.md for the recommended
        # follow-up (scale the cap with recent legitimate admission
        # velocity rather than a single federation-wide constant).
        self.org_volume_detector = AdaptiveOrgVolumeDetector() if adaptive_org_volume \
            else SlidingWindowVolumeDetector(window=40, cap=0.35)
        # adaptive_org_volume=False by default: a fixed cap is what every
        # existing pentest/main.py number was calibrated against (see
        # THREAT_MODEL.md 14 for why AdaptiveOrgVolumeDetector's
        # calibration-poisoning trade-off means this is a deliberate
        # choice, not a missing default.

        # Phase 1 item 4 (v7.4): a structurally independent second
        # detector -- topology-based (distinct-target fan-out), not
        # magnitude-based like CUSUM/SlidingWindowVolumeDetector above.
        # Closes a real blind spot both magnitude detectors share by
        # construction: an attacker who keeps every taint_delta
        # arbitrarily small evades both, regardless of tuning, because
        # neither tracks WHO the messages go to. See
        # orchestration.FanOutAnomalyDetector's docstring and
        # pentest/pt16_fanout_evasion.py.
        self.fanout_detector = FanOutAnomalyDetector(window=20, cap=6)

        # PENTEST FINDING (fixed, PT-01): an agent may only be accepted
        # as `from_agent` in send() once it has presented a currently
        # valid credential via admit_agent(). {agent_id: {"org", "expires_at"}}
        self.admitted_sessions: Dict[str, Dict] = {}

        self.total_messages = 0
        self.tainted_messages = 0

        # check_same_thread=False: safe specifically BECAUSE self._lock
        # (v7.1) now serializes every state-mutating method that touches
        # self.db -- no two threads can be inside a @_locked method
        # simultaneously, so the DB connection is never actually
        # accessed concurrently even though different OS threads may
        # call into it over the connection's lifetime. Without the
        # lock, this flag would be genuinely unsafe.
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self._last_row_hash = GENESIS_HASH

        # v7.6 (audit-write failure handling -- THREAT_MODEL.md Section 17,
        # flagged since v7.4's chaos testing and left open through v7.5):
        # a mid-write SQLite failure (disk full, permissions, corruption)
        # previously propagated as an unhandled exception out of
        # _write_audit_row(), crashing whatever public method called it
        # (send(), write_memory(), etc.) even though the underlying
        # security decision had already been made correctly. That's safe
        # (no control is bypassed) but not resilient (ordinary infra
        # flakiness becomes a hard crash instead of degrading gracefully).
        # This buffer holds rows whose SQLite persistence failed so they
        # can be retried once the DB is writable again, without ever
        # re-raising past this point. See flush_buffered_audit_rows()
        # and pentest/pt21_audit_write_resilience.py.
        self._audit_write_buffer: List[tuple] = []
        self._audit_write_failures = 0

        # LINDDUN fix (v7.5, Disclosure of information -- THREAT_MODEL.md
        # Section 14/RISK_APPENDIX.md Part A): audit rows previously
        # stored full plaintext identities and reason strings in the
        # on-disk SQLite file, with no consideration of whether someone
        # who stole the raw DB file (backup theft, misconfigured
        # permissions, decommissioned disk) should be able to read them.
        # This key encrypts the `reason` field before it's written; see
        # _write_audit_row(). Honest scope: this protects against RAW
        # DISK/FILE theft specifically -- it does NOT protect against a
        # compromise of this running process, which holds the key in
        # memory for as long as it's alive (real protection against a
        # compromised process needs the key to live outside the bus
        # entirely, e.g. a KMS -- see THREAT_MODEL.md Section 9's
        # already-deferred HSM/KMS item, which this doesn't replace).
        #
        # PENTEST FINDING (fixed, PT-19): the key was originally
        # regenerated fresh on every __init__, which meant a bus
        # "restart" (a NEW instance opening the SAME db_path -- the
        # exact scenario test_chaos_bus_restart_* simulates) made every
        # prior row's `reason` field PERMANENTLY undecryptable. That's
        # not a security property, it's data loss -- the operator loses
        # their own legitimate access to audit history on every
        # restart. Fixed: persist the key to a companion file
        # (`{db_path}.key`), loaded on subsequent opens of the same
        # db_path. A companion file (not stored inside the DB itself)
        # means stealing the DB file alone still doesn't grant
        # decryption -- the thief needs BOTH files. In a real cloud
        # deployment this key file should be a KMS-backed secret, not a
        # plain file with OS permissions as the only protection -- same
        # caveat as every other in-process key in this prototype.
        key_path = db_path + ".key"
        if os.path.exists(key_path):
            # v7.6: a corrupted/truncated key file (e.g. a crash mid-write
            # -- the write below isn't atomic, same caveat as
            # save_pseudonym_registry(), see THREAT_MODEL.md Section 21)
            # previously raised whatever raw exception AESGCM's decrypt
            # path happened to produce, much later and far from the real
            # cause, the first time an encrypted `reason` field was
            # touched -- or crashed __init__ outright on a permissions
            # error, with a bare traceback and no indication of WHICH
            # file or what to do about it. This is deliberately NOT
            # "catch and silently generate a fresh key": doing that would
            # quietly abandon the ability to decrypt every prior audit
            # row's reason field, which is a data-loss decision the
            # operator should make explicitly, not one this constructor
            # should make for them. Fail loudly, at startup, with an
            # actionable message instead.
            try:
                with open(key_path, "rb") as f:
                    key_bytes = f.read()
                if len(key_bytes) != 32:  # AESGCM.generate_key(bit_length=256) -> 32 bytes
                    raise ValueError(f"expected a 32-byte key, got {len(key_bytes)} bytes")
                self._audit_encryption_key = key_bytes
            except (OSError, ValueError) as exc:
                raise RuntimeError(
                    f"FARF audit encryption key file '{key_path}' exists but could not be "
                    f"read as a valid key ({exc}). Refusing to silently generate a fresh key, "
                    f"since that would permanently abandon the ability to decrypt every "
                    f"existing audit row's 'reason' field. If you have a backup of this file, "
                    f"restore it. If this key is genuinely unrecoverable and you accept losing "
                    f"access to historical audit reasons, back up '{db_path}' first, then "
                    f"remove '{key_path}' and retry."
                ) from exc
        else:
            self._audit_encryption_key = AESGCM.generate_key(bit_length=256)
            with open(key_path, "wb") as f:
                f.write(self._audit_encryption_key)

        # Companion pseudonym-registry file (separate from BOTH the DB
        # and the key file -- raw theft of any ONE of the three still
        # reveals nothing usable on its own). Loaded here so a bus
        # restart doesn't permanently lose the operator's ability to
        # resolve historical pseudonyms back to real identities -- see
        # trust_protocol.save_pseudonym_registry()'s docstring.
        self._pseudonym_registry_path = db_path + ".pseudonyms.json"
        self.trust.load_pseudonym_registry(self._pseudonym_registry_path)
        self._init_db()

    def _init_db(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL, message_id TEXT, from_agent TEXT, to_agent TEXT,
                decision TEXT, taint_level REAL, reason TEXT,
                prev_hash TEXT, row_hash TEXT
            )
        """)
        self.db.commit()
        # resume the hash chain from wherever a previous run left off
        row = self.db.execute("SELECT row_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        if row:
            self._last_row_hash = row[0]

    # ---- federation setup ----------------------------------------------
    def register_organisation(self, org: str):
        """
        Registers `org` with the Trust Protocol. When `quorum_mode ==
        "pbft_dynamic"`, also triggers a quorum recompute (see
        `_recompute_quorum()`) -- this is the "membership-reactive"
        behaviour: joining OR re-joining (calling this again for an org
        already present -- there is no org-removal path in this
        prototype today, so "re-join" is the closest exercisable
        analogue) both flow through here, and `len(self.trust.identities)`
        is a dict keyed by org name, so re-registering an already-present
        org does not inflate the count PBFT is computed against.
        """
        self.trust.register_organisation(org)
        if self.quorum_mode == "pbft_dynamic":
            self._recompute_quorum()

    def _recompute_quorum(self):
        """
        Recomputes `ledger.quorum_required` from the CURRENT org count
        via `FederationLedger.recommended_quorum_for_pbft()`. Only
        called when `quorum_mode == "pbft_dynamic"`.

        `quorum_recompute_strategy`:
          - "immediate" (the only implemented strategy today): recomputes
            synchronously, right here, on every call. Simple and
            provably correct, at the cost of paying a (cheap -- O(1),
            just `max(0, (n-1)//3)` arithmetic) recompute on every single
            org join. Fine at today's scale.
          - "batched": reserved for later. `FederationBus.__init__`
            already refuses to construct a bus with this combination
            (see its docstring) -- if you're reading this because that
            changed, this branch still needs a real implementation
            (e.g. accumulate a `_pending_quorum_recompute` flag here
            instead of recomputing, and flush it from a caller-driven
            `flush_pending_quorum_recompute()` or a join-count threshold)
            before it can be selected.
        """
        if self.quorum_recompute_strategy == "immediate":
            n = len(self.trust.identities)
            new_value = float(self.ledger.recommended_quorum_for_pbft(n))
            if new_value != self.ledger.quorum_required:
                log.info("quorum recomputed on membership change", extra={
                    "event": "quorum_recomputed", "n_orgs": n,
                    "old_quorum_required": self.ledger.quorum_required,
                    "new_quorum_required": new_value,
                })
            self.ledger.quorum_required = new_value
        else:  # pragma: no cover -- unreachable while __init__ refuses "batched"
            raise NotImplementedError(
                f"quorum_recompute_strategy={self.quorum_recompute_strategy!r} has no "
                f"implementation -- see this method's docstring."
            )

    def register_agent(self, agent_id: str, org: str, base_privilege: float = 0.1):
        self.adversary_model.add_agent(agent_id, org, base_privilege)

    # ---- identity admission (binds Trust Protocol to the message bus) --
    @_locked
    def admit_agent(self, agent_id: str, org: str, vc) -> Dict:
        """
        PENTEST FINDING (fixed, PT-01): send() used to accept any
        `from_agent` string with zero credential check -- the Trust
        Protocol (artefact 2) was never actually consulted by the
        runtime message path (artefacts 3/4). An agent must now call
        this (presenting a currently valid, org-issued credential)
        before send() will accept it as a sender.
        """
        if self.trust.is_revoked(agent_id):
            return {"valid": False, "reason": "agent_revoked"}
        result = self.verify_trust_boundary(vc, org, requesting_agent=agent_id)
        if result["valid"]:
            if agent_id not in self.trust.agent_identities:
                self.trust.register_agent_identity(agent_id)
            self.admitted_sessions[agent_id] = {
                "org": org, "expires_at": vc.issued_at + vc.ttl_seconds,
                "did": self.trust.agent_identities[agent_id].did,
            }
        return result

    @_locked
    def revoke_agent(self, agent_id: str):
        """
        Immediately and permanently kills an agent's trust, independent
        of its credential's remaining TTL. Closes the gap where a
        leaked/compromised agent stayed fully trusted until its
        credential happened to expire on its own. Revocation persists
        across admit_agent() calls -- a revoked agent cannot be
        re-admitted even with a brand-new, otherwise-valid credential
        (see pentest/pt09_stale_trust_after_compromise.py).
        """
        self.trust.revoke_agent(agent_id)
        self.admitted_sessions.pop(agent_id, None)

    def _is_admitted(self, agent_id: str, org: str) -> bool:
        if self.trust.is_revoked(agent_id):
            return False
        session = self.admitted_sessions.get(agent_id)
        if session is None or session["org"] != org:
            return False
        return time.time() <= session["expires_at"]

    # ---- trust-boundary verification (routed through the same audit/FARS pipeline) --
    def verify_trust_boundary(self, vc, issuer_org: str, requesting_agent: str = None) -> Dict:
        """
        Verifies a credential via the Federated Trust Protocol AND records
        the outcome in the same audit trail / FARS inputs used for
        message traffic -- mirroring the diagram's 'Trust Token -> FARS
        Engine' path, so a trust-boundary violation degrades FARS and can
        reach the Feedback Loop exactly like a behavioural or taint
        violation does.
        """
        result = self.trust.verify_credential(vc, issuer_org)
        agent_id = requesting_agent or f"unverified-caller@{issuer_org}"
        decision = Decision.ALLOW if result["valid"] else Decision.BLOCK
        event = ActionEvent(agent_id=agent_id, org=issuer_org, action_type="trust_verification",
                             payload={"valid": result["valid"]}, taint_score=0.0)
        self.orchestration._log(event, decision, result["reason"])
        self._write_audit_row(f"vc:{vc.nonce}", agent_id, "federation_bus", decision.value, 0.0, result["reason"])
        return result

    # ---- adaptive recovery, gated on re-attestation ---------------------
    @_locked
    def reinstate_with_reattestation(self, agent_id: str, org: str, vc) -> Dict:
        """
        PENTEST FINDING (fixed, PT-05): orchestration.reinstate() has no
        authorisation check at all -- anything with a reference to the
        orchestration object could clear a quarantine with zero proof of
        remediation. This is now THE supported path for adaptive
        recovery: quarantine is only lifted if a freshly issued, valid,
        unexpired credential is presented (i.e. real re-attestation).

        PENTEST FINDING (fixed, PT-07): if `org` is currently flagged
        federation-wide (an org-wide Sybil quarantine, not an ordinary
        single-agent one), this path is refused -- a single org's own
        credential is self-attestation and must not be sufficient to
        clear a federation-wide quarantine on itself. Use
        propose_federation_reinstatement() + witness_federation_reinstatement()
        instead, which requires independent quorum.
        """
        if org in self.federation_wide_quarantined:
            return {"valid": False, "reason": "requires_federation_quorum",
                     "hint": "use propose_federation_reinstatement() + witness_federation_reinstatement()"}
        result = self.verify_trust_boundary(vc, org, requesting_agent=agent_id)
        if result["valid"]:
            self.orchestration.reinstate(agent_id, capability=self.orchestration._reinstate_capability)
            self.recovery_tracker.mark_recovered(agent_id, time.time())
            if agent_id not in self.trust.agent_identities:
                self.trust.register_agent_identity(agent_id)
            self.admitted_sessions[agent_id] = {
                "org": org, "expires_at": vc.issued_at + vc.ttl_seconds,
                "did": self.trust.agent_identities[agent_id].did,
            }
        return result

    # ---- federation-wide recovery, gated on independent quorum (PT-07 fix) --
    def enable_pbft_quorum(self, n_orgs: Optional[int] = None) -> float:
        """
        Opt-in (v7.1): switches the ledger's quorum_required from the
        fixed default (2.0) to the PBFT-proportional value for the
        current (or given) federation size, using
        FederationLedger.recommended_quorum_for_pbft(). Deliberately
        NOT the default -- for a 3-org federation, PBFT-correct
        behaviour requires UNANIMITY (all 3 orgs must witness), which
        is stricter than today's fixed quorum=2 and would silently
        change the behaviour of anything already relying on 2-of-3.
        Call this explicitly, after your federation's org count is
        settled, once you're ready for that. See THREAT_MODEL.md
        12 for the full comparison table and
        pentest/pt11_ledger_witness_forgery.py Part D for a worked
        demonstration.
        """
        n = n_orgs if n_orgs is not None else len(self.trust.identities)
        self.ledger.quorum_required = float(self.ledger.recommended_quorum_for_pbft(n))
        return self.ledger.quorum_required

    @_locked
    def propose_federation_reinstatement(self, org: str) -> Dict:
        """Any org (typically the accused one) opens a recovery proposal."""
        proposal_id = self.ledger.propose_reinstatement(org)
        return {"proposed": True, "proposal_id": proposal_id, "quorum_required": self.ledger.quorum_required}

    @staticmethod
    def canonical_witness_bytes(proposal_id: str, witnessing_org: str, nonce: str) -> bytes:
        body = {"proposal_id": proposal_id, "witnessing_org": witnessing_org, "nonce": nonce}
        return json.dumps(body, sort_keys=True).encode()

    def sign_and_witness_federation_reinstatement(self, proposal_id: str, witnessing_org: str) -> Dict:
        """Supported entry point: signs the attestation with witnessing_org's
        own org-level DID key (the same identity issue_credential() uses to
        sign VCs) and calls witness_federation_reinstatement()."""
        import secrets as _secrets
        nonce = _secrets.token_hex(8)
        payload_bytes = self.canonical_witness_bytes(proposal_id, witnessing_org, nonce)
        identity = self.trust.identities.get(witnessing_org)
        if identity is None:
            return {"accepted": False, "reason": "unknown_witnessing_org"}
        signature = identity.sign(payload_bytes)
        return self.witness_federation_reinstatement(proposal_id, witnessing_org, signature=signature, nonce=nonce)

    @_locked
    def witness_federation_reinstatement(self, proposal_id: str, witnessing_org: str,
                                          signature: Optional[str] = None, nonce: Optional[str] = None) -> Dict:
        """
        An org (ideally NOT the accused one) attests it has independently
        reviewed the proposal. Once the total weighted vote reaches
        quorum, every agent belonging to the accused org is reinstated
        in one step and the org's federation-wide quarantine flag is
        cleared. Reinstated agents still need a fresh credential via
        admit_agent() before they can send messages again -- lifting
        quarantine is not the same as re-admitting a session, by design
        (defence in depth).

        PENTEST FINDING (fixed, PT-11 / cryptographic witness
        accountability): witness() calls used to carry no proof that
        the claimed witnessing_org actually made the call -- anyone who
        knew an org's name could vote as it. A signature is now
        required from that org's own DID key, verified the same way
        `send()` verifies a message signature, plus a single-use nonce
        (shares the same TTL-bounded replay cache as messages/memory
        writes -- see `_message_nonce_expiry`).
        """
        if signature is None or nonce is None:
            return {"accepted": False, "reason": "missing_witness_signature"}
        identity = self.trust.identities.get(witnessing_org)
        if identity is None:
            return {"accepted": False, "reason": "unknown_witnessing_org"}
        self._prune_expired_message_nonces()
        if nonce in self._message_nonce_expiry:
            return {"accepted": False, "reason": "witness_replayed"}
        payload_bytes = self.canonical_witness_bytes(proposal_id, witnessing_org, nonce)
        try:
            identity.public_key().verify(decode_signature(signature), payload_bytes)
        except InvalidSignature:
            return {"accepted": False, "reason": "invalid_witness_signature"}
        self._message_nonce_expiry[nonce] = time.time() + self.message_nonce_ttl_seconds

        result = self.ledger.witness(proposal_id, witnessing_org, weight=self.ledger.stake_of(witnessing_org))
        if result.get("committed"):
            org = self.ledger.proposals[proposal_id]["org"]
            self._restore_org(org)
        return result

    def _restore_org(self, org: str):
        now = time.time()
        for node, data in self.adversary_model.graph.nodes(data=True):
            if data.get("org") == org:
                self.orchestration.reinstate(node, capability=self.orchestration._reinstate_capability)
                self.recovery_tracker.mark_recovered(node, now)
        self.federation_wide_quarantined.discard(org)
        self.recovery_tracker.mark_recovered(org, now)

    # ---- runtime message routing ---------------------------------------
    @staticmethod
    def canonical_message_bytes(from_agent: str, to_agent: str, action_type: str,
                                 payload: Dict, nonce: str) -> bytes:
        body = {"from": from_agent, "to": to_agent, "action_type": action_type,
                "payload": payload, "nonce": nonce}
        return json.dumps(body, sort_keys=True).encode()

    def _prune_expired_message_nonces(self):
        """
        Bounds _message_nonce_expiry to 'nonces seen within the last
        message_nonce_ttl_seconds' instead of growing forever -- same
        fix already applied to the credential-layer nonce cache in
        trust_protocol.py (that PENTEST FINDING: an unbounded seen-nonce
        set is a slow memory-exhaustion leak on any long-running,
        high-message-throughput federation). Unlike a credential, a
        message has no natural TTL of its own to piggyback on, so this
        uses a fixed window (message_nonce_ttl_seconds, default 300s)
        instead.
        """
        now = time.time()
        expired = [n for n, exp in self._message_nonce_expiry.items() if exp < now]
        for n in expired:
            del self._message_nonce_expiry[n]

    def sign_and_send(self, from_agent: str, from_org: str, to_agent: str, to_org: str,
                       action_type: str, payload: Dict, taint_delta: float = 0.0) -> Dict:
        """Convenience wrapper: signs the message with from_agent's own
        registered key (see trust.register_agent_identity, set up
        automatically at admit_agent() time) and calls send(). This is
        the supported way to send once require_message_signatures=True
        -- prefer this over calling send() directly with a hand-built
        signature/nonce."""
        import secrets as _secrets
        nonce = _secrets.token_hex(8)
        payload_bytes = self.canonical_message_bytes(from_agent, to_agent, action_type, payload, nonce)
        signature = self.trust.sign_message(from_agent, payload_bytes)
        return self.send(from_agent, from_org, to_agent, to_org, action_type, payload,
                          taint_delta=taint_delta, signature=signature, nonce=nonce)

    @_locked
    def _block_pre_send(self, from_agent: str, to_agent: str, reason: str) -> Dict:
        """Shared helper for the fail-closed pre-send gates below --
        keeps the audit row + structured log + return value in sync
        for every early-BLOCK path instead of repeating all three at
        each call site."""
        self._write_audit_row(None, from_agent, to_agent, Decision.BLOCK.value, 0.0, reason)
        log.warning("bus decision", extra={
            "event": "bus_decision", "decision": Decision.BLOCK.value,
            "from_agent": from_agent, "to_agent": to_agent, "taint_level": 0.0, "reason": reason})
        return {"message_id": None, "decision": Decision.BLOCK.value,
                "taint_level": 0.0, "reason": reason}

    def send(self, from_agent: str, from_org: str, to_agent: str, to_org: str,
              action_type: str, payload: Dict, taint_delta: float = 0.0,
              signature: Optional[str] = None, nonce: Optional[str] = None) -> Dict:
        # 0. Identity admission gate -- fail CLOSED, before the message
        #    touches the taint graph or the orchestration layer at all.
        if not self._is_admitted(from_agent, from_org):
            return self._block_pre_send(from_agent, to_agent, "unadmitted_identity")

        # 0b. PENTEST FINDING (fixed, PT-08): per-message Zero-Trust
        #     signature check -- possession of an admitted agent_id/org
        #     pair is no longer sufficient on its own (see __init__
        #     docstring; on by default as of v4).
        if self.require_message_signatures:
            self._prune_expired_message_nonces()
            if signature is None or nonce is None:
                return self._block_pre_send(from_agent, to_agent, "missing_message_signature")
            if nonce in self._message_nonce_expiry:
                return self._block_pre_send(from_agent, to_agent, "message_replayed")
            session_did = self.admitted_sessions[from_agent]["did"]
            payload_bytes = self.canonical_message_bytes(from_agent, to_agent, action_type, payload, nonce)
            try:
                did_to_public_key(session_did).verify(decode_signature(signature), payload_bytes)
            except InvalidSignature:
                return self._block_pre_send(from_agent, to_agent, "invalid_message_signature")
            # retain the nonce only for message_nonce_ttl_seconds -- long
            # enough to catch a realistic replay window, not forever
            self._message_nonce_expiry[nonce] = time.time() + self.message_nonce_ttl_seconds

        message_id = str(uuid.uuid4())
        self.total_messages += 1

        # 1. Provenance-aware taint propagation (BEFORE the policy check,
        #    so the orchestration layer can react to accumulated taint)
        self.taint.propagate(message_id, from_agent, to_agent, to_org, taint_delta)
        taint_level = self.taint.taints[message_id].taint_level
        if self.taint.is_tainted(message_id):
            self.tainted_messages += 1

        # 2. Secure orchestration & behavioural governance decision (agent-level)
        # ADR-010 (cross-cloud build): records whether this hop crosses an
        # org boundary -- in a genuine two-cloud deployment, also a network
        # boundary (ADR-001/ADR-004). Observational only; does not change
        # send()'s own control flow, only what evaluate() logs.
        crosses_org_boundary = (from_org != to_org)
        event = ActionEvent(agent_id=from_agent, org=from_org, action_type=action_type,
                             payload=payload, taint_score=taint_level,
                             crosses_org_boundary=crosses_org_boundary)

        # Phase 1 item 2 (v7.4): mark every message BEFORE evaluating it,
        # so detection latency is measured from the first message
        # involving this key, not from whenever detection happens to
        # occur. Tracked at both agent- and org- granularity (prefixed
        # keys) since detectors trip at both levels.
        now = time.time()
        self.detection_latency_tracker.mark_message(f"agent:{from_agent}", now)
        self.detection_latency_tracker.mark_message(f"org:{from_org}", now)

        decision = self.orchestration.evaluate(event)
        if decision == Decision.QUARANTINE:
            agent_detector_reason = self.orchestration.audit_log[-1]["reason"]
            if agent_detector_reason in ("behavioural_drift_cusum", "behavioural_drift_sliding_window"):
                self.detection_latency_tracker.mark_detected(f"agent:{from_agent}", now, agent_detector_reason)

        # 2b. PENTEST FINDING (fixed, PT-04): org-level rolling volume,
        #     independent of the per-agent checks above, to catch a
        #     Sybil-fragmented attack that stays under every individual
        #     agent's threshold but not under the organisation's. Only
        #     consulted when the per-agent layer already said ALLOW --
        #     if a per-agent rule already caught this message, that
        #     reason is more specific and must not be masked by the
        #     coarser org-level one. Gated on governance_enabled so a
        #     "no governance" comparator orchestration layer (see
        #     tests/test_04_*) is a true apples-to-apples baseline.
        if decision == Decision.ALLOW and getattr(self.orchestration, "governance_enabled", True) and \
                self.org_volume_detector.update(from_org, taint_delta):
            self._quarantine_org(from_org)
            decision = Decision.QUARANTINE
            self.orchestration._log(event, decision, "org_wide_behavioural_drift")
            self.recovery_tracker.mark_quarantined(from_org, time.time())
            self.detection_latency_tracker.mark_detected(f"org:{from_org}", now, "org_wide_behavioural_drift")

        # 2c. Phase 1 item 4 (v7.4): structurally independent, topology-
        #     based detector -- catches an attacker who keeps every
        #     taint_delta arbitrarily small (evading 2a/2b by
        #     construction, since neither tracks WHO messages go to) but
        #     rapidly contacts many distinct targets. Same "only if
        #     still ALLOW" gating as 2b, for the same reason.
        if decision == Decision.ALLOW and getattr(self.orchestration, "governance_enabled", True) and \
                self.fanout_detector.update(from_agent, to_agent):
            self.orchestration.quarantined_agents.add(from_agent)
            decision = Decision.QUARANTINE
            self.orchestration._log(event, decision, "fanout_anomaly")
            self.recovery_tracker.mark_quarantined(from_agent, time.time())
            self.detection_latency_tracker.mark_detected(f"agent:{from_agent}", now, "fanout_anomaly")

        # 3. Containment: sever outgoing taint edges from quarantined agents
        if decision == Decision.QUARANTINE:
            self.taint.quarantine_edges_from(from_agent)
            self.recovery_tracker.mark_quarantined(from_agent, time.time())

        # 4. Persist to the audit trail (forensic repository, hash-chained)
        reason = self.orchestration.audit_log[-1]["reason"] if self.orchestration.audit_log else ""
        self._write_audit_row(message_id, from_agent, to_agent, decision.value, taint_level, reason)

        # v7.7: structured, level-scaled operational log alongside the
        # durable SQLite audit row -- lets an operator/SIEM watch
        # decisions live without querying the DB. ALLOW is the common
        # case (DEBUG, not chatty by default); BLOCK/QUARANTINE are the
        # cases an operator actually needs surfaced (WARNING/ERROR).
        log_fn = {Decision.ALLOW: log.debug, Decision.BLOCK: log.warning,
                  Decision.QUARANTINE: log.error}[decision]
        log_fn("bus decision", extra={
            "event": "bus_decision", "decision": decision.value, "from_agent": from_agent,
            "from_org": from_org, "to_agent": to_agent, "to_org": to_org,
            "action_type": action_type, "taint_level": round(taint_level, 3), "reason": reason})

        return {"message_id": message_id, "decision": decision.value,
                "taint_level": round(taint_level, 3), "reason": reason}

    # ---- memory / context integrity (v6, ASI06 fix) ----------------------
    @staticmethod
    def canonical_memory_bytes(owner_agent_id: str, key: str, value: Dict, nonce: str) -> bytes:
        body = {"agent_id": owner_agent_id, "key": key, "value": value, "nonce": nonce}
        return json.dumps(body, sort_keys=True).encode()

    def sign_and_write_memory(self, owner_agent_id: str, key: str, value: Dict,
                               writer_agent_id: Optional[str] = None) -> Dict:
        """Supported entry point: signs the write with the WRITER's own
        registered key (defaults to owner_agent_id itself, i.e. a
        self-write) and calls write_memory(). If writer_agent_id differs
        from owner_agent_id, this is a delegated write and requires an
        active grant from grant_memory_delegation() -- see write_memory()."""
        import secrets as _secrets
        writer_agent_id = writer_agent_id or owner_agent_id
        nonce = _secrets.token_hex(8)
        payload_bytes = self.canonical_memory_bytes(owner_agent_id, key, value, nonce)
        signature = self.trust.sign_message(writer_agent_id, payload_bytes)
        return self.write_memory(owner_agent_id, key, value, writer_agent_id=writer_agent_id,
                                  signature=signature, nonce=nonce)

    @_locked
    def write_memory(self, owner_agent_id: str, key: str, value: Dict,
                      writer_agent_id: Optional[str] = None,
                      signature: Optional[str] = None, nonce: Optional[str] = None) -> Dict:
        """
        PENTEST FINDING (fixed, PT-10): reuses the exact same Zero-Trust
        signing/replay machinery as send() (PT-08), applied to memory
        writes instead of inter-agent messages -- an admitted session,
        a valid Ed25519 signature over the write's own content verified
        against the WRITER's did:key, and a single-use TTL-bounded
        nonce.

        v7.1 -- delegated writes: `writer_agent_id` (default:
        `owner_agent_id`, i.e. a self-write) may be a DIFFERENT admitted
        agent, but only if `owner_agent_id` has an active, unexpired
        grant naming that writer for this key (or for all keys) via
        grant_memory_delegation(). The signature is always verified
        against the WRITER's own did -- nobody without the writer's
        private key can produce it regardless of what the grant says --
        so a forged delegation claim still can't produce a valid write;
        the grant only widens WHO is allowed to write into
        owner_agent_id's namespace, it never substitutes for proof of
        key possession.
        """
        writer_agent_id = writer_agent_id or owner_agent_id
        writer_session = self.admitted_sessions.get(writer_agent_id)
        if writer_session is None or not self._is_admitted(writer_agent_id, writer_session["org"]):
            return {"written": False, "reason": "unadmitted_identity"}
        if writer_agent_id != owner_agent_id and not self._has_valid_memory_delegation(
                owner_agent_id, writer_agent_id, key):
            return {"written": False, "reason": "no_delegation_grant"}
        if signature is None or nonce is None:
            return {"written": False, "reason": "missing_write_signature"}
        self._prune_expired_message_nonces()
        if nonce in self._message_nonce_expiry:
            return {"written": False, "reason": "write_replayed"}
        payload_bytes = self.canonical_memory_bytes(owner_agent_id, key, value, nonce)
        try:
            did_to_public_key(writer_session["did"]).verify(decode_signature(signature), payload_bytes)
        except InvalidSignature:
            return {"written": False, "reason": "invalid_write_signature"}
        self._message_nonce_expiry[nonce] = time.time() + self.message_nonce_ttl_seconds
        record = self.memory.write(owner_agent_id, key, value, writer_agent_id=writer_agent_id,
                                    writer_did=writer_session["did"])
        return {"written": True, "record_hash": record.record_hash, "content_hash": record.content_hash}

    # ---- delegated memory writes (v7.1) -----------------------------------
    @staticmethod
    def canonical_grant_bytes(owner_agent_id: str, delegate_agent_id: str,
                               keys: Optional[Set[str]], expires_at: float, nonce: str) -> bytes:
        body = {"owner": owner_agent_id, "delegate": delegate_agent_id,
                "keys": sorted(keys) if keys else None, "expires_at": expires_at, "nonce": nonce}
        return json.dumps(body, sort_keys=True).encode()

    def sign_and_grant_memory_delegation(self, owner_agent_id: str, delegate_agent_id: str,
                                          keys: Optional[Set[str]] = None,
                                          ttl_seconds: float = 300.0) -> Dict:
        """Supported entry point: owner_agent_id signs its own grant with
        its own key (never the delegate's) and calls grant_memory_delegation()."""
        import secrets as _secrets
        nonce = _secrets.token_hex(8)
        expires_at = time.time() + ttl_seconds
        payload_bytes = self.canonical_grant_bytes(owner_agent_id, delegate_agent_id, keys, expires_at, nonce)
        signature = self.trust.sign_message(owner_agent_id, payload_bytes)
        return self.grant_memory_delegation(owner_agent_id, delegate_agent_id, keys=keys,
                                             expires_at=expires_at, signature=signature, nonce=nonce)

    @_locked
    def grant_memory_delegation(self, owner_agent_id: str, delegate_agent_id: str,
                                 keys: Optional[Set[str]] = None, expires_at: Optional[float] = None,
                                 signature: Optional[str] = None, nonce: Optional[str] = None) -> Dict:
        """
        An agent can only delegate write access to its OWN memory
        namespace, and only via a grant signed with its own key (never
        by the delegate, and never by an operator on its behalf) --
        consistent with every other Zero-Trust surface in this
        codebase: a capability is only as strong as who can prove they
        issued it. `keys=None` grants all keys; a set restricts to
        specific ones. The write itself (write_memory) still separately
        requires the delegate's own valid signature -- this grant only
        widens WHO is allowed, it is not itself sufficient to write.
        """
        owner_session = self.admitted_sessions.get(owner_agent_id)
        if owner_session is None or not self._is_admitted(owner_agent_id, owner_session["org"]):
            return {"granted": False, "reason": "owner_not_admitted"}
        if signature is None or nonce is None or expires_at is None:
            return {"granted": False, "reason": "missing_grant_signature"}
        self._prune_expired_message_nonces()
        if nonce in self._message_nonce_expiry:
            return {"granted": False, "reason": "grant_replayed"}
        payload_bytes = self.canonical_grant_bytes(owner_agent_id, delegate_agent_id, keys, expires_at, nonce)
        try:
            did_to_public_key(owner_session["did"]).verify(decode_signature(signature), payload_bytes)
        except InvalidSignature:
            return {"granted": False, "reason": "invalid_grant_signature"}
        self._message_nonce_expiry[nonce] = time.time() + self.message_nonce_ttl_seconds
        grants = self.memory_delegations.setdefault(owner_agent_id, [])
        grants.append({"delegate": delegate_agent_id, "keys": set(keys) if keys else None,
                        "expires_at": expires_at})
        return {"granted": True, "expires_at": expires_at}

    def _has_valid_memory_delegation(self, owner_agent_id: str, delegate_agent_id: str, key: str) -> bool:
        now = time.time()
        for grant in self.memory_delegations.get(owner_agent_id, []):
            if grant["delegate"] == delegate_agent_id and grant["expires_at"] >= now:
                if grant["keys"] is None or key in grant["keys"]:
                    return True
        return False

    def read_memory(self, agent_id: str, key: str) -> Optional[Dict]:
        """Returns the current record's value plus its content_hash --
        callers implementing a check/use pattern should capture
        content_hash at "check" time and pass both hashes through a
        memory_recall_use message (see orchestration.py's
        memory_toctou_mismatch rule) so a mutation between check and
        use is caught the same way execute_action's TOCTOU rule already
        catches a mutated external resource.

        v7.7: `value` is decrypted via memory.decrypt(). Note that a
        crypto-shredded key looks identical to an ordinary
        revoke_memory_record() tombstone from THIS method's point of
        view -- both mean "no current value" and both return None here,
        by design (an ordinary reader shouldn't be able to tell the
        difference between "revoked" and "erased" any more than they
        could read either). Use inspect_memory_history() for the
        compliance-reviewer view that DOES distinguish the two."""
        record = self.memory.read(agent_id, key)
        if record is None:
            return None
        value = self.memory.decrypt(record)
        return {"key": record.key, "value": value, "content_hash": record.content_hash,
                "writer_agent_id": record.writer_agent_id, "writer_did": record.writer_did,
                "timestamp": record.timestamp}

    def verify_memory_integrity(self, agent_id: str) -> Dict:
        return self.memory.verify_integrity(agent_id)

    @_locked
    def revoke_memory_record(self, agent_id: str, key: str, reason: str = "poisoned",
                              mode: str = "tombstone") -> Dict:
        """
        v7.1 (10's documented gap, now closed): purges ONE
        specific already-written memory record without revoking the
        agent's whole identity. This is an OPERATOR action -- like
        revoke_agent(), it's called out-of-band by whoever runs the bus,
        not signed by an in-federation agent, since the premise is
        exactly that the record in question might have been written by
        an agent that's since turned out to be compromised (its own
        signature on the bad write is not evidence it should be trusted
        to also sign the record's removal).

        v7.9.10: `mode` is the single configurable choice-point the
        thesis supervisor asked for (see memory_store.py's
        revoke_record() docstring for the full correction/rationale --
        both underlying mechanisms already existed before this change;
        what was missing was exactly this one-parameter dispatcher).
          - mode="tombstone" (default, unchanged from v7.1): appends a
            tombstone rather than mutating history -- see
            memory_store.py's module docstring for why. The key remains
            writable afterward: a fresh legitimate write simply becomes
            the new latest (non-tombstone) record. Non-destructive --
            the right choice when data-retention policy requires the
            revoked value to stay recoverable for compliance review.
          - mode="crypto_shred": destructive, permanent. Delegates to
            erase_memory_record() below (the actual GDPR Art. 17 path,
            unchanged) rather than duplicating its audit-row-writing
            logic -- so calling revoke_memory_record(..., mode=
            "crypto_shred") and calling erase_memory_record() directly
            are equivalent, not two different code paths that could
            drift apart.
        """
        if mode == "crypto_shred":
            result = self.erase_memory_record(agent_id, key, reason=reason)
            # Normalised so a caller of revoke_memory_record() gets a
            # consistent {"revoked": bool, "mode": str, ...} shape
            # regardless of which mode they picked, instead of having to
            # branch on mode to know which keys exist. erase_memory_record()
            # itself is untouched -- its own direct callers still get its
            # original {"erased": ..., "records_shredded": ...} shape.
            return {**result, "revoked": result.get("erased", False), "mode": "crypto_shred",
                    "record_hash": result.get("marker_record_hash")}
        if mode != "tombstone":
            raise ValueError(f"mode must be 'tombstone' or 'crypto_shred', got {mode!r}")
        record = self.memory.revoke_record(agent_id, key, revoker_agent_id="__operator__",
                                             revoker_did="did:key:operator", reason=reason,
                                             mode="tombstone")
        if record is None:
            return {"revoked": False, "reason": "no_such_record"}
        return {"revoked": True, "record_hash": record.record_hash, "mode": "tombstone"}

    @_locked
    def erase_memory_record(self, agent_id: str, key: str,
                             reason: str = "gdpr_article_17") -> Dict:
        """
        v7.7 -- the actual GDPR Art. 17 "right to erasure" entry point
        (distinct from revoke_memory_record(), which only hides a
        record from ordinary reads while leaving it forensically
        recoverable via the chain -- see memory_store.py's module
        docstring for why those are genuinely different operations).
        This is also an OPERATOR action, same rationale as
        revoke_memory_record(): called out-of-band in response to an
        erasure request, not signed by an in-federation agent, since
        the value being erased might itself be what a compromised
        agent wrote.
        """
        result = self.memory.erase_record_for_subject(
            agent_id, key, eraser_agent_id="__operator__",
            eraser_did="did:key:operator", reason=reason)
        self._write_audit_row(None, "__operator__", agent_id, "memory_erased", 0.0,
                               f"gdpr_erasure:{key}:{result['records_shredded']}_records")
        return result

    def inspect_memory_history(self, agent_id: str, key: str) -> List[Dict]:
        """Compliance-reviewer view: walks the FULL chain for `key`
        (not just the current record), reporting each record's
        recoverability without ever attempting to decrypt an erased
        one. This is what distinguishes "revoked" (hidden from reads,
        but a compliance reviewer with access to this method can still
        see it existed and, if not crypto-shredded, still recover it)
        from "erased" (permanently unrecoverable, key discarded) --
        deliberately not exposed via read_memory(), which only ever
        answers "what's the current value", not "what happened here".
        """
        history = []
        for r in self.memory.get_chain(agent_id):
            if r.key != key:
                continue
            recoverable = self.memory.decrypt(r) is not None
            history.append({
                "record_hash": r.record_hash, "timestamp": r.timestamp,
                "writer_agent_id": r.writer_agent_id, "tombstone": r.tombstone,
                "crypto_shredded": r.crypto_shredded, "tombstone_reason": r.tombstone_reason,
                "recoverable": recoverable,
            })
        return history

    def _quarantine_org(self, org: str):
        """Contain every currently-known agent belonging to `org` in one
        step -- the response to a detected org-wide (Sybil) attack."""
        quarantined_agents = []
        for node, data in self.adversary_model.graph.nodes(data=True):
            if data.get("org") == org:
                self.orchestration.quarantined_agents.add(node)
                self.taint.quarantine_edges_from(node)
                self.admitted_sessions.pop(node, None)
                quarantined_agents.append(node)
        self.federation_wide_quarantined.add(org)
        log.error("organisation quarantined", extra={
            "event": "org_quarantine", "org": org, "agents_quarantined": quarantined_agents})

    # ---- tamper-evident audit log ----------------------------------------
    def _encrypt_field(self, plaintext: str) -> str:
        aesgcm = AESGCM(self._audit_encryption_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.urlsafe_b64encode(nonce + ct).decode()

    def _decrypt_field(self, blob_b64: str) -> str:
        raw = base64.urlsafe_b64decode(blob_b64.encode())
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(self._audit_encryption_key).decrypt(nonce, ct, None).decode()

    def _write_audit_row(self, message_id: Optional[str], from_agent: str, to_agent: str,
                          decision: str, taint_level: float, reason: str):
        """
        v7.5 (LINDDUN fix): what's PERSISTED to disk here is
        pseudonymized (from_agent/to_agent) and the reason field is
        encrypted -- see the class docstring's encryption-key comment
        and trust_protocol.FederatedTrustProtocol's pseudonym registry.
        This is deliberately separate from `self.orchestration.audit_log`
        (the in-memory list many pentest scripts/detectors consult
        directly), which keeps using REAL identifiers -- that list never
        leaves this process and is exactly what CUSUM/revocation/
        accountability need; pseudonymization only applies to what could
        leave the process via a stolen DB file or an audit export.

        v7.6 (audit-write failure handling -- THREAT_MODEL.md Section 17,
        pentest/pt21_audit_write_resilience.py): the row's position in
        the hash chain (prev_hash/row_hash) is now fixed the moment this
        method is CALLED, not the moment the write successfully commits.
        This matters for correctness under failure: if self._last_row_hash
        only advanced after a successful commit (the old behaviour, by
        virtue of the exception aborting before that line was reached),
        a caller that catches and continues past a failed write would
        compute the NEXT row's prev_hash against a stale pointer -- two
        logically-different rows would both claim the same prev_hash
        once persistence eventually catches up, breaking the chain's
        ordering guarantee. Advancing unconditionally means the chain
        always reflects true event order, independent of which rows
        have actually reached disk yet; verify_audit_integrity() only
        ever walks what IS persisted, so a gap from buffered-but-not-
        yet-flushed rows is invisible to it by design -- those rows
        simply aren't in the table until flush_buffered_audit_rows()
        (or the opportunistic flush below) succeeds.
        """
        ts = time.time()
        before_count = len(self.trust.pseudonym_to_agent)
        persisted_from = self.trust.pseudonym_for(from_agent) if from_agent else from_agent
        persisted_to = self.trust.pseudonym_for(to_agent) if to_agent else to_agent
        if len(self.trust.pseudonym_to_agent) != before_count:
            # a NEW pseudonym was minted this call -- persist immediately
            # so it survives a restart; unchanged calls (existing
            # pseudonym reused) skip the disk write.
            self.trust.save_pseudonym_registry(self._pseudonym_registry_path)
        persisted_reason = self._encrypt_field(reason) if reason else reason
        row_repr = f"{ts}|{message_id}|{persisted_from}|{persisted_to}|{decision}|{taint_level}|{persisted_reason}|{self._last_row_hash}"
        row_hash = hashlib.sha256(row_repr.encode()).hexdigest()
        row_values = (ts, message_id, persisted_from, persisted_to, decision, taint_level,
                      persisted_reason, self._last_row_hash, row_hash)
        self._last_row_hash = row_hash  # advance the chain BEFORE attempting persistence -- see docstring

        # Opportunistic self-healing: if earlier rows are still waiting
        # to be flushed, try them first so persisted rows stay in order
        # on disk. A failure here just re-buffers and falls through to
        # buffering the current row too -- never raises.
        if self._audit_write_buffer:
            self._flush_buffered_audit_rows_locked()

        try:
            self.db.execute(
                "INSERT INTO audit (timestamp, message_id, from_agent, to_agent, decision, taint_level, "
                "reason, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                row_values,
            )
            self.db.commit()
        except sqlite3.Error as exc:
            # PENTEST FINDING (fixed, v7.6 / audit-write resilience): this
            # used to propagate uncaught, crashing whatever public method
            # called it. The security decision (allow/block/quarantine)
            # has ALREADY been made by this point -- that decision stands
            # regardless of whether the audit row makes it to disk
            # immediately, buffered, or later on flush.
            self._audit_write_buffer.append(row_values)
            self._audit_write_failures += 1
            log.warning("audit write failed; row buffered", extra={
                "event": "audit_write_failed", "error": str(exc),
                "buffered_rows": len(self._audit_write_buffer),
                "total_failures_this_session": self._audit_write_failures})

    def _flush_buffered_audit_rows_locked(self) -> int:
        """
        Internal helper -- assumes the caller already holds self._lock
        (both call sites, _write_audit_row and the public
        flush_buffered_audit_rows(), are reached only from @_locked
        methods or acquire the lock themselves). Flushes buffered rows
        IN ORDER, stopping at the first failure so on-disk ordering is
        preserved -- never reorders, never skips ahead.
        """
        flushed = 0
        while self._audit_write_buffer:
            row_values = self._audit_write_buffer[0]
            try:
                self.db.execute(
                    "INSERT INTO audit (timestamp, message_id, from_agent, to_agent, decision, "
                    "taint_level, reason, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    row_values,
                )
                self.db.commit()
            except sqlite3.Error:
                break  # still down -- leave remaining buffered rows in place, in order
            self._audit_write_buffer.pop(0)
            flushed += 1
        return flushed

    @_locked
    def flush_buffered_audit_rows(self) -> Dict:
        """
        Public, explicitly-callable retry path for rows that failed to
        persist earlier (e.g. an operator/health-check calling this
        after confirming disk space was freed or a permissions issue
        was fixed). Also called opportunistically inside
        _write_audit_row() itself, so recovery is automatic on the next
        message even if nobody calls this directly -- this method exists
        for callers who want to force/confirm a flush (or check
        `pending` without waiting for more traffic).
        """
        flushed = self._flush_buffered_audit_rows_locked()
        return {"flushed": flushed, "pending": len(self._audit_write_buffer),
                "total_failures_this_session": self._audit_write_failures}

    def read_audit_log(self, resolve_identities: bool = False) -> List[Dict]:
        """
        Legitimate read path for the persisted (pseudonymized, reason-
        encrypted) audit table -- decrypts `reason` automatically (this
        running process holds the key), and resolves pseudonyms back to
        real agent_ids ONLY if resolve_identities=True, an explicit
        bus-operator escalation for legitimate investigation, not the
        default. Someone reading the raw SQLite file directly (bypassing
        this method entirely) sees neither.
        """
        rows = self.db.execute(
            "SELECT timestamp, message_id, from_agent, to_agent, decision, taint_level, reason "
            "FROM audit ORDER BY id ASC"
        ).fetchall()
        result = []
        for ts, message_id, from_agent, to_agent, decision, taint_level, reason in rows:
            entry = {
                "timestamp": ts, "message_id": message_id,
                "from_agent": from_agent, "to_agent": to_agent,
                "decision": decision, "taint_level": taint_level,
                "reason": self._decrypt_field(reason) if reason else reason,
            }
            if resolve_identities:
                entry["from_agent"] = self.trust.resolve_pseudonym(from_agent) or from_agent
                entry["to_agent"] = self.trust.resolve_pseudonym(to_agent) or to_agent
            result.append(entry)
        return result

    def verify_audit_integrity(self) -> Dict:
        """
        Walks the audit hash chain and reports whether it's intact.
        Detects tampering/deletion of past rows (each row's hash commits
        to the previous row's hash). Documented limitation: this is
        tamper-EVIDENT, not tamper-PROOF -- an attacker with full DB
        write access and enough patience could recompute the whole chain
        forward after an edit. True tamper-proofing needs external
        anchoring or a signing key the DB itself never holds.
        """
        rows = self.db.execute(
            "SELECT timestamp, message_id, from_agent, to_agent, decision, taint_level, "
            "reason, prev_hash, row_hash FROM audit ORDER BY id ASC"
        ).fetchall()
        expected_prev = GENESIS_HASH
        for i, row in enumerate(rows):
            ts, message_id, from_agent, to_agent, decision, taint_level, reason, prev_hash, row_hash = row
            if prev_hash != expected_prev:
                return {"intact": False, "first_broken_row": i, "reason": "prev_hash_mismatch"}
            recomputed = hashlib.sha256(
                f"{ts}|{message_id}|{from_agent}|{to_agent}|{decision}|{taint_level}|{reason}|{prev_hash}".encode()
            ).hexdigest()
            if recomputed != row_hash:
                return {"intact": False, "first_broken_row": i, "reason": "row_hash_mismatch"}
            expected_prev = row_hash
        return {"intact": True, "rows_checked": len(rows)}

    # ---- resilience scoring ---------------------------------------------
    def current_fars(self) -> Dict:
        total_agents = self.adversary_model.graph.number_of_nodes() or 1
        max_blast_fraction = self.taint.max_blast_radius_fraction(total_agents)
        result = self.fars_engine.compute(
            graph=self.adversary_model.graph,
            quarantined_agents=len(self.orchestration.quarantined_agents),
            total_agents=total_agents,
            tainted_messages=self.tainted_messages,
            total_messages=self.total_messages or 1,
            policy_violations=sum(1 for e in self.orchestration.audit_log if e["decision"] != "allow"),
            total_events=len(self.orchestration.audit_log) or 1,
            max_blast_radius_fraction=max_blast_fraction,
        )
        # v7: EWMA gives the snapshot memory of recent trajectory instead
        # of being purely point-in-time -- see fars.py's compute_ewma docstring.
        self._fars_ewma = self.fars_engine.compute_ewma(result["FARS"], self._fars_ewma, alpha=self.fars_ewma_alpha)
        result["FARS_ewma"] = round(self._fars_ewma, 2)
        self.fars_history.append({"timestamp": time.time(), "FARS": result["FARS"], "FARS_ewma": result["FARS_ewma"]})
        if len(self.fars_history) > self._fars_history_cap:
            self.fars_history.pop(0)
        return result

    def recovery_time_stats(self) -> Dict:
        """Distinct from the steady-state FARS score: how long, on
        average, does it actually take to go from quarantined to
        reinstated in this run? See fars.RecoveryTimeTracker."""
        return self.recovery_tracker.stats()

    def detection_latency_stats(self) -> Dict:
        """Phase 1 item 2 (v7.4): how many messages/how much wall-clock
        time elapsed before an attack was first detected, broken down
        PER DETECTOR FAMILY (behavioural_drift_cusum,
        behavioural_drift_sliding_window, org_wide_behavioural_drift,
        fanout_anomaly) -- see fars.DetectionLatencyTracker."""
        return self.detection_latency_tracker.stats_by_detector()

    def resilience_timing_report(self) -> Dict:
        """Combined report pairing detection latency with recovery
        time -- the full resilience timeline in one place: how fast an
        attack was caught (detection_latency, broken down per detector
        family) and how fast the federation recovered afterward
        (recovery_time). Neither alone tells the whole story: a
        federation could detect fast but recover slowly, or vice versa,
        and only reporting one would hide that trade-off."""
        return {
            "detection_latency_by_detector": self.detection_latency_stats(),
            "recovery_time": self.recovery_time_stats(),
        }

    def close(self):
        # v7.6: give the buffer one last chance to drain before shutdown
        # -- if the DB recovered but nothing triggered an opportunistic
        # flush (e.g. no further send() calls happened), don't lose rows
        # unnecessarily on a clean close.
        if self._audit_write_buffer:
            with self._lock:
                self._flush_buffered_audit_rows_locked()
            if self._audit_write_buffer:
                log.error("closing with unpersisted audit rows -- will be lost", extra={
                    "event": "audit_data_loss_on_close",
                    "unpersisted_rows": len(self._audit_write_buffer)})
        self.db.close()
