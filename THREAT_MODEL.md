# FARF Prototype -- Threat Model & Penetration Test Report

Scope: the five FARF artefacts and the Federation Bus integration layer,
as implemented in this prototype. Methodology: STRIDE per component,
each material finding backed by a runnable exploit script in `pentest/`
run against the actual code (not a theoretical exercise). Severity uses
a simple High/Medium/Low scale based on (a) how directly the finding
undermines FARF's core resilience claim and (b) how cheap the exploit
is to mount.

**Headline result: 6/6 scripted exploits succeeded against the
pre-hardening code.** All six are now fixed (see Section 4) and the
same scripts are re-run in Section 5 to confirm mitigation.

---

## 1. Component inventory

| # | Component | File | Trust boundary it sits on |
|---|---|---|---|
| 1 | Federated Adversary Model | `adversary_model.py` | Structural/offline -- no external input at runtime |
| 2 | Federated Trust Protocol | `trust_protocol.py` | Org <-> Org identity/credential exchange |
| 3 | Secure Orchestration & Behavioural Governance | `orchestration.py` | Agent <-> Federation Bus action admission |
| 4 | Provenance-aware Taint Propagation Engine | `taint_engine.py` | Message <-> Message provenance/propagation |
| 5 | Federated Adversarial Resilience Score (FARS) | `fars.py` | Aggregation/reporting -- consumes 1-4's outputs |
| 6 | Federation Bus (integration layer) | `federation_bus.py` | **The actual trust boundary**: everything above is only as strong as what this file enforces |

---

## 2. STRIDE analysis per component

### 2.1 Federation Bus (integration layer) -- the critical path

| STRIDE | Finding | Severity | Evidence |
|---|---|---|---|
| **Spoofing** | `send()` accepts `from_agent`/`from_org` as bare, unverified strings. Artefact 2 (Trust Protocol) and artefacts 3/4 (Orchestration/Taint) are **not cryptographically linked** -- nothing requires a caller to have ever presented a valid credential before originating traffic. | **HIGH** | `pentest/pt01_identity_spoofing.py` -- forged identity `allow`ed, zero credential check |
| **Tampering** | The SQLite audit log has no integrity protection. Anyone with filesystem access (or a bug elsewhere in the process) can rewrite/delete rows with no detection. For a *forensic/resilience* framework this is a foundational gap -- the evidence trail itself isn't trustworthy. | **HIGH** | Code review: `_init_db()` schema has no hash/signature columns |
| **Repudiation** | Because of the above, an organisation could plausibly deny an audit entry ever existed ("prove the log wasn't altered"). | MEDIUM | Consequence of Tampering finding above |
| **Denial of Service** | `current_fars()` calls `nx.average_node_connectivity()`, which is expensive on larger graphs. Called after every message, on an unbounded federation size (nothing caps registered agents), this is a resource-exhaustion vector if an attacker can get many Sybil agents registered. | MEDIUM | Code review; not separately scripted (shares root cause with PT-04) |
| **Elevation of Privilege** | `reinstate()` is callable with zero authorisation (see 2.3). | HIGH | `pentest/pt05_unauthorised_reinstatement.py` |

### 2.2 Federated Trust Protocol (`trust_protocol.py`)

| STRIDE | Finding | Severity | Evidence |
|---|---|---|---|
| **Information Disclosure** | `issue_zk_attestation()` returns the salt in the *same* object as the commitment. Anyone who intercepts the attestation can mount an offline dictionary attack against the underlying secret with zero interaction with the issuer -- this isn't zero-knowledge in any meaningful sense, it's a hash the caller already holds the key to open. | **HIGH** | `pentest/pt06_zk_salt_exposure.py` -- secret fully recovered offline |
| **Denial of Service** | `_seen_nonces` is an unbounded, never-pruned Python `set`. A long-running federation with legitimate high credential throughput grows this forever -- a slow memory-exhaustion leak, not an attack exactly, but a real operational hazard. | MEDIUM | Code review |
| **Repudiation / no revocation** | There is no revocation registry (CRL/status-list equivalent). If a private key is compromised, the `did:key` identity is untrustworthy *forever* with no way to signal that federation-wide. | MEDIUM | Code review -- architectural gap, not scripted |
| **Spoofing (mitigated)** | Replay and issuer-spoofing are correctly caught (`replay_detected`, `unknown_or_spoofed_issuer`) -- this is the one sub-area of the protocol that held up under testing. | -- (control passed) | Covered by `test_02_attack_detection.py::test_e3_*` |

### 2.3 Secure Orchestration & Behavioural Governance (`orchestration.py`)

| STRIDE | Finding | Severity | Evidence |
|---|---|---|---|
| **Tampering (rule bypass)** | Both the TOCTOU rule and the privilege-ceiling rule trust attacker-controlled payload fields as ground truth. Omitting the field the rule inspects makes the predicate `False` by default -- the rule silently doesn't fire, rather than failing closed. | **HIGH** | `pentest/pt02_field_omission_bypass.py` -- both rules bypassed by omission |
| **Tampering (CUSUM evasion)** | `CUSUMDetector`'s slack `k=0.05` is a hardcoded, disclosed, static parameter. Any agent contributing taint `<= k` per message keeps its cumulative sum at zero *forever*, regardless of message volume. | **HIGH** | `pentest/pt03_cusum_slow_drip.py` -- 200 tainted messages, zero containment |
| **Elevation of Privilege** | `reinstate(agent_id)` has no authorisation parameter at all -- any code holding a reference to the orchestration object can clear any agent's quarantine with zero proof of remediation, contradicting the "Trust Recalibration" step in the diagram (which implies re-attestation is required). | **HIGH** | `pentest/pt05_unauthorised_reinstatement.py` |
| **Denial of Service (implicit)** | No detection is aggregated above the single-agent level -- see Taint Engine / Federation Bus row on Sybil attacks. | HIGH | `pentest/pt04_distributed_sybil_attack.py` |
| **Repudiation (mitigated)** | Every decision is logged with agent, org, action_type, decision, and reason -- this part of the design is sound, it's the *input trust* and *authorisation* around it that's weak. | -- (control passed) | -- |

### 2.4 Provenance-aware Taint Propagation Engine (`taint_engine.py`)

| STRIDE | Finding | Severity | Evidence |
|---|---|---|---|
| **Spoofing (Sybil)** | Taint tracking is keyed purely by `agent_id` strings with no identity binding (same root cause as 2.1's Spoofing finding). An attacker can fragment an attack across many synthetic agent identities to stay under every per-identity signal. | **HIGH** | `pentest/pt04_distributed_sybil_attack.py` |
| **Denial of Service (containment cost)** | `quarantine_edges_from()` is only called from `FederationBus.send()`'s synchronous, single-threaded call path. If the bus were ever made concurrent/async (a near-certain requirement for a real deployment), there's a TOCTOU race between `propagate()` adding an edge and `evaluate()` deciding to quarantine -- i.e. the defensive system has the exact same vulnerability class it's designed to detect in the agents it's protecting. Not exploitable in the current synchronous prototype, but a latent design risk to flag before any concurrency work. | MEDIUM (latent) | Code review -- architectural note, not scripted (would require concurrency to demonstrate) |

### 2.5 Federated Adversarial Resilience Score (`fars.py`)

| STRIDE | Finding | Severity | Evidence |
|---|---|---|---|
| **Tampering (metric gaming)** | The score formula and its weights are fixed and fully disclosed in source. An attacker who understands the formula can specifically optimise for "stay under every individual threshold" (exactly what PT-03/PT-04 do), which *directly* maximises FARS rather than merely evading detection as a side effect -- undetected attacks score *higher* than detected ones. This was found and partially fixed during earlier statistical-validation testing (blast-radius blending, see `TEST_PROTOCOL.md` section 4b); PT-03/PT-04 in this report show the underlying detection gap it depends on is still exploitable at the orchestration layer. | HIGH (partially mitigated already; root cause addressed in Section 4 below) | `pentest/pt04_distributed_sybil_attack.py` output: FARS 75.41/100 *during* a live, fully-uncontained Sybil attack |
| **Denial of Service** | `average_node_connectivity` cost scales poorly; see 2.1. | MEDIUM | -- |
| **No temporal memory** | FARS is a point-in-time snapshot. An agent that gets compromised, reinstated (even legitimately), compromised again, etc. never has that instability reflected -- two federations with identical *current* state but very different *histories* get identical scores. | LOW-MEDIUM | Code review -- design limitation, out of scope to fix in this pass |

### 2.6 Federated Adversary Model (`adversary_model.py`)

| STRIDE | Finding | Severity | Evidence |
|---|---|---|---|
| **Information Disclosure (indirect)** | Purely structural/offline -- doesn't process untrusted input at runtime, so its STRIDE surface is narrow. Its main dependency risk is *garbage in*: it's only as trustworthy as the delegation edges registered by `federation_bus.register_agent()`/adversary-model wiring, which (per 2.1) isn't gated on any verified identity either. | LOW (inherits Spoofing risk from Federation Bus) | -- |

### 2.7 Agents (`agents.py`)

| STRIDE | Finding | Severity | Evidence |
|---|---|---|---|
| **Tampering (detection evasion)** | Prompt-injection detection is a single hardcoded substring match (`"ignore previous instructions" in lowered`). Trivially bypassed by rewording, unicode homoglyphs, splitting the phrase across messages, or any paraphrase a real attacker (or real LLM) would naturally produce. | MEDIUM (known/documented, not separately scripted -- this is a content-classification problem, not an architecture problem, and full NLP-based detection is out of scope for this lightweight prototype) | Code review |

---

## 3. Summary table

| ID | Finding | Component(s) | Severity | Status pre-report | Status post-hardening |
|---|---|---|---|---|---|
| PT-01 | Unauthenticated identity spoofing on the bus | Federation Bus | HIGH | Exploitable | **Fixed** -- `admit_agent()` gate |
| PT-02 | Policy rule bypass via payload field omission | Orchestration | HIGH | Exploitable | **Fixed** -- fail-closed schema rule |
| PT-03 | CUSUM slow-drip evasion (single agent) | Orchestration | HIGH | Exploitable | **Fixed** -- sliding-window volume detector |
| PT-04 | Distributed/Sybil low-and-slow evasion | Orchestration, Taint Engine | HIGH | Exploitable | **Fixed** -- org-level rolling volume + org-wide quarantine |
| PT-05 | Unauthorised self-service reinstatement | Orchestration | HIGH | Exploitable | **Fixed** for the supported API; residual risk documented for the raw internal primitive |
| PT-06 | ZK attestation salt exposure | Trust Protocol | HIGH | Exploitable | **Fixed** -- salt retained server-side |
| -- | Unbounded nonce cache (memory leak) | Trust Protocol | MEDIUM | Documented | **Fixed** -- self-pruning nonce dict |
| -- | No audit-log tamper evidence | Federation Bus | HIGH | Documented | **Fixed** (tamper-evident, not tamper-proof) -- hash-chained audit rows + `verify_audit_integrity()` |
| -- | No credential revocation registry | Trust Protocol | MEDIUM | Documented | **Fixed in v5** -- see Section 8 (`revoke_agent()`); this row is left in the original table for historical continuity but is stale as written -- struck through in spirit, corrected here rather than silently updated |
| -- | Connectivity-metric DoS cost | FARS, Federation Bus | MEDIUM | Documented | Not fixed -- out of scope this pass |
| -- | Latent async TOCTOU in the bus itself | Federation Bus, Taint Engine | MEDIUM (latent) | Documented | Not fixed -- prototype remains synchronous, so not currently exploitable; flag before any concurrency work |
| -- | FARS has no temporal memory | FARS | LOW-MEDIUM | Documented | Not fixed -- out of scope this pass |
| -- | Prompt-injection detection is a naive substring match | Agents | MEDIUM | Documented | Not fixed -- out of scope this pass (content-classification problem, not architecture) |

**Note on this table (added v7.6):** this is a point-in-time snapshot
taken early in the hardening process and intentionally left unedited
as later sections extend it, so the report shows its own history
rather than silently rewriting the past. That means some rows here go
stale as later work fixes what they describe -- "No credential
revocation registry" (above) was fixed in v5 (Section 8) but this row
still read "Not fixed" until this note was added. Section 11's
"What's still open" summary and this file's Table of Contents-adjacent
running commentary are the authoritative up-to-date status; this table
is a historical artefact, not a live tracker -- worth stating
explicitly rather than leaving a reader to notice the contradiction
unassisted.

---

## 4. Hardening applied

All six HIGH-severity scripted findings (PT-01 through PT-06) were fixed,
plus the nonce-cache leak and audit-log tamper-evidence gaps (cheap and
high-value to close). Summary of the mechanism for each:

| Finding | Fix | Where |
|---|---|---|
| PT-01 identity spoofing | New `FederationBus.admit_agent(agent_id, org, vc)` -- an agent must present a currently-valid credential before `send()` will accept it as `from_agent`. Unadmitted senders are rejected *before* touching the taint graph or orchestration (fail closed). | `federation_bus.py` |
| PT-02 field omission | New schema-based `incomplete_action_schema` rule, checked *first*, before any other rule: each `action_type` has a required-field set (`DEFAULT_ACTION_SCHEMAS`); a missing required field is itself a violation instead of silently skipping the check it would have enabled. | `orchestration.py` |
| PT-03 CUSUM slow-drip | New `SlidingWindowVolumeDetector`: sums taint contributions over a rolling window independent of CUSUM's per-step slack subtraction, so staying under the slack forever no longer evades detection. | `orchestration.py` |
| PT-04 Sybil attack | Federation Bus now tracks a **per-organisation** rolling taint volume (reusing the same detector, keyed by org instead of agent). If it trips, *every* currently-known agent belonging to that org is quarantined and contained in one step. | `federation_bus.py` |
| PT-05 unauthorised reinstatement | New gated path `FederationBus.reinstate_with_reattestation(agent_id, org, vc)` -- requires a fresh, valid, unexpired credential before lifting quarantine. The raw `orchestration.reinstate()` primitive still exists (Python can't truly seal it) but is now documented as internal-only. | `federation_bus.py`, `orchestration.py` |
| PT-06 ZK salt exposure | The salt is now retained **server-side** inside the `FederatedTrustProtocol` instance, keyed by an opaque `attestation_id`; only the commitment and the id leave the issuer. Still not a true ZK-SNARK (documented), but the concrete exploit is closed. | `trust_protocol.py` |
| Nonce cache leak | `_seen_nonces` (unbounded set) replaced with `_nonce_expiry` (dict pruned of expired entries on every verification call). | `trust_protocol.py` |
| Audit tamper evidence | Every audit row now stores `prev_hash`/`row_hash`, chained like a minimal ledger; `FederationBus.verify_audit_integrity()` walks the chain and reports the first broken link, if any. Documented limitation: this detects tampering, it doesn't cryptographically *prevent* a sufficiently privileged attacker from rewriting the whole chain forward -- true tamper-*proofing* needs external anchoring or a signing key the DB itself never holds. | `federation_bus.py` |

## 5. Post-hardening re-test (actual output, `pentest/*.py` re-run against hardened code)

```
PT-01 identity_spoofing:      NOT VULNERABLE -- forged identity rejected (reason: unadmitted_identity)
PT-02 field_omission_bypass:  NOT VULNERABLE -- both TOCTOU and privilege-ceiling omission attempts
                               caught by the new 'incomplete_action_schema' fail-closed rule
PT-03 cusum_slow_drip:        NOT VULNERABLE -- 200-message drip attack contained by message #6
                               (sliding-window volume detector; CUSUM alone still wouldn't have caught it)
PT-04 distributed_sybil:      NOT VULNERABLE -- org-level rolling volume tripped and contained
                               10/10 Sybil agents in one step once the aggregate crossed the cap
PT-05 unauthorised_reinstate: SUPPORTED PATH FIXED -- bogus re-attestation refused, valid
                               re-attestation succeeded. RESIDUAL RISK CONFIRMED (documented,
                               not fully fixable in pure Python): the raw orchestration.reinstate()
                               primitive still bypasses authorisation if that object is reachable
                               by untrusted code -- real deployments must not expose it outside
                               the Federation Bus module.
PT-06 zk_salt_exposure:       NOT VULNERABLE -- salt never leaves the issuer; offline dictionary
                               attack has nothing to combine with the intercepted commitment.
```

Full regression suite (`pytest tests/ -v`) after all hardening: **25 passed, 1 skipped
(documented reason), 0 failed** -- identical pass count to before hardening, confirming
no behavioural regressions were introduced for legitimate traffic.

## 6. Two things the hardening process itself found (worth knowing before you trust these numbers)

**(a) The org-level cap needed empirical tuning, not a guess.** The first
value chosen (cap=0.8 over a 40-message window) required ~21 low-intensity
Sybil agents to trip -- a 10-agent swarm (PT-04's original test) sailed
through untouched. Lowering it to 0.35 catches the 10-agent case. This is
a genuine, unavoidable trade-off: a lower cap catches smaller/stealthier
Sybil swarms faster but raises the false-positive risk against legitimate
high-volume multi-agent organisations. **This constant is not adaptive**
(see the residual-limitation note in `federation_bus.py`) -- a real
deployment should scale it against each organisation's normal traffic
baseline rather than use one federation-wide number. Flagging this
explicitly rather than quietly picking a value that made the demo pass.

**(b) A logging-order bug briefly reintroduced a forensic regression.**
The first implementation of the org-level check ran unconditionally after
the per-agent check, so when BOTH layers caught the same message, the
coarser org-level reason (`org_wide_behavioural_drift`) silently
overwrote the more specific, more actionable per-agent reason
(`unauthorised_instruction_override`) in the audit log. Caught by the
existing regression suite (`test_e1_behaviour_monitor_detects_prompt_injection`
failed on the reason string), not by a new pentest script -- a good
illustration of why the diagram-derived regression tests from
`TEST_PROTOCOL.md` and the adversarial pentest scripts here are
complementary, not redundant. Fixed by only consulting the org-level
check when the per-agent layer already returned `ALLOW`.

## 7. v3 additions: Federation Ledger + Zero-Trust per-message signing

**PT-07 -- Unilateral federation-wide clearing (fixed).** An org-wide
(Sybil) quarantine (`_quarantine_org()`, Section 5) used to be
recoverable via `reinstate_with_reattestation()` with a credential
issued by the ACCUSED org's own key -- self-attestation standing in for
independent verification. Fix: federation-wide recovery is now gated on
`FederationLedger` quorum (>= 2 independently witnessing orgs, see
`federation_ledger.py`); `reinstate_with_reattestation()` refuses
outright (`requires_federation_quorum`) once an org is flagged
federation-wide. Documented limitation: this is an in-memory,
single-process stand-in for real distributed BFT consensus across
independently-operated org nodes, and `witness()` calls carry no
cryptographic proof of review -- a production version should require a
signed attestation per witness the same way credential issuance does.

**PT-08 -- Message-layer session hijack (fixed, mandatory as of v5).**
Identity admission (PT-01) only checks that a session token is
currently valid; it does not, on its own, prove that each subsequent
message actually originated from that agent's process rather than from
anyone who merely learned the admitted `agent_id`/`org` pair. Fix:
`FederationBus.send()` requires (by default, since v5)
`require_message_signatures=True` -- every message must carry an
Ed25519 signature (verified against the sender's `did:key` via the new
`did_to_public_key()` helper in `trust_protocol.py`) plus a single-use,
TTL-bounded nonce (`message_nonce_ttl_seconds`, default 300s), checked
independently of the credential-layer nonce cache. `sign_and_send()` is
the supported entry point; `main.py`'s four scenarios and PT-01–06 were
all migrated to it. Test-suite call sites (`tests/conftest.py`'s
`fresh_bus`, `test_04_statistical_validation.py`) and PT-07
deliberately opt back out with `require_message_signatures=False` and a
documented reason -- they exercise other layers (orchestration
behaviour, statistical comparison, ledger quorum) and re-signing every
call there would add noise without adding coverage; the signing path
itself has its own dedicated end-to-end test, PT-08.

## 8. v5 additions: revocation registry + reinstate() capability gate

Two further findings closed, both software-only fixes that didn't need
any HSM/KMS-backed key storage -- see Section 9 for what genuinely does
need that and was deliberately left for FARF Cloud instead.

**Revocation registry (fixed).** Previously, a leaked or compromised
agent credential/key stayed fully trusted until its TTL naturally
expired -- there was no way to cut it off early. `FederatedTrustProtocol.revoke_agent()`
/ `FederationBus.revoke_agent()` now give an immediate, permanent
override: a revoked agent's current session is killed instantly, and it
cannot be re-admitted even with a brand-new, otherwise-valid credential
(`admit_agent()` checks the registry before anything else). See
`pentest/pt09_stale_trust_after_compromise.py` Part A.

**`reinstate()` capability gate (narrowed, not eliminated).**
`SecureOrchestrationLayer.reinstate()` previously had zero authorisation
check -- calling it directly cleared any quarantine. It now requires a
capability token (`_reinstate_capability`, a 256-bit value minted once
per instance) that only `FederationBus` is meant to hold and pass
through `reinstate_with_reattestation()` / `witness_federation_reinstatement()`.
Calling it with no token now raises `PermissionError` (see
`pentest/pt09_*` Part B and the updated `pentest/pt05_*`). **This is
explicitly not full process isolation:** anyone with attribute-level
access to the `orchestration` object can still read
`_reinstate_capability` off it directly and forge a valid call -- Python
has no true private fields. What this closes is casual/careless misuse
and the original zero-effort pentest bypass; what it does NOT close is
a determined attacker who already has object-level access, which is a
narrower and honestly harder problem than "no check at all" was.

## 9. Deliberately deferred to FARF Cloud (not laptop scope)

These three items came up during v5 hardening and were deliberately
**not** attempted here, because a laptop prototype can't meaningfully
implement them without either faking the security property or building
infrastructure the thesis doesn't need to stand up:

  - **HSM/KMS-backed key storage.** Agent and org private keys
    currently live in-process, in plain Python memory, for the
    lifetime of the run. Signing defends against a network-only
    attacker; it does nothing against anyone with process/host memory
    access. A "software HSM" on a laptop wouldn't demonstrate anything
    a real HSM/KMS integration (AWS KMS, Azure Key Vault, HashiCorp
    Vault, or an actual hardware module) would -- this is an
    infrastructure dependency, not a code fix.
  - **Key rotation against a real KMS.** Rotation logic itself
    (issue a new keypair, update the admitted session) is easy to
    write in pure Python; the reason it's deferred is that rotation
    only matters once keys are actually KMS-backed -- rotating an
    in-memory demo key doesn't meaningfully change the threat model
    above.
  - **PKI/CA root-of-trust hierarchy for org identities.** Currently
    every org self-issues its own DID with no external attestation of
    "this DID really belongs to this organisation." A real federation
    needs an answer to that (a CA, a consortium-run registrar, or a
    blockchain-anchored identity registry) that requires real
    multi-party infrastructure to be meaningful, not a data structure
    inside this codebase.

## 10. v6 additions: Memory & Context Integrity (OWASP ASI06)

**PT-10 -- Memory poisoning + memory TOCTOU (fixed).** Prior to this,
nothing in the prototype gave an agent a real persistent memory store
to attack or defend -- the "memory manipulation" scenario (E4)
simulated compromise purely through instruction text, with no actual
write/read surface. `memory_store.py` adds a hash-chained, per-writer-
signed memory namespace per agent (`FederationBus.write_memory()` /
`sign_and_write_memory()` reuse the exact same Zero-Trust signing
machinery PT-08 added for messages), plus a `memory_toctou_mismatch`
policy rule in `orchestration.py` that mirrors the existing
`toctou_resource_mismatch` rule exactly, applied to memory reads
instead of external resources. `verify_memory_integrity()` recomputes
BOTH the content hash (from the record's live value) and the chain
hash on every record -- recomputing only the chain hash would miss an
attacker with raw datastore access who edits a record's value in place
while leaving its stored content_hash field untouched.

Documented limitations: single-process/in-memory (same as the audit
log and Federation Ledger); no way to revoke or purge a single
already-written poisoned record (only the writer's whole identity can
be revoked, stopping further writes, not retroactively invalidating
what's already there); self-writes only, no delegated-write model yet
for e.g. an advisor legitimately writing into an executor's memory.

**MAESTRO framing:** this closes the gap on MAESTRO Layer 3 (Agent
Frameworks) that Section 8 of the earlier assessment flagged as
untouched. Layer 7 (Agent Ecosystem) concerns -- how a wholly unknown
external agent or org first gets discovered and trusted, federation-
wide reputation, marketplace-style trust -- remain out of scope; the
Federation Ledger's quorum-witness model (Section 6) is the closest
existing artefact but was built for recovery, not initial trust
establishment.

## 11. What's still open

**Superseded by Section 23** (v7.7 closed several of the items
originally listed here -- the PT-15 paraphrase gap, the append-only-
chain-vs-erasure tension, and the missing-logging-module gap -- see
that section for the current, accurate list). Kept here, unedited,
purely as a historical snapshot of v7.1--v7.6 status, since several
in-text cross-references elsewhere in this document still point at
"Section 11" by name.

As of v7.1: FARS's connectivity-metric cost and lack of temporal memory
were addressed (Section 14). The naive prompt-injection detector, the
latent async TOCTOU risk, delegated memory writes, and single-record
revocation were all addressed (Section 15). Dynamic PBFT-proportional
quorum is available and demonstrated but remains opt-in, not default
(Sections 12/15 -- safe to adopt for any 2-org scenario, stricter at
N=3+). As of v7.5: the two highest-Trike-risk LINDDUN findings
(Linkability/Identifiability, Disclosure of information) were closed
(Section 20).

Genuinely still open: the HSM/KMS-backed key storage, key rotation, and
PKI root-of-trust items deliberately deferred to FARF Cloud (Section 9,
needs real infrastructure); MAESTRO Layer 7 ecosystem-level trust
(agent discovery, cross-federation reputation, Section 13); the
remaining LINDDUN gaps -- Non-repudiation-as-privacy-risk and
Detectability (Section 20, lower Trike risk than the two closed, closer
to policy/design-tension questions than implementation gaps); OCTAVE/
Trike's formal asset-and-risk layer (Section 13, useful for
dissertation rigor, not indicating an unfound vulnerability); VAST's
CI-automation recommendation (Section 13, delivered as
`tools/farf_security_lint.py`); the adaptive volume detector's
calibration-poisoning trade-off (Section 14, an operational decision
left to the deployer, not a code gap). CUSUM's inability to be the
first detector for a continuous-drift attack under normal calibration
(Section 19) is no longer listed as open -- v7.5 repositioned and
evidence-backed it as intentional defence-in-depth (PT-20 proves it
independently catches the same attack when the faster layers are
disabled/misconfigured), which is a resolved documentation/design
question, not a remaining gap. The audit-write failure-handling gap
found via chaos testing (Section 17) is also no longer open -- v7.6
closes it with buffer-and-retry handling, verified in Section 21. What
remains listed here are genuinely still open, reasonable candidates for
a "Future Work" section in the dissertation, or (Section 9's items)
require real cloud infrastructure this laptop prototype cannot
meaningfully fake.

## 12. v7 additions: cryptographically-accountable, stake-weighted ledger

**PT-11 -- Unauthenticated witness forgery + stake weighting (fixed).**
Section 6 originally documented two open limitations on the Federation
Ledger: witness() calls carried no proof of who actually made them, and
quorum was pure one-org-one-vote. Both closed:

  - **Signed witnesses.** `FederationBus.witness_federation_reinstatement()`
    now requires a signature from the claimed org's own DID key
    (the same key `issue_credential()` already uses), verified against
    that org's registered public key, plus a single-use nonce sharing
    the same TTL-bounded replay cache as message/memory-write nonces.
    `sign_and_witness_federation_reinstatement()` is the supported entry
    point. PT-11 proves a forged vote (right org name, attacker's own
    key) is rejected with `invalid_witness_signature`, and only a
    genuinely-signed vote counts.
  - **Stake-weighted quorum.** `quorum_required` is now a weight
    threshold, not a headcount; `FederationLedger.set_stake(org, weight)`
    lets an operator down-weight (or zero out) an org's vote -- e.g. a
    newly-joined, not-yet-vetted member. PT-11 demonstrates a zero-stake
    org's witness contributing nothing toward quorum while a
    normal-stake org's does.

**PBFT-style fault tolerance (documented and made computable, not
adopted by default).** The ledger's `quorum_required` remains a FIXED
constant chosen at construction time (default 2.0), not automatically
proportional to federation size N. This matters: classic PBFT requires
N >= 3f+1 total participants to tolerate f Byzantine/colluding
participants, with quorum = 2f+1. A fixed quorum of 2 does not scale --
for a 2-org federation it offers ZERO fault tolerance (the one "other"
org IS the entire independent check), and for a 100-org federation it's
comically under-strength relative to what the federation's size could
actually support. `FederationLedger.recommended_quorum_for_pbft(n_orgs)`
computes the PBFT-correct value:

| N (total orgs) | Fixed quorum=2 tolerates | PBFT-proportional quorum | PBFT quorum tolerates |
|---|---|---|---|
| 2  | 0 Byzantine orgs | 1 | 0 Byzantine orgs |
| 3  | 0 (same as above) | 1 | 0 Byzantine orgs |
| 4  | 0 (same as above) | 3 | 1 Byzantine org |
| 7  | 0 (same as above) | 5 | 2 Byzantine orgs |
| 10 | 0 (same as above) | 7 | 3 Byzantine orgs |
| 100| 0 (same as above) | 67 | 33 Byzantine orgs |

**Why the default wasn't changed:** every existing pentest and the
thesis's documented numbers assume a 2-3 org test federation with
quorum=2 (unanimous, by coincidence, at that small size). Flipping the
default to `recommended_quorum_for_pbft(len(orgs))` is a one-line change
at `FederationBus.__init__` once you're ready to re-baseline those
numbers -- flagged in 11 as deferred, not forgotten. In an
actual larger deployment, adopting the proportional formula (or a
governance-set quorum somewhere between the two) is the right call --
a fixed constant is only defensible for the specific 2-3-org
prototype scale this thesis tests at.

**Still an open limitation (Section 6's original point stands):** all
of this consensus logic still runs in one process. Signed witnesses
prove WHO cast a vote; they do not by themselves distribute the ledger
itself across independently-operated org nodes the way a real
permissioned BFT deployment (e.g. Hyperledger Fabric's endorsement-
policy model) would. That remains genuine infrastructure work for FARF
Cloud, not something more Python can close.

## 13. Threat-modeling methodology coverage (beyond STRIDE + MAESTRO)

**Tier 2 update:** the assessment below identifies WHICH additional
methodologies would help and why. The actual deliverables -- a full
LINDDUN privacy analysis, an OCTAVE asset/stakeholder risk profile, a
Trike risk matrix, and a PASTA business-impact overlay -- are built out
in full in the companion document `RISK_APPENDIX.md`, not just
described here. A working VAST-style automated CI check is also
delivered as `tools/farf_security_lint.py`. This section remains as the
initial assessment; `RISK_APPENDIX.md` is where each recommendation was
actually followed through.

Section 2 used STRIDE (component-level, "what can go wrong per
artefact") and Section 8 mapped FARF onto MAESTRO's 7-layer agentic
structure. Five other well-established methodologies each apply a
genuinely different lens; briefly assessing FARF against each surfaces
gaps STRIDE+MAESTRO don't, because they optimize for different
questions (attacker motive and business impact, privacy, organisational
risk to assets, formalised risk acceptance, and design-time scale/
automation, respectively).

**PASTA (Process for Attack Simulation and Threat Analysis)** is
attacker-centric and business-impact-driven: it starts from business
objectives and asks what a motivated attacker gains by breaking them,
then works backward to attack trees. FARF's pentest suite (PT-01–11)
is already implicitly PASTA-shaped -- each script is a concrete attack
simulation with a clear "what does the attacker gain" framing (spoof an
identity, poison a memory, forge a witness vote). What PASTA would add
that isn't here: an explicit business-impact ranking. THREAT_MODEL.md's
Section 3 severity table (HIGH/MEDIUM) is a technical-severity
judgment, not a business-impact one -- for a real deployment, "PT-07's
finding" and "PT-10's finding" should be ranked by what a specific
attacker actually gains (data exfiltration value, regulatory exposure,
reputational cost), not just by exploit mechanics. Worth adding as an
explicit column if this threat model is extended for a non-academic
audience.

**LINDDUN (privacy threat modeling: Linkability, Identifiability,
Non-repudiation, Detectability, Disclosure of information, Unawareness,
Non-compliance)** is the biggest genuine gap. FARF's entire threat model
is written from a security (CIA-triad-adjacent) perspective; nothing in
Sections 1-13 asks a privacy question. Concretely, applying LINDDUN's
categories to FARF surfaces real open items:
  - *Identifiability/Linkability*: every agent's `did:key` is a stable,
    long-lived identifier used in every signed message and memory
    write. An observer with access to the audit trail (or the message-
    layer nonce/signature traffic on the wire) can trivially link every
    action a given agent ever took across the whole federation --
    there's no unlinkability mechanism (e.g. rotating pseudonymous
    per-session identifiers) at all.
  - *Disclosure of information*: `memory_store.py`'s records and
    `federation_bus.py`'s audit rows store full plaintext payloads.
    Nothing in FARF considers whether a message or memory payload might
    itself contain personal data that shouldn't be retained in an
    unencrypted, indefinitely-growing SQLite/in-memory log.
  - *Non-repudiation* is actually a place FARF is intentionally STRONG
    on the security side (signed messages/witnesses are non-repudiable
    by design, Section 7/13) -- but LINDDUN treats non-repudiation as a
    potential PRIVACY risk, not just a security benefit: an agent (or a
    human operator behind one) may have a legitimate interest in
    plausible deniability that FARF's design removes entirely. Worth
    flagging as a real design tension, not resolving it away.
  This is genuinely unaddressed and, if FARF ever touches real
  user/customer data flowing through agent memory or messages, is a
  higher-priority gap than most of 11's open items.

**OCTAVE (Operationally Critical Threat, Asset, and Vulnerability
Evaluation)** is organisational- and asset-driven rather than
component-driven: it starts from "what assets matter to the
organisation" and works outward. FARF has no explicit asset inventory
or organisational-risk-tolerance statement at all -- Section 1's
"component inventory" lists CODE artefacts (the five FARF modules),
not business ASSETS (customer data, an org's reputation, regulatory
standing, uptime SLAs). An OCTAVE-style pass would ask questions FARF
currently has no answer to: which federation member's data is most
sensitive, what's each org's actual risk tolerance for a false-positive
quarantine versus a missed attack, and who within an org owns that
risk decision. This is a reasonable candidate for a short "Asset &
Stakeholder Risk Profile" appendix in the dissertation, distinct from
the existing technical threat model.

**Trike** is explicitly risk-based: it builds a requirements model,
assigns acceptable risk levels per stakeholder/asset/action, and treats
anything exceeding that threshold as a finding. FARF doesn't formalize
"acceptable risk" anywhere -- the pentest verdicts are binary
(VULNERABLE / NOT VULNERABLE), not risk-scored against an explicit
threshold. A Trike-style pass would produce a risk matrix (e.g. by
combining OCTAVE's asset values with STRIDE's per-component findings and
an explicit likelihood estimate) rather than a pass/fail list -- useful
if the dissertation wants to argue not just "these attacks are blocked"
but "the residual risk after hardening is X, which is below the stated
tolerance of Y." Currently FARS is the closest thing FARF has to a
risk score, but it measures aggregate resilience, not per-finding
residual risk in Trike's sense.

**VAST (Visual, Agile, Simple Threat modeling)** is about SCALE and
process integration -- automated, continuous threat modeling across many
services in an agile/DevOps pipeline, not deep manual analysis of one
system. FARF's threat modeling has all been manual and one-shot per
version (v3, v5, v6, v7 hardening passes, each with a written
THREAT_MODEL.md update). What VAST would add: a lightweight, automated
"does this pull request introduce a new action_type without a
corresponding orchestration rule, a new send() call site that bypasses
sign_and_send(), or a new memory write path that bypasses
write_memory()'s signature check" CI check, run on every change --
turning this document's manual review process into a repeatable gate.
This is realistic future work (a static-analysis script, not a
research contribution) and worth a one-paragraph mention in a "Future
Work" section as the process-maturity complement to the technical
hardening already done.

**Net assessment:** STRIDE + MAESTRO give FARF strong technical/
component and agentic-architecture coverage. PASTA is largely already
implicit in the pentest suite's framing. LINDDUN is the clearest actual
gap (privacy was never in scope) and should be named explicitly as
future work rather than silently absent. OCTAVE and Trike would mainly
add a formal risk/asset layer on TOP of the existing technical findings
-- valuable for a dissertation's rigor but not indicating an unfound
vulnerability. VAST is a process/tooling recommendation, not a finding.

## 14. v7 additions: temporally-adaptive FARS

FARS (Artefact 5 in Section 1's component inventory) was previously a pure point-in-time
snapshot, recomputed from ALL-TIME cumulative totals on every call --
flagged as a limitation because it has no memory of trajectory: a
federation that was compromised for an hour and just recovered looks
identical to one that's been healthy throughout, as long as the
cumulative ratios happen to converge to the same values. Three fixes,
validated together in `pentest/pt12_temporal_fars_validation.py`:

**EWMA memory.** `FARSEngine.compute_ewma()` maintains an exponentially
weighted moving average alongside the raw snapshot (`current_fars()`
now returns both `FARS` and `FARS_ewma`). PT-12 confirms the EWMA
genuinely lags a sudden quarantine event rather than snapping instantly
-- in the recorded run, raw FARS dropped from 81.25 to 31.25 in one
event while the EWMA only moved to 66.25, i.e. it actually remembers
the pre-incident trajectory instead of forgetting it immediately.
`fars_ewma_alpha` (default 0.3) controls the memory/reactivity
trade-off; `fars_history` retains a capped (500-entry) rolling log of
both values over time for later inspection or plotting.

**Recovery-time tracking.** `RecoveryTimeTracker` (fars.py) measures
wall-clock time from "a key (agent_id or org) first entered
quarantine" to "that key was reinstated" -- via
`reinstate_with_reattestation()` and `_restore_org()`, both now call
`mark_quarantined`/`mark_recovered` at the right points.
`FederationBus.recovery_time_stats()` exposes count/mean/min/max as
its own metric, deliberately separate from the steady-state FARS score
-- two federations can have identical steady-state FARS but very
different recovery speeds, and only this metric would show that.

**Adaptive org-level volume cap (opt-in, not default).**
`adaptive_detection.py`'s `AdaptiveOrgVolumeDetector` calibrates each
org's own volume cap from that org's own observed traffic during an
initial calibration window (default 20 messages), instead of one fixed
constant (0.35) for every org regardless of size. PT-12 Part C confirms
two differently-sized orgs calibrate to different caps rather than
sharing one. Enabled via `FederationBus(adaptive_org_volume=True)`.
**Deliberately NOT the default**, for an honest reason documented in
`adaptive_detection.py`'s module docstring: if an attack is already
running during the calibration window, the baseline itself gets
poisoned upward and the detector becomes LESS sensitive than the fixed-
cap version for the rest of that org's session. This is a real, open
problem in anomaly detection generally (not specific to this
prototype), and the fix -- calibrating from trusted/offline traffic
rather than live traffic on first contact -- is an operational decision
about where that trusted data comes from, which this codebase
deliberately leaves to the deployer rather than silently assuming.

## 15. v7.1 additions: Tier 1 hardening (memory, concurrency, detection)

Five items closed together, all deliberately scoped to what's feasible
without new infrastructure -- see the earlier "what's still open"
sections for what genuinely isn't.

**PBFT quorum bug fix.** While wiring `enable_pbft_quorum()` (Section
13's utility) up to a real opt-in call path, the naive `quorum=2f+1`
formula was caught producing quorum=1 for a 2-org federation -- which
would have let the accused org's own self-witness alone reach quorum,
silently defeating PT-07's entire premise. Fixed: when f=0 (N<4, i.e.
zero tolerable Byzantine participants), quorum must equal N
(unanimity), not the naive formula's 1. Demonstrated in
`pentest/pt11_ledger_witness_forgery.py` Part D, which also confirms
this correction happens to match today's existing fixed default
(quorum=2) exactly at N=2 -- so opting in via `enable_pbft_quorum()` is
safe for every existing 2-org pentest scenario, and only becomes
stricter (correctly, requiring unanimity) at N=3.

**Single-record memory revocation.** `MemoryStore.revoke_record()` /
`FederationBus.revoke_memory_record()` purge one specific
already-written record via an appended tombstone, rather than requiring
the whole writer identity to be revoked (Section 8's registry, which
only stops FUTURE writes). Append-only by design -- mutating history in
place would be indistinguishable from the exact in-place-tampering
attack `verify_integrity()` exists to catch. `read()` treats a
tombstoned key as empty; the key remains writable afterward. Verified
in `pentest/pt13_memory_revocation_and_delegation.py` Part A.

**Delegated memory writes.** `grant_memory_delegation()` /
`sign_and_grant_memory_delegation()` let an owner agent explicitly and
verifiably authorise another agent to write into its namespace --
previously writes were structurally self-write-only (10). A
grant must be signed by the OWNER's own key (never the delegate, never
an operator on the owner's behalf), can be scoped to specific keys, and
expires. Critically, the grant only widens WHO is allowed to attempt a
write -- the delegate's own signature is still separately required on
every write, so a forged delegation claim alone can never produce a
valid write. PT-13 Part B verifies all four angles: no grant blocks,
an impostor's forged grant is rejected, a genuine scoped grant works,
and both key-scoping and expiry are enforced.

**Latent async TOCTOU (closed).** Section 3 flagged every check-then-
act sequence in `FederationBus` (nonce check -> insert, admission check
-> session mutation, org-volume check -> quarantine trigger) as
unguarded, "safe" only because the prototype had always been called
synchronously -- explicitly marked as something to revisit before any
concurrency work. This is that revisit: a single `threading.RLock`,
applied via a `@_locked` decorator, now serializes every state-mutating
`FederationBus` method into an atomic critical section (RLock because
several locked methods call other locked methods on the same bus in the
same thread, e.g. `sign_and_send()` -> `send()`). This was NOT just
theoretical -- `pentest/pt14_concurrent_replay_race.py` races 60 real
threads submitting the identical valid (signature, nonce) pair
simultaneously: with the lock, exactly one message is accepted and zero
errors occur, every run; with the lock forcibly disabled (simulating
the pre-v7.1 state), concurrent unsynchronized access genuinely
corrupts shared state, producing unhandled errors on 4-5 of the 60
threads every run. (A real SQLite thread-safety bug was also caught and
fixed in the process: `check_same_thread=False` is only safe because
the lock now guarantees the DB connection is never touched by two
threads at once.)

**Prompt-injection heuristic broadened.** The original detector
(Section 3) matched exactly two hardcoded phrases via bare substring
search. `agents.py`'s `detect_prompt_injection()` is a genuine upgrade,
not a reframing: a broader phrase family, role/delimiter injection
pattern matching, and normalization that defeats simple obfuscation
(zero-width characters, a handful of Cyrillic/Greek homoglyphs, mixed
case/whitespace tricks). `pentest/pt15_prompt_injection_heuristic.py`
verifies known phrases and three obfuscated variants are now all
caught. **Documented honestly, not oversold:** Part C of that same
script demonstrates a genuinely novel PARAPHRASE of the same intent
correctly evades this heuristic -- and confirms that's expected, not a
bug. Closing that gap is a content-classification problem needing a
real trained classifier or an LLM-based judge, not a bigger rule list;
still out of scope for this laptop prototype and listed as future work.

## 16. v7.2 finding: a genuine perverse incentive in FARS's trust_health component

Discovered during Phase 1 resilience-improvement work, specifically
while fixing `tests/test_04_statistical_validation.py`'s severity
sampling (which was entirely on the wrong side of the actual
containment boundary -- see the test file's updated docstring). Fixing
the sampling produced real variance in outcomes for the first time,
which immediately surfaced something the always-skipped test had been
hiding: **FARS scored successfully-contained attacks LOWER than
attacks that propagated completely unchecked.**

### Evidence

Traced via direct component inspection (`fars.py`'s `compute()` broken
into its four parts), holding the attack pattern fixed and varying only
severity/org-count:

| Outcome | `blast_fraction` | `quarantined_fraction` | `trust_health` | `taint_containment` | `FARS` |
|---|---|---|---|---|---|
| Attack fully escapes, uncontained | 1.00 | 0.000 | **1.000** | 1.000 | **81.25** |
| Attack correctly contained by CUSUM | 0.00 | 0.200-0.250 | **0.750-0.800** | 1.000 | **72.5-74.3** |

The uncontained case scores HIGHER than the correctly-contained case.
`fars_discriminative_validity()` (the ROC AUC metric added alongside
this fix) confirmed it numerically: AUC = 0.10 (should be > 0.5 -- an
AUC this far below 0.5 means FARS is anti-correlated with the outcome
it's supposed to predict, not just noisy).

### Root cause: two separate bugs, not one design flaw

**Bug 1 -- `trust_health_score()` penalizes ALL quarantine identically.**
`fars.py`: `max(0.0, 1.0 - (quarantined/total_agents))`. This cannot
distinguish "agents quarantined because we correctly caught an attack"
(good -- the system working as designed) from "agents quarantined for
no good reason" (bad). Every quarantined agent is pure penalty, with no
credit for what that quarantine achieved.

**Bug 2 -- `taint_containment_score()` was completely uninformative in
this scenario, for two compounding reasons, which is what let Bug 1
dominate the outcome unopposed:**
  - `TaintPropagationEngine.max_blast_radius_fraction()` only counts
    edges with `taint_level > 0.1` (the default `taint_threshold`).
    The memory-manipulation attack pattern's corrected severity range
    (`[0.03, 0.16]`, see Section on the statistical validation fix)
    straddles that threshold -- several trials never produce a single
    edge above it, so `max_blast_radius_fraction()` returns 0.0
    (perfectly "contained") regardless of what `blast_radius()`
    (a DIFFERENT, unfiltered method, used for the ground-truth
    `observed_resilience` proxy) actually reports for the same event.
  - Worse: `quarantine_edges_from()` -- the CORRECT, working
    containment mechanism -- physically removes the quarantined agent's
    outgoing edges from `flow_graph`. Since `max_blast_radius_fraction()`
    recomputes fresh from the CURRENT graph state every time it's
    called, successfully quarantining an attacker erases the very
    edges that would prove propagation happened before containment
    kicked in. **The act of successfully containing an attack destroys
    the evidence FARS needs to recognize that containment occurred.**

Combined: `taint_containment` stayed pinned near 1.0 in both the
contained and uncontained cases in this scenario (for different
reasons in each), contributing nothing to differentiate them, while
`trust_health` swung hard in the WRONG direction. With `taint_containment`
neutralized, `trust_health`'s perverse penalty was free to dominate the
30%-weighted average unopposed.

### Fix (four changes, applied and verified -- not just designed)

This took three iterations to get genuinely right, not one clean pass --
worth recording honestly since the intermediate attempts each surfaced
a real, distinct additional bug rather than being wasted effort.

**1. `TaintPropagationEngine._peak_reach`** (fixes evidence erasure).
Tracked incrementally on every `propagate()` call, BEFORE any future
`quarantine_edges_from()` call can remove the evidence. Successfully
containing an attack no longer erases the proof that it needed to be
contained. Also lowered the default edge-taint noise threshold
(0.1 -> 0.02), which was independently excluding this attack pattern's
real severity range from ever registering as "tainted" at all.

**2. `trust_health_score()` made interactive** with the *structural*
containment signal (see #4 below for why it's specifically the
structural signal, not the blended one) -- justified quarantine now
costs a small constant operational-capacity penalty (0.15) instead of
the full per-agent penalty; quarantine that happened but still failed
to contain the attack still costs the full penalty.

**3. First iteration bug, caught and fixed**: initially coupled
`trust_health` to the *blended* `taint_containment_score` (which also
folds in `per_message` -- did any single message look individually
severe). This double-penalized a fast, fully-successful containment
(0 blast radius) whenever the 1-2 messages that got through before
quarantine happened to be individually severe -- a real high-severity
attack, quickly and completely contained, was still scoring near-zero
trust_health. Fixed by decoupling: `trust_health` now takes
`graph_level` (the direct reachability/outcome signal) specifically,
not the blend.

**4. Second iteration bug, caught and fixed**: `taint_containment_score`
itself combined `per_message` and `graph_level` via `min()` (pessimistic
worst-of-two). That's the wrong combination here -- `per_message`
answers "was any single message individually severe," a genuinely
different question from "did propagation actually get contained," and
`min()` let a high-but-quickly-caught severity attack (blast_radius=0,
but 1-2 individually severe messages got through first) score WORSE
than a low-severity attack that fully escaped every single agent
(every message individually mild, so `per_message` looked artificially
"clean"). Changed to a weighted blend (`0.3*per_message + 0.7*graph_level`)
that trusts the direct outcome measure more, while `per_message` still
contributes rather than being able to veto a genuine containment
success.

**5. Sampling range widened again**: even with all of the above fixed,
the test's severity range (`[0.03, 0.16]`) was still concentrated almost
entirely in the genuinely ambiguous near-boundary zone (marginal, late
containment legitimately produces noisier FARS behaviour than a clean
catch). Widened to `Uniform[0.02, 0.4]`, spanning from clearly-
uncontained low severity through the marginal zone into clearly-well-
contained higher severity, where the now-fixed components show clean
separation.

**Final verified result:** AUC = 0.799, Pearson r = 0.397 (p=0.030,
statistically significant), test passes outright -- no skip. Confirmed
against the full regression suite: all 15 pentest scripts, both
`main.py` scenarios, and the full pytest-equivalent test suite
(26 passed, 0 skipped, 0 failed -- one more test than before, since
this one no longer needs to skip).

## 17. v7.4 additions: chaos engineering + property-based fuzzing (Phase 1 item 3)

`tests/test_05_chaos_and_fuzzing.py` closes a real gap: every other
test in this codebase (all 15 pentest scripts, all of `tests/`) assumes
a deliberate attacker. Nothing tested ordinary bad luck.

**Property-based fuzz tests (6, custom seeded fuzzer -- `hypothesis`
isn't installable in this offline sandbox, same limitation as the
offline pytest harness used elsewhere; same spirit -- many random
cases per property, not hand-picked examples -- with less tooling).**
Signature round-trip always verifies for genuine pairs; a signature
never verifies against a mismatched identity; flipping any single bit
of a valid signature always breaks verification; `MemoryStore`'s hash
chain stays intact across any random sequence of legitimate writes/
revocations; tampering is detected regardless of WHERE in a random-
length history it's injected; `FederationLedger`'s quorum commits if
and only if cumulative distinct-org stake has actually reached the
threshold, across random stake/witness-order combinations. All pass,
200 iterations each where applicable.

**Non-adversarial failure injection (3):**
  - A witness org that simply never responds leaves the proposal
    indefinitely, correctly uncommitted -- no crash, no timeout-based
    auto-commit, and the rest of the bus keeps working normally for
    everything unrelated.
  - A bus "restart" (new instance, same on-disk audit DB, simulating a
    process crash) correctly preserves audit history (SQLite
    persistence working as intended) while losing all admitted
    sessions -- every agent must re-admit, which is the SECURE default,
    not a bug.
  - **A genuine, documented finding, closed in v7.6:** injecting a
    simulated database failure into the audit-write path showed it
    propagated as an unhandled exception rather than degrading
    gracefully. This was SAFE in the sense that it never silently
    treated a blocked message as allowed (no security control was ever
    bypassed by a DB failure), but it WAS a robustness gap: no
    fallback, retry, or in-memory buffering for audit-log failures, so
    a flaky disk turned into a hard crash of whatever called `send()`/
    `write_memory()`/etc., rather than a logged-and-continue. Left open
    through v7.5 (LINDDUN and the CUSUM defence-in-depth work were
    prioritised first) -- see Section 21 for the v7.6 fix and its
    verification.

## 18. v7.4 additions: independent detector + scale testing (Phase 1 items 4-5)

**PT-16 -- Structurally independent fan-out detector (Phase 1 item 4).**
CUSUM and `SlidingWindowVolumeDetector` (Section 5) are BOTH magnitude-
based -- they track the size/sum of `taint_delta` values. That's a
shared blind spot, not two independent defences: an attacker who keeps
every single `taint_delta` arbitrarily small evades both simultaneously,
by construction, regardless of how well either is tuned, because
neither tracks WHO messages go to. `orchestration.FanOutAnomalyDetector`
tracks a completely orthogonal signal -- distinct targets contacted
within a sliding window -- catching reconnaissance/lateral-movement/
Sybil-style fan-out that stays invisible to magnitude no matter how
low. PT-16 proves the gap is real (confirms CUSUM and the volume
detector both genuinely never trip against a 0.001-taint, 11-distinct-
target attack) and that the new detector catches it, specifically via
the `fanout_anomaly` reason, not a coincidental magnitude trip.

**PT-17 -- Scale testing at 50 and 100 orgs (Phase 1 item 5).** Every
prior pentest and statistical trial ran at N=1-6 orgs. Verified at
N=50/100: PBFT quorum computation, quorum-witnessing commit timing
(commits at EXACTLY the computed quorum, not before/after), org-level
Sybil containment, and the fan-out detector -- all correct at scale, not
just in a small federation.

**A genuine, quantified performance finding, then fixed.** FARS's
connectivity component (`nx.average_node_connectivity()`) was flagged
as an open cost concern very early (Section 3) but never measured.
PT-17 quantified it directly: **2.7s at 100 agents, 20.3s at 200
agents** -- roughly O(N^2.9), since it computes an exact min-cut for
EVERY pair of nodes. Naive extrapolation puts a 1000-agent federation
at several hours per FARS computation, which would be completely
impractical. Fixed: for graphs at or under 20 nodes (comfortably above
every existing pentest/`main.py` scenario -- all previously-calibrated
FARS numbers are byte-identical, confirmed by re-running the full
regression suite), compute exactly as before. Above that, sample a
bounded number (200) of random node pairs instead of all C(N,2) --
verified accurate (0.9% relative error against the exact value at a
size still small enough to compute both) and deterministic (fixed
seed). Result: **486ms at 100 agents (5.5x faster), 963ms at 200 agents
(21x faster)**, and scaling is now approximately linear instead of
super-linear.

## 19. v7.4 addition: combined detection-latency metric (Phase 1 item 2)

`fars.DetectionLatencyTracker` measures how many messages/how much
wall-clock time elapsed before an attack was first detected, broken
down PER DETECTOR FAMILY -- deliberately built after 18's
independent fan-out detector, so detection speed could be compared
ACROSS genuinely different detector families (CUSUM, agent-level
volume, org-level volume, fan-out), not reported as one
undifferentiated number. `FederationBus.resilience_timing_report()`
pairs this with the existing recovery-time metric (Section 7) --
neither alone tells the whole story: a federation could detect fast but
recover slowly, or vice versa, and reporting only one would hide that
trade-off. Verified in `pentest/pt18_detection_latency_validation.py`.

**A genuine structural finding, surfaced while building this test.**
Attempting to naturally trigger CUSUM as the FIRST detector via the
real `send()` pipeline failed every time -- not a bug in the test, a
real property of the current calibration. Agent-level
`SlidingWindowVolumeDetector` (cap=0.5, no slack subtraction)
mathematically reaches its threshold on or before CUSUM's slack-
adjusted effective threshold (`0.5 + n*k`, strictly higher for any
`n>0`) for ANY continuous-drift attack on the same per-agent stream --
CUSUM subtracts a fixed slack every step, so it structurally needs MORE
cumulative raw taint to trip than a same-capped raw-sum detector, full
stop. **Under the current calibration, CUSUM cannot be the first
detector to fire for a straightforward continuous-drift attack --
agent-level or org-level volume always wins the race.** CUSUM's
genuine, distinct advantage -- surviving windowed eviction of old
high-taint messages that a sliding-window detector would "forget" --
doesn't help in the scenarios tested here because the volume
detectors' windows (20-40 messages) are already large enough to
contain the attacker's threshold-crossing traffic before eviction
matters. This means CUSUM, as currently calibrated, is functionally
redundant with the volume detectors for the attack shapes this
codebase's pentest suite exercises -- it may still have genuine value
against a specifically gapped/intermittent attack pattern designed to
exploit windowed eviction, but that's a different, not-yet-tested
attack shape. Worth investigating further (re-tuning CUSUM's k/h so it
CAN win the race for at least some realistic attack shapes, or
explicitly documenting CUSUM's role as redundancy/defence-in-depth
rather than a distinctly faster detector) -- pursued below (v7.5).

**v7.5 update: CUSUM's role formally repositioned, backed by evidence,
not just reframed in prose.** `pentest/pt20_cusum_defense_in_depth.py`
tests the actual question this finding raises: if CUSUM never wins the
race under normal calibration, does it have ANY standalone value, or is
it dead code? Answer: simulating the volume detectors disabled/
misconfigured (a real operational failure mode -- a bad deploy, a
misapplied config change, a bug in a future refactor, not a contrived
worst case) shows CUSUM independently catches the identical
continuous-drift attack on its own -- message 4 with volume detection
active, message 10 with it disabled, CUSUM alone. **CUSUM's documented
role from v7.5 onward: defence-in-depth against the failure of the
FASTER layers, not a distinctly faster detector in its own right.**
This is the correct way to read redundancy in a layered defence: the
value isn't "which layer wins the race under normal operation," it's
"does losing one layer still leave the system caught by another,
independently." Kept in the detector chain and NOT removed as
"redundant dead code" precisely because of this result.

## 20. v7.5 addition: LINDDUN privacy fix (Linkability/Identifiability + Disclosure of information)

Section 13/`RISK_APPENDIX.md` Part A identified these as the two
highest-impact unaddressed findings in the entire risk matrix (Risk
15-16, above every remaining security finding). Both closed together,
since they center on the same persisted surface -- the SQLite audit
log -- verified in `pentest/pt19_linddun_privacy_protections.py`.

**Disclosure of information.** `FederationBus._write_audit_row()`
previously stored the `reason` field as plaintext. Now encrypted
(AES-256-GCM) before writing; `read_audit_log()` decrypts transparently
for legitimate callers.

**Linkability/Identifiability.** Every agent's permanent `did:key`
previously appeared directly in every persisted audit row -- trivially
linkable across the federation's entire history by anyone with access
to an export or a stolen DB file. `trust_protocol.py`'s new pseudonym
registry gives each agent a rotating pseudonym used specifically for
what's persisted; the real-identity mapping stays bus-internal, never
written into the audit rows themselves.

**Two real bugs found and fixed while building the verification test,
not just designed on paper:**
  1. The encryption key was originally regenerated fresh on every
     `FederationBus.__init__` -- meaning a bus restart (the exact
     scenario `test_chaos_bus_restart_*` already simulates) made every
     prior row's `reason` field PERMANENTLY undecryptable. Not a
     security property, data loss. Fixed: the key persists to a
     companion file (`{db_path}.key`), loaded on subsequent opens of
     the same `db_path`.
  2. The pseudonym mapping was originally kept in-memory only, by
     design ("never persisted to disk") -- which sounded like a privacy
     win but actually meant the operator PERMANENTLY lost the ability
     to resolve any historical pseudonym back to a real identity after
     any restart, destroying legitimate accountability, not just
     attacker linkability. Fixed: persisted to a SEPARATE companion
     file (`{db_path}.pseudonyms.json`, distinct from both the DB and
     the key file) -- raw theft of any ONE of the three files still
     reveals nothing usable; all three would be needed together.

**PT-19 proves the actual threat model, not just the API:** simulates
literal raw SQLite file theft (a second process opening the `.db` file
directly, bypassing the bus API entirely) and confirms neither real
identities nor plaintext reasons are present in the stolen file, while
the legitimate `read_audit_log()` API works transparently (pseudonyms
+ decrypted reasons by default, real identities only via an explicit
`resolve_identities=True` operator escalation), and the tamper-evidence
hash chain remains completely unaffected.

**Honest scope, stated explicitly rather than left implicit:** this
protects against RAW FILE/DISK theft specifically (a stolen backup, a
decommissioned disk, misconfigured file permissions). It does NOT
protect against a compromise of the running bus PROCESS itself, which
holds the encryption key, the pseudonym mapping, and every agent's
signing key in memory for as long as it's alive. Real protection
against a compromised process needs these secrets to live outside the
bus entirely -- a KMS, not a companion file -- which is exactly
Section 9's already-deferred HSM/KMS item. This fix does not replace
that; it closes a different, real, and previously completely
unaddressed gap in the meantime.

**What's still open (LINDDUN, per `RISK_APPENDIX.md` Part A):**
Non-repudiation-as-privacy-risk (the design tension between signed,
non-repudiable messages and legitimate plausible-deniability interests)
and Detectability (the mere presence of audit rows/ledger blocks
reveals federation membership) remain unaddressed -- both are lower
per-item Trike risk than the two closed here, and neither has as clean
a technical fix (they're closer to policy/design-tension questions than
implementation gaps).

## 21. v7.6 addition: audit-write failure handling (Section 17 finding, closed)

Section 17's chaos test (`tests/test_05_chaos_and_fuzzing.py`) found that
a mid-write SQLite failure propagated as an unhandled exception out of
`_write_audit_row()`, crashing whatever public method called it. This
was left open through v7.5 because LINDDUN (Section 20) needed a second,
unplanned bug-fix pass -- the encryption key and pseudonym registry not
surviving a bus restart -- which consumed the session time originally
budgeted for this item.

**The fix.** `_write_audit_row()` now wraps the `INSERT`/`commit()` in
`try/except sqlite3.Error`. On failure, the row is appended to an
in-memory `self._audit_write_buffer` list, a failure counter increments,
a warning is logged to stderr, and -- critically -- **nothing is
re-raised**. The security decision (allow/block/quarantine) has already
been computed and returned to the caller by the time `_write_audit_row()`
runs; that decision now stands regardless of whether the audit row
reaches disk immediately, later, or (in a sustained outage) only after
the process restarts and the buffer is lost.

**Hash-chain correctness under buffering.** The subtle part of this fix
isn't the try/except -- it's *when* `self._last_row_hash` advances.
Previously it only advanced after a successful `commit()`, which was
fine when failure meant "crash" (nothing after that line ever executed).
Once failure means "catch and continue," advancing the pointer only on
success would let two logically-different rows compute against the same
stale `prev_hash`, once persistence eventually catches up -- a broken
chain. The fix advances `self._last_row_hash` unconditionally, the
moment the row is computed, independent of whether persistence
succeeds. `verify_audit_integrity()` needed no changes: it only ever
walks what's actually IN the SQLite table, so buffered-but-not-yet-
flushed rows are simply invisible to it until they land -- never a gap
it has to reason about specially.

**Recovery has two paths.** `flush_buffered_audit_rows()` is a public,
explicitly-callable method for an operator/health-check to force a
retry and inspect `{flushed, pending, total_failures_this_session}`.
But `_write_audit_row()` also opportunistically attempts to flush any
existing buffer *before* writing its own new row, so a federation
self-heals automatically on the very next message once the DB recovers
-- no operator action required. Both paths flush strictly in order
(oldest buffered row first), stopping at the first renewed failure
rather than reordering or skipping ahead, so on-disk row order always
matches true event order.

**Verification: `pentest/pt21_audit_write_resilience.py`.** Goes beyond
the chaos test's single-failure/explicit-flush check to cover three
scenarios that matter specifically for a security audit trail:

- **Part A (sustained outage, 5 consecutive failures):** every `send()`
  during the outage still returns the correct decision -- an attacker
  gains nothing from timing an attack to coincide with a DB outage. All
  5 rows buffer; nothing crashes.
- **Part B (recovery + explicit flush):** once the DB recovers,
  `flush_buffered_audit_rows()` drains all 5 buffered rows in order,
  and `verify_audit_integrity()` confirms the hash chain is fully
  intact across the buffer-and-recover cycle.
- **Part C (opportunistic auto-flush):** a fresh single failure
  buffers one row; the *next* `send()` -- with no explicit flush call
  anywhere in the test -- both writes its own row and drains the
  pending one automatically, and the chain stays intact.

All 8 checks pass. Also re-verified: `tests/test_05_chaos_and_fuzzing.py`'s
original chaos test was updated in place (same scenario, new expected
behaviour -- `raised is False` instead of `raised is True`) since the
finding it documented is now fixed rather than merely observed. Full
regression: 21/21 pentest scripts pass, both `main.py --scenario all`
and `--scenario composite` produce byte-identical FARS numbers to v7.5
(72.12 / 65.78 respectively), confirming this fix touches only the
failure path and changes no existing behaviour on the happy path.

**Known residual limitation, stated explicitly.** The buffer is
in-memory only. If the process itself crashes (not just the DB) while
rows are buffered, those specific rows are lost -- `close()` now makes
one last opportunistic flush attempt and, if rows remain, logs an
explicit warning naming how many will be lost, rather than silently
dropping them. This is an honest, disclosed limitation, not a hidden
gap: a production deployment wanting zero audit-row loss across a
process crash needs the buffer itself to be durable (e.g. a local
write-ahead file or a message queue the bus writes to synchronously
before attempting SQLite) -- infrastructure-dependent, and a reasonable
Phase 2 item alongside the other SPOF-driven durability work.

**Adjacent findings closed in the same pass: startup-time file
corruption and CLI cleanup-on-error.** Sweeping the codebase for other
places with the same *shape* of gap (an unhandled exception where a
clear, actionable failure or a graceful continuation would be better)
turned up two more, both fixed alongside the audit-write handling
above since they're part of the same robustness story:

- **Corrupted companion files (`{db_path}.key`, `{db_path}.pseudonyms.json`)
  at startup.** Both were read with no exception handling -- a
  truncated key file or invalid-JSON pseudonym registry (e.g. from a
  process kill mid-write, since neither write was atomic) crashed
  `FederationBus.__init__()` with a raw, unhelpful traceback. Unlike
  the audit-write case, the right fix here is NOT graceful continuation:
  silently generating a fresh key or an empty pseudonym registry would
  permanently abandon the ability to decrypt/resolve every existing
  audit row, which is a data-loss decision an operator should make
  explicitly. Both now fail loudly with a specific, actionable
  `RuntimeError` naming the file and the recovery options, instead of
  an unexplained crash. `save_pseudonym_registry()` was also made
  atomic (write to a temp file, then `os.replace()`), which prevents
  the corrupted-file scenario from being self-inflicted by a crash
  during the bus's own write in the first place.
- **`main.py` not guaranteeing `bus.close()` on a mid-scenario
  exception.** All three CLI branches (`all`, `composite`, single-
  scenario) now wrap scenario execution in `try/finally`, so the bus
  (and, since v7.6, any final opportunistic audit-buffer flush) always
  gets a chance to close cleanly even if a scenario raises partway
  through, rather than leaking the open SQLite connection and silently
  skipping the close-time buffered-row warning.

Full regression re-run after these three files changed together:
21/21 pentest scripts, both `main.py` modes byte-identical to the
audit-write-only fix above, plus manual verification that both new
`RuntimeError` paths produce the intended message (rather than the
mere absence of a crash) and that the atomic pseudonym-registry write
round-trips correctly with no leftover temp file.

## 22. v7.7 additions: prompt-injection classifier, crypto-shredding, structured logging

Closes the three items PHASE1_GAP_REPORT_v7.6.md scoped as "worth fixing
before Phase 2 cloud work" -- one genuinely open detection gap (PT-15's
paraphrase evasion), one genuine structural tension (append-only chains
vs. GDPR Art. 17 erasure), and one mechanical-but-blocking observability
gap (no `logging` module usage anywhere in the codebase).

**Prompt-injection classifier (closes PT-15's documented paraphrase
gap).** Section 15 broadened the original two-phrase exact match into a
multi-signal heuristic, but honestly documented one residual gap: a
genuinely novel paraphrase evades any keyword/regex list, however
broad. `agents.py`'s `detect_prompt_injection()` now adds a second,
independent signal -- a TF-IDF + logistic-regression classifier trained
(at process start, ~30 illustrative examples, well under 100ms on CPU)
on override-vs-benign instruction pairs. The two signals combine
fail-closed (either firing is sufficient), and the classifier degrades
to a documented fail-closed-on-ambiguity fallback if scikit-learn isn't
installed, rather than silently disabling the second signal.
`pentest/pt15_prompt_injection_heuristic.py` was updated (not just
re-run) to verify the fix against the EXACT paraphrase that originally
demonstrated the gap (now caught, via the classifier, not the
heuristic) plus an honest Part D stress test against a harder, more
indirect paraphrase deliberately worded outside the training corpus's
vocabulary -- reported, not asserted, since a ~30-example illustrative
corpus is not claimed to catch everything. **Explicitly not closed:**
this remains a small illustrative corpus, disclosed as such in
`agents.py`'s module docstring; production use needs a real labelled
dataset (AgentDojo/INJEC per the proposal's Tab 7.6) before citing ASR
figures against it.

**Crypto-shredding (closes the append-only-vs-erasure structural
tension, RISK_APPENDIX.md Part A "Non-compliance" row, HIGH severity).**
Every memory write now encrypts its value with a fresh per-record
AES-256-GCM key before it enters the hash chain; only the ciphertext is
stored. `content_hash` is redefined as the hash of the ciphertext, not
the plaintext -- this is what makes tamper-evidence independent of
whether the plaintext is still recoverable.
`FederationBus.erase_memory_record()` (a new operator entry point,
alongside the existing `revoke_memory_record()`) discards the
per-record key(s) for every record ever written at a key, which is what
GDPR Art. 17 erasure actually requires: the ciphertext blob stays in
the chain (structural integrity, ordering, and "something existed here
and was erased on <date> for <reason>" all remain fully auditable via
the new `inspect_memory_history()` compliance-reviewer view), but the
DATA is permanently gone. `pentest/pt22_crypto_shredding_erasure.py`
verifies all four required properties hold simultaneously: erasure is
genuinely irreversible (not just hidden from the ordinary read API),
tamper-evidence survives erasure of the tampered record, the audit
trail still shows the erasure event, and revoke (recoverable) is
demonstrably different from erase (unrecoverable). **Explicitly not
closed:** the per-record key keystore is itself in-memory,
single-process, same limitation as everything else in this prototype
(Section 9) -- Phase 2/cloud swaps it for a managed KMS with envelope
encryption without changing anything above it.

**Structured logging (closes PHASE1_GAP_REPORT_v7.6.md's "one item
worth a deliberate decision" -- resolved as: fix now, not defer).** A
new `farf_logging.py` module gives every production-path component
(`federation_bus.py`, `agents.py`, `memory_store.py`, and every other
component via the same pattern) a standard `logging.Logger`, with level
(`FARF_LOG_LEVEL`) and format (`FARF_LOG_FORMAT=text|json`) controlled
entirely by environment variables -- no code change needed to move
from laptop demo output to a JSON stream a cloud log sink
(CloudWatch/Cloud Logging/Azure Monitor) can tail directly. The two
previously-bare `print(..., file=sys.stderr)` audit-write warnings are
now `log.warning`/`log.error` calls with structured fields; the main
`send()` decision choke point and org-wide quarantine now emit a
structured event per decision (severity scaled to the decision itself:
ALLOW at DEBUG, BLOCK at WARNING, QUARANTINE at ERROR) alongside the
existing durable SQLite audit row, so an operator can watch live
decisions without querying the DB. **Deliberately out of scope,
documented, not an oversight:** `main.py`'s scenario narration (the
print() calls describing what each attack scenario is doing) and every
module's own `if __name__ == "__main__":` self-test block stay as plain
`print()` -- see `farf_logging.py`'s module docstring for why
collapsing narration and logging into one channel would make the demo
worse without making anything more observable.

**Full regression after all three changes.** 22/22 pentest scripts pass
(21 pre-existing plus the new `pt22_crypto_shredding_erasure.py`), both
`main.py --scenario all` and `--scenario composite` run end-to-end with
no behavioural regression, and both log formats (`text`, `json`) were
manually verified to emit the same structured events. Two pre-existing
tests had to be updated in place because they directly manipulated the
now-removed `MemoryRecord.value` field to simulate raw-datastore
tampering: `pentest/pt10_memory_poisoning_and_toctou.py` Part B and
`tests/test_05_chaos_and_fuzzing.py`'s
`test_fuzz_memory_chain_detects_tampering_at_any_random_point` now
tamper `record.ciphertext` directly instead -- same attack (bypass the
signed-write API, mutate the stored value in place), same expected
detection outcome, updated only because the field it targets moved.

## 23. What v7.7 leaves genuinely open

As of v7.6 (Section 11): the HSM/KMS-backed key storage, key rotation,
and PKI root-of-trust items deliberately deferred to FARF Cloud
(Section 9); MAESTRO Layer 7 ecosystem-level trust (Section 13); the
remaining LINDDUN gaps -- Non-repudiation-as-privacy-risk and
Detectability (Section 20, design-tension questions, not implementation
gaps); OCTAVE/Trike's formal asset-and-risk layer (Section 13); VAST's
CI-automation recommendation (delivered as `tools/farf_security_lint.py`);
the adaptive volume detector's calibration-poisoning trade-off
(Section 14, an operational decision, not a code gap).

**Closed by v7.7, removed from the open list:** the PT-15 paraphrase
detection gap (Section 15/22 -- reduced via a real classifier, not
eliminated; residual risk against a sufficiently novel attacker
against this specific small training corpus remains and is disclosed);
the append-only-chain-vs-erasure structural tension (RISK_APPENDIX.md
Part A, Section 22 -- crypto-shredding resolves the tension by design,
not by picking a side); the missing-`logging`-module observability gap
(PHASE1_GAP_REPORT_v7.6.md Section 5, Section 22 -- structured logging
now in place on the production call path).

**New residual item this pass created, disclosed rather than hidden:**
the per-record crypto-shredding keystore (`MemoryStore._record_keys`)
is in-memory and single-process, same limitation as every other
in-process secret in this prototype (Section 9) -- Phase 2/cloud needs
this backed by a real KMS with envelope encryption, not a Python dict,
before the erasure guarantee holds against anything beyond
process-memory-level trust.

What remains genuinely open are reasonable candidates for a "Future
Work" section in the dissertation, or (Section 9's items) require real
cloud infrastructure this laptop prototype cannot meaningfully fake.
