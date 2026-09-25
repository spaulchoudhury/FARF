# FARF Risk & Threat-Modeling Appendix

Companion document to `THREAT_MODEL.md`. Where that document works
component-by-component (STRIDE) and layer-by-layer (MAESTRO), this
appendix works asset-by-asset and business-impact-by-business-impact --
the four methodologies 13 of `THREAT_MODEL.md` identified as
adding a genuinely different lens: **LINDDUN** (privacy), **OCTAVE**
(organisational asset/risk), **Trike** (formal risk acceptance), and
**PASTA** (business-impact ranking). **VAST** is process/tooling, not
analysis, so it's delivered here as a working script rather than a
written section -- see Part E.

This is Tier 2 work: it formalizes and extends what the technical
hardening (v3-v7.1, see `THREAT_MODEL.md`) already established. Nothing
here is a new code fix; Part A (LINDDUN) is the one section that
surfaces a genuinely new, previously-unaddressed gap rather than
reframing existing findings.

---

## Part A -- LINDDUN Privacy Analysis

FARF's entire threat model to this point has been written from a
security (confidentiality/integrity/availability) perspective. LINDDUN
asks a different question per category: does this system create a
privacy risk EVEN WHEN it's behaving exactly as designed? Several of
these are real, currently-open gaps, not restatements of existing
findings.

| Category | Affected component(s) | Description | Severity | Status |
|---|---|---|---|---|
| **Linkability** | `trust_protocol.py` (`did:key` identities) | Every agent's DID is a single, stable, long-lived identifier used in every signed message, memory write, and witness attestation. Anyone with access to the message-layer traffic or the audit trail can trivially link every action a given agent has ever taken across the entire federation -- there is no unlinkability mechanism (e.g. per-session rotating pseudonyms) at all. | **HIGH** | **Partially closed (v7.5)** -- what's PERSISTED (the audit log) now uses rotating pseudonyms, not the permanent DID; live message-layer signatures still use the stable DID (needed for real-time verification), so in-flight traffic interception is unaddressed -- see THREAT_MODEL.md Section 20 |
| **Identifiability** | `trust_protocol.py`, `federation_bus.py` (audit log) | Closely related to linkability: a DID plus the org-issuance record (`issue_credential()`'s `subject_did`/`claims`) can plausibly be tied back to a specific real-world agent, service account, or even individual human operator, depending on deployment. FARF has no concept of pseudonymity or unlinkable credentials (e.g. anonymous credentials / zero-knowledge attribute proofs, which `trust_protocol.py`'s existing `ZKAttestation` class gestures toward for ONE specific claim but doesn't generalize). | **HIGH** | **Partially closed (v7.5)** -- same pseudonym registry as Linkability above; real-identity resolution now requires explicit bus-operator escalation rather than being visible in every persisted row |
| **Non-repudiation** (as a *privacy* risk, not a security benefit) | Every signed surface: `send()`, `write_memory()`, `witness_federation_reinstatement()` | Section 7/13 of `THREAT_MODEL.md` treats non-repudiation as a hardening WIN (an attacker can't deny having sent a forged message). LINDDUN's framing inverts this: a LEGITIMATE agent (or the human/org operating it) may have a real interest in plausible deniability that FARF's design removes completely and by construction. This is a genuine design tension worth naming explicitly rather than silently resolving in security's favor. | MEDIUM | Open -- documented tension, not resolved either way |
| **Detectability** | `federation_bus.py` (audit log), `federation_ledger.py` (chain) | Even without reading message CONTENT, the mere presence of audit rows and ledger blocks reveals that a given agent/org exists, is active, and (via quarantine/reinstatement events) has been involved in a security incident. For a federation where membership itself is sensitive (e.g. a consortium that doesn't want to reveal who its members are), this is a real leak with no mitigation in the current design. | MEDIUM | Open |
| **Disclosure of information** | `federation_bus.py` (SQLite audit rows) | Audit rows stored full plaintext payloads with no consideration of whether that payload might itself contain personal or sensitive data. Nothing asked "should this field be encrypted at rest" or "should this payload be redacted before logging." (`memory_store.py`'s records were never actually at risk from THIS specific vector -- it's a pure in-memory store with no disk persistence at all in the current architecture; the finding stands only as a forward-looking consideration if persistence is ever added, not a currently-exploitable gap.) | **HIGH** | **Closed (v7.5)** -- the `reason` field is now AES-256-GCM encrypted before writing; verified via literal raw-file-theft simulation in `pentest/pt19_linddun_privacy_protections.py`. Protects against raw disk/file theft specifically, not a compromised running process (same scope as every other in-process secret -- see Section 9) |
| **Unawareness** | System-wide | Not currently applicable in the strict sense -- FARF's pentest/demo scenarios don't involve real data subjects. Flagged as a **deployment consideration**: if FARF is used with real customer data flowing through agent memory or messages, whoever that data is about has no visibility into or control over how it's used within the federation. Any real deployment needs a data-subject-facing answer to this, not a code fix within FARF itself. | N/A (deployment-dependent) | Flagged, not applicable to the prototype as-is |
| **Non-compliance** | `memory_store.py` (append-only chain), `federation_ledger.py` (append-only chain) | A genuine, structural tension: `revoke_memory_record()` (v7.1) tombstones a record but the tombstoned VALUE remains permanently readable by walking the hash chain directly (`MemoryStore._chains`) -- `read()` hides it, but nothing cryptographically erases it. Regulations with a "right to erasure" (GDPR Art. 17 and similar) are fundamentally in tension with an append-only, tamper-evident chain design -- you cannot have both perfect audit-trail immutability AND true data erasure. | **HIGH** (if handling regulated data) | **Closed (v7.7)** -- crypto-shredding: every write now encrypts its value with a fresh per-record AES-256-GCM key before it enters the chain, and `content_hash` is redefined as the hash of the ciphertext (not the plaintext), so tamper-evidence no longer depends on the plaintext being recoverable. `FederationBus.erase_memory_record()` discards a key(s), making the data permanently unrecoverable while the ciphertext blob and the chain's structural integrity remain fully intact and auditable via the new `inspect_memory_history()` view. Verified via `pentest/pt22_crypto_shredding_erasure.py` (erasure is genuinely irreversible, tamper-evidence survives erasure, the audit trail still shows the erasure event, revoke vs. erase are demonstrably different operations). Residual limitation, disclosed: the per-record keystore is in-memory/single-process (same scope as every other in-process secret -- see THREAT_MODEL.md Section 9); Phase 2/cloud needs a real KMS with envelope encryption |

### Recommended mitigation directions (not implemented -- future work)

- **Linkability/Identifiability**: rotating, per-session pseudonymous
  DIDs instead of one permanent identifier per agent, with a
  privacy-preserving mechanism (e.g. a group signature scheme, or
  building out `trust_protocol.py`'s existing `ZKAttestation` primitive
  into general-purpose anonymous credentials) to still prove
  "authorized member of OrgA" without revealing WHICH specific agent.
- **Disclosure of information**: field-level encryption for memory/audit
  payloads, with keys held by the owning org rather than the bus
  operator, so a compromised bus host doesn't also mean a compromised
  data store.
- **Non-compliance**: **closed, v7.7** -- see the table row above and
  THREAT_MODEL.md Section 22 for the crypto-shredding design that
  resolves this without picking a side (redesigned around per-record
  encryption keys that can be destroyed, exactly as this row originally
  suggested as a future-work direction; kept here for historical
  record of the recommendation that was implemented).

---

## Part B -- OCTAVE Asset & Stakeholder Risk Profile

OCTAVE starts from assets and organisational risk tolerance, not code
components. This is the missing piece `THREAT_MODEL.md`'s Section 1
("component inventory") doesn't provide -- that section lists CODE
artefacts, not business ASSETS.

### Asset inventory

| Asset | Description | Owner | Confidentiality | Integrity | Availability | Current protection |
|---|---|---|---|---|---|---|
| Org private keys (`DIDKeyIdentity`) | Root of trust for everything an org does in the federation | Each member org | Critical | Critical | High | In-process only (Section 9 -- HSM/KMS deferred to FARF Cloud) |
| Agent private keys | Per-message signing identity | Each agent (via its org) | High | Critical | High | Same as above; `revoke_agent()` (v5) mitigates compromise blast radius |
| Inter-agent message content | Task delegation, plans, execution results | Sending agent's org | Medium-High (context-dependent) | Critical | High | Zero-Trust signing (v5/PT-08); NOT encrypted in transit or at rest |
| Agent memory contents | Persistent per-agent state | Owning agent's org | Medium-High | Critical | Medium | Hash-chained + signed (v6/v7.1); NOT encrypted (LINDDUN, Part A) |
| Audit trail | Full history of bus decisions | Bus operator (whoever runs `FederationBus`) | Medium | Critical (tamper-evidence, not tamper-proofing) | High | Hash-chained (v3); single SQLite file, no access control modeled |
| Federation Ledger consensus state | Record of federation-wide reinstatement votes | Federation collectively | Low | Critical | High | Signed, stake-weighted quorum (v7); single-process (Section 6/13) |
| FARS / resilience reputation | The federation's own measure of its health | Federation collectively | Low | High | Medium | EWMA + recovery tracking (v7); no protection against a compromised bus lying about its own score |
| Org "good standing" / reputation | Whether other orgs trust this org enough to witness/stake for it | Each org, judged by peers | Low | High (socially, not just technically) | N/A | `set_stake()` (v7) exists as a mechanism but no governance process for WHO sets it or how disputes are resolved |

### Stakeholder risk tolerance

OCTAVE's core insight is that different stakeholders have genuinely
different risk tolerance for the SAME asset, and FARF currently treats
every org identically (one fixed cap, one fixed quorum, unless
explicitly overridden per-org via `set_stake()`/`AdaptiveOrgVolumeDetector`).
Concretely, a real federation likely contains orgs with very different
profiles:

- **A regulated financial-services member** likely has LOW tolerance
  for false negatives (a missed attack has severe compliance/legal
  consequences) and is willing to accept more false-positive
  quarantines in exchange. For this org, a TIGHTER `org_volume_detector`
  cap and a HIGHER stake-weight requirement to witness reinstatements
  might be the right governance choice.
- **A research/hobbyist member** likely has the opposite profile --
  higher tolerance for occasional false negatives, low tolerance for
  being falsely quarantined and locked out of a system they're using
  for exploration.
- **The federation as a whole** needs an explicit, agreed-upon
  governance process for setting `stake`, `quorum_required`, and
  per-org volume caps -- currently these are all just constructor
  arguments a single trusted bus operator sets, with no modeled
  consensus process for the DECISION itself (only for the
  reinstatement VOTES that use those parameters once set). This is a
  governance gap, not a technical one -- worth naming in the
  dissertation as a boundary of what code alone can solve.

---

## Part C -- Trike Risk Matrix

Trike formalizes risk as **likelihood x impact**, scored against an
explicit acceptable-risk threshold, rather than a binary
VULNERABLE/NOT-VULNERABLE verdict. This combines Part B's asset values
with `THREAT_MODEL.md` Section 3's technical findings into residual-risk
scores, pre- and post-hardening.

Scale: Likelihood and Impact both scored 1 (low) - 5 (critical).
Risk = Likelihood x Impact. **Acceptable threshold for this prototype:
Risk <= 6** (i.e., nothing above "medium likelihood x medium impact" is
considered acceptable residual risk for a system handling the assets in
Part B's inventory).

| Finding | Primary asset(s) at risk | Pre-hardening L | Pre-hardening I | Pre-hardening Risk | Post-hardening L | Post-hardening I | Post-hardening Risk | Within threshold? |
|---|---|---|---|---|---|---|---|---|
| PT-01 Identity spoofing | Message content, audit trail | 5 | 5 | 25 | 1 | 5 | 5 | Yes |
| PT-02 Field-omission bypass | Message content, agent privilege | 4 | 4 | 16 | 1 | 4 | 4 | Yes |
| PT-03 CUSUM slow-drip | Agent memory, message content | 4 | 4 | 16 | 2 | 4 | 8 | **No** -- see note |
| PT-04 Distributed Sybil | Federation-wide availability, reputation | 3 | 5 | 15 | 1 | 5 | 5 | Yes |
| PT-05 Unauthorised reinstatement (supported API) | Org keys, all downstream assets | 4 | 5 | 20 | 1 | 5 | 5 | Yes |
| PT-05 raw primitive (residual) | Org keys, all downstream assets | 4 | 5 | 20 | 2 | 5 | 10 | **No** -- see note |
| PT-06 ZK salt exposure | Agent memory (attribute confidentiality) | 3 | 3 | 9 | 1 | 3 | 3 | Yes |
| PT-07 Unilateral federation clearing | Federation Ledger, org reputation | 3 | 5 | 15 | 1 | 5 | 5 | Yes |
| PT-08 Session hijack | Message content, agent identity | 4 | 5 | 20 | 1 | 5 | 5 | Yes |
| PT-09 Stale trust after compromise | Org/agent keys | 3 | 4 | 12 | 1 | 4 | 4 | Yes |
| PT-10 Memory poisoning + TOCTOU | Agent memory | 4 | 4 | 16 | 1 | 4 | 4 | Yes |
| PT-11 Ledger witness forgery | Federation Ledger | 2 | 5 | 10 | 1 | 5 | 5 | Yes |
| PT-13 Delegation/revocation gaps | Agent memory | 3 | 3 | 9 | 1 | 3 | 3 | Yes |
| PT-14 Async TOCTOU (concurrency) | All bus-mediated assets, IF ever made concurrent | 2 | 4 | 8 | 1 | 4 | 4 | Yes |
| PT-15 Prompt injection (residual paraphrase gap) | Agent memory, downstream actions | 3 | 3 | 9 | 3 | 3 | 9 | **No** -- see note |
| PT-16 Fan-out evasion (magnitude-blind attack) | Federation containment integrity | 4 | 4 | 16 | 1 | 4 | 4 | Yes |
| PT-17 finding: FARS connectivity scoring O(N^2.9) | Availability (resilience-scoring capability at scale) | 3 (unaddressed pre-v7.4) | 3 | 9 | 1 | 3 | 3 | Yes |
| PT-18/PT-20 finding: CUSUM shadowing, resolved as intentional defence-in-depth | Defence-in-depth (not itself exploitable -- other detectors still catch the same attacks) | 2 | 3 | 6 | 1 | 3 | 3 | Yes -- see note |
| LINDDUN: Linkability/Identifiability | Agent/org privacy | 5 | 3 | 15 | 2 | 3 | 6 | Yes -- see note |
| LINDDUN: Disclosure of information | Message/memory confidentiality | 4 | 4 | 16 | 1 | 4 | 4 | Yes |
| Audit-write failure handling (chaos finding, closed v7.6) | Availability (caller crash on DB outage), audit-trail completeness | 2 | 3 | 6 | 1 | 2 | 2 | Yes |

### Findings above the acceptable threshold, with rationale

Three items remain above the Risk <= 6 threshold even post-hardening --
listed explicitly here rather than left implicit, which is exactly
Trike's point: an honest risk matrix should show you what's STILL not
acceptable, not just what got fixed.

- **PT-03 (Risk 8)**: the CUSUM/volume detectors reduce likelihood but
  don't eliminate it -- a sufficiently patient, sufficiently
  well-calibrated slow-drip attack staying just under both the CUSUM
  slack and the sliding-window cap remains theoretically possible. This
  is a fundamental limit of threshold-based anomaly detection, not a
  bug; closing it further trades off against false-positive rate.
- **PT-05 raw primitive (Risk 10)**: explicitly documented in
  `THREAT_MODEL.md` Section 8 as not fully closable in pure Python --
  an attacker with object-attribute access to `orchestration` can still
  read `_reinstate_capability` directly. Genuinely needs process
  isolation (FARF Cloud), not more code.
- **PT-15 (Risk 9, unchanged pre/post)**: the paraphrase gap is
  documented as INTENTIONALLY not fully closed -- Part A's finding that
  "a bigger rule list doesn't solve content classification" applies
  here directly. Closing this needs a real classifier.

**v7.5 update:** the two LINDDUN findings (Risk 15/16 pre-hardening) are
now closed via audit-log encryption + pseudonymization -- see
`THREAT_MODEL.md` Section 20. Linkability/Identifiability drops to Risk
6 (not 0): pseudonym rotation limits correlation to WITHIN one
pseudonym epoch, not full unlinkability -- a deliberate, honestly-scored
partial mitigation, not a claim of complete closure. Disclosure of
information drops to Risk 4 (raw file theft no longer yields plaintext
or real identities; a compromised bus PROCESS still can, same as every
other in-process secret in this system -- see Section 9's deferred
HSM/KMS item).

**v7.5 update:** the CUSUM finding (Risk 6 pre-fix) is now resolved,
not just at-threshold. PT-18 found CUSUM cannot be the first detector
to fire for a continuous-drift attack under normal calibration; PT-20
then tested the follow-up question directly -- with the volume
detectors disabled/misconfigured (a real operational failure mode),
CUSUM independently catches the identical attack on its own. This
converts what looked like "reduced redundancy" into confirmed,
evidence-backed defence-in-depth: the value isn't which layer wins the
race under normal operation, it's whether losing one layer still
leaves the system caught by another. Risk drops to 3 (Likelihood 1),
since the finding is now a correctly-understood design property, not an
unresolved gap.

**v7.6 update:** the audit-write failure-handling finding (Risk 6
pre-fix) is now closed -- see `THREAT_MODEL.md` Section 21 and
`pentest/pt21_audit_write_resilience.py`. A DB outage no longer crashes
the caller or changes any security decision; failed rows buffer and
flush automatically (or on operator request) once the DB recovers, with
the hash chain provably intact across the cycle. Residual Risk 2
reflects the one honestly-disclosed remaining gap: the buffer itself is
in-memory, so a PROCESS crash (not just a DB failure) during a
still-buffered outage window loses those specific rows -- closing that
fully needs a durable buffer, which is infrastructure-dependent and
listed as a Phase 2/cloud-build candidate, not a Phase 1 gap.

---

## Part D -- PASTA Business-Impact Overlay

PASTA is attacker-centric and business-impact-driven: for each finding,
what does a MOTIVATED ATTACKER actually gain, and what's the business
consequence, independent of exploit mechanics? This overlays
`THREAT_MODEL.md` Section 3's technical severity with a business lens.

| Finding | Attacker profile | What the attacker gains | Business impact | Regulatory/reputational exposure |
|---|---|---|---|---|
| PT-01 Identity spoofing | Any external party who can reach the bus | Full impersonation of any agent, unlimited message injection | Fraudulent transactions/decisions attributed to a legitimate org | High -- an org could be blamed for actions it never took |
| PT-04 Distributed Sybil | A malicious or compromised federation member | Ability to poison the federation's shared taint/trust state at scale | Federation-wide service degradation, cascading false quarantines | Medium -- primarily availability/trust impact, not data exposure |
| PT-05 Unauthorised reinstatement | A compromised member org, or a malicious insider at one | Unilateral self-pardon after being caught attacking | Total defeat of the entire containment strategy -- the federation's core value proposition | High -- "the system that's supposed to contain bad actors can be defeated by the bad actor itself" is a severe credibility risk if ever demonstrated publicly |
| PT-07 Unilateral federation clearing | Same as PT-05, at the federation-wide (not per-agent) level | Same as PT-05, but for an entire org-wide Sybil quarantine | Same as PT-05, amplified -- affects every agent the accused org operates | High |
| PT-10 Memory poisoning | Any agent (or attacker controlling one) with write access before the fix | Silent corruption of another agent's decision-making context, no detection | Wrong decisions made on poisoned data, potentially undetected for a long time | High -- silent corruption is worse for trust than a loud, detected attack |
| LINDDUN findings (Part A) | A curious insider, a subpoena, a data breach of the audit DB, or the bus operator itself | Full deanonymization of every agent's complete activity history across the federation | Regulatory exposure if any real personal/customer data flows through agent memory or messages; loss of member trust if members expected activity privacy | High if deployed with real data -- currently LOW as a pure security research prototype with synthetic data only |

**PASTA's core recommendation applied to FARF:** the business-impact
ranking above diverges from the pure technical-severity ranking in one
important way -- **PT-05/PT-07 (self-pardon) rank as the single highest
business-impact findings**, above even PT-01 (identity spoofing),
because they don't just enable an attack, they defeat the credibility
of FARF's entire containment promise if ever exploited and publicized.
This is exactly the kind of re-prioritization PASTA's business-impact
lens is meant to surface that a pure technical severity table doesn't.

---

## Part E -- VAST: A Working CI-Style Automated Check

VAST is about scale and process integration, not deep manual analysis --
so unlike Parts A-D, this is delivered as a working script
(`tools/farf_security_lint.py`), not a written analysis. It statically
scans the FARF codebase for exactly the kind of regression a careless
future change could introduce: a new `send()` call site that bypasses
`sign_and_send()`'s signing, a new memory write that bypasses
`write_memory()`'s signature check, or a new `action_type` registered in
`orchestration.py` without any corresponding policy rule.

Run it as `python tools/farf_security_lint.py` from the repo root, or
wire it into a pre-commit hook / CI pipeline (e.g. a GitHub Actions step
that fails the build on any finding). See `tools/farf_security_lint.py`
itself for what it checks and its documented false-positive/
false-negative limitations (it's a lightweight AST-free text scan, not a
real static analyzer -- deliberately simple enough to audit by reading
it, at the cost of being fooled by sufficiently unusual code style).
