# FARF Prototype — Phase 1 Completion Gap Report (v7.6, closed out in v7.7)

Cross-referenced against `README.md`, `THREAT_MODEL.md`, and `RISK_APPENDIX.md`. Originally
written after the v7.6 audit-write fix; **updated in place (not superseded) after the v7.7
session** that closed the three items §5's summary table originally listed as open (the
`logging` module gap, the PT-15 paraphrase-detection gap, and the append-only-vs-erasure
structural tension) — see each section below and `THREAT_MODEL.md` §22 for what changed.
Every item below is either (a) already fully documented in those files and reproduced here
just to categorize it, (b) a small new finding surfaced while closing the audit-write gap
and fixed in the same v7.6 pass (marked **[NEW, FIXED]**), or (c) closed in the v7.7 pass
(marked **Closed in v7.7**). Nothing here is being reported for the first time as *unfixed*
— the purpose of this report is to organize what's genuinely left, by layer, so you can
decide what belongs in the Phase 1 write-up versus what's honestly a Phase 2/cloud item.

---

## 1. Structural gaps
*(Design-level tensions inherent to the chosen architecture — not bugs, not fixable by
writing more code within the current model.)*

| Gap | Where documented | Nature |
|---|---|---|
| **Append-only chains vs. "right to erasure"** | `RISK_APPENDIX.md`, LINDDUN Non-compliance row | **Closed in v7.7** — crypto-shredding (per-record AES-256-GCM keys, `content_hash` re-anchored on ciphertext, `erase_memory_record()` discards keys) resolves the tension by design rather than picking immutability or erasure. See `THREAT_MODEL.md` §22, verified by `pentest/pt22_crypto_shredding_erasure.py`. Residual, disclosed: the keystore itself is in-memory/single-process, a Phase 2/KMS item. |
| **Non-repudiation as a privacy risk** | `RISK_APPENDIX.md` LINDDUN row; `THREAT_MODEL.md` §20 | Signed messages are a security *win* (no forgery) but a privacy *loss* — a legitimate agent/org has no plausible deniability. Genuine, unresolved design tension, correctly left open rather than silently resolved in either direction. |
| **FARS has no temporal memory** | `THREAT_MODEL.md` §2.5 | Point-in-time snapshot; a federation with a volatile compromise/reinstate history scores identically to one with a clean history, given identical *current* state. Design limitation, not a code defect. |
| **Tamper-evident, not tamper-proof audit chain** | `THREAT_MODEL.md` §4 | `verify_audit_integrity()` detects a broken hash chain but cannot cryptographically prevent a sufficiently privileged attacker from rewriting the chain forward. True tamper-proofing needs external anchoring (e.g. periodic hash publication to a third party) or a signing key the DB process itself never holds — an infrastructure decision. |
| **In-memory buffer as the last line of audit durability [touches v7.6 fix]** | `THREAT_MODEL.md` §21 | The new audit-write buffer closes the *DB-outage* case but is honestly disclosed as not closing the *process-crash-while-buffered* case — still-buffered rows are lost if the process itself dies, not just the DB. Durable buffering (WAL file, queue) is a Phase 2 item. |

**Phase 1 disposition:** these are correctly *documented tensions*, appropriate as a
"Known Limitations" or "Future Work" subsection in the dissertation rather than something
to code away — several (erasure vs. immutability especially) are genuinely open research/
design questions worth a paragraph of discussion in their own right.

---

## 2. Architectural gaps
*(Follow from the single-process design choice — already the subject of the earlier SPOF
audit; listed here for completeness against the six-category ask.)*

| Gap | Where documented | Nature |
|---|---|---|
| **Single-process `FederationBus`, single global lock** | `THREAT_MODEL.md` §7 (ledger), prior SPOF audit S1/S2 | Every state mutation serializes through one `RLock`; the process itself is a hard SPOF. Deliberate for a laptop-runnable Phase 1 prototype (proposal §7.7 confirms lightweight/CPU-bound design was the explicit scope). |
| **Latent async TOCTOU in the taint engine** | `THREAT_MODEL.md` §2.4 | `quarantine_edges_from()` only runs safely because the bus is synchronous. Not currently exploitable (no concurrency exists to race), but flagged explicitly as a design risk *before* any future concurrency work, so it doesn't get rediscovered the hard way. |
| **Federation Ledger consensus is an in-memory single-process stand-in** | `THREAT_MODEL.md` §7 | Explicitly named as *not* real distributed BFT consensus; `witness()` calls carry no cryptographic per-witness proof. This is the single highest-value Phase 2 item (real multi-node Docker Compose simulation), already flagged in the earlier SPOF report as priority #1. |
| **No delegated-write model for memory** | `THREAT_MODEL.md` §10 | Only self-writes are supported; there's no model yet for e.g. an advisor legitimately writing into an executor's memory namespace. Architectural gap, not a bug — the write-permission model itself needs extending. |

**Phase 1 disposition:** all four are already correctly scoped as Phase 2/cloud-build
items in the existing docs and the earlier SPOF audit. Nothing new to close here for
Phase 1 — the single-process design was the right call for a laptop-runnable security
*logic* validation, per the proposal's own scope statement (§6).

---

## 3. Application-layer gaps
*(Logic/algorithm limitations inside a component, independent of process architecture.)*

| Gap | Where documented | Nature |
|---|---|---|
| **Prompt-injection detection is a single hardcoded substring match** | `THREAT_MODEL.md` §2.7 | **Reduced in v7.7** — `detect_prompt_injection()` now combines the existing heuristic with a TF-IDF + logistic-regression classifier as a second, independent signal, specifically closing the documented paraphrase-evasion gap from PT-15. Verified against the exact paraphrase that originally demonstrated the gap, plus an honest stress test against a harder novel paraphrase (reported, not asserted). Still explicitly not production-grade — a ~30-example illustrative training corpus, disclosed as such — worth naming in the dissertation's limitations section as "reduced, not eliminated," with production use needing a real labelled dataset. See `THREAT_MODEL.md` §22. |
| **`reinstate()` capability gate — object-attribute-access residual** | `THREAT_MODEL.md` §8, `RISK_APPENDIX.md` Part C | The gate closes the *supported API* bypass but not a determined attacker with direct object-attribute access (`orchestration._reinstate_capability`) — Python has no true private fields. Correctly documented as "narrowed, not eliminated"; closing it fully needs process isolation (a separate privileged service behind an RPC boundary), which is architecture, not application logic — this is the single highest unresolved Trike score in the whole risk matrix (Risk 10) precisely because it straddles both categories. |
| **Static (non-adaptive) volume-detector threshold** | `THREAT_MODEL.md` §14 | The Sybil-swarm detection cap is one federation-wide constant, not scaled per-organisation traffic baseline. Documented as a genuine, unavoidable trade-off (lower cap = faster detection of small swarms, higher false-positive risk against legitimate high-volume orgs) — an operational calibration decision left to the deployer, not a code gap. |
| **FARS formula is fully disclosed, enabling metric-gaming** | `THREAT_MODEL.md` §2.5 | An attacker who reads the source can optimise specifically to "stay under every threshold," which maximizes FARS directly rather than as a side effect. Partially mitigated (blast-radius blending, `TEST_PROTOCOL.md` §4b); the underlying detection-gap dependency is closed by the org-level volume detector (PT-04), but the general "published-formula gaming" risk is structural to any fully-disclosed scoring system, not fully closable. |
| **No credential revocation registry entry expiry/cleanup** | `THREAT_MODEL.md` §3 summary table | Documented, not fixed — out of scope this pass, MEDIUM severity. |

**Phase 1 disposition:** all correctly triaged already — genuine content-classification
and architecture-boundary problems, not oversights. Fine to carry into the dissertation's
limitations section as-is.

---

## 4. Memory / OS-level gaps

| Gap | Where documented | Nature |
|---|---|---|
| **In-process plain-memory private keys** | `THREAT_MODEL.md` §9 | Deliberately deferred to FARF Cloud — a laptop "software HSM" wouldn't demonstrate anything a real KMS integration would. Infrastructure dependency, not a code fix. |
| **In-process, single-process `MemoryStore`** | `THREAT_MODEL.md` §10 | No disk persistence at all — total loss on any restart. Needs a persistence *design* before it can even be made durable; new work, not "add replicas." |
| **Companion key/pseudonym files: corrupted-load handling [NEW, FIXED]** | `THREAT_MODEL.md` §21 (new note) | Found while closing the audit-write gap: neither file's read path had exception handling, so a truncated/corrupted file crashed `__init__()` with a raw traceback. **Fixed**: both now fail loudly with an actionable `RuntimeError` naming the file and the recovery trade-off, rather than silently generating fresh state (which would orphan historical audit data) or crashing uninformatively. |
| **Companion pseudonym-registry write was non-atomic [NEW, FIXED]** | `THREAT_MODEL.md` §21 (new note) | `save_pseudonym_registry()` wrote directly to the target path; a process kill mid-write left a half-written file that would then fail the *next* startup's load. **Fixed**: now writes to a temp file and `os.replace()`s it — atomic on POSIX and Windows, so the on-disk file is always fully old or fully new, never partial. |
| **SQLite: single file, single writer, local disk** | Prior SPOF audit, S3 | Disk failure permanently stops new audit writes going forward (the v7.6 buffer defers, not eliminates, this — see structural §1 above). Managed HA datastore is a Phase 2 item. |

**Phase 1 disposition:** the two new findings are now closed and verified. The remaining
items (in-process keys, in-memory-only `MemoryStore`, single-file SQLite) are genuinely
infrastructure-dependent and correctly deferred to Phase 2/cloud, consistent with how
Section 9 already treats the closely-related key-storage item.

---

## 5. System / log-level gaps

| Gap | Status |
|---|---|
| **No `logging` module usage anywhere in the codebase — everything is raw `print()`, including the new v7.6 audit-write warnings.** | **Closed in v7.7.** New `farf_logging.py` module gives the production call path (`federation_bus.py`, `agents.py`, `memory_store.py`) a standard `logging.Logger` with real levels (DEBUG/INFO/WARNING/ERROR, scaled to decision severity) and two output formats controlled by environment variable (`FARF_LOG_FORMAT=text\|json`) — no code change needed to redirect to a file/syslog/structured sink. `main.py`'s scenario narration and each module's `__main__` self-test block are deliberately left as `print()` — see `farf_logging.py`'s module docstring for the scoping rationale. |
| **stderr warnings (audit-write buffering, close-time data-loss) use bare `print(..., file=sys.stderr)`** | **Closed in v7.7** — both are now `log.warning`/`log.error` calls with structured fields (`event`, `buffered_rows`, `total_failures_this_session`, etc.), machine-parseable in JSON mode. |
| **No structured/JSON logging option** | **Closed in v7.7** — `FARF_LOG_FORMAT=json` emits one JSON object per line, directly consumable by CloudWatch Logs/Cloud Logging/Azure Monitor via standard stdout-tailing, with no in-app SDK dependency needed for Phase 1's purposes. |

**Phase 1 disposition:** all three items in this category are now closed. See
`THREAT_MODEL.md` §22 for the full design, and `farf_logging.py`'s module docstring for
the explicit, documented scope boundary (production call path vs. CLI narration vs.
self-test demos) — this was a deliberate decision, not an oversight, matching how the
codebase already treats narration vs. audit trail elsewhere.

---

## 6. Presentation gaps

| Gap | Status |
|---|---|
| **`main.py` didn't guarantee `bus.close()` on a mid-scenario exception [NEW, FIXED]** | **Fixed.** All three CLI branches now wrap execution in `try/finally`. Previously, an exception partway through a scenario skipped cleanup entirely — leaking the SQLite connection and (since v7.6) skipping the close-time buffered-audit-row warning. |
| **No top-level exception handling in `main()` for a clean user-facing error** | **Still open.** An uncaught exception anywhere in a scenario currently surfaces as a raw Python traceback to whoever runs `python main.py`. Low severity (this is a research prototype run by its own author, not end-user-facing software) but worth a one-line note in the dissertation's limitations rather than silently leaving it implicit — a `try/except Exception` at the very top of `main()` printing a clean one-line summary plus `sys.exit(1)` would close this cheaply if wanted. |
| **`print_fars()` output is a raw `json.dumps(..., indent=2)` dump** | Developer-facing, not narrative — fine for the current audience (yourself, running experiments) and consistent with the rest of the CLI's style; would need reformatting only if this becomes something a non-technical reviewer runs directly. |
| **No `--quiet`/`--verbose` flag** | All scenarios always print full narration; no way to get just the final FARS number for scripted/batch runs. Minor convenience gap, not a defect. |

**Phase 1 disposition:** the cleanup-on-error gap is now closed. The remaining two are
genuinely cosmetic/convenience items appropriate to leave as-is for a research prototype
whose primary audience is the author and examiners reading the code directly, not a
polished CLI tool — flagging them here for completeness against your six-category ask
rather than because they block calling Phase 1 done.

---

## 7. Summary: what's actually left before Phase 1 is "complete"

| # | Item | Category | Status |
|---|---|---|---|
| 1 | Audit-write failure handling | System-log / Structural | **Closed** (v7.6 — PT-21, THREAT_MODEL §21) |
| 2 | Corrupted companion-file handling at startup | Memory/OS | **Closed** (v7.6) |
| 3 | Non-atomic pseudonym-registry write | Memory/OS | **Closed** (v7.6) |
| 4 | `main.py` cleanup-on-error | Presentation | **Closed** (v7.6) |
| 5 | No `logging` module (raw `print()` throughout) | System-log | **Closed** (v7.7 — `farf_logging.py`, THREAT_MODEL §22) |
| 6 | Prompt-injection detection is a substring/heuristic match only (PT-15 paraphrase gap) | Application-layer | **Reduced, not eliminated** (v7.7 — classifier signal added, THREAT_MODEL §22; residual: small illustrative training corpus, disclosed) |
| 7 | Append-only chains vs. "right to erasure" (GDPR Art. 17) | Structural | **Closed** (v7.7 — crypto-shredding, THREAT_MODEL §22, PT-22; residual: in-memory keystore, deferred to Phase 2/KMS) |
| 8 | Everything else in §1 (structural), §2 (architectural), the rest of §3 (application), and the infrastructure-dependent parts of §4 (memory/OS) | — | **Correctly triaged as design tensions or Phase 2/cloud items already** — nothing to "complete" here within Phase 1's own scope; appropriate material for the dissertation's Limitations/Future Work section as-is. |

Regression status after the v7.6 session's three code changes (audit-write buffering,
companion-file handling, `main.py` cleanup): 21/21 pentest scripts passed, both
`main.py` modes produced FARS scores byte-identical to the v7.5 baseline.

Regression status after this v7.7 session's three additional changes (prompt-injection
classifier, crypto-shredding, structured logging): **22/22 pentest scripts pass**
(21 pre-existing plus new `pt22_crypto_shredding_erasure.py`), both `main.py --scenario
all` and `--scenario composite` run end-to-end with no behavioural regression on the
happy path, and both log output formats (`text`, `json`) were manually verified end-to-
end through `main.py`. Two pre-existing tests (`pentest/pt10_memory_poisoning_and_toctou.py`
Part B, `tests/test_05_chaos_and_fuzzing.py`'s tampering-detection fuzz test) were updated
in place because they directly manipulated the now-removed `MemoryRecord.value` field —
same attack, same expected outcome, updated only because the target field moved to
`record.ciphertext` as part of the crypto-shredding design.

With items 5-7 closed, **Phase 1 is now complete** against all six categories from the
original gap-analysis ask — everything remaining is either a documented design tension
appropriate for the dissertation's Limitations section, or genuinely requires real cloud
infrastructure (Section 9's items) that this laptop prototype was never scoped to fake.
Phase 2 (cloud build) can now proceed against `ARCHITECTURE_DECISIONS_1.md`
(this line originally pointed at `ARCHITECTURE_DECISIONS.md`, written
before the GCP-alternative revision with ADR-013–016 existed under its
current filename — corrected in the v7.9.8 documentation-sync pass, see
`CHANGELOG_v7.9.8.md`).
