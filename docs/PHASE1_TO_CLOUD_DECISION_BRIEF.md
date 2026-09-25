# PHASE1_TO_CLOUD_DECISION_BRIEF.md

**v7.9.10 — adversarial self-review, requested explicitly by the
researcher: challenge the prior session's own recommendations, re-verify
every item in an earlier (partially stale) gap-report excerpt against
the live code, and lay out — without deciding for the researcher — the
options for closing the Phase 1 → cloud-build decision loop.**

Everything in this document is either (a) something I ran live this
session and observed the output of, or (b) explicitly marked as
reasoning/opinion, not evidence. No claim below is restated from a
prior session's summary without being independently re-checked here.

---

## 1. The strongest counterargument to my own prior recommendation

My prior session's `ARCHITECTURE_DECISIONS_1.md` summary said ADR-006
was "**Partially closed** — PBFT-proportional quorum is now the actual
default for any config-built federation" and ADR-012 was "**Substantially
closed**." Both statements are **true as literally written** and
**misleading as headlines** — and I only caught this because the
researcher pushed back and asked me to re-verify rather than restate.

**The live proof:**

```
$ python -c "
from federation_bus import FederationBus
from main import build_federation
bus = FederationBus(db_path=':memory:')
agents = build_federation(bus, n_orgs=3)
print(bus.ledger.quorum_required)"
2
```

`main.py`'s real `build_federation()` — the function `tests/conftest.py`,
every one of the 57 pre-existing tests, `tests/evaluation_metrics_tab78_repeated.py`
(the actual source of the dissertation's Tab 7.8/7.9 statistics), and
plain `python main.py --scenario all` all call — **still produces
`quorum_required == 2`**, not the PBFT-safe unanimity value of 3 for
N=3 orgs. `federation_config.py`'s `build_federation_from_config()` path
computes the correct value (verified N=3→3, N=4→3, N=7→5) — but that
path has **zero callers anywhere in the test suite**, and as of this
session, exactly one caller total: the dry-run validation I added in
`runtime_config.py`'s `_handle_runtime_config()`.

**Why this matters more than the cloud-provider cost question:**

The previous session's chat reply led with "AWS + GCP beats AWS + Azure
on cost." That recommendation implicitly assumes the thing being
migrated to the cloud is a system whose consensus safety property (PBFT
quorum) is already correct and just needs geographic/provider
distribution. **It isn't, yet — not in the path anyone actually runs.**
Optimizing which cloud pair is cheapest for a federation whose own
demo/test/dissertation-statistics path runs an under-quorum'd ledger is
optimizing the wrong variable first. A reasonable reviewer's strongest
objection to my prior recommendation: *"You told me which cloud is
cheaper before confirming the thing I'm paying to run there is even
correct by the paper's own stated design (ADR-006, THREAT_MODEL.md
§7/§12)."* That objection is fair, and I did not raise it proactively
last session — the researcher's request to challenge my own output is
what surfaced it.

**Counter-counterargument, for balance:** the cost analysis and the
quorum-default fix are not mutually exclusive — nothing about knowing
GCP is cheaper for this traffic shape depends on which quorum default
ships. They can proceed in parallel. But *sequencing* them as "cloud
provider first, quorum-default fix later" (as my prior framing implied
by leading with the cost recommendation) inverts the actual dependency:
fixing the default is cheap, Phase-1-completable, and directly affects
what "ready for cloud build" even means, whereas the cloud-provider
choice is reversible infrastructure-as-code work that can happen at any
point. See §3 for the concrete fix and §4 for sequencing options.

---

## 2. Full re-audit of the pasted gap-report items — verified live, not restated

The researcher's pasted document is an earlier-session gap report. Some
of its findings are now stale (already fixed by code written *after*
that report, in response to it) and some are still genuinely live. Each
row below was checked against the actual code this session, not
inferred from either document.

| # | Pasted-report claim | Verified current status | Evidence |
|---|---|---|---|
| 1 | Credential revocation registry — open | **Resolved (agent-granularity).** `trust_protocol.py`'s `revoked_agents: Set[str]` + `revoke_agent()`, documented as fixing pentest finding PT-09. | Read live in `trust_protocol.py` lines ~113–120 |
| 2 | FARS's connectivity-metric compute cost — open | **Resolved with a caveat.** `_connectivity_score()` switches to a sampling estimator above `max_exact_nodes=20`, avoiding the O(n²) exact-computation blowup. | `fars.py` `_connectivity_score()` |
| 3 | FARS's lack of temporal memory — open | **Resolved.** `FARSEngine.compute_ewma()` blends current score with a persisted previous EWMA (`alpha=0.3`); actually exercised — `main.py --scenario all`'s real output includes `"FARS_ewma": 70.45`, not just a defined-but-unused method. | Live run this session + `fars.py` |
| 4 | Naive prompt-injection via substring match — open | **Resolved, now three-layer.** Rule-based heuristic (v7.1) + TF-IDF/logistic-regression classifier (v7.7, catches paraphrases) + optional local-Ollama LLM judge (`llm_judge.py`, reasons about meaning). Each layer's own honest residual gap is documented (PT-15 Parts C/D). | `agents.py` `detect_prompt_injection()` docstring + code |
| 5 | Latent async TOCTOU risk — open | **Still open, correctly deferred** — no concurrency exists yet to actually race, ADR-010 already scopes the fix as cloud-build work. | Confirmed against ADR-010 |
| 6 | Federation Ledger in-memory quorum stand-in → real cross-process consensus — open | **Still open**, and worse than the prior audit stated — see §1. Not just "cross-*process*" open, the *default* itself is still the pre-fix value in the exercised path. | §1 above |
| 7 | Memory/context integrity (ASI06) — nothing signs/hashes/provenance-tags agent memory writes — open | **Resolved, substantially.** `memory_store.py`: hash-chained, per-writer-signed (Ed25519, same scheme as `FederationBus.send()`'s message signing), AES-256-GCM encrypted, `verify_integrity()` recomputes both content-hash and chain-hash (catches in-place tampering that bypasses the signed-write API). Real callers: `federation_bus.py`, `tests/test_05_chaos_and_fuzzing.py`, `pentest/pt10_memory_poisoning_and_toctou.py`, `pentest/pt22_crypto_shredding_erasure.py` — not dead code. | `memory_store.py` + grep for real callers |
| 8 | MAESTRO L7 ecosystem trust, delegated memory writes, **single-record revocation**, HSM/KMS rotation, PKI root-of-trust — deferred to FARF Cloud | ~~Still accurately deferred, with one nuance...~~ **ERRATUM (v7.9.10): this row was WRONG.** Per-record revocation already existed at the time this brief was written — `memory_store.py`'s `revoke_record()` (tombstone) and `erase_record_for_subject()` (crypto-shred) both pre-date this document. The claim below ("genuinely doesn't exist yet... only whole-agent `revoke_agent()` exists") was produced by an incomplete grep pattern that simply didn't match either method's name, and `memory_store.py` was never fully read before writing this row. Caught and corrected in `CHANGELOG_v7.9.10.md` §4 when the thesis supervisor asked for exactly this feature — it turned out to already be built, just not exposed as a single configurable choice-point, which is what v7.9.10 actually added (`revoke_record(mode="tombstone"\|"crypto_shred")`). Left the original wrong text below, struck through, rather than deleting it — the mistake and how it was caught are worth keeping visible. | `memory_store.py` has no per-record revoke; only whole-agent `revoke_agent()` exists — **this evidence line was itself the error; see `grep -n "revoke_record\|erase_record_for_subject" memory_store.py` for the methods it missed** |
| 9 | Dynamic PBFT quorum adoption — open | **Confirmed still open, live-checked.** `register_organisation()` never recomputes `quorum_required`; nothing re-triggers `enable_pbft_quorum()` on org join/leave after federation build. Quorum is a one-time snapshot at build time, not membership-reactive. | `federation_bus.py`/`federation_ledger.py`, read live |
| 10 | LINDDUN Non-repudiation-as-privacy-risk / Detectability — open | Unchanged, still open, still a disclosed design tension (dissertation Limitations material). | No new evidence needed — consistent with prior audits |
| 11 | Adaptive-detector calibration-poisoning trade-off — open | Unchanged, still open (`RISK_APPENDIX.md` Part C). | Consistent with prior audits |
| 12 | OCTAVE/Trike formal risk layer — deferred | Unchanged, correctly deferred. | Consistent |
| 13 | VAST's CI recommendation — open | **Partially resolved, honestly self-scoped.** `.github/workflows/farf_ci.yml` implements the pre-merge gate (lint + pytest) in full; the pre-deploy IaC gate is an explicit documented stub pending Terraform/Bicep, which don't exist yet. Not overclaimed in the file's own header comment. | `.github/workflows/farf_ci.yml`, read live |
| 14 | No logging module, raw `print()` everywhere, no log levels, no way to separate warnings from narration — open, `farf_logging.py`'s docstring claim of 7-module production wiring "false for 4 of 7" | **Resolved, contradicts the pasted claim as currently written.** Live-checked: all 7 named modules have real `logger.*` calls in their production code (2 each). The `print()` calls that remain in `orchestration.py`/`trust_protocol.py`/`taint_engine.py`/`federation_ledger.py` are confined to each file's own `if __name__ == "__main__"` self-test block — never on the path `federation_bus.py` actually imports and executes. This is a case where the *pasted* document is the stale one, not my prior summary. | Per-file `grep -c` for logger vs. print this session; manual read of every remaining `print()` line's location |
| 15 | No top-level exception handling in `main()` — open | **Closed this session (v7.9.9)** — see `CHANGELOG_v7.9.9.md` §1. | Prior turn, re-verified passing this session |
| 16 | `print_fars()` raw `json.dumps` dump — minor | Still true, still genuinely minor (developer-facing CLI, correct current audience). | No change needed |
| 17 | No `--quiet`/`--verbose` flag — minor | Still true, still a convenience gap not a defect. Cheap Phase 1 fix if wanted — see §3. | Confirmed absent |
| 18 | CUSUM defence-in-depth positioning — resolved (v7.5) | Confirmed still resolved, no regression. | Consistent |
| 19 | ADR-001's "1,000 concurrent requests" mis-citation to §2.4 | Not re-checked this session — low-severity citation nit, not re-verified live; flagging that this row is **not** independently confirmed here, unlike the rows above. | Not re-audited |
| 20 | Tab 7.8 Precision 0.8214 weakest metric | Statistical finding from a prior run, not something to "resolve" — it's evidence, not a gap. No change needed. | N/A |
| 21 | N=3 unanimity has no compensating control for real network partitions | Still open, correctly scoped as cloud-build work (needs real multi-node partition testing). | Consistent |
| 22 | FARS's magic constants remain statistically untested | **Partially resolved.** `tools/fars_sensitivity_sweep.py` is real and was run live this session — see §2a below. It ranks which constants matter (connectivity_divisor dominates, up to ±5.6 FARS points on a ±30% perturbation; the others are near-negligible) but **explicitly only covers one representative scenario**, by its own docstring's admission — no confidence intervals, no multi-scenario robustness check. "Statistically untested" is still fair to call directionally true. | Live run, output in §2a |
| 23 | N>20 connectivity-sampling path unvalidated for scale claims | **Partially resolved.** `tools/validate_connectivity_sampling.py` is real, was run live this session (`PYTHONPATH=. python tools/validate_connectivity_sampling.py`) — see §2b below. Found no material systematic bias for N=21–64 agents (mean signed bias +0.0006). **But the script's own output explicitly caveats it doesn't reach the 200-agent worst case** the estimator's docstring references — so "unvalidated for scale claims" remains directionally true at the scale that actually matters for a real cloud federation. | Live run, output in §2b |

### 2a. `fars_sensitivity_sweep.py` — live output this session

```
connectivity_divisor    +/-30%   max shift +5.62 FARS points  <- dominant lever
ewma_alpha               +/-30%   max shift +0.87 FARS points
baseline_operational_cost+/-30%   max shift +0.19 FARS points
taint_blend_per_message  +/-30%   max shift +0.00 FARS points  <- essentially inert
```

Actionable reading: if you only have budget to calibrate one FARS
constant against real cloud data before citing a FARS Correlation
Coefficient number in the dissertation, `connectivity_divisor` is
where the return is.

### 2b. `validate_connectivity_sampling.py` — live output this session

```
n_agents range tested: 21–64
Overall mean signed bias: +0.0006   (negligible)
Overall mean |diff|:      0.0079
Verdict: no material systematic bias detected in this range.
Caveat (from the script itself): doesn't reach the 200-agent worst case
the estimator's own docstring cites as its runtime-cost justification.
```

---

## 3. What's genuinely completable in Phase 1 (desktop, no cloud account needed)

Ranked by how directly each affects the accuracy of claims already made
in this file's Summary table — not by implementation difficulty alone.

| Fix | Effort | Why it's Phase-1-doable | What it would close |
|---|---|---|---|
| ~~Make `main.py`'s `build_federation()` call `enable_pbft_quorum()` by default...~~ | ~~Small~~ | ~~Pure code~~ | **Closed in v7.9.10** — see `CHANGELOG_v7.9.10.md` §1/§3 and the corrected ADR-006 row in `ARCHITECTURE_DECISIONS_1.md` |
| ~~Recompute `quorum_required` when `register_organisation()` adds an org...~~ | ~~Small–medium~~ | ~~Pure code~~ | **Closed in v7.9.10** — `FederationBus._recompute_quorum()`, `quorum_mode="pbft_dynamic"` |
| ~~Extend `fars_sensitivity_sweep.py` to run across several representative scenarios...~~ | ~~Medium~~ | ~~Pure compute~~ | **Closed in v7.9.10** — 5 scenarios, live-run: `connectivity_divisor`'s max-shift ranged 0.96–5.62 FARS points depending on regime, confirming the sensitivity ranking is genuinely scenario-dependent, not a fixed property. Still doesn't resolve "statistically untested" against real cloud-collected data — that part remains open by design |
| ~~Extend `validate_connectivity_sampling.py` to actually reach ~200 agents...~~ | ~~Medium~~ | ~~Pure compute~~ | **Closed in v7.9.10** — live-run up to N=200 (the exact computation timed at ~16s per graph in this environment), no material bias found even at 200 agents specifically (signed bias +0.0069) |
| ~~Per-record (not just per-agent) revocation in `memory_store.py`~~ **Superseded — see erratum on item 8 above: this already existed.** What v7.9.10 actually did: unified the two pre-existing methods into one configurable `mode=` dispatcher, since a caller previously had to already know both method names existed | Small (was mis-estimated as Medium based on the wrong premise that it needed building from scratch) | Pure code | Closed in v7.9.10 — `CHANGELOG_v7.9.10.md` §4 |
| `--quiet`/`--verbose` CLI flag | Trivial | Pure code | Item 17 |
| `print_fars()` reformatting | Trivial, arguably skip — no real audience change yet | Pure code | Item 16, genuinely cosmetic |

**Deliberately NOT proposed for Phase 1** (would need real cloud
accounts/infra to mean anything, doing them now would produce fake
confidence): ADR-003 real KMS wiring, ADR-006's cross-*cloud* witness
distribution, ADR-005 registrar, HSM/PKI rotation, ADR-007's actual
cloud log shipping. Consistent with the existing Summary table's
"correctly deferred, not blockers" framing — nothing in this section
changes that list, it only adds the quorum-default fix as a *new*,
previously-mis-scoped Phase 1 item.

**None of the above were implemented this session** — per your
instruction on the ADR-006 question last turn to present pros/cons
rather than assume, and because this request was explicitly framed as
"figure out what's left open," not "fix it." Pros/cons on *how* to
approach the top one (the quorum-default fix, since it's the one that
actually changes what "cloud-build ready" means) below.

---

## 4. Closing the decision loop — options for the quorum-default fix, with pros/cons

> **RESOLVED in v7.9.10.** The thesis supervisor selected **Option B**
> ("Fix + re-run as a comparison") after the first supervisor meeting
> following this brief. `tools/quorum_policy_comparison.py` was built and
> run for real (not just reasoned about); the swap was then made because
> the data showed PBFT-dynamic strictly dominant on the security
> dimension, with the availability cost disclosed rather than hidden.
> Full results in `CHANGELOG_v7.9.10.md` §1/§3. The options below are
> kept as originally written for the record of what was actually weighed.

**Option A: Flip `build_federation()`'s default to call `enable_pbft_quorum()`.**
- *Pros*: One-line change at the actual call site; immediately makes
  the exercised system match the documented claim; every existing test
  still passes structurally (they don't assert on the specific value 2).
- *Cons*: Would silently change the Tab 7.8/7.9 dissertation statistics'
  underlying quorum value if those tests are ever re-run — anything
  currently cited from those tables would need re-generating and
  re-citing under the new default, which is real work with a real
  academic-integrity dimension (can't just swap the default and leave
  old numbers standing). This is the option that most directly resolves
  §1, but it's not free.

**Option B: Leave `build_federation()`'s default as-is; make
`build_federation_from_config()` the documented, recommended path going
forward, and re-run the Tab 7.8/7.9 statistics under it deliberately
(a conscious "here's the delta a correct default makes" comparison).**
- *Pros*: Produces a genuinely interesting result for the dissertation
  itself — before/after PBFT-default numbers, not just a silent swap;
  doesn't retroactively invalidate anything already written up.
- *Cons*: Leaves the exercised/default system running the unsafe value
  indefinitely unless someone remembers to always pass the new config
  path; more moving parts (two build paths to keep in sync going
  forward, exactly the kind of drift this whole audit exists to catch).

**Option C: Do nothing to the default; explicitly document the
quorum=2-by-default behaviour as a *known, disclosed* Phase 1
limitation in the dissertation's own Limitations section (same
treatment already given to the LINDDUN/OCTAVE gaps), and defer the
actual default-flip to the cloud build, where a fresh set of witness
nodes will need to be configured from scratch anyway.**
- *Pros*: Zero risk to already-collected statistics; honest; consistent
  with how several other genuinely-open items in this file are already
  handled (disclosed, not silently fixed mid-writeup).
- *Cons*: Doesn't actually close the gap — just names it more precisely
  than before. If the cloud build inherits the same "opt-in, easy to
  forget" pattern, the same discrepancy could resurface there too.

**My honest read, not a decision:** Option C is the safest *this week*
if the dissertation write-up is close to finalized and re-running
statistics is costly; Option A is the right *engineering* answer if
there's still runway before submission. Option B is worth doing
regardless of which of A/C you pick, purely because "here's what the
correct default changes" is a legitimate, citable finding on its own.
This is exactly the kind of call that benefits from your judgment about
where you are in the writeup timeline, not mine to make unilaterally.

---

## 5. Cloud-build path — options for sequencing, with pros/cons

**Option 1: Fix the quorum-default gap (§4) before starting any cloud
provisioning.**
- *Pros*: "Cloud build" then genuinely starts from a corrected baseline;
  avoids inheriting the same easy-to-forget opt-in pattern into
  multi-cloud witness code, where a similar oversight would be far more
  expensive to catch (real infra, real cost, harder to reset).
- *Cons*: Delays the (reversible, parallelizable) infra work behind a
  (also real, but conceptually separate) correctness fix. If the two
  genuinely don't block each other technically, this ordering is a
  process choice, not a hard dependency.

**Option 2: Start cloud-provider evaluation/account setup in parallel
with §4, treat them as independent workstreams.**
- *Pros*: No idle time; account provisioning, IAM setup, and the
  AWS-vs-GCP pricing verification (already done, `CLOUD_PROVIDER_COMPARISON.md`)
  can proceed regardless of which quorum-fix option you pick.
- *Cons*: Risk of the same "we'll fix the default properly later"
  drift that produced the §1 discrepancy in the first place — cloud
  witness-node code written against an already-flawed local baseline
  is more likely to inherit the flaw than code written after the fix
  lands.

**Option 3: Small pilot deployment first (single service, one
provider, e.g., just the Federation Bus relay on Cloud Run) to
de-risk the cloud-specific unknowns — real KMS latency, real
inter-region cost, real IAM friction — before committing to a full
multi-org, multi-cloud build-out.**
- *Pros*: Cheap way to validate `CLOUD_PROVIDER_COMPARISON.md`'s
  numbers against real billing data instead of published rate cards
  only (the doc's own caveat: "illustrative, not a guaranteed rate for
  every region pair"); surfaces IAM/account friction early, when it's
  cheap to fix.
- *Cons*: A single-service pilot doesn't exercise the multi-node quorum
  question at all — it's orthogonal to §1/§4, not a substitute for
  deciding that question.

**These are not mutually exclusive** — Option 3 (pilot) can run
alongside either Option 1 or Option 2's sequencing choice for the
quorum-default fix; they're answering different questions (infra
unknowns vs. correctness-default timing). Presented separately so each
can be decided on its own merits rather than bundled into one big
yes/no.

---

## Documentation sync

- `ARCHITECTURE_DECISIONS_1.md`: ADR-006 and ADR-007 Summary-table rows
  corrected (both were accurate-as-written but misleading-as-headline;
  now explicitly cite the live quorum=2 finding and the logging
  re-verification). No other rows changed.
- This file is new. No code changed this session — this was
  investigation and documentation only, consistent with the request
  ("don't assume and progress... provide pros and cons").
