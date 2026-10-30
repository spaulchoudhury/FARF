# CHANGELOG_v7.9.10.md

Thesis-supervisor-directed session. Four items, all requested after the
first meeting with the new supervisor, all four now closed and
re-verified end-to-end (89/89 tests, 0 high-confidence lint findings,
22/22 pentest, full `main.py --scenario all` run clean).

## 1. Quorum-default gap — Option B ("Fix + re-run as a comparison")

Supervisor's decision, verbatim: *"we chose Fix + re-run as a comparison
option to document the before/after finding of Dynamic PBFT quorum
adoption and making it membership reactive. And if PBFT quorum adoption
shows better promise than current `build_federation()` method, go for
the swap."*

### What was built

- `FederationBus` gained `quorum_mode` (`"static"` default, unchanged
  behaviour / `"pbft_dynamic"`) and `quorum_recompute_strategy`
  (`"immediate"`, implemented / `"batched"`, explicitly reserved —
  raises `NotImplementedError` at construction, not silently treated as
  "immediate").
- `register_organisation()` now calls `_recompute_quorum()` when
  `quorum_mode="pbft_dynamic"` — this is item 3 below, delivered
  together with item 1 since they're the same mechanism.
- `federation_config.py`'s `FederationConfig` gained
  `quorum_dynamic: bool = True` (default on, matching ADR-006's
  "default, not opt-in") and `quorum_recompute_strategy`, wired through
  `build_federation_from_config()`.
- New `tools/quorum_policy_comparison.py` — **the actual comparison**,
  run live, not just reasoned about. Deliberately NOT a Monte-Carlo/
  repeated-trials script: both dimensions measured (security, availability)
  are deterministic closed-form functions of N and stake, so a fake
  repeated-trials treatment would have been statistical theater. Instead:
  an analytical table for N=2..10, cross-checked against the REAL
  `FederationBus`/`FederationLedger` witness flow for N=3 and N=4 (not
  just arithmetic on paper).

### The comparison result (live run this session)

| | Legacy static (quorum=2) | PBFT-dynamic |
|---|---|---|
| **N=3, orgs needed to collude to force a false quarantine-clear** | 2 of 3 | **3 of 3 (unanimity)** |
| **N=3, orgs that must be online for a legitimate clear** | 2 of 3 | 3 of 3 |
| **N=4, orgs needed to collude** | 2 of 4 | **3 of 4** |
| **N=4, orgs that must be online** | 2 of 4 | 3 of 4 |

Empirical cross-check against real code (not just the formula) confirmed
these numbers exactly — e.g. at N=3 pbft_dynamic, "accused + 1 other org
witnesses" does NOT commit (`committed=False`), only "accused + ALL
other orgs" does.

**Verdict, and why the swap was made:** PBFT-dynamic is strictly more
collusion-resistant at every N tested — at N=3 specifically, legacy's
"2 of 3" bar is uncomfortably close to the exact single-dishonest-org
scenario the Federation Ledger's own module docstring says it exists to
prevent. The availability cost (needs every org online, vs. legacy
tolerating one down) is real and disclosed, not hidden — it's the same
"N=3 unanimity has no compensating control for network partitions"
concern already flagged in `ARCHITECTURE_DECISIONS_1.md`, now quantified
rather than left as a general worry. Given the core purpose of this
subsystem is exactly the security property PBFT-dynamic strengthens, the
swap was made.

### The swap itself

`main.py`'s three `FederationBus(...)` construction sites (the `--scenario
all` isolated-run loop, the single-scenario branch, and the composite
branch) now all pass `quorum_mode="pbft_dynamic"`. **Scoped, not global**:
`FederationBus`'s own class-level default stays `"static"` — `pentest/
pt07_unilateral_federation_clearing.py` and `pt11_ledger_witness_forgery.py`
specifically construct their own bus instances to exercise the legacy
quorum=2 behaviour as part of what they're testing, and remain correct
and unaffected. Confirmed safe for existing statistics before swapping:
`grep -rn "ledger\|quorum\|witness\|reinstat" tests/evaluation_metrics_tab78*.py`
returns nothing — the Tab 7.8/7.9 dissertation statistics never touch
this subsystem, so the swap does not retroactively change any
already-cited number.

**Verified live:** `python main.py --scenario all` now logs real
`"quorum recomputed on membership change"` events; all 89 tests pass; all
22 pentest scripts (including pt07/pt11) pass unchanged.

## 2. FARS `connectivity_divisor` — multi-scenario sensitivity + 200-agent scale validation

Supervisor's decision, verbatim: *"FARS magic constant adjustment around
`connectivity_divisor` for multi-scenario sensitivity and test it for
scale validation ~200-agent case."*

### `tools/fars_sensitivity_sweep.py` — extended, run live

Added 5 representative scenarios (healthy/no-incident, moderate E1-style
prompt injection, the original single scenario, a severe multi-org Sybil
case, and a large sparse federation) spanning the regimes `main.py`'s own
scenario functions and `THREAT_MODEL.md` actually describe, not arbitrary
points. `multi_scenario_sweep()` runs the existing per-constant sweep
across all 5 and reports min/mean/max/spread instead of one point
estimate.

**Live result for `connectivity_divisor`** (the supervisor's named
constant): max-shift ranged **0.96 to 5.62 FARS points** depending on
scenario — spread of 4.66 points, flagged MATERIAL by the script's own
threshold. **This is the headline finding**: the original single-scenario
sweep's "connectivity_divisor is the dominant lever" conclusion was
correct in direction but understated how much the magnitude itself
depends on which regime the federation is actually in — a healthy
federation and a severe-Sybil federation don't just have different FARS
scores, they have different *sensitivities* to this constant. All three
other constants were also checked (not just the one named) — spreads
were smaller but present, logged in full script output.

**Still open, correctly**: this strengthens the local evidence
considerably but does not by itself constitute "statistically validated
against real cloud-collected data" — that genuinely needs real
production telemetry, which is cloud-build work.

### `tools/validate_connectivity_sampling.py` — extended to 200 agents, run live

Timed the exact `nx.node_connectivity()`-based computation first
(≈15.9s for a single 200-agent graph in this sandbox) to size the trial
budget sensibly, then extended the size sweep from the original 64-agent
ceiling up to the real 200-agent case the estimator's own docstring cites
as its runtime-cost justification, with `n_trials` reduced as `n_agents`
grows (15 trials at the small end down to 5 at 200 agents) so the whole
sweep finishes in a few minutes instead of tens.

**Live result**: no material systematic bias detected anywhere from
11 to 200 agents. **The 200-agent row specifically** (reported on its own,
not just folded into the aggregate, in case an aggregate masked a
large-N-specific bias): signed bias **+0.0069**, mean |diff| 0.0074 —
negligible. This closes the "N>20 connectivity-sampling path unvalidated
for scale claims" gap at the actual scale that was cited as the concern,
not just at a smaller range that happened to be convenient to run.

## 3. Dynamic quorum recompute on org join/rejoin, with a batch-mode provision

Supervisor's decision, verbatim: *"Recompute `quorum_required` at every
org join/rejoin for now and keep provision for switching to batch mode
for future, if it becomes too much of load."*

Delivered together with item 1 (`_recompute_quorum()`,
`quorum_recompute_strategy`) — see above for the mechanism.
**"Rejoin" honesty note**: this prototype has no org-removal path at all
(orgs are only ever added, never removed), so "rejoin" isn't independently
exercisable yet — re-registering an already-present org is the closest
analogue, and is correctly idempotent (`len(self.trust.identities)` is a
dict keyed by org name, so re-registering doesn't inflate the count PBFT
is computed against — verified live in the smoke test this session).

**Batch-mode provision**: `quorum_recompute_strategy="batched"` is a
real, selectable enum value that raises `NotImplementedError` at
`FederationBus.__init__` time (fail-fast, not on first org join) with a
docstring explaining exactly what a future implementation would need to
do (accumulate a pending-recompute flag, flush on a threshold or timer).
This is a deliberate design choice: a caller who selects "batched" gets
an immediate, unambiguous signal that it doesn't exist yet, rather than
an untested code path silently standing in for "immediate."

## 4. Per-record revocation in `memory_store.py`, configurable — with an erratum

Supervisor's decision, verbatim: *"Per-record (not just per-agent)
revocation in `memory_store.py`: keep it as a configurable choice, with
Tombstone default but workable for soft delete where data retention is
higher."*

### Erratum, disclosed rather than silently fixed

While implementing this, discovered that **per-record revocation already
existed** — `memory_store.py`'s `revoke_record()` (tombstone, non-
destructive) and `erase_record_for_subject()` (crypto-shred, permanent,
GDPR Art. 17-style) both pre-date this session, with `FederationBus`
wrappers `revoke_memory_record()`/`erase_memory_record()` already in
production use. `PHASE1_TO_CLOUD_DECISION_BRIEF.md` §2 item 8 had
incorrectly claimed this "genuinely doesn't exist yet, only whole-agent
revocation does" — that claim was produced by an incomplete grep pattern
(`grep -n "def write\|def verify\|signature\|sign("`) that simply didn't
match either method's name, and the file was never fully read before
writing that row. **Corrected in place in the decision brief with a
visible strikethrough erratum, not silently edited** — the mistake and
how it was caught are left visible rather than removed.

### What v7.9.10 actually added

Given the above, the genuinely missing piece was narrower than originally
scoped: a single **configurable choice-point**. Previously a caller had
to already know both method names existed and pick the right one by
hand — there was no `mode` parameter, no unified entry point.

- `MemoryStore.revoke_record(..., mode="tombstone")` (default, unchanged
  behaviour) or `mode="crypto_shred"` (delegates to
  `erase_record_for_subject()`). Backward compatible — the pre-v7.9.10
  positional call shape (`store.revoke_record(agent_id, key, writer,
  did, reason=...)`, used by `tests/test_05_chaos_and_fuzzing.py`) still
  works unchanged, `mode` defaults to `"tombstone"`.
- **Real bug found and fixed during testing**: the first draft of
  `mode="crypto_shred"` didn't check whether the key existed before
  calling `erase_record_for_subject()`, unlike `mode="tombstone"`'s
  existing early-return — meaning it would write a misleading "0 records
  shredded" audit marker for a key that was never written. Fixed with a
  matching existence check.
- `FederationBus.revoke_memory_record(..., mode="tombstone"|"crypto_shred")`
  — the operator-facing wrapper. `mode="crypto_shred"` delegates to the
  existing `erase_memory_record()` (reusing its audit-row-writing logic,
  not duplicating it) and normalises the return shape so both modes give
  a caller a consistent `{"revoked": bool, "mode": str, ...}` contract
  instead of `mode="tombstone"` and `mode="crypto_shred"` returning
  differently-shaped dicts.
- New `tests/test_09_memory_revocation_modes.py` — 12 tests: default-mode
  backward compatibility, the tombstone-vs-crypto_shred recoverability
  difference (the actual thing that matters — proven side-by-side on two
  agents from the same starting value), invalid-mode rejection,
  nonexistent-key handling in both modes, the `FederationBus` wrapper's
  return-shape normalisation, and equivalence between
  `revoke_memory_record(mode="crypto_shred")` and calling
  `erase_memory_record()` directly.

**Interpretation of "tombstone default, workable for soft delete where
retention is higher"**: tombstone mode *is* the soft-delete mechanism —
non-destructive, the prior record's plaintext stays recoverable via
`get_chain()` + `decrypt()` for a compliance reviewer, which is exactly
what "data retention is higher" requires. `crypto_shred` is the separate,
harder option for an actual erasure requirement. This reading was applied
rather than assumed to need a third mode — if it doesn't match the
supervisor's intent, the `mode` parameter is there to extend.

## Full regression, all four items together

- `pytest tests/ -q`: **89 passed** (77 pre-existing + 12 new), 0 skipped.
- `farf_security_lint.py`: 0 high-confidence, 3 low-confidence (unchanged,
  same 3 pre-existing).
- All 22 `pentest/pt*.py`: exit 0, including pt07/pt11 (legacy quorum
  behaviour, confirmed unaffected by the item 1/3 swap).
- `python main.py --scenario all`: clean run, real `quorum_mode="pbft_dynamic"`
  in effect, `FARS_ewma` computed as before.

## Documentation sync

- `ARCHITECTURE_DECISIONS_1.md`: ADR-006 Summary-table row rewritten from
  the v7.9.9 "Correction" (which was itself only half the story) to
  reflect the actual v7.9.10 closure, with the security/availability
  trade-off and the pentest-scoping decision stated explicitly.
- `PHASE1_TO_CLOUD_DECISION_BRIEF.md`: §2's item 8 row corrected in place
  with a visible erratum (not silently edited); §3's Phase-1-completable
  table has all four rows struck through and marked closed with pointers
  here; §4 gained a resolution note at the top pointing to the actual
  decision made, while leaving the original options text intact as a
  record of what was weighed.
- This file is new.
