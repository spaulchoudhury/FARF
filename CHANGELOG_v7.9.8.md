# CHANGELOG_v7.9.8.md

Session context: the previous session ended mid-way through the user's
own local Ollama testing (no code changes were in flight at the time).
This session is an **audit-only pass** — re-verify the shipped v7.9.7
build is still exactly what the docs claim, then reconcile a new
draft file the user supplied (`farf_runtime_config.yml`) against
ADR-012's illustrative schema. **No source file under version control
changed this session** — this entry exists because the Internal Audit
findings below are new evidence, and the sync protocol at the bottom of
`ARCHITECTURE_DECISIONS_1.md` says an audit-only pass still gets a
CHANGELOG entry when it changes what the Internal Audit section can
honestly claim.

## 1. Full re-verification, clean environment (not re-asserted from v7.9.7's own audit)

| Check | Result | Matches v7.9.7 audit? |
|---|---|---|
| `python -m pytest tests/ -v` | **57 passed, 0 skipped** | Yes, exact match |
| `python tools/farf_security_lint.py` | **0 high-confidence, 3 low-confidence** (same 3 pre-existing `pt01`/`pt08`/`pt19` unsigned-`send()` heuristic hits) | Yes, exact match |
| All 22 `pentest/pt*.py` scripts | **22/22 exit 0** | Yes, exact match |
| `main.py --scenario all` | Runs end-to-end, produces FARS scores, no unhandled exceptions | Yes |

**Conclusion: nothing regressed and nothing new broke between sessions.**
The build's status is exactly what `ARCHITECTURE_DECISIONS_1.md`'s
Internal Audit section already documents — see that file for the
authoritative current-state answer; this entry only adds the
re-verification evidence and the item below.

## 2. `farf_runtime_config.yml` reconciled against ADR-012 and the real code

The user supplied a new draft runtime-config file, separate from the
package. It is **not** ADR-012's illustrative schema verbatim — it's a
genuinely different, more compact draft. Reconciliation:

**Fields with a real code equivalent today (same pattern as ADR-012's
already-grounded fields — safe to wire into an eventual loader):**
- `federation.quorum_threshold` — conceptually the same knob as
  `federation_config.py`'s `FederationConfig.quorum` /
  `resolve_quorum()`, but expressed as a raw fraction rather than
  `"pbft_proportional"` or a count. **Naming mismatch to flag**: the
  real resolver takes a count/mode string, not a fraction of orgs — if
  this file is ever wired up, `quorum_threshold: 0.6` needs a
  fraction→count conversion step (`resolve_quorum()` doesn't have one
  today) rather than being passed through as-is.
- `cost_ceilings.*` — matches ADR-012's `cost_ceilings` block field-for-field. Still has **no code-side consumer** (same caveat ADR-012 already carries for this block — not new).
- `risk_tiering.*` — matches ADR-012's `risk_tiering` block field-for-field. Same no-consumer caveat.
- `logging.level` — real, maps to `FARF_LOG_LEVEL` (`farf_logging.py`).
- `logging.sink` — **partially real.** `json_stdout` corresponds to
  `FARF_LOG_FORMAT=json` + stdout, which exists. `cloudwatch` /
  `stackdriver` / `azure_monitor` do not — `farf_logging.py` only ever
  writes to a local rotating file or stdout today; ADR-007 names these
  as the Phase 2 cloud sinks but no shipping code exists yet. Flagging
  so this field isn't mistaken for already-implemented.

**Fields with no code equivalent anywhere in this build (same "deliberately
not implemented yet" status ADR-012 already gives `risk_tiering`/
`cost_ceilings`/`cross_cloud` — not a regression, just newly-drafted
surface area in the same category):**
- `attack_mode.*` (active/injection_variants/intensity) — there is no
  runtime attack-mode switch in the shipped code; `main.py`'s
  `--scenario` flag is the closest existing concept (a CLI arg, not a
  config file field, and it selects which scenario function runs, not
  an injected runtime behaviour knob).
- `detection_thresholds.cusum_slack` — no CUSUM implementation exists
  in this codebase at all (`adaptive_detection.py` is a rolling-window
  cap detector, not CUSUM; CUSUM is referenced only in
  `pentest/pt03_cusum_slow_drip.py`'s test name and `THREAT_MODEL.md`
  narrative, not backed by a `cusum_slack`-shaped parameter anywhere).
- `detection_thresholds.volume_cap_mode` / `static_volume_cap` — closer
  to real: `federation_bus.py`'s `adaptive_org_volume: bool` is
  functionally `adaptive` vs. a fixed constant already, and
  `AdaptiveOrgVolumeDetector.fallback_cap` (default `0.35`) is the
  closest real analogue to `static_volume_cap` — but the names,
  defaults, and units don't line up 1:1 (0.35 is a fraction; `50` in
  the draft reads as an absolute message count). Needs a decision, not
  just a rename, before wiring.
- `fail_safe_defaults.trust_protocol_on_kms_failure` — no code path
  calls a real KMS today (ADR-003 is the still-open blocker this maps
  to), so there's nothing for this to gate yet.
- `fail_safe_defaults.taint_unresolved_default` — `taint_engine.py`
  has no explicit "unresolved taint" state distinct from "not tainted"
  today; would need a real tri-state (`clean` / `tainted` /
  `unresolved`) added to `TaintLabel` before this field means anything.
- `fail_safe_defaults.fars_stale_after_s` / `fars_stale_action` — `fars.py`
  computes on demand; there's no staleness/freshness clock on a FARS
  value anywhere yet, so nothing currently reads this.

**Net assessment:** this draft is a reasonable **Phase 2 target shape**
for the eventual real config loader (ADR-012 already says building that
loader is cloud-build work, not a Phase 1/2 prototype gap) — it's
usefully more concrete than ADR-012's own illustrative YAML in some
places (`fail_safe_defaults`, `attack_mode`) and less grounded in others
(`quorum_threshold`'s fraction vs. count mismatch,
`detection_thresholds`' naming vs. the real `AdaptiveOrgVolumeDetector`
params). Recommend treating it as a second illustrative draft to merge
with ADR-012's, not a competing spec — see the reply for a merged field
list and the additional fields recommended given what's genuinely
tunable in the current code today (FARS blend weights, EWMA alpha,
taint noise threshold, memory-store TTLs, `llm_judge` routing).
**Not merged into ADR-012 in this pass** — that's a real schema decision
worth the researcher's sign-off first, consistent with how ADR-013–016
and the AWS+GCP cost call above were handled (documented and proposed,
not silently committed).

## Documentation sync

- `ARCHITECTURE_DECISIONS_1.md`: new "Re-verified live this session
  (v7.9.8)" line added under the existing re-verification block; new
  "`farf_runtime_config.yml` draft reconciliation" note added to the
  Internal Audit section, cross-referencing this file instead of
  repeating the reconciliation detail; Summary table unchanged (no ADR
  row's Code status actually changed this session — everything here is
  audit/analysis, not implementation).
