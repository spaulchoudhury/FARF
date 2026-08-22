# CHANGELOG_v7.9.1.md

Continuation of v7.9. Closes the escalation-threshold hysteresis gap,
the ADR-001 citation error, and folds a full cross-document internal
audit into `ARCHITECTURE_DECISIONS_1.md` itself so it travels with the
build going forward.

## 1. `adversary_model.py` (modified) -- Tab 7.8 Precision fix

- `simulate_privilege_escalation()` gained `edge_floor_ratio` (default
  0.5): a flagged path must now clear the aggregate `threshold` AND have
  every individual edge at or above `threshold * edge_floor_ratio`.
- Root cause: diminishing-returns accumulation let several individually
  moderate delegations compound past 0.8 by chance -- 21 false positives
  / 200 trials in the original measurement (precision 0.8214).
- Deliberately expressed as a *ratio* of `threshold`, not a flat
  constant: this function is called at two different threshold regimes
  in this codebase (0.8 in the Tab78 harness; 0.6 in the real E4
  memory-manipulation test, whose actual `main.py`-built edges are
  0.3/0.4). A flat edge_floor tuned for one broke the other -- caught by
  running the full test suite before shipping, not asserted from theory.
- Re-measured via the real, unmodified `tests/evaluation_metrics_tab78.py`
  harness across 5 seeds: precision 0.97-1.0 (seed 0: exactly 1.0), recall
  unchanged at 1.0 throughout.
- Full regression: 44 passed, 1 skipped (unchanged from before this fix).
  Lint: 0 high-confidence findings (unchanged).

## 2. `ARCHITECTURE_DECISIONS_1.md` (modified, in place)

- ADR-001's GCP-equivalent note corrected: the "1,000 concurrent requests
  per instance" figure was attributed to `CLOUD_PROVIDER_COMPARISON.md`
  §2.4, which doesn't actually state it (independently verified true via
  Google's own docs, but mis-sourced). Now cites each claim to its real
  source.
- "Summary: gap -> decision -> cloud mechanism" table gained a **Code
  status** column, reviewed against the actual v7.9 codebase line by
  line -- not re-asserted from memory.
- Added a new **Internal Audit** section: cross-references
  README.md, THREAT_MODEL.md, RISK_APPENDIX.md, TEST_PROTOCOL.md,
  PHASE1_GAP_REPORT_v7.6.md, CLOUD_PROVIDER_COMPARISON.md, and every
  CHANGELOG, categorizing every open item as a genuine cloud-build
  blocker (3 items, all requiring real cloud infrastructure), correctly
  deferred cloud-build work (everything else), or documentation hygiene.
- Surfaced two items that were tracked (in `RISK_APPENDIX.md`) but not
  previously cross-referenced into this file: LINDDUN's
  Non-repudiation-as-privacy-risk and Detectability findings, and
  OCTAVE's governance-process gap. Both are deliberate, disclosed design
  tensions -- not newly discovered bugs -- now named explicitly in the
  "explicitly out of scope" list instead of being absent from it.
- This file is now packaged inside the prototype zip (was previously
  upload-only) and carries a "keeping this file in sync" protocol for
  future sessions.

## Genuinely open cloud-build blockers (unchanged by this session, listed for completeness)

1. ADR-003's real KMS wiring -- `home_cloud`/`kms_key_ref` remain inert
   metadata until an actual cloud KMS client call exists.
2. ADR-006's remaining half -- quorum math is correct and defaults on;
   witness nodes still all run in one local process, not across two
   real clouds.
3. Actual AWS + Azure (or GCP) accounts, IAM roles, provisioned KMS
   keys -- operational, not a code or doc gap.

Everything else previously flagged as "open" is either correctly-deferred
cloud-build work (the ADR table's own "Open -- cloud-build work itself"
rows) or a disclosed design tension appropriate for the dissertation's
Limitations section, not a blocker. See
`ARCHITECTURE_DECISIONS_1.md`'s Internal Audit section for the full,
evidenced breakdown.
