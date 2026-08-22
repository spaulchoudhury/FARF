# CHANGELOG_v7.9.md

Session-continuation build closing four items from the cloud-build review
thread: ADR-012's ttl/quorum config gap, the ADR-006 PBFT-default gap, the
untested FARS connectivity-sampling path, and the classifier's
generalization gap. Every number below is measured against the actual
shipped code in this build, not asserted.

## 1. `federation_config.py` (new)

- Closes ADR-012: `credential_ttl_seconds` now actually flows into
  `issue_credential()`; `resolve_quorum()` is the missing string->float
  translation code for `quorum_required`.
- Closes ADR-006: PBFT-proportional quorum (`recommended_quorum_for_pbft`)
  is now the default a config-built federation gets, not opt-in.
  Verified: N=3 -> quorum 3.0 (unanimity), N=4 -> 3, N=7 -> 5.
- `adaptive_org_volume` defaults `True` for cloud config (was `False`).
- Verified drop-in: existing `main.py` `scenario_*()` functions run
  unmodified against a config-built federation.

## 2. `.github/workflows/farf_ci.yml` (new)

- Implements ADR-016's decided pre-merge gate (lint + pytest via GitHub
  Actions). Pre-deploy gate left as a documented stub pending the actual
  Terraform/Bicep workflow.
- Verified locally: lint exits 0 (3 low-confidence findings, same as
  pre-existing), 44 passed / 1 skipped on the full test suite.

## 3. `tools/synthetic_federation_topology.py` (new)

- Closes README.md's own TODO item 2 / Tab 7.6's "50+ synthetic
  federation topologies" requirement. Two generator families
  (`gnp_random_graph`, `barabasi_albert_graph`) as README suggested.
- `generate_corpus(n_topologies=50)` sweeps n_orgs 2-10 with guaranteed
  coverage at both ends (not left to random chance).
- Sample run (seed 42, 50 topologies): 66% contain a privilege-escalation
  path at threshold 0.8, 94% contain a cross-org attack path, avg 48.2
  cross-org paths per topology.

## 4. `tools/validate_connectivity_sampling.py` (new)

- Closes the "untested N>20 sampling estimator" gap flagged earlier.
  Compares `FARSEngine._connectivity_score()`'s exact vs. sampled code
  path on the same generated graphs.
- Result at N=22-52 agents (8 configs x 15 trials): overall mean signed
  bias +0.0006, mean |diff| 0.0079 -- no material systematic bias
  detected in this range. Caveat included in the script's own output:
  only tested to ~64 agents, not the docstring's 200-agent reference
  point.

## 5. `tools/fars_sensitivity_sweep.py` (new)

- Ranks FARS's four uncited constants by how much a +/-30% change moves
  the final score. Result: connectivity divisor (max shift 5.62 points)
  >> EWMA alpha (0.87, a lag effect) > baseline_operational_cost (0.19)
  > taint blend weight (0.00 in the tested scenario -- caveat: that's an
  artifact of the chosen scenario having per-message and graph-level
  containment numerically equal, not a general result).
- Priority for calibration effort: connectivity divisor first.

## 6. `agents.py` (modified) -- classifier training corpus

- Root cause found while investigating dataset options: the original
  29-example hand-authored corpus scored 0.800 precision / 0.733 recall
  in its own 5-fold CV, but generalized very poorly to real attacks --
  trained on it alone and evaluated against 181 held-out real examples
  from AgentDojo + InjecAgent, it scored precision=0.655, recall=0.190,
  f1=0.295 (missed 81% of real-world-style attacks).
- Merged in 181 real examples (100 attack / 81 benign) extracted from:
  - **AgentDojo** (Debenedetti et al., 2024) -- pip-installable, real
    `GOAL`/`PROMPT` strings extracted from its injection/user task suites
    across all shipped versions.
  - **InjecAgent** (Zhan et al., 2024, github.com/uiuc-kang-lab/InjecAgent)
    -- the real, citable benchmark behind the proposal's "INJEC"
    shorthand. That exact name doesn't resolve to a standalone released
    dataset; Hossain et al. 2025's own paper (also cited in the proposal
    alongside "INJEC") uses a self-authored 400-attack corpus, not a
    dataset by that name. Flagging this naming gap for the dissertation's
    citation list.
- Merged corpus (210 examples) 5-fold CV: precision=0.872 (+/-0.056),
  recall=0.929 (+/-0.060), f1=0.898 (+/-0.042) -- both higher and far
  more stable than the original (whose +/-0.400 std on n=29 was mostly
  noise, not a real confidence interval).
- Retraining time: ~17ms for `.fit()` on 210 examples (measured
  standalone) -- unchanged from the "well under 100ms" design goal.
- Full test suite still passes: 44 passed, 1 skipped, unchanged from
  before this change.
- Source data merge script's intermediate artifact kept at
  `tools_data/data_agentdojo_injecagent_merged.json` for reproducibility.

## Important scope correction

Tab 7.8's existing Precision=0.8214 metric (`run_adversary_model_trials`
in `tests/evaluation_metrics_tab78.py`) measures the **Federated Adversary
Model's escalation-threshold detector** (graph/privilege math) -- it does
**not** call `agents.py`'s classifier at all. The classifier retrain in
this build closes a real, separate, previously-unmeasured generalization
gap; it does not move the 0.8214 number. That number is still open --
see the earlier hysteresis/corroborating-signal recommendation.

## Still open (unchanged from before this build)

- `home_cloud`/`kms_key_ref` real KMS wiring (ADR-003) -- not started.
- `risk_tiering`/`cost_ceilings`/`cross_cloud` -- no code-side equivalent,
  deliberately not faked.
- ADR-001's "1,000 concurrent requests" citation to CLOUD_PROVIDER_COMPARISON.md
  Section 2.4 -- one-line fix, not yet applied to the source ADR doc.
- Escalation-threshold hysteresis (the actual fix for Precision=0.8214).
