# Tab 7.8 Evaluation Metrics — Gap Closure Note

Cross-referenced against `Research_Proposal_v2.pdf` Tab 7.8. Of the 14 named
metrics, 3 (FARS Correlation Coefficient, plus the cross-cutting descriptive/
significance/effect-size battery) already had real, repeated-trial statistical
computation in `tests/stats_utils.py` + `tests/test_04_statistical_validation.py`.
The remaining 9 (and 2 more that existed only as informal pentest evidence, not
an aggregated rate) are closed here.

## What was added

- `tests/evaluation_metrics_tab78.py` — one function per metric family, each
  driving the *real* FARF components (`FederatedAdversaryModel`,
  `FederatedTrustProtocol`, `SecureOrchestrationLayer`, `TaintPropagationEngine`,
  `FederationBus`) against randomised, labelled trials.
- `tests/test_06_tab78_evaluation_metrics.py` — pytest wrapper with sanity-floor
  assertions (not tuned pass bars) and a report writer.
- `tab78_evaluation_report.csv` — one row per Tab 7.8 metric, generated fresh
  from the code above (not hand-entered).

## Three bugs found and fixed while actually running the trials

Writing the trial-generation code is not the same as it being correct — running it
surfaced three genuine test-harness bugs (all in the new test code, not in the
FARF artefacts themselves), each confirmed against a minimal manual reproduction
before being fixed:

1. **Credential Verification Success Rate initially read 34.5%.** The trial
   harness inverted `y_pred`'s semantics for the spoofed/replay cases (scoring
   "was this correctly rejected" against a "should this verify" ground truth) —
   every correctly-rejected spoofed/replayed credential was counted as a false
   positive. A direct manual call to `verify_credential()` confirmed the
   underlying protocol was correct throughout (legit → valid, spoofed issuer →
   `unknown_or_spoofed_issuer`, replay → `replay_detected`); only the test's
   label bookkeeping was wrong. Fixed by making `y_pred` consistently mean "did
   it verify as valid" in all three branches.
2. **Policy Enforcement Accuracy initially read 53.3%.** The trial harness
   reused a pool of 5 `agent_id`s across 300 trials; `SecureOrchestrationLayer`
   deliberately persists quarantine state per `agent_id` (that's the point of
   quarantine), so a QUARANTINE decision on an early trial poisoned every later
   *benign* trial sharing that agent_id, regardless of that later action's own
   merits. Fixed by giving every trial its own unique agent identity, isolating
   each trial's outcome to its own planted label.
3. **Privilege Path Reconstruction Accuracy initially read 0.0%.**
   `reconstruct_privilege_path(compromised_agent)` walks *forward* from the
   given agent; the trial called it on the *last* node of the planted chain
   (which has no outgoing propagation edges of its own), guaranteeing an empty
   result every time. Fixed by calling it on the chain's origin.

Flagging these explicitly rather than quietly fixing them, because a dissertation
evaluation chapter citing these numbers should be able to say the metric code
was actually exercised and debugged against its own output, not just written
and trusted.

## Results (single run, N per family noted below)

| Dimension | Metric | Value | N |
|---|---|---|---|
| Security Effectiveness | Attack Detection Rate (ADR) | 1.000 | 200 |
| Security Effectiveness | Precision | 0.833 | 200 |
| Security Effectiveness | Recall | 1.000 | 200 |
| Security Effectiveness | F1-Score | 0.909 | 200 |
| Trust Assurance | Credential Verification Success Rate | 1.000 | 200 |
| Trust Assurance | Delegation Integrity Rate | 1.000 | 80 |
| Trust Assurance | Trust Establishment Latency (mean) | 0.150 ms | 200 |
| Orchestration Effectiveness | Policy Enforcement Accuracy | 1.000 | 300 |
| Orchestration Effectiveness | Behavioural Anomaly Detection Rate | 1.000 (FP rate 0.019) | 100 |
| Orchestration Effectiveness | Workflow Completion Rate | 1.000 | 50 |
| Provenance Integrity | Provenance Identification Accuracy | 1.000 | 150 |
| Provenance Integrity | Taint Containment Rate | 1.000 (threshold ≤0.5 blast radius) | 50 |
| Provenance Integrity | Privilege Path Reconstruction Accuracy | 1.000 | 150 |

## Repeated-trial rigor upgrade (v7.8, `tests/evaluation_metrics_tab78_repeated.py`)

The single-run numbers above are real but don't say how much they'd move on a
re-run with a different seed. Closed by wrapping each `run_*_trials()` call in
an outer loop of **20 independent repeats** (different seed each time, same
`n_trials` per repeat), feeding the resulting 20-value list into
`stats_utils.descriptive_statistics()` — the exact same mean/SD/95% CI
function already used for the FARS validation work, so both metric families
are now reported the same way. Full output: `tab78_evaluation_report_with_ci.csv`.

| Metric | Mean | SD | 95% CI |
|---|---|---|---|
| Attack Detection Rate (ADR) | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Precision | 0.8214 | 0.0287 | (0.8080, 0.8348) |
| Recall | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| F1-Score | 0.9017 | 0.0174 | (0.8935, 0.9098) |
| Credential Verification Success Rate | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Trust Establishment Latency (ms) | 0.1315 | 0.0049 | (0.1293, 0.1338) |
| Delegation Integrity Rate | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Policy Enforcement Accuracy | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Behavioural Anomaly Detection Rate | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Behavioural False Positive Rate | 0.0039 | 0.0080 | (0.0001, 0.0076) |
| Workflow Completion Rate | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Provenance Identification Accuracy | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Taint Containment Rate | 1.0000 | 0.0000 | (1.0000, 1.0000) |
| Privilege Path Reconstruction Accuracy | 1.0000 | 0.0000 | (1.0000, 1.0000) |

**SD = 0.0000 across 20 independent repeats is expected, not a red flag,
for the deterministic-mechanism metrics** — the underlying logic is an exact
rule/cryptographic match evaluated against synthetic cases specifically
designed to be unambiguous, at trial counts (80–300 per repeat) large enough
that sampling noise from the random inputs washes out completely. It means
the mechanism is perfectly reproducible under this trial design, not that the
trial design has stopped exercising the boundary. The two metric families
built with deliberately boundary-straddling randomness — Adversary Model
(Precision/F1) and Behavioural Drift (false-positive rate) — are exactly the
ones showing real, non-zero variance and a genuinely informative CI, which is
the expected signature of a correctly-designed stochastic trial next to
correctly-designed deterministic ones, not an inconsistency.

## Honest reading of "1.000 across most rows" — do not cite this as "FARF is perfect"

Most of these mechanisms are **deterministic, rule-based checks** (exact
schema/threshold comparisons, exact cryptographic verification, exact hash
matches) being tested against **clear-cut labelled cases**. Scoring 1.0 there
confirms the mechanism does what it's specified to do — it is not evidence of
robustness under adversarial pressure designed to find the boundary. The two
metrics that show genuine, informative imperfection are the two trial designs
that deliberately inject boundary-straddling randomness:

- **Adversary Model F1 = 0.909** (precision 0.833, 21 false positives, 0 false
  negatives out of 200): trials draw edge privileges from overlapping high/low
  ranges specifically so some "benign" trials still cross the escalation
  threshold by chance. Zero false negatives but nonzero false positives is a
  believable, reportable finding — the threshold-based detector never misses an
  intended escalation in this design, at the cost of some false alarms near the
  boundary.
- **Behavioural Anomaly Detection Rate = 1.0, false-positive rate = 0.019**:
  real, non-trivial numbers from a stochastic drift-vs-noise trial design.

## What was honestly still missing before this matched the FARS work's rigor

**Now closed.** The FARS validation (`test_04`) reports descriptive statistics,
a normality test, Wilcoxon significance, Cohen's d, and 95% confidence
intervals across repeated sample sizes (n=30→400). The Tab 7.8 metrics above
now carry the same mean/SD/95% CI treatment across 20 independent repeats each
(`tests/evaluation_metrics_tab78_repeated.py`), using the identical
`stats_utils.descriptive_statistics()` function. Genuinely still open, if
pursued further: the FARS work also scales `n` itself (30→50→100→200→400) to
show convergence; the Tab 7.8 metrics currently fix `n_trials` per repeat and
vary only the repeat count. Extending to an n-scaling sweep the same way would
be the next increment, not a correctness gap in what's here now.
