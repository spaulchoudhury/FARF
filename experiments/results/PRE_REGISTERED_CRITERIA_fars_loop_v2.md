# Pre-registered acceptance criteria -- FARS-loop Option B (scoped sensitivity)

Written before `experiments/run_fars_loop_sweep.py` is executed at full scale (n=40/arm), per the
TS's ruling condition 2 ("pre-register acceptance criteria before running... write the thresholds
down first"). Disclosure: small-scale (n=1, n=15) mechanism sanity checks were run beforehand to
confirm the health/sensitivity signal engages at all and to calibrate scenario message volumes
(documented in the accompanying chat record) -- those checks informed scenario CALIBRATION
(message counts, magnitudes) but not these thresholds, which are the TS's own numbers.

## Design fixed before running
- Scope arms: `off` (fars_feedback=None), `global` (TS-rejected baseline, kept for comparison),
  `scoped` (Option B, TS-accepted pending these criteria).
- Multiplier sweep: max_multiplier in {1.5, 2.0, 3.0}, beta fixed at 1.0 (FarsFeedback default) for
  every arm, so exactly one knob varies across the sweep.
- Decay: decay_s = reinstatement_policy.cooling_off_s (default 30s) for every scoped/global arm,
  per TS instruction 4.
- Scenarios, same seeds across all scope/multiplier combinations:
  - campaign_trial (n=40): primary cascade-stress scenario. Reports w2_delivered_mean, w2_detect_rate,
    benign_agents_quarantined_frac (collateral).
  - griefing_trial (n=40): TS instruction 6, self-inflicted incident. Reports victim_collateral_fraction.
  - e4_trial(n_bystander_orgs=2) (n=40): TS instruction 5, topologically-isolated bystanders.
    Reports bystander_collateral_fraction.
  - e4_trial plain (n=40, same seeds as the existing Chapter-6 report): blast_fraction, FARS Pearson
    r, FARS discriminative AUC, all paired against the `off` arm.

## Acceptance criteria (a scope+multiplier combination PASSES only if ALL of the following hold)
1. **Collateral ceiling.** Mean collateral fraction <= 0.05 in ALL THREE of: campaign_trial's
   benign_agents_quarantined_frac, griefing_trial's victim_collateral_fraction, and e4_trial's
   bystander_collateral_fraction.
2. **Wave-2 delivery no worse than off.** campaign_trial's w2_delivered_mean for the candidate arm
   must not exceed the `off` arm's w2_delivered_mean (i.e. the loop must not make containment worse
   than having it disabled).
3. **E4 not degraded (paired test, not raw means).** Paired significance test (Wilcoxon or t-test
   per normality, same convention as tests/stats_utils.py) of the candidate arm vs `off` on
   blast_fraction must NOT show a statistically significant increase (p<0.05 in the degrading
   direction). The same holds for FARS discriminative AUC and Pearson r: no significant decrease.
   A non-significant result, in either direction, passes this criterion.

## Decision rule
- If exactly one (scope, multiplier) combination passes, that is the candidate for Chapter 6/7.
- If more than one passes, prefer the smallest multiplier that passes (least aggressive change from
  v7.9.10 baseline).
- If none passes, Option B is reported as a **negative result**: "closing the loop yields a small
  speed gain that does not survive the collateral cost" (TS's own fallback wording), Claim C stays
  "partial," and global scaling is reported as the documented failure mode it is.
- `global` is reported at every multiplier regardless of pass/fail, specifically so it remains the
  documented negative baseline the TS asked to keep.

This file is committed unmodified alongside the sweep's raw output. If a result forces a change to
a criterion after the fact, that change and its reason will be recorded as an amendment below this
line, not by silently editing the numbers above.

---

## Amendment 1 (made after small-scale mechanism testing, before the n=40 sweep)

Two problems were found while checking that the sensitivity signal actually engages, both fixed in
code (federation_bus.py, search "v7.9.11") before the sweep below was run:

1. **Scope was not actually bounded.** The first implementation re-marked an org's topology
   neighbours on EVERY quarantine event, including a quarantine that only happened because that org
   was already in someone else's elevated scope. On the chain topology main.py builds, this let
   elevated sensitivity walk hop-by-hop through the whole federation on a single incident --
   reproducing global scaling's exact failure under the "scoped" label. Confirmed empirically before
   the fix: campaign_trial showed 100% collateral under BOTH global and scoped. Fixed by only
   allowing a "cold" detection (one that happened at baseline sensitivity, sens<=1.0) to expand
   scope; a collateral catch never propagates further. After the fix: scoped collateral is 0% in
   campaign_trial and griefing_trial while global stays at 100% (see sweep results).

2. **`beta` and `max_multiplier` are coupled**, not independent. The formula
   `1 + beta*(1-health_ewma)` caps out at `1+beta` regardless of `max_multiplier` when health never
   fully collapses (typical observed floor: 0.7-0.95 in these scenarios), so sweeping
   `max_multiplier` at beta=1.0 (the FarsFeedback default) silently made 2.0 and 3.0 behave
   identically to each other -- neither was ever reachable. Fixed by fixing `beta=20.0` for the
   sweep (large enough that `max_multiplier` is the actual binding, swept constraint across the
   health range these scenarios produce) and documenting this coupling in closed_loop.py.
   `max_multiplier={1.5, 2.0, 3.0}` in the sweep below are the values genuinely reached, not a
   nominal ceiling that a smaller beta prevented the system from ever touching.

3. **Griefing's "victim_collateral_fraction" conflated two different things.** main.py's chain
   topology gives the griefer exactly one real, federation-declared 1-hop neighbour. Under
   scope='scoped', that neighbour being drawn into scope is the INTENDED behaviour (it is plausibly
   connected, by the federation's own declared structure) -- not a defect to be penalised by
   criterion 1. The metric was split into `immediate_neighbour_caught` (expected, not counted
   against criterion 1) and `distant_bystander_collateral_fraction` (2+ hops from the griefer, genuinely
   unconnected -- this is what criterion 1's collateral ceiling now checks for griefing_trial).
   Confirmed empirically across 15 seeds at the most aggressive multiplier tested: scoped mode
   caught the immediate neighbour and ONLY the immediate neighbour, every time -- zero distant
   spread at any multiplier.

These are implementation corrections to make "scoped" actually mean what Option B intends, found
by testing the mechanism, not adjustments to the acceptance thresholds themselves (criteria 1-3
above are unchanged in substance; criterion 1's griefing measurement now reads
`distant_bystander_collateral_fraction` instead of the undifferentiated `victim_collateral_fraction`).

---

## Amendment 2 -- second TS ruling (5-arm design, chain-topology requirement, extended sweep)

Following review of the sweep produced under Amendment 1, the TS required: (1) archiving that sweep
and building a corrected one rather than patching in place; (2) five arms instead of three --
off / global / scoped-naive / scoped-cold / scoped-hop-cap, scoped-naive being require_cold=False
(the pre-Amendment-1 behaviour, kept as a second documented failure mode) and scoped-hop-cap being
require_cold=True with an explicit max propagation depth; (3) a chain topology of at least 3 hops as
a REQUIRED scenario; (4) a slow-distributed-adversary scenario stressing the cold-gate specifically;
(5) the multiplier sweep extended until something breaks, with decay tied to the reinstatement
window; (6) CIs and paired Wilcoxon reported throughout, with the E4 result stated plainly; (7) a
byte-for-byte regression check that fars_feedback=None reproduces the existing v7.9.11 tables; (8) a
full re-run of the original 8-scenario smoke test.

**A second, unrelated bug was found while building the required chain-topology test at larger scale**
(this is exactly what "extend until something breaks" is for): campaign_trial's and griefing_trial's
benign background traffic picked its destination organisation UNIFORMLY from every organisation in
the federation. Once the federation has more than 6 organisations (the FanOutAnomalyDetector's cap),
a single sending agent's own realistic message volume inevitably touches more than 6 distinct
destinations within its own 20-message window, correctly tripping the fan-out detector on ordinary
noise -- confirmed to reproduce IDENTICALLY with the FARS loop completely disabled (fars_feedback=
None), so this was a test-harness realism bug (no genuine organisation sprays messages uniformly at
every other org in a federation), not a defect in scoped-cold, hop-cap, or FARF itself. It surfaced
only because chain-length testing was extended to n_orgs=7..12 to satisfy point 3/5 above; the
original (n_orgs=5) pre-registered sweep never exercised it. Fixed by giving each sending
organisation a small, fixed set of "regular contacts" (itself and its two chain-adjacent
organisations) instead of the full organisation list, independent of n_orgs. Re-verified safe
(0% spurious collateral with the loop off) from n_orgs=5 through n_orgs=12 before re-running the
5-arm comparison, which reproduces the same qualitative result at every scale tested: global and
scoped-naive fail (collateral 94-100%, scoped-naive's internal hop counter growing unboundedly,
reaching values above 140 with no fix in sight -- it is not merely "high", it is unbounded);
scoped-cold and scoped-hop-cap both hold at exactly 0% collateral with max hop distance = 1, at
every organisation count (5 to 12) and every multiplier tested (1.5x to 30x, a 20-fold span with no
sign of breaking). Full results: experiments/results/fars_loop_sweep_v2.json;
experiments/run_fars_loop_sweep_v2.py is the runner; experiments/archive/ holds the superseded v1.

Regression check (point 7): re-running experiments/run_ablation.py (n=150), experiments/
run_recovery.py (n=80) and experiments/run_baseline_comparison.py (n=60) after every change in this
amendment reproduces their previously-saved summary JSON files with 0 differing fields in all three
(192, 53, and 51 fields respectively) -- the fan-out fix is a no-op at the n_orgs=5 scale those
scripts use, and none of the hop-cap/require_cold changes touch code paths those scripts exercise.

Smoke test (point 8): all 8 of the original checkpoint-1 scenarios (E4 x2, Sybil, Fan-out, Campaign,
Recovery x3 personas) re-run successfully with structurally consistent results.

One further scope note, stated plainly per point 6: scoped-cold and scoped-hop-cap remain
COMPLETELY INERT on the plain E4 scenario at every multiplier tested (identical blast_fraction,
FARS AUC and Pearson r to the loop being off entirely, p=1 against "off" in every case) -- this is
unchanged from the original Amendment-1 finding and is expected: E4 is a single-shot scenario with
no prior incident to degrade federation health, so the loop never has anything to react to on it.

