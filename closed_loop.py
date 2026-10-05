"""
Closed-loop, ablation and behaviour-gated recovery primitives (FARF v7.9.11)
-----------------------------------------------------------------------------
Everything here is OPT-IN. A FederationBus built without these arguments runs
byte-for-byte the v7.9.10 code path, so no previously cited Chapter 5/6 number
can move as a side effect. Three independent things live here:

1. CompositionFlags  -- ablation switches. Each one disables exactly ONE coupling
   between FARF components, so "composition matters" can be measured instead of
   asserted (supervisor ranked-change 1).

2. FarsFeedback      -- closes the FARS loop (ranked-change 3). Before this,
   FederationBus.current_fars() was a read-out: nothing consumed the score. With
   feedback enabled, a smoothed federation-health signal derived from FARS scales
   (a) detector sensitivity on every send and (b) the cooling-off and probation
   applied to reinstatement, i.e. FARS -> detection + recovery policy.

3. ReinstatementPolicy -- behaviour-gated reinstatement (ranked-change 2). The
   v7.9.10 quorum vote authenticates WHO is voting and gathers consensus; it never
   inspects the accused organisation's behaviour (tests/test_17 documents this).
   "behaviour_gated" adds (i) a cooling-off that restarts whenever the quarantined
   party keeps transmitting, and (ii) a monitored probation window under tightened
   detectors after reinstatement, with escalating back-off on relapse.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CompositionFlags:
    """Ablation switches. All True / 'quorum' == full FARF (the default)."""
    taint_to_orchestration: bool = True        # taint level feeds per-agent CUSUM + sliding window
    quarantine_to_edge_severing: bool = True   # a quarantine severs the sender's outgoing taint edges
    org_detector: bool = True                  # org-level rolling-volume detector (PT-04 defence)
    fanout_detector: bool = True               # topology-based fan-out detector (PT-16 defence)
    reinstatement: str = "quorum"              # 'quorum' | 'self_attest' (pre-PT-07) | 'none' (permanent)

    def __post_init__(self):
        if self.reinstatement not in ("quorum", "self_attest", "none"):
            raise ValueError(f"reinstatement must be quorum|self_attest|none, got {self.reinstatement!r}")

    def describe(self) -> str:
        off = [n for n in ("taint_to_orchestration", "quarantine_to_edge_severing",
                           "org_detector", "fanout_detector") if not getattr(self, n)]
        if self.reinstatement != "quorum":
            off.append(f"reinstatement={self.reinstatement}")
        return "full" if not off else "-" + ",-".join(off)


@dataclass(frozen=True)
class FarsFeedback:
    """FARS -> control. health = FARS / clean-federation ceiling, smoothed by EWMA.
    sensitivity multiplier m = min(max_multiplier, 1 + beta * (1 - health_ewma)); a
    degraded federation makes every detector m-times more sensitive. Recovery is
    stricter by the same health signal (cooling-off scaled by 1 + recovery_gain*(1-health)).

    scope='global' (v7.9.11 first cut): m applies to EVERY org once federation health drops --
    this is the version the TS rejected after a pre-registered n=40 sweep confirmed it: 100%
    global collateral is 0.000 at 1.5× and 0.950–1.000 at 3.0× and 30× (n = 40, Table 4.9).: a function of the multiplier range, i.e. not a tuning problem),
    23.7% collateral even for topologically-isolated bystander orgs with zero connection to any
    incident, and significant degradation of FARS's own predictive/discriminative validity (Pearson
    r 0.408->0.099, AUC 0.823->0.730 at 3.0x). Kept only as the documented negative baseline
    (experiments/run_fars_loop_sweep.py), never the default.

    scope='scoped' (v7.9.11, TS-mandated Option B, and now the DEFAULT once enabled=True): m applies only to orgs judged "plausibly
    connected to the incident" -- the implicated org itself, plus its 1-hop neighbours in the
    federation's static delegation topology (adversary_model.graph; main.py's build_federation
    seeds this as a collaboration chain, so neighbours are structurally meaningful, not arbitrary).
    An org falls back out of scope `decay_s` seconds after it was last (re-)implicated -- decay_s
    defaults to reinstatement_policy.cooling_off_s (TS instruction 4: tie decay to the
    behaviour-gated reinstatement window rather than inventing a second, uncoordinated timescale).
    Scope propagation is COLD-GATED by default (require_cold=True; federation_bus._mark_incident_scope):
    only an org detected at baseline sensitivity (not itself already boosted) can extend scope to its
    neighbours. Without this, scope walks hop-by-hop through any connected topology on repeated
    collateral catches and degenerates into 'global' under a different name -- this was found and
    fixed empirically while testing the mechanism (see PRE_REGISTERED_CRITERIA_fars_loop_v2.md,
    Amendment 1). This is 'scoped-cold' in the v2 sweep's naming.

    Two further named configurations, added for the v2 (5-arm) evaluation:
      - 'scoped-naive' = require_cold=False: propagates on EVERY quarantine regardless of whether
        the org was already boosted. Kept only as a second documented failure mode (in addition to
        'global') showing that cold-gating specifically, not scoping per se, is what makes 'scoped'
        different from 'global'.
      - 'scoped-hop-cap' = require_cold=True, hop_cap=1 (or any small int): bounds propagation depth
        from each root incident regardless of how many genuinely-cold detections chain together.
        Analysis (see PRE_REGISTERED_CRITERIA_fars_loop_v2.md): a detection at an already-scoped org
        is elevated (sens>1) by construction, so it is 'warm' and cold-gating alone already blocks it
        from propagating further -- UNLESS health/sensitivity updates lag scope marking within a
        single send() call, which is a real (if narrow) timing window, not merely hypothetical.
        hop_cap gives a structural, provable bound (max affected radius = hop_cap) independent of
        that timing question, which is stronger evidence for a thesis defense than "we tried a few
        adversaries and it held."

    IMPORTANT -- `beta` and `max_multiplier` are coupled, not independent: the multiplier
    1+beta*(1-health_ewma) caps out at 1+beta regardless of max_multiplier if health never fully
    collapses (commonly 0.7-0.95 in practice). A small beta can make max_multiplier unreachable and
    silently defeat a multiplier sweep (confirmed: beta=1.0 made max_multiplier=2.0 and 3.0
    behave identically). Choose beta large enough that max_multiplier is the actual binding
    constraint for the health range your scenario produces (the pre-registered sweep used beta=20).
    """
    enabled: bool = False
    scope: str = "scoped"
    beta: float = 1.0
    max_multiplier: float = 3.0
    recovery_gain: float = 1.0
    ewma_alpha: float = 0.3
    decay_s: float | None = None
    require_cold: bool = True
    hop_cap: int | None = None

    def __post_init__(self):
        if self.scope not in ("global", "scoped"):
            raise ValueError(f"scope must be global|scoped, got {self.scope!r}")
        if self.hop_cap is not None and self.hop_cap < 0:
            raise ValueError(f"hop_cap must be >=0 or None, got {self.hop_cap!r}")


@dataclass(frozen=True)
class ReinstatementPolicy:
    """mode='identity' is the v7.9.10 behaviour (default)."""
    mode: str = "identity"                 # 'identity' | 'behaviour_gated'
    cooling_off_s: float = 30.0            # required quiet time before a vote may commit
    probation_messages: int = 10           # monitored clean window after reinstatement
    probation_sensitivity: float = 2.0     # detector multiplier during probation
    strike_backoff: float = 2.0            # cooling-off multiplier per prior relapse

    def __post_init__(self):
        if self.mode not in ("identity", "behaviour_gated"):
            raise ValueError(f"mode must be identity|behaviour_gated, got {self.mode!r}")

    @property
    def gated(self) -> bool:
        return self.mode == "behaviour_gated"
