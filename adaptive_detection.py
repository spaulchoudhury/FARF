"""
Adaptive Org-Level Volume Detector (FARF hardening -- v7)
------------------------------------------------------------
PENTEST FINDING (addressed, opt-in): FederationBus's org_volume_detector
previously used ONE fixed cap (0.35, empirically tuned against a
10-agent Sybil swarm -- see pentest/pt04's docstring) for every org
regardless of that org's actual size or normal traffic pattern. This
has two failure modes:
  - A large, genuinely busy org's normal traffic can exceed a cap tuned
    for a small org -- false positive, legitimate traffic quarantined.
  - A large org's low-and-slow Sybil attack can stay under a cap tuned
    for a small org's total traffic volume, since the cap doesn't scale
    with org size -- false negative, real attack missed.

AdaptiveOrgVolumeDetector calibrates each org's own cap from that org's
own observed traffic during an initial calibration window, instead of
one constant for everyone.

Documented, HONEST limitation (this is a real, unsolved problem in
anomaly detection, not swept under the rug): if an attack is already
running DURING the calibration window, the calibrated baseline itself
gets poisoned upward, and the detector will be less sensitive than the
fixed-cap version for the rest of that org's session. A production
deployment should calibrate from an offline/trusted traffic sample (a
staging period, or historical logs known to predate any compromise),
not from live traffic on first contact -- this class is intentionally
NOT the default in FederationBus precisely because that trade-off needs
a human decision about where trusted calibration data comes from, not
because the logic itself is unfinished. See THREAT_MODEL.md 14.
"""
from typing import Dict, List

from farf_logging import get_logger

log = get_logger(__name__)


class AdaptiveOrgVolumeDetector:
    def __init__(self, window: int = 40, calibration_messages: int = 20,
                 cap_multiplier: float = 3.0, fallback_cap: float = 0.35):
        self.window = window
        self.calibration_messages = calibration_messages
        self.cap_multiplier = cap_multiplier
        self.fallback_cap = fallback_cap
        self._history: Dict[str, List[float]] = {}
        self._calibration_samples: Dict[str, List[float]] = {}
        self._calibrated_cap: Dict[str, float] = {}
        self._frozen: Dict[str, bool] = {}

    def cap_for(self, org: str) -> float:
        return self._calibrated_cap.get(org, self.fallback_cap)

    def update(self, org: str, value: float) -> bool:
        """Feed one event's taint_delta for `org`; returns True if the
        rolling window sum now exceeds that org's own calibrated cap."""
        if not self._frozen.get(org, False):
            samples = self._calibration_samples.setdefault(org, [])
            if len(samples) < self.calibration_messages:
                samples.append(value)
                if len(samples) == self.calibration_messages:
                    mean = sum(samples) / len(samples)
                    # calibrated cap = (this org's own average per-message
                    # taint) x window x safety multiplier -- scales with
                    # both the org's normal traffic AND the detector's
                    # own window size, unlike a bare constant.
                    self._calibrated_cap[org] = max(self.fallback_cap * 0.1,
                                                      mean * self.window * self.cap_multiplier)
                    log.info("org volume cap calibrated", extra={
                        "event": "adaptive_cap_calibrated", "org": org,
                        "calibrated_cap": round(self._calibrated_cap[org], 4),
                        "sample_mean": round(mean, 4)})

        hist = self._history.setdefault(org, [])
        hist.append(value)
        if len(hist) > self.window:
            hist.pop(0)
        tripped = sum(hist) > self.cap_for(org)
        if tripped:
            # freeze calibration once tripped -- an ongoing attack must
            # not be allowed to keep dragging its own cap upward.
            self._frozen[org] = True
            log.error("adaptive org volume cap tripped", extra={
                "event": "adaptive_cap_tripped", "org": org,
                "window_sum": round(sum(hist), 4), "cap": round(self.cap_for(org), 4)})
        return tripped

    def reset(self, org: str):
        self._history[org] = []
