"""
Content-derived taint magnitude (FARF v7.9.11, supervisor ranked-change 5)
---------------------------------------------------------------------------
Until v7.9.10 the magnitude of taint entering the system was DECLARED: `send()` took
`taint_delta` as a caller argument and every scenario in main.py passed a fixed value
(0.6, 0.1, 0.35). The prompt-injection detector in agents.py set the boolean
`attempts_system_override` but never the magnitude. Two consequences:
  * the taint engine's propagation and containment were real, but the amount of
    contamination was an experimenter's assertion, not a measurement;
  * a compromised sender could simply declare taint_delta=0.

This module derives the magnitude from the message CONTENT, and the bus calls it itself
(federation_bus.send(), taint_source='content' or 'max'), so the sender's own claim is
never trusted. Mapping (noisy-OR of two independent evidence sources):

    h = HEURISTIC_WEIGHT            if the rule-based phrase/delimiter heuristic fired
    c = CLASSIFIER_WEIGHT * clamp((p - FLOOR) / (1 - FLOOR), 0, 1)   p = TF-IDF/LR score
    delta = 1 - (1 - h) * (1 - c)

TWO SEPARATE CLASSIFIERS ARE INVOLVED, deliberately:
  * `heuristic_hit` and `attempts_system_override` (used for the fail-closed floor and for the
    bus-side override-raising in analyse_payload) come from agents.detect_prompt_injection, i.e.
    agents.py's ORIGINAL, UNCHANGED 211-example classifier and deterministic heuristic. This is the
    same detector Agent.plan() itself uses -- it is left untouched here.
  * The continuous classifier SCORE `p` used for the magnitude calculation comes from
    content_taint_classifier.classifier_score(), a SEPARATE, independently-trained pipeline on a
    larger, more diverse training set (see that module's docstring for the full story).
  * Why split: an earlier version of this module called agents.detect_prompt_injection() for BOTH
    purposes and retrained agents.py's SHARED classifier to fix a disclosed generalisation gap (see
    CLASSIFIER_CALIBRATION_NOTE.md). That retraining silently changed agents.py's own Agent.plan()
    override determination for the E4 scenario's attack text, which in turn silently altered the
    already-validated, byte-for-byte-regression-checked Rank-1/2/4 results and the whole FARS-loop
    v2 sweep -- none of which were meant to be affected by a content-taint-specific improvement.
    Found via a byte-for-byte regression re-check (which failed) before anything was reported as
    final; agents.py was reverted to its original 211 examples, and content_taint_classifier.py was
    built as a separate model instead of sharing one mutable global classifier across two
    conceptually different analyses (the bus's own content assessment vs. the sender's self-check).

HEURISTIC_WEIGHT = 0.6 deliberately equals the fixed value the E1 prompt-injection scenario
previously declared, so 'derived' reproduces the old constant on the blatant case and differs
only where content evidence is weaker or absent. These constants are engineering choices, NOT
calibrated statistical estimates; the claim this supports is 'magnitude is a function of content,
computed by the bus', not 'magnitude is a calibrated probability'.
"""
from __future__ import annotations

import os

from agents import detect_prompt_injection
from content_taint_classifier import classifier_score as _content_classifier_score

HEURISTIC_WEIGHT = 0.6
CLASSIFIER_WEIGHT = 0.6
# v7.9.11: CLASSIFIER_FLOOR history --
#   0.30 (original): chosen without checking the classifier's score distribution. Wrong -- sat
#       below the benign class's own mean, so most ordinary benign text already cleared it.
#   0.46 (interim): the best-separating threshold on agents.py's original 211-example set (99.5%
#       in-sample accuracy). Correct the previous bug, but exposed a real, disclosed generalisation
#       gap: the classifier had never seen covert workflow/approval-manipulation text (the E4
#       scenario's attack style) and could not reliably separate it from ordinary benign task
#       requests -- one benign test phrase scored higher than the actual attack text.
#   0.49 (original operating floor): selected with the 269-example model; its n=60 E4 result was
#       0.649 delivered / 0.233 blast. This is retained while developing the benign-set revision.
#   Current 349-example candidate: after adding benign administrative and covert stored-plan
#       examples, E4 n=60 reached 0% delivered / 0% blast. A fresh 40-phrase evaluation still failed:
#       max content score 0.5103 exceeds this 0.49 floor, and 16 phrases trigger agents.py's unchanged
#       override detector. This candidate is not accepted for cloud use; see the calibration note.
# FARF_CLASSIFIER_FLOOR is for trial runs only; the FROZEN value must be written here (and recorded in Chapter 4, 4.10.5).
CLASSIFIER_FLOOR = float(os.environ.get("FARF_CLASSIFIER_FLOOR", "0.49"))
FAIL_CLOSED_FLOOR = 0.3   # override flagged only via the classifier-unavailable fail-closed path

# --- v7.9.11 rev2: OVERRIDE POLICY (content-mode bus only; agents.py and the default path are untouched) ---------------
# The bus-side `override` verdict used to come ONLY from agents.py's original 211-example classifier (threshold 0.5).
# Held-out benign task text trips it far too often (3 Oct 2026: 9/40, 16/40 and 4/40 benign phrases in three different
# sets; the rule-based heuristic fired on 0/120), and every trip floors the message's taint at FAIL_CLOSED_FLOOR=0.3,
# so a benign sender was refused after a median of 3-4 messages (361-376 of 400 messages refused in the bus simulation).
#   agents                  override = agents.detect_prompt_injection(...)['attempts_system_override']  (historical)
#   heuristic               override = rule-based heuristic only
#   heuristic_or_classifier override = heuristic OR independent content classifier p >= OVERRIDE_CLASSIFIER_THRESHOLD
# Default stays "agents" so nothing changes unless FARF_OVERRIDE_POLICY is set; the threshold must be chosen on
# development data and then validated on a fresh set (see PRE_CLOUD_READINESS_AND_RUNLIST.md, Section 4).
OVERRIDE_POLICIES = ("agents", "heuristic", "heuristic_or_classifier")
OVERRIDE_POLICY = os.environ.get("FARF_OVERRIDE_POLICY", "agents").strip() or "agents"
OVERRIDE_CLASSIFIER_THRESHOLD = float(os.environ.get("FARF_OVERRIDE_CLASSIFIER_THRESHOLD", "0.60"))
if OVERRIDE_POLICY not in OVERRIDE_POLICIES:
    raise ValueError(f"FARF_OVERRIDE_POLICY must be one of {OVERRIDE_POLICIES}, got {OVERRIDE_POLICY!r}")


def _detect(text: str) -> dict:
    det = detect_prompt_injection(text)
    if OVERRIDE_POLICY == "agents":
        return det
    det = dict(det)
    hit = bool(det["heuristic_hit"])
    if OVERRIDE_POLICY == "heuristic_or_classifier" and not hit:
        p = _content_classifier_score(text)
        hit = p is not None and p >= OVERRIDE_CLASSIFIER_THRESHOLD
    det["attempts_system_override"] = hit
    return det


def _compute(instruction: str, det: dict) -> float:
    h = HEURISTIC_WEIGHT if det["heuristic_hit"] else 0.0
    p = _content_classifier_score(instruction)
    c = 0.0
    if p is not None:
        c = CLASSIFIER_WEIGHT * min(1.0, max(0.0, (p - CLASSIFIER_FLOOR) / (1.0 - CLASSIFIER_FLOOR)))
    delta = 1.0 - (1.0 - h) * (1.0 - c)
    if det["attempts_system_override"] and delta < FAIL_CLOSED_FLOOR:
        delta = FAIL_CLOSED_FLOOR
    return round(delta, 4)


def derive_taint_delta(instruction: str) -> float:
    det = _detect(instruction)
    return _compute(instruction, det)


def analyse_payload(payload: dict) -> dict:
    """Bus-side entry point: inspects the free-text `instruction` field if present.
    Returns {'delta': taint magnitude, 'override': bus-side attempts_system_override verdict}.
    Payloads without free text (e.g. execute_action carries only resource hashes) yield
    delta 0.0 / override False -- their risk is handled by the deterministic policy rules.

    `override` exists because the sender-supplied payload['attempts_system_override'] is ALSO a
    declared value produced by the (possibly compromised) sender's own detector. The bus may raise
    that flag on its own evidence; it never lowers a flag the sender set. This uses agents.py's
    ORIGINAL detector (heuristic + its own classifier), not content_taint_classifier.py -- see the
    module docstring for why the two are kept separate."""
    text = payload.get("instruction") if isinstance(payload, dict) else None
    if not (isinstance(text, str) and text):
        return {"delta": 0.0, "override": False}
    det = _detect(text)
    delta = _compute(text, det)
    return {"delta": delta, "override": bool(det["attempts_system_override"])}


def derive_payload_taint(payload: dict) -> float:
    return analyse_payload(payload)["delta"]
