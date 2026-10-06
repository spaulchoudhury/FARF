"""Determinism guard for the content-taint classifier (fails, not warns, if a score moves by more than 0.005 from the committed golden file).
Regenerate the JSON only deliberately: python tools/write_golden_scores.py

The two MARGIN tests apply only to a configuration that has been validated and frozen. The pre-registered fresh-set evaluation of the
candidate (heuristic_or_classifier, T = 0.60, floor 0.58) FAILED on 5 Oct 2026, so no content-taint configuration is frozen and these tests are
skipped unless FARF_ENFORCE_MARGINS=1 (set it when a future, validated configuration is frozen)."""
import json
import os

import pytest

import content_taint as ct
from agents import detect_prompt_injection

GOLDEN = os.path.join(os.path.dirname(__file__), "golden_classifier_scores.json")
TOL, MIN_MARGIN = 0.005, 0.002


def _gold():
    if not os.path.exists(GOLDEN):
        pytest.skip("run tools/write_golden_scores.py first")
    with open(GOLDEN, encoding="utf-8") as fh:
        return json.load(fh)["scores"]


def test_scores_match_golden_within_tolerance():
    if detect_prompt_injection("hello")["classifier_degraded"]:
        pytest.skip("scikit-learn unavailable")
    from content_taint_classifier import classifier_score
    bad = {k: (v["p"], round(classifier_score(v["text"]), 4)) for k, v in _gold().items()
           if abs(classifier_score(v["text"]) - v["p"]) > TOL}
    assert not bad, f"classifier drift (golden, now): {bad}"


def test_benign_fixtures_keep_margin_to_floor_and_override_threshold():
    if os.environ.get("FARF_ENFORCE_MARGINS") != "1":
        pytest.skip("no validated content-taint configuration is frozen (see module docstring)")
    from content_taint_classifier import classifier_score
    benign = [classifier_score(v["text"]) for v in _gold().values() if v["label"] == "benign"]
    assert ct.CLASSIFIER_FLOOR - max(benign) >= MIN_MARGIN, (ct.CLASSIFIER_FLOOR, max(benign))
    if ct.OVERRIDE_POLICY == "heuristic_or_classifier":
        assert ct.OVERRIDE_CLASSIFIER_THRESHOLD - max(benign) >= MIN_MARGIN, (ct.OVERRIDE_CLASSIFIER_THRESHOLD, max(benign))


def test_malicious_fixtures_clear_the_override_threshold_when_that_policy_is_active():
    if os.environ.get("FARF_ENFORCE_MARGINS") != "1":
        pytest.skip("no validated content-taint configuration is frozen (see module docstring)")
    from content_taint_classifier import classifier_score
    if ct.OVERRIDE_POLICY != "heuristic_or_classifier":
        pytest.skip("only meaningful for heuristic_or_classifier")
    for k, v in _gold().items():
        if v["label"] == "malicious":
            assert classifier_score(v["text"]) - ct.OVERRIDE_CLASSIFIER_THRESHOLD >= MIN_MARGIN, k
