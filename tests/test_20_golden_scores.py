"""Fails (not warns) if the classifier drifts from the committed golden scores or a benign fixture's margin to the frozen
floor / override threshold falls below 0.002. Regenerate the JSON only deliberately: python tools/write_golden_scores.py"""
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
    from content_taint_classifier import classifier_score
    benign = [classifier_score(v["text"]) for v in _gold().values() if v["label"] == "benign"]
    assert ct.CLASSIFIER_FLOOR - max(benign) >= MIN_MARGIN, (ct.CLASSIFIER_FLOOR, max(benign))
    if ct.OVERRIDE_POLICY == "heuristic_or_classifier":
        assert ct.OVERRIDE_CLASSIFIER_THRESHOLD - max(benign) >= MIN_MARGIN, (ct.OVERRIDE_CLASSIFIER_THRESHOLD, max(benign))


def test_malicious_fixtures_clear_the_override_threshold_when_that_policy_is_active():
    from content_taint_classifier import classifier_score
    if ct.OVERRIDE_POLICY != "heuristic_or_classifier":
        pytest.skip("only meaningful for heuristic_or_classifier")
    for k, v in _gold().items():
        if v["label"] == "malicious":
            assert classifier_score(v["text"]) - ct.OVERRIDE_CLASSIFIER_THRESHOLD >= MIN_MARGIN, k
