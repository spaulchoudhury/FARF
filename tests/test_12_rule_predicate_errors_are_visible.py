"""Characterisation test for orchestration.SecureOrchestrationLayer.evaluate().

A policy rule whose predicate raises is SKIPPED (evaluation continues with the next rule). That fail-open
behaviour is unchanged from the cited build; what changed is that it is no longer silent. This test pins both
facts. If you later decide a raising rule should fail closed, change the behaviour AND this test on purpose.
"""
import logging

import orchestration as orch
from orchestration import ActionEvent, Decision, PolicyRule, SecureOrchestrationLayer


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _event():
    return ActionEvent(agent_id="agent-x", org="OrgA", action_type="plan_forward", payload={})


def _boom(_event):
    raise RuntimeError("faulty predicate")


def _layer(*rules):
    layer = SecureOrchestrationLayer()
    layer.rules = list(rules)
    return layer


def test_raising_rule_is_skipped_and_later_rule_still_decides():
    layer = _layer(PolicyRule("boom", _boom, Decision.QUARANTINE),
                   PolicyRule("later_rule", lambda e: True, Decision.BLOCK))
    assert layer.evaluate(_event()) is Decision.BLOCK


def test_raising_rule_alone_falls_through_to_allow_today():
    """Documents the fail-open fall-through. Not an endorsement of it."""
    layer = _layer(PolicyRule("boom", _boom, Decision.QUARANTINE))
    assert layer.evaluate(_event()) is Decision.ALLOW


def test_raising_rule_is_logged_not_silent():
    cap = _Capture()
    orch.log.addHandler(cap)
    try:
        _layer(PolicyRule("boom", _boom, Decision.QUARANTINE)).evaluate(_event())
    finally:
        orch.log.removeHandler(cap)
    hits = [r for r in cap.records if r.getMessage() == "rule_predicate_error"]
    assert len(hits) == 1
    assert hits[0].rule == "boom" and hits[0].agent_id == "agent-x"
    assert hits[0].exc_info is not None
