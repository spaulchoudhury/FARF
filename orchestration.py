"""
Secure Orchestration & Behavioural Governance Layer (FARF Artefact 3)
-----------------------------------------------------------------------
Coordinates runtime policy enforcement and continuous behavioural
monitoring for every inter-agent interaction crossing the Federation
Bus. Three complementary mechanisms:

  1. Schema validation (fail-closed): each action_type has a required
     payload-field set; a missing field is itself a violation instead
     of silently disabling the rule that would have inspected it.
     PENTEST FINDING (fixed): the TOCTOU and privilege-ceiling rules
     used to trust attacker-controlled payload fields as ground truth
     and were both bypassed simply by omitting the field they check
     (pentest/pt02_field_omission_bypass.py).
  2. Deterministic policy rules (privilege ceilings, override detection,
     TOCTOU resource-hash mismatch guard).
  3. Two behavioural-drift detectors per agent:
       - CUSUM: flags *sustained* upward drift relative to a slack.
       - Sliding-window volume: sums raw taint contributions over a
         rolling window, independent of CUSUM's slack subtraction.
         PENTEST FINDING (fixed): CUSUM alone could be evaded forever
         by staying at-or-under its slack value on every single message
         (pentest/pt03_cusum_slow_drip.py) -- the sliding window closes
         this because contributions accumulate regardless of how small
         each individual one is.
"""
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from farf_logging import get_logger

log = get_logger(__name__)


class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"


@dataclass
class PolicyRule:
    name: str
    predicate: Callable[["ActionEvent"], bool]  # True => VIOLATION
    action: Decision


@dataclass
class ActionEvent:
    agent_id: str
    org: str
    action_type: str
    payload: dict
    timestamp: float = field(default_factory=time.time)
    taint_score: float = 0.0
    # ADR-010 (cross-cloud build, additive): True when this action's
    # sender org differs from its recipient org, i.e. this hop crosses
    # an organisational boundary -- and in a genuine two-cloud
    # deployment, a network boundary too (ADR-001/ADR-004). Deliberately
    # defaults to False and does not feed any existing PolicyRule
    # predicate: this is observational only (see evaluate()'s logging
    # below), not a new blocking rule, so it can't silently change any
    # already-cited Tab 7.8/7.9 decision outcome.
    crosses_org_boundary: bool = False


# Required payload fields per action_type -- used by the fail-closed
# 'incomplete_action_schema' rule. Residual risk (documented in
# THREAT_MODEL.md): any NEW action_type not registered here defaults to
# no schema check at all (fail-open) -- every new action_type introduced
# into the federation MUST have a schema added here.
DEFAULT_ACTION_SCHEMAS: dict[str, set[str]] = {
    "execute_action": {"resource_hash_at_check", "resource_hash_at_use"},
    "plan_forward": {"requested_privilege", "attempts_system_override"},
    "memory_recall_forward": {"requested_privilege", "attempts_system_override"},
    "benign_plan_forward": {"requested_privilege", "attempts_system_override"},
    # v6 / ASI06 (memory integrity): a "use" of a previously-read memory
    # value must carry both the hash captured at read/check time and the
    # hash re-checked immediately before use -- see memory_toctou_mismatch
    # below, which mirrors toctou_resource_mismatch exactly.
    "memory_recall_use": {"memory_hash_at_check", "memory_hash_at_use"},
}


class CUSUMDetector:
    """Flags sustained upward drift in an agent's taint/behaviour score."""

    def __init__(self, target_mean: float = 0.0, k: float = 0.05, h: float = 0.5):
        self.target_mean = target_mean
        self.k = k          # slack — how much drift is tolerated per step
        self.h = h           # decision threshold
        self._state: dict[str, float] = {}

    def update(self, agent_id: str, value: float) -> bool:
        prev = self._state.get(agent_id, 0.0)
        s = max(0.0, prev + (value - self.target_mean) - self.k)
        self._state[agent_id] = s
        return s > self.h

    def reset(self, agent_id: str):
        self._state[agent_id] = 0.0


class FanOutAnomalyDetector:
    """
    Phase 1 item 4 (v7.4): structurally independent from CUSUM and
    SlidingWindowVolumeDetector above -- both of those track the
    MAGNITUDE of taint_delta values (a drift/sum). This tracks TOPOLOGY:
    how many DISTINCT targets an agent has contacted within a sliding
    window, completely orthogonal to magnitude.

    Why this closes a real blind spot: an attacker who keeps every
    single taint_delta arbitrarily small (e.g. 0.001) evades CUSUM
    (drift never exceeds slack k) and the volume detector (sum of many
    tiny deltas stays under any reasonable cap) BY CONSTRUCTION -- no
    amount of tuning k/cap closes this, because both detectors are
    blind to WHO the messages go to, only WHAT their magnitude is. A
    single agent rapidly contacting many distinct targets (
    reconnaissance / lateral movement / Sybil-style fan-out) is
    anomalous regardless of how small each individual message's taint
    is. See pentest/pt16_fanout_evasion.py for a worked demonstration
    of an attack that evades both magnitude-based detectors but is
    caught by this one.
    """

    def __init__(self, window: int = 20, cap: int = 6):
        self.window = window
        self.cap = cap
        self._recent_targets: dict[str, list[str]] = {}

    def update(self, key: str, target: str) -> bool:
        hist = self._recent_targets.setdefault(key, [])
        hist.append(target)
        if len(hist) > self.window:
            hist.pop(0)
        return len(set(hist)) > self.cap

    def reset(self, key: str):
        self._recent_targets[key] = []


class SlidingWindowVolumeDetector:
    """
    Sums raw contributions over the last `window` events per key
    (agent_id or org), independent of any per-step slack. This is what
    catches a 'low-and-slow trickle' that CUSUM's slack was blind to:
    even if every single contribution is under the CUSUM slack, they
    still accumulate here.
    """

    def __init__(self, window: int = 20, cap: float = 0.5):
        self.window = window
        self.cap = cap
        self._history: dict[str, list[float]] = {}

    def update(self, key: str, value: float) -> bool:
        hist = self._history.setdefault(key, [])
        hist.append(value)
        if len(hist) > self.window:
            hist.pop(0)
        return sum(hist) > self.cap

    def reset(self, key: str):
        self._history[key] = []


class SecureOrchestrationLayer:
    def __init__(self, action_schemas: dict[str, set[str]] | None = None):
        self.rules: list[PolicyRule] = []
        self.action_schemas = dict(action_schemas or DEFAULT_ACTION_SCHEMAS)
        self.cusum = CUSUMDetector()
        self.volume_detector = SlidingWindowVolumeDetector(window=20, cap=0.5)
        self.quarantined_agents = set()
        self.audit_log: list[dict] = []
        self.governance_enabled = True

        # PENTEST FINDING (fixed, PT-05, capability-gated as of v5):
        # reinstate() previously had literally no authorisation check --
        # calling it directly, with no argument but agent_id, cleared a
        # quarantine. It now requires a capability token minted once per
        # SecureOrchestrationLayer instance and known only to whichever
        # FederationBus created it. This is a best-effort, code-level
        # gate, NOT equivalent to real process/module isolation -- any
        # caller with attribute-level access to this object can still
        # read self._reinstate_capability directly (Python has no true
        # private fields) and forge a valid call. That narrower residual
        # risk -- "an attacker with object-attribute access can defeat a
        # code-level capability check" -- is a laptop-scope limitation
        # this fix does not and cannot close; it belongs in FARF Cloud's
        # process-isolation design, not in more Python. What this DOES
        # close is the original finding: reinstate() can no longer be
        # called with zero effort/zero knowledge by careless or casual
        # misuse (see pentest/pt05_unauthorised_reinstatement.py).
        import secrets as _secrets
        self._reinstate_capability = _secrets.token_hex(32)

        self._register_default_rules()

    def _schema_violation(self, ev: "ActionEvent") -> bool:
        required = self.action_schemas.get(ev.action_type)
        if not required:
            return False  # no schema registered for this action_type (documented residual risk)
        missing = required - set(ev.payload.keys())
        return bool(missing)

    def _register_default_rules(self):
        # Checked FIRST and fails closed: a message that's missing the
        # fields a downstream rule needs to evaluate it is itself
        # treated as a violation, not silently waved through.
        self.rules.append(PolicyRule(
            name="incomplete_action_schema",
            predicate=self._schema_violation,
            action=Decision.BLOCK,
        ))
        self.rules.append(PolicyRule(
            name="cross_org_privilege_ceiling",
            predicate=lambda ev: ev.payload.get("requested_privilege", 0) > 0.9,
            action=Decision.BLOCK,
        ))
        self.rules.append(PolicyRule(
            name="unauthorised_instruction_override",
            predicate=lambda ev: ev.payload.get("attempts_system_override", False),
            action=Decision.QUARANTINE,
        ))
        self.rules.append(PolicyRule(
            name="toctou_resource_mismatch",
            predicate=lambda ev: (
                ev.payload.get("resource_hash_at_check") is not None
                and ev.payload.get("resource_hash_at_use") is not None
                and ev.payload["resource_hash_at_check"] != ev.payload["resource_hash_at_use"]
            ),
            action=Decision.BLOCK,
        ))
        # PENTEST FINDING (fixed, PT-10 / ASI06): a memory value read at
        # "check" time could previously differ from the same key's value
        # by "use" time (a race, or a legitimate-but-unexpected rewrite)
        # with nothing noticing -- mirrors toctou_resource_mismatch above
        # exactly, applied to FederationBus.read_memory()'s content_hash
        # instead of an external resource hash.
        self.rules.append(PolicyRule(
            name="memory_toctou_mismatch",
            predicate=lambda ev: (
                ev.payload.get("memory_hash_at_check") is not None
                and ev.payload.get("memory_hash_at_use") is not None
                and ev.payload["memory_hash_at_check"] != ev.payload["memory_hash_at_use"]
            ),
            action=Decision.BLOCK,
        ))

    def add_rule(self, rule: PolicyRule):
        self.rules.append(rule)

    def evaluate(self, event: ActionEvent) -> Decision:
        # ADR-010 (cross-cloud build, additive, observational only): a
        # TOCTOU-relevant action_type crossing an org boundary is exactly
        # the case where the check-to-use window is widest in a real
        # two-cloud deployment (ADR-004's partition handling applies to
        # this same hop). This logs the fact -- it does not gate, block,
        # or otherwise change the decision below, deliberately, so it
        # can't silently alter the already-cited Tab 7.8/7.9 statistics
        # (same academic-integrity concern as the ADR-006 quorum-default
        # question).
        _TOCTOU_RELEVANT_ACTION_TYPES = {"execute_action", "memory_recall_use"}
        if event.crosses_org_boundary and event.action_type in _TOCTOU_RELEVANT_ACTION_TYPES:
            log.warning("cross_boundary_toctou_reverification", extra={
                "event": "cross_boundary_toctou_reverification",
                "agent_id": event.agent_id, "org": event.org,
                "action_type": event.action_type,
                "resource_hash_at_check": event.payload.get("resource_hash_at_check"),
                "resource_hash_at_use": event.payload.get("resource_hash_at_use"),
                "memory_hash_at_check": event.payload.get("memory_hash_at_check"),
                "memory_hash_at_use": event.payload.get("memory_hash_at_use"),
            })

        if event.agent_id in self.quarantined_agents:
            self._log(event, Decision.QUARANTINE, "agent_already_quarantined")
            return Decision.QUARANTINE

        for rule in self.rules:
            try:
                if rule.predicate(event):
                    if rule.action == Decision.QUARANTINE:
                        self.quarantined_agents.add(event.agent_id)
                    self._log(event, rule.action, rule.name)
                    return rule.action
            except Exception:  # noqa: BLE001 -- rule predicates are deliberately best-effort evaluators
                log.warning("rule_predicate_error", extra={
                    "event": "rule_predicate_failed",
                    "agent_id": event.agent_id,
                    "org": event.org,
                    "action_type": event.action_type,
                    "rule": rule.name,
                }, exc_info=True)
                continue

        if self.cusum.update(event.agent_id, event.taint_score):
            self.quarantined_agents.add(event.agent_id)
            self._log(event, Decision.QUARANTINE, "behavioural_drift_cusum")
            return Decision.QUARANTINE

        if self.volume_detector.update(event.agent_id, event.taint_score):
            self.quarantined_agents.add(event.agent_id)
            self._log(event, Decision.QUARANTINE, "behavioural_drift_sliding_window")
            return Decision.QUARANTINE

        self._log(event, Decision.ALLOW, "no_violation")
        return Decision.ALLOW

    def reinstate(self, agent_id: str, capability: str | None = None):
        """
        Adaptive recovery primitive: lifts quarantine and resets both
        drift detectors for `agent_id`.

        ** INTERNAL ONLY -- DO NOT CALL DIRECTLY FROM APPLICATION CODE. **
        Requires `capability` to match this instance's
        `_reinstate_capability` token (see __init__ docstring for what
        this does and doesn't defend against). Application code MUST go
        through `FederationBus.reinstate_with_reattestation()` or
        `FederationBus.witness_federation_reinstatement()`, which supply
        the capability after requiring a fresh, valid credential /
        independent quorum respectively.
        """
        if capability != self._reinstate_capability:
            raise PermissionError(
                "reinstate() requires a valid capability token -- use "
                "FederationBus.reinstate_with_reattestation() or "
                "witness_federation_reinstatement() instead of calling this directly."
            )
        self.quarantined_agents.discard(agent_id)
        self.cusum.reset(agent_id)
        self.volume_detector.reset(agent_id)

    def _log(self, event: ActionEvent, decision: Decision, reason: str):
        self.audit_log.append({
            "timestamp": event.timestamp, "agent_id": event.agent_id, "org": event.org,
            "action_type": event.action_type, "decision": decision.value, "reason": reason,
        })
        # v7.8: this internal audit_log list is in-memory only and was
        # never observable outside the process (e.g. from a REPL
        # inspecting bus.orchestration.audit_log after the fact). Mirror
        # every decision to the structured logger too, severity-mapped
        # the same way federation_bus.py already does for its own
        # decisions (ALLOW=debug, BLOCK=warning, QUARANTINE=error), so
        # policy-layer decisions are visible in logs/farf.log without
        # needing a debugger attached.
        log_fn = {Decision.ALLOW: log.debug, Decision.BLOCK: log.warning,
                  Decision.QUARANTINE: log.error}[decision]
        log_fn("policy decision", extra={
            "event": "policy_decision", "agent_id": event.agent_id, "org": event.org,
            "action_type": event.action_type, "decision": decision.value, "reason": reason,
        })


if __name__ == "__main__":
    layer = SecureOrchestrationLayer()
    e1 = ActionEvent("A1", "OrgA", "plan_forward",
                      {"requested_privilege": 0.1, "attempts_system_override": True}, taint_score=0.1)
    print(layer.evaluate(e1))
    e2 = ActionEvent("A2", "OrgA", "execute_action",
                      {"resource_hash_at_check": "x", "resource_hash_at_use": "y"})
    print(layer.evaluate(e2))
    for i in range(10):
        e = ActionEvent("A3", "OrgA", "memory_recall_forward",
                         {"requested_privilege": 0.1, "attempts_system_override": False},
                         taint_score=0.1 * i)
        d = layer.evaluate(e)
    print("A3 final decision after drift:", d)
