"""
B1 -- DART-style reputation-and-quarantine gate (independent comparator)
------------------------------------------------------------------------
Adapted from: Kumal, Liu & Xu, "DART: A DAG-Based Reputation and Incentive Framework via
Blockchain-Enabled Governance for Trustworthy LLM Multi-Agent Collaboration", arXiv:2609.05529
(1 Sep 2026). This is an ADAPTATION of DART's reputation/quarantine loop to a message bus, not a
reproduction of DART, and it must be described that way in the thesis.

What is taken from the paper (its own equation numbers):
  Eq.6   B = w1(1-s) + w2(1-q) + w3(1-V) + w4(1-M) + w5*D, with the paper's w = (.30,.25,.25,.10,.10)
  Eq.8   Psi = mean of B over the last W messages of the agent            (paper: W = 5)
  Eq.12  P   = g1*s + g2*q + g3*M + g4*V - g5*D
  Eq.13  Omega = cumulative failure rate
  Eq.14  rho' = clip(eta*rho + (1-eta)*(P - kappa*Omega - mu*Psi), 0, 1)   (rho0 = 0.5)
  Quarantine rule: agent is flagged and PERMANENTLY removed when Psi >= theta_flag (paper: 0.65).
                   DART has no reinstatement path -- its "recovery" is system-level success rate
                   returning to baseline after isolation, not an agent being re-admitted.

What is NOT taken / cannot be mapped (disclose in the thesis):
  * Eq.3-4 allocation (rho -> softmax task assignment): FARF scenarios have fixed destinations, so
    reputation cannot steer routing here. rho is tracked (and can optionally block below rho_block)
    but the paper's flag decision is Psi, which is what is implemented.
  * eta, kappa, mu, g are not given in the paper; defaults below are my choices and do not affect
    the Psi-based flag rule.
  * Signal mapping. DART's telemetry (task success, GPT-4o quality, verification, latency) does not
    exist on a message bus. B1 is fed EXACTLY the information FARF's per-agent layer sees:
      s = 0 if the message is 'corrupt' (taint level >= corrupt_taint OR a policy rule fired) else 1
      q = 1 - taint level
      V = 0 if any deterministic policy rule fires (override flag, schema, privilege ceiling, TOCTOU)
      M = 1, D = 0
    so B1 and FARF differ in MECHANISM (windowed-mean reputation + permanent flag vs CUSUM +
    sliding-window + org-level + fan-out + quorum reinstatement), not in information.
  * Containment of a V=0 message (BLOCK) mirrors DART's output containment.
"""
from __future__ import annotations

from collections import deque

from orchestration import ActionEvent, Decision, SecureOrchestrationLayer

PAPER_OMEGA = (0.30, 0.25, 0.25, 0.10, 0.10)
PAPER_W = 5
PAPER_THETA_FLAG = 0.65


class DartStyleOrchestrationLayer:
    def __init__(self, theta_flag: float = PAPER_THETA_FLAG, window: int = PAPER_W,
                 corrupt_taint: float = 0.5, eta: float = 0.8, kappa: float = 0.3, mu: float = 0.5,
                 gamma=(0.30, 0.25, 0.10, 0.25, 0.10), rho_block: float | None = None):
        self.theta_flag, self.window, self.corrupt_taint = theta_flag, window, corrupt_taint
        self.eta, self.kappa, self.mu, self.gamma, self.rho_block = eta, kappa, mu, gamma, rho_block
        self.quarantined_agents: set[str] = set()
        self.audit_log: list[dict] = []
        self.governance_enabled = False          # DART has no org-level / fan-out detectors
        self._reinstate_capability = None
        self._rules = SecureOrchestrationLayer().rules      # V: same deterministic verification as FARF
        self.rho: dict[str, float] = {}
        self._hist: dict[str, deque] = {}
        self._n: dict[str, int] = {}
        self._fail: dict[str, int] = {}

    # --- DART equations -------------------------------------------------------------------------
    def _verify(self, ev: ActionEvent) -> bool:
        """V in {0,1}: independent verification. False => a deterministic rule fired."""
        for r in self._rules:
            try:
                if r.predicate(ev):
                    return False
            except Exception:  # noqa: BLE001, S112 -- mirror SecureOrchestrationLayer's best-effort predicates
                continue
        return True

    def _step(self, agent: str, taint: float, verified: bool):
        corrupt = (taint >= self.corrupt_taint) or (not verified)
        s, q, V, M, D = (0.0 if corrupt else 1.0), max(0.0, 1.0 - taint), (1.0 if verified else 0.0), 1.0, 0.0
        w, g = PAPER_OMEGA, self.gamma
        B = w[0] * (1 - s) + w[1] * (1 - q) + w[2] * (1 - V) + w[3] * (1 - M) + w[4] * D          # Eq.6
        h = self._hist.setdefault(agent, deque(maxlen=self.window))
        h.append(B)
        psi = sum(h) / len(h)                                                                     # Eq.8
        n = self._n[agent] = self._n.get(agent, 0) + 1
        f = self._fail[agent] = self._fail.get(agent, 0) + (1 if s == 0 else 0)
        omega = f / n                                                                             # Eq.13
        P = g[0] * s + g[1] * q + g[2] * M + g[3] * V - g[4] * D                                  # Eq.12
        rho = self.rho.get(agent, 0.5)
        self.rho[agent] = min(1.0, max(0.0, self.eta * rho + (1 - self.eta) * (P - self.kappa * omega - self.mu * psi)))  # Eq.14
        return psi, verified

    # --- drop-in for SecureOrchestrationLayer.evaluate -------------------------------------------
    def evaluate(self, ev: ActionEvent) -> Decision:
        if ev.agent_id in self.quarantined_agents:
            self._log(ev, Decision.QUARANTINE, "agent_already_quarantined")
            return Decision.QUARANTINE
        verified = self._verify(ev)
        psi, _ = self._step(ev.agent_id, ev.taint_score, verified)
        if psi >= self.theta_flag:                                   # permanent isolation
            self.quarantined_agents.add(ev.agent_id)
            self._log(ev, Decision.QUARANTINE, "dart_psi_flag")
            return Decision.QUARANTINE
        if not verified:
            self._log(ev, Decision.BLOCK, "dart_verification_failed")
            return Decision.BLOCK
        if self.rho_block is not None and self.rho.get(ev.agent_id, 0.5) < self.rho_block:
            self._log(ev, Decision.BLOCK, "dart_low_reputation")
            return Decision.BLOCK
        self._log(ev, Decision.ALLOW, "no_violation")
        return Decision.ALLOW

    def reinstate(self, agent_id, capability=None):
        """DART defines no reinstatement: quarantine is permanent. Deliberately a no-op."""
        return None

    def _log(self, ev: ActionEvent, decision: Decision, reason: str):
        self.audit_log.append({"timestamp": ev.timestamp, "agent_id": ev.agent_id, "org": ev.org,
                               "action_type": ev.action_type, "decision": decision.value, "reason": reason})
