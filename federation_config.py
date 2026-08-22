"""
federation_config.py -- closes ADR-012's config-schema gap (Phase 2 / cloud build)

WHAT THIS FIXES (vs. the schema shown in ARCHITECTURE_DECISIONS_1.md's ADR-012):

  1. `credential_ttl_seconds` / `ttl_seconds` mismatch.
     ADR-012 wrote `credential_ttl_seconds: 300.0` and called it "grounded in
     real parameter names." The real parameter is
     `FederatedTrustProtocol.issue_credential(..., ttl_seconds: float = 60.0)`.
     `main.py`'s `build_federation()` DOES call it with 300.0 today -- but
     that value is hardcoded at the call site, not configurable. This module
     makes it actually configurable, keeps the 300.0 default (matching
     today's real runtime behaviour, not the method's bare 60.0 default),
     and documents the discrepancy so it can't go silently stale again.

  2. `quorum_required: "pbft_proportional"` (string) vs. the real
     `FederationLedger.quorum_required` (a plain float).
     There was no translation code anywhere. `resolve_quorum()` below is
     that missing piece -- it calls the REAL, already-implemented
     `FederationLedger.recommended_quorum_for_pbft(n_orgs)` static method.

  3. `FederationBus.__init__` currently hardcodes `FederationLedger(quorum=2)`
     internally (see federation_bus.py L108) and never calls the opt-in
     `enable_pbft_quorum()` from `build_federation()`. That means a fresh
     federation defaults to a flat quorum=2 -- which is NOT PBFT-correct for
     N=3 (correct value is unanimity=3; see
     `recommended_quorum_for_pbft`'s own docstring on why quorum=1 was a
     real vulnerability at N=2). ADR-006 explicitly decided PBFT-proportional
     quorum "becomes the default, not opt-in, for the cloud build" -- that
     decision was never wired into code. `build_federation_from_config()`
     below wires it, with an explicit opt-out for anyone who deliberately
     wants the legacy fixed value.

  4. `adaptive_org_volume` defaults to False on `FederationBus` today. This
     config makes the cloud-build default True (per-org calibrated Sybil
     cap instead of one federation-wide constant), overridable per
     deployment.

NOT CLOSED HERE (left honestly open, not faked):
  `home_cloud` / `kms_key_ref` are accepted and stored on `OrgConfig` as
  metadata for the deployment topology, but neither is wired to a real
  cloud KMS call anywhere in this prototype -- ADR-003's actual cloud KMS
  integration doesn't exist in the Phase 1 code yet, so there's nothing to
  ground these fields against. Don't read their presence here as "KMS
  wiring done." `risk_tiering` / `cost_ceilings` / `cross_cloud` from
  ADR-012's original schema are deliberately NOT reproduced here -- they
  had no code-side equivalent at all (not even a partial one) and
  including them would repeat the exact mistake being fixed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

from federation_bus import FederationBus
from federation_ledger import FederationLedger
from agents import Agent


# --------------------------------------------------------------------------
# Org-level config
# --------------------------------------------------------------------------

@dataclass
class OrgConfig:
    name: str
    # Metadata only today -- see module docstring point (4). Stored so the
    # cloud build's deployment tooling (Terraform/Bicep, outside this repo)
    # has one source of truth for "which org runs where," even though this
    # prototype's own crypto path doesn't yet call out to either value.
    home_cloud: Optional[str] = None          # "aws" | "azure" | "gcp" | None
    kms_key_ref: Optional[str] = None
    advisor_base_privilege: float = 0.2       # matches main.py's current hardcode
    executor_base_privilege: float = 0.1      # matches main.py's current hardcode
    stake: float = 1.0                        # -> FederationLedger.set_stake()


# --------------------------------------------------------------------------
# Federation-level config
# --------------------------------------------------------------------------

QuorumSpec = Union[str, float, int]


@dataclass
class FederationConfig:
    orgs: List[OrgConfig] = field(default_factory=list)

    # --- fix (1): real field name, real default, actually plumbed through ---
    credential_ttl_seconds: float = 300.0

    # --- fix (2)/(3): accepts "pbft_proportional" (default, closes ADR-006)
    # or a raw numeric override for anyone who explicitly wants the legacy
    # fixed value. Never silently falls back to the unsafe quorum=2 default.
    quorum: QuorumSpec = "pbft_proportional"

    # v7.9.10: closes "dynamic PBFT quorum adoption" (confirmed absent,
    # PHASE1_TO_CLOUD_DECISION_BRIEF.md \u00a72 item 9) -- when True, the
    # built federation's quorum stays PBFT-proportional to membership as
    # orgs join, instead of being fixed once at build time by `quorum`
    # above. Default True: a config-built federation should track its own
    # membership by default, matching ADR-006's "default, not opt-in" call.
    quorum_dynamic: bool = True
    quorum_recompute_strategy: str = "immediate"  # "batched" not yet implemented, see federation_bus.py

    # real FederationBus params, now actually surfaced in one config object
    message_nonce_ttl_seconds: float = 300.0
    require_message_signatures: bool = True
    db_path: str = "farf_audit.db"

    # --- fix (4): cloud-build default flips this on ---
    adaptive_org_volume: bool = True

    def n_orgs(self) -> int:
        return len(self.orgs)


def default_cloud_config(n_orgs: int = 3, home_clouds: Optional[List[str]] = None) -> FederationConfig:
    """
    Convenience constructor matching today's `main.py build_federation()`
    org-naming convention (OrgA, OrgB, ...) so this is a drop-in replacement,
    not a parallel scheme to keep in sync by hand.
    """
    if home_clouds is None:
        home_clouds = []
    orgs = []
    for i in range(n_orgs):
        name = f"Org{chr(65 + i)}"
        cloud = home_clouds[i] if i < len(home_clouds) else None
        orgs.append(OrgConfig(name=name, home_cloud=cloud,
                               kms_key_ref=f"{name.lower()}-kms-key" if cloud else None))
    return FederationConfig(orgs=orgs)


# --------------------------------------------------------------------------
# The missing translation code: resolve_quorum()
# --------------------------------------------------------------------------

def resolve_quorum(spec: QuorumSpec, n_orgs: int) -> float:
    """
    Translates a QuorumSpec into the float FederationLedger.quorum_required
    actually needs. This function is what ADR-012's schema assumed already
    existed and didn't.
    """
    if isinstance(spec, (int, float)):
        return float(spec)
    if isinstance(spec, str) and spec == "pbft_proportional":
        # the REAL, already-implemented, already-correct static method --
        # see federation_ledger.py for the unanimity-at-f=0 reasoning.
        return float(FederationLedger.recommended_quorum_for_pbft(n_orgs))
    raise ValueError(
        f"Unrecognised quorum spec {spec!r}. Use a number, or the string "
        f"'pbft_proportional' (recommended -- closes ADR-006's default-PBFT "
        f"decision)."
    )


# --------------------------------------------------------------------------
# Real wiring: config -> live FederationBus + agents
# --------------------------------------------------------------------------

def build_federation_from_config(config: FederationConfig):
    """
    Config-driven replacement for main.py's build_federation(int) -> dict.
    Same return shape ({org: {"advisor": Agent, "executor": Agent}}), so
    every scenario_*() function in main.py works against it unchanged --
    this is additive, not a breaking rewrite of the demo path.
    """
    n = config.n_orgs()
    if n == 0:
        raise ValueError("FederationConfig has no orgs configured.")

    bus = FederationBus(
        db_path=config.db_path,
        require_message_signatures=config.require_message_signatures,
        message_nonce_ttl_seconds=config.message_nonce_ttl_seconds,
        adaptive_org_volume=config.adaptive_org_volume,
        quorum_mode="pbft_dynamic" if config.quorum_dynamic else "static",
        quorum_recompute_strategy=config.quorum_recompute_strategy,
    )

    # --- close fix (3): make PBFT-proportional quorum the actual default,
    # not opt-in, per ADR-006. Falls back to the legacy federation_bus.py
    # default (quorum=2) ONLY if the operator explicitly passes a raw
    # number equal to that -- resolve_quorum() never picks it implicitly.
    # When quorum_dynamic=True (the default), org registration below
    # keeps this current automatically -- this initial resolve_quorum()
    # call still matters for the quorum_dynamic=False case, and gives an
    # accurate quorum_value to return even when dynamic mode will
    # immediately recompute the same number on the first register_organisation().
    quorum_value = resolve_quorum(config.quorum, n)
    bus.ledger.quorum_required = quorum_value

    agents: Dict[str, Dict[str, Agent]] = {}
    for org_cfg in config.orgs:
        org = org_cfg.name
        bus.register_organisation(org)
        bus.ledger.set_stake(org, org_cfg.stake)

        advisor = Agent(f"{org}-advisor", org, "advisor")
        executor = Agent(f"{org}-executor", org, "executor")
        bus.register_agent(advisor.agent_id, org, base_privilege=org_cfg.advisor_base_privilege)
        bus.register_agent(executor.agent_id, org, base_privilege=org_cfg.executor_base_privilege)
        bus.adversary_model.add_delegation(advisor.agent_id, executor.agent_id, privilege=0.4)
        agents[org] = {"advisor": advisor, "executor": executor}

        for agent in (advisor, executor):
            vc = bus.trust.issue_credential(
                org, subject_did=f"did:key:agent:{agent.agent_id}",
                claims={"role": agent.role},
                ttl_seconds=config.credential_ttl_seconds,  # <-- now actually configurable
            )
            admission = bus.admit_agent(agent.agent_id, org, vc)
            assert admission["valid"], f"setup failure: could not admit {agent.agent_id}"

    org_list = [c.name for c in config.orgs]
    for i in range(len(org_list) - 1):
        bus.adversary_model.add_delegation(
            agents[org_list[i]]["executor"].agent_id,
            agents[org_list[i + 1]]["advisor"].agent_id,
            privilege=0.3,
        )

    # Return the ACTUAL final quorum_required, not the pre-registration
    # resolve_quorum() estimate -- in quorum_dynamic=True mode (the
    # default) these converge to the same number once every org is
    # registered, but if a caller explicitly combines a raw numeric
    # `config.quorum` override WITH `quorum_dynamic=True`, the dynamic
    # recompute inside register_organisation() above wins (fires on
    # every join) and the initial resolve_quorum() value would be stale
    # -- returning bus.ledger.quorum_required directly means this
    # function never reports a number the bus itself disagrees with.
    return bus, agents, bus.ledger.quorum_required
