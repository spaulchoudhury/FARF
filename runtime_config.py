"""
runtime_config.py -- makes `farf_runtime_config.yml` a REAL, loadable
config file (v7.9.8).

Before this module existed, ADR-012 in ARCHITECTURE_DECISIONS_1.md was
explicit that "no module in this codebase parses YAML" and that the
runtime-config YAML shown there was illustrative only, with every real
knob actually read from an `os.environ` `FARF_*` lookup instead. This
module closes that gap for the file the researcher actually drafted
(`farf_runtime_config.yml`) -- but does so HONESTLY: several fields in
that file describe behaviour that doesn't exist anywhere in this
codebase yet (no CUSUM detector, no attack-injection engine, no
risk-tier-aware autonomy gating, no token-budget accounting, no KMS
client, no taint tri-state, no FARS staleness clock). Wiring those up
is a real design decision each -- see CHANGELOG_v7.9.9.md for the
pros/cons this module deliberately leaves for the researcher to decide,
rather than guessing at semantics no code currently implements.

CONTRACT: every field in the YAML file is parsed and classified as
exactly one of:

  APPLIED      -- wired to a real code parameter; takes effect this run.
  PARSED_ONLY  -- successfully validated and made available on the
                  returned RuntimeConfig, but nothing in this codebase
                  consumes it yet. Never silently dropped -- every
                  PARSED_ONLY field is named in `PARSED_ONLY_REASONS`
                  below and reported by `summarise()` so a user reading
                  the startup output knows exactly what the file did
                  and did not do.

This module never raises on an unknown/extra field in the YAML (config
files are allowed to describe future intent) and never crashes the
caller if the file is missing or malformed -- callers get a clear
`RuntimeConfigError` they can choose how to handle, consistent with
this codebase's fail-closed-on-ambiguity posture elsewhere (see
`agents.py`'s `detect_prompt_injection()` docstring for the same
philosophy applied to a different module).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError as _e:  # pragma: no cover -- exercised via test monkeypatch
    yaml = None
    _YAML_IMPORT_ERROR = _e
else:
    _YAML_IMPORT_ERROR = None

from federation_config import FederationConfig, OrgConfig

logger = logging.getLogger("farf.runtime_config")


class RuntimeConfigError(Exception):
    """Raised for a missing file, unparsable YAML, or a structurally
    invalid `federation.orgs` list (the one field this module actually
    depends on to build a federation). Never raised for merely-unknown
    or merely-unimplemented fields -- those are PARSED_ONLY, not errors."""


# --------------------------------------------------------------------------
# What each PARSED_ONLY field means and why it isn't wired yet -- kept as
# data (not scattered comments) so `summarise()` can print it and so the
# reasons live in exactly one place instead of drifting from the docs.
# --------------------------------------------------------------------------
PARSED_ONLY_REASONS: dict[str, str] = {
    "federation.quorum_threshold":
        "Real quorum resolution (federation_config.resolve_quorum) takes "
        "a count or the string 'pbft_proportional', not a fraction of "
        "orgs. Converting 0.6 -> a count needs a decision (e.g. "
        "ceil(threshold * n_orgs) vs. something PBFT-aware) this module "
        "does not make unilaterally -- see CHANGELOG_v7.9.9.md. Quorum "
        "falls back to the safe 'pbft_proportional' default instead of "
        "guessing.",
    "attack_mode":
        "No runtime attack-injection engine exists in this codebase -- "
        "main.py's --scenario flag selects a hardcoded scenario function; "
        "there is no config-driven mechanism to vary injection_variants/ "
        "intensity against a running federation. Building one is a real "
        "feature, not a wiring fix -- see pros/cons in CHANGELOG_v7.9.9.md.",
    "risk_tiering":
        "No code path currently classifies an action into low/medium/high "
        "risk or gates autonomy on that classification -- ADR-012 already "
        "flagged this block as having no Phase 1 code equivalent.",
    "detection_thresholds.cusum_slack":
        "No CUSUM (cumulative sum control chart) detector exists anywhere "
        "in this codebase. adaptive_detection.py implements a rolling-"
        "window calibrated cap, a different algorithm family; pentest/"
        "pt03_cusum_slow_drip.py exercises the SCENARIO (a slow-drip "
        "attack) but tests against the real rolling-window detector, not "
        "a CUSUM implementation.",
    "detection_thresholds.volume_cap_mode":
        "adaptive_detection.py's AdaptiveOrgVolumeDetector doesn't expose "
        "a mode switch of this shape from FederationBus's constructor -- "
        "FederationBus's own adaptive_org_volume bool is the closest real "
        "analogue ('adaptive' vs a fixed cap) but is federation-wide, not "
        "per-call like this field implies.",
    "detection_thresholds.static_volume_cap":
        "Unit mismatch with the real fallback: AdaptiveOrgVolumeDetector."
        "fallback_cap (default 0.35) is a FRACTION of calibrated baseline "
        "traffic; this field's value (50) reads as an absolute message "
        "count. Converting one to the other needs a decision about what "
        "denominator to use, not a safe default -- left unresolved.",
    "fail_safe_defaults.trust_protocol_on_kms_failure":
        "No code path calls a real cloud KMS anywhere in this build "
        "(ADR-003 is still an open cloud-build blocker) -- there is no "
        "KMS failure for this to gate a response to yet.",
    "fail_safe_defaults.taint_unresolved_default":
        "taint_engine.py's TaintLabel has no 'unresolved' state distinct "
        "from 'not tainted' today -- would need a real tri-state added "
        "before this field could mean anything.",
    "fail_safe_defaults.fars_stale_after_s":
        "fars.py computes FARS on demand from current state; there is no "
        "staleness/freshness clock on a FARS value anywhere in this "
        "codebase for this threshold to gate.",
    "fail_safe_defaults.fars_stale_action":
        "Same root cause as fars_stale_after_s immediately above -- no "
        "staleness concept exists yet for an action to trigger from.",
    "cost_ceilings":
        "No token-budget accounting exists anywhere in this codebase -- "
        "agents.py's Agent class has no notion of tokens spent, so there "
        "is nothing for a daily ceiling or a throttle action to act on.",
}

APPLIED_FIELDS = (
    "federation.orgs",
    "logging.level",
    ("logging.sink (only the 'json_stdout' value; other values fall back "
    "to the existing local-file sink with a warning, see below)"),
)


@dataclass
class RuntimeConfig:
    path: str
    raw: dict[str, Any]
    org_names: list[str]
    quorum_threshold: float | None
    logging_level: str | None
    logging_sink: str | None
    applied: dict[str, Any] = field(default_factory=dict)
    parsed_only: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def summarise(self) -> str:
        lines = [f"[FARF] runtime config loaded from {self.path}:"]
        lines.append(f"  APPLIED (took effect this run): {sorted(self.applied.keys())}")
        lines.append("  PARSED_ONLY (stored, not yet wired to any code -- see reason below):")
        for k in sorted(self.parsed_only.keys()):
            reason = PARSED_ONLY_REASONS.get(k, "no consumer implemented yet")
            lines.append(f"    - {k} = {self.parsed_only[k]!r} :: {reason}")
        if self.warnings:
            lines.append("  WARNINGS:")
            for w in self.warnings:
                lines.append(f"    - {w}")
        return "\n".join(lines)


def _get(d: dict[str, Any], dotted: str, default=None):
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def load_runtime_config(path: str) -> RuntimeConfig:
    """Parses `path` (expected shape: farf_runtime_config.yml) into a
    RuntimeConfig. Does NOT apply anything to process state -- call
    `apply_runtime_config()` separately so loading (safe, side-effect-free,
    easy to unit test) and applying (mutates os.environ) stay decoupled."""
    if yaml is None:
        raise RuntimeConfigError(
            f"PyYAML is required to load {path} but is not installed "
            f"(import failed: {_YAML_IMPORT_ERROR}). Run "
            f"`pip install -r requirements.txt`."
        )
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise RuntimeConfigError(f"Runtime config file not found: {path}") from e
    except yaml.YAMLError as e:
        raise RuntimeConfigError(f"Malformed YAML in {path}: {e}") from e

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise RuntimeConfigError(
            f"{path} must parse to a YAML mapping at the top level, got {type(raw).__name__}."
        )

    org_names = _get(raw, "federation.orgs", [])
    if org_names is not None and not isinstance(org_names, list):
        raise RuntimeConfigError(
            f"federation.orgs must be a list of org names, got {type(org_names).__name__}."
        )
    org_names = org_names or []
    if org_names and not all(isinstance(n, str) and n for n in org_names):
        raise RuntimeConfigError("federation.orgs must be a list of non-empty strings.")

    quorum_threshold = _get(raw, "federation.quorum_threshold")
    logging_level = _get(raw, "logging.level")
    logging_sink = _get(raw, "logging.sink")

    cfg = RuntimeConfig(
        path=path,
        raw=raw,
        org_names=org_names,
        quorum_threshold=quorum_threshold,
        logging_level=logging_level,
        logging_sink=logging_sink,
    )

    # --- classify every top-level (and named nested) field as
    # APPLIED or PARSED_ONLY. This loop is deliberately explicit rather
    # than "everything not in a hardcoded APPLIED list is parsed_only by
    # default" -- an explicit list means a newly-added YAML field that
    # nobody has categorised yet fails loudly (KeyError-shaped, caught
    # below and surfaced as a warning) instead of silently being treated
    # as either status.
    if org_names:
        cfg.applied["federation.orgs"] = org_names
    if quorum_threshold is not None:
        cfg.parsed_only["federation.quorum_threshold"] = quorum_threshold
    if logging_level is not None:
        cfg.applied["logging.level"] = logging_level
    if logging_sink is not None:
        if logging_sink == "json_stdout":
            cfg.applied["logging.sink"] = logging_sink
        else:
            cfg.parsed_only["logging.sink"] = logging_sink
            cfg.warnings.append(
                f"logging.sink={logging_sink!r} is not implemented "
                f"(ADR-007's cloud sinks -- cloudwatch/stackdriver/"
                f"azure_monitor -- are cloud-build work, not shipped in "
                f"this prototype). Falling back to the existing local "
                f"rotating-file sink; nothing crashes, but logs are NOT "
                f"actually going to {logging_sink}."
            )

    for section in ("attack_mode", "risk_tiering", "cost_ceilings"):
        if section in raw:
            cfg.parsed_only[section] = raw[section]

    for leaf in ("cusum_slack", "volume_cap_mode", "static_volume_cap"):
        val = _get(raw, f"detection_thresholds.{leaf}")
        if val is not None:
            cfg.parsed_only[f"detection_thresholds.{leaf}"] = val

    for leaf in ("trust_protocol_on_kms_failure", "taint_unresolved_default",
                 "fars_stale_after_s", "fars_stale_action"):
        val = _get(raw, f"fail_safe_defaults.{leaf}")
        if val is not None:
            cfg.parsed_only[f"fail_safe_defaults.{leaf}"] = val

    return cfg


def apply_runtime_config(cfg: RuntimeConfig) -> RuntimeConfig:
    """Mutates process state (os.environ) for the APPLIED fields only.
    Safe to call more than once (idempotent). Returns the same object
    for chaining, e.g. `cfg = apply_runtime_config(load_runtime_config(path))`."""
    if "logging.level" in cfg.applied:
        os.environ.setdefault("FARF_LOG_LEVEL", str(cfg.applied["logging.level"]).upper())
        # setdefault, not direct assignment: an operator-set FARF_LOG_LEVEL
        # in the real environment takes precedence over the config file,
        # consistent with the general "env var is the real mechanism"
        # precedence already established for llm_judge.py's FARF_LLM_JUDGE_MODEL.
    if cfg.applied.get("logging.sink") == "json_stdout":
        os.environ.setdefault("FARF_LOG_FORMAT", "json")
    return cfg


def to_federation_config(cfg: RuntimeConfig, **overrides) -> FederationConfig:
    """Builds a real FederationConfig from the APPLIED org list.
    `**overrides` are passed straight through to FederationConfig's other
    fields (credential_ttl_seconds, db_path, etc.) so callers aren't
    forced to accept every default. quorum_threshold is deliberately NOT
    consulted here -- see PARSED_ONLY_REASONS['federation.quorum_threshold']
    -- FederationConfig's own safe 'pbft_proportional' default applies
    unless the caller explicitly overrides `quorum=`."""
    if not cfg.org_names:
        raise RuntimeConfigError(
            f"{cfg.path} has no federation.orgs entries -- cannot build a federation from it."
        )
    orgs = [OrgConfig(name=n) for n in cfg.org_names]
    return FederationConfig(orgs=orgs, **overrides)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "farf_runtime_config.yml"
    loaded = apply_runtime_config(load_runtime_config(target))
    print(loaded.summarise())
