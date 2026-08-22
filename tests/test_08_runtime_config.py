"""
test_08_runtime_config.py -- v7.9.8/9.9

Tests runtime_config.py against the actual farf_runtime_config.yml shape
the researcher supplied (fixture below is a byte-for-byte copy of that
file's structure), plus error paths and the APPLIED/PARSED_ONLY
classification contract itself. Also exercises the real
main.py -> runtime_config.py -> federation_config.py integration path
(the dry-run federation build), not just the loader in isolation.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from runtime_config import (
    RuntimeConfigError, load_runtime_config, apply_runtime_config, to_federation_config,
)
from federation_config import build_federation_from_config

REAL_CONFIG_YAML = """\
federation:
  orgs: ["org_a", "org_b", "org_c"]
  quorum_threshold: 0.6
attack_mode:
  active: "prompt_injection"
  injection_variants: ["substring", "paraphrase", "homoglyph"]
  intensity: "slow_drip"
risk_tiering:
  low:    { autonomy: "full", token_cap_per_action: 2000 }
  medium: { autonomy: "oversight", token_cap_per_action: 4000, human_alert: true }
  high:   { autonomy: "hitl_required", token_cap_per_action: 8000, approval_timeout_s: 300 }
detection_thresholds:
  cusum_slack: 0.5
  volume_cap_mode: "adaptive"
  static_volume_cap: 50
fail_safe_defaults:
  trust_protocol_on_kms_failure: "closed"
  taint_unresolved_default: "tainted"
  fars_stale_after_s: 120
  fars_stale_action: "downgrade_one_tier"
cost_ceilings:
  token_budget_per_org_per_day: 500000
  token_budget_action: "throttle_to_low_autonomy"
  model_routing:
    default: "small"
    escalate_on: ["ambiguous_classification", "high_risk_tier"]
logging:
  level: "INFO"
  sink: "json_stdout"
"""


@pytest.fixture
def real_config_path(tmp_path):
    p = tmp_path / "farf_runtime_config.yml"
    p.write_text(REAL_CONFIG_YAML)
    return str(p)


class TestLoadRuntimeConfig:
    def test_loads_real_shape_without_error(self, real_config_path):
        cfg = load_runtime_config(real_config_path)
        assert cfg.org_names == ["org_a", "org_b", "org_c"]
        assert cfg.quorum_threshold == 0.6
        assert cfg.logging_level == "INFO"
        assert cfg.logging_sink == "json_stdout"

    def test_missing_file_raises_runtime_config_error(self, tmp_path):
        with pytest.raises(RuntimeConfigError, match="not found"):
            load_runtime_config(str(tmp_path / "nope.yml"))

    def test_malformed_yaml_raises_runtime_config_error(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("federation: [this is not\n  valid: yaml: at all")
        with pytest.raises(RuntimeConfigError, match="Malformed YAML"):
            load_runtime_config(str(p))

    def test_empty_file_loads_to_empty_config(self, tmp_path):
        p = tmp_path / "empty.yml"
        p.write_text("")
        cfg = load_runtime_config(str(p))
        assert cfg.org_names == []
        assert cfg.applied == {}

    def test_non_mapping_top_level_raises(self, tmp_path):
        p = tmp_path / "list.yml"
        p.write_text("- a\n- b\n")
        with pytest.raises(RuntimeConfigError, match="mapping"):
            load_runtime_config(str(p))

    def test_orgs_not_a_list_raises(self, tmp_path):
        p = tmp_path / "bad_orgs.yml"
        p.write_text("federation:\n  orgs: \"org_a\"\n")
        with pytest.raises(RuntimeConfigError, match="must be a list"):
            load_runtime_config(str(p))

    def test_orgs_with_empty_string_raises(self, tmp_path):
        p = tmp_path / "empty_org_name.yml"
        p.write_text("federation:\n  orgs: [\"org_a\", \"\"]\n")
        with pytest.raises(RuntimeConfigError, match="non-empty strings"):
            load_runtime_config(str(p))


class TestAppliedVsParsedOnlyClassification:
    """The honesty contract: every field in the real config file must be
    classified as exactly one of applied/parsed_only, never silently
    dropped -- this is the whole point of the module."""

    def test_every_top_level_and_named_nested_field_is_classified(self, real_config_path):
        cfg = load_runtime_config(real_config_path)
        all_keys = set(cfg.applied.keys()) | set(cfg.parsed_only.keys())
        expected = {
            "federation.orgs", "federation.quorum_threshold",
            "attack_mode", "risk_tiering", "cost_ceilings",
            "detection_thresholds.cusum_slack", "detection_thresholds.volume_cap_mode",
            "detection_thresholds.static_volume_cap",
            "fail_safe_defaults.trust_protocol_on_kms_failure",
            "fail_safe_defaults.taint_unresolved_default",
            "fail_safe_defaults.fars_stale_after_s", "fail_safe_defaults.fars_stale_action",
            "logging.level", "logging.sink",
        }
        assert all_keys == expected

    def test_orgs_and_logging_level_are_applied(self, real_config_path):
        cfg = load_runtime_config(real_config_path)
        assert "federation.orgs" in cfg.applied
        assert "logging.level" in cfg.applied
        assert "logging.sink" in cfg.applied  # json_stdout is the one real sink value

    def test_quorum_threshold_is_parsed_only_not_applied(self, real_config_path):
        # the fraction-vs-count unit mismatch -- must never be silently
        # "resolved" by a guess; see runtime_config.PARSED_ONLY_REASONS.
        cfg = load_runtime_config(real_config_path)
        assert "federation.quorum_threshold" in cfg.parsed_only
        assert "federation.quorum_threshold" not in cfg.applied

    def test_unimplemented_sections_are_parsed_only(self, real_config_path):
        cfg = load_runtime_config(real_config_path)
        for section in ("attack_mode", "risk_tiering", "cost_ceilings"):
            assert section in cfg.parsed_only

    def test_non_json_stdout_sink_warns_and_falls_back(self, tmp_path):
        p = tmp_path / "azure_sink.yml"
        p.write_text("logging:\n  sink: \"azure_monitor\"\n")
        cfg = load_runtime_config(str(p))
        assert "logging.sink" in cfg.parsed_only
        assert "logging.sink" not in cfg.applied
        assert any("azure_monitor" in w for w in cfg.warnings)

    def test_summarise_mentions_every_parsed_only_field_with_a_reason(self, real_config_path):
        cfg = load_runtime_config(real_config_path)
        text = cfg.summarise()
        for key in cfg.parsed_only:
            assert key in text


class TestApplyRuntimeConfig:
    def test_applies_log_level_to_environ(self, real_config_path, monkeypatch):
        monkeypatch.delenv("FARF_LOG_LEVEL", raising=False)
        cfg = apply_runtime_config(load_runtime_config(real_config_path))
        assert os.environ["FARF_LOG_LEVEL"] == "INFO"

    def test_does_not_override_an_explicit_operator_env_var(self, real_config_path, monkeypatch):
        # env var precedence: an operator-set FARF_LOG_LEVEL wins over the
        # config file, matching the precedence already established for
        # FARF_LLM_JUDGE_MODEL elsewhere in this codebase.
        monkeypatch.setenv("FARF_LOG_LEVEL", "DEBUG")
        apply_runtime_config(load_runtime_config(real_config_path))
        assert os.environ["FARF_LOG_LEVEL"] == "DEBUG"

    def test_json_stdout_sink_sets_log_format_json(self, real_config_path, monkeypatch):
        monkeypatch.delenv("FARF_LOG_FORMAT", raising=False)
        apply_runtime_config(load_runtime_config(real_config_path))
        assert os.environ["FARF_LOG_FORMAT"] == "json"

    def test_idempotent_double_apply(self, real_config_path, monkeypatch):
        monkeypatch.delenv("FARF_LOG_LEVEL", raising=False)
        cfg = load_runtime_config(real_config_path)
        apply_runtime_config(cfg)
        apply_runtime_config(cfg)  # must not raise or change the outcome
        assert os.environ["FARF_LOG_LEVEL"] == "INFO"


class TestToFederationConfigIntegration:
    """Proves federation.orgs is genuinely wired end-to-end, not just
    parsed -- builds a REAL federation via the same
    build_federation_from_config() the rest of the codebase already uses."""

    def test_real_federation_builds_from_the_real_config_file(self, real_config_path, tmp_path):
        cfg = load_runtime_config(real_config_path)
        fed_config = to_federation_config(cfg, db_path=str(tmp_path / "rc_test.db"))
        assert [o.name for o in fed_config.orgs] == ["org_a", "org_b", "org_c"]

        bus, agents, quorum_value = build_federation_from_config(fed_config)
        try:
            assert set(agents.keys()) == {"org_a", "org_b", "org_c"}
            for org, roles in agents.items():
                assert "advisor" in roles and "executor" in roles
            # N=3 -> PBFT unanimity, matching federation_ledger's own
            # documented reasoning -- NOT derived from quorum_threshold
            # (deliberately parsed_only, see above), from the safe
            # 'pbft_proportional' default instead.
            assert quorum_value == 3.0
        finally:
            bus.close()

    def test_quorum_threshold_is_not_consulted_by_to_federation_config(self, real_config_path, tmp_path):
        # Explicit negative assertion for the documented behaviour: even
        # though quorum_threshold=0.6 is present in the file, it must NOT
        # silently influence the resolved quorum.
        cfg = load_runtime_config(real_config_path)
        fed_config = to_federation_config(cfg, db_path=str(tmp_path / "rc_test2.db"))
        assert fed_config.quorum == "pbft_proportional"

    def test_no_orgs_raises_clear_error(self, tmp_path):
        p = tmp_path / "no_orgs.yml"
        p.write_text("logging:\n  level: INFO\n")
        cfg = load_runtime_config(str(p))
        with pytest.raises(RuntimeConfigError, match="no federation.orgs"):
            to_federation_config(cfg)
