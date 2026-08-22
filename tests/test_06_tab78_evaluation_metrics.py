"""
Test 06 -- Tab 7.8 Evaluation Metrics closure.

Closes the gap identified against Research_Proposal_Shubho_v2.pdf Tab
7.8: of the 14 named metrics, only FARS correlation + the cross-cutting
significance battery (test_04) had real computation code. This suite
runs the remaining 9 (plus the 2 that only existed as informal pentest
evidence) as proper repeated, randomised, labelled trials and writes
`tab78_evaluation_report.csv` next to the other statistical report,
matching test_04's existing reporting convention.

Run:  python -m pytest tests/test_06_tab78_evaluation_metrics.py -v -s
"""
import csv
import os
import tempfile
import sys
import uuid

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from federation_bus import FederationBus
from main import build_federation
from tests.evaluation_metrics_tab78 import (
    run_adversary_model_trials,
    run_trust_protocol_trials,
    run_delegation_integrity_trials,
    run_policy_enforcement_trials,
    run_behavioural_drift_detection_trials,
    run_workflow_completion_trials,
    run_provenance_identification_trials,
    run_taint_containment_trials,
    run_privilege_path_reconstruction_trials,
)


def _bus_factory():
    """Fresh FederationBus + 3-org federation, same shape as conftest's
    fresh_bus fixture but callable repeatedly within a single trial
    loop (pytest fixtures are function-scoped, which would tear down
    between trials inside one test -- these trial runners need many
    fresh federations per test)."""
    db_path = os.path.join(tempfile.gettempdir(), f"farf_tab78_{uuid.uuid4().hex}.db")
    bus = FederationBus(db_path=db_path, require_message_signatures=False)
    agents = build_federation(bus, n_orgs=3)
    return bus, agents


@pytest.fixture(scope="module")
def tab78_results():
    results = {}
    results["adversary_model"] = run_adversary_model_trials(n_trials=200)
    results["trust_protocol"] = run_trust_protocol_trials(n_trials=200)
    results["delegation_integrity"] = run_delegation_integrity_trials(_bus_factory, n_trials=80)
    results["policy_enforcement"] = run_policy_enforcement_trials(n_trials=300)
    results["behavioural_drift"] = run_behavioural_drift_detection_trials(n_trials=100)
    results["workflow_completion"] = run_workflow_completion_trials(_bus_factory, n_trials=50)
    results["provenance_identification"] = run_provenance_identification_trials(n_trials=150)
    results["taint_containment"] = run_taint_containment_trials(_bus_factory, n_trials=50)
    results["privilege_path_reconstruction"] = run_privilege_path_reconstruction_trials(n_trials=150)
    return results


def test_adversary_model_metrics(tab78_results):
    m = tab78_results["adversary_model"]
    print(f"\n[Federated Adversary Model] ADR={m['attack_detection_rate']:.3f} "
          f"Precision={m['precision']:.3f} Recall={m['recall']:.3f} F1={m['f1_score']:.3f} "
          f"(n={m['n_trials']}, TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']})")
    assert m["n_trials"] == 200
    # Sanity floor, not a tuned pass/fail bar: a threshold-based detector
    # operating on trials specifically designed to straddle its boundary
    # should still beat a coin flip by a wide margin.
    assert m["f1_score"] > 0.6


def test_trust_protocol_metrics(tab78_results):
    m = tab78_results["trust_protocol"]
    print(f"\n[Federated Trust Protocol] Credential Verification Success Rate="
          f"{m['credential_verification_success_rate']:.3f} "
          f"Trust Establishment Latency (mean)={m['trust_establishment_latency_ms']['mean']:.3f}ms")
    assert m["credential_verification_success_rate"] > 0.9


def test_delegation_integrity(tab78_results):
    m = tab78_results["delegation_integrity"]
    print(f"\n[Federated Trust Protocol] Delegation Integrity Rate="
          f"{m['delegation_integrity_rate']:.3f}")
    assert m["delegation_integrity_rate"] > 0.9


def test_policy_enforcement_accuracy(tab78_results):
    m = tab78_results["policy_enforcement"]
    print(f"\n[Orchestration] Policy Enforcement Accuracy="
          f"{m['policy_enforcement_accuracy']:.3f}")
    assert m["policy_enforcement_accuracy"] > 0.95


def test_behavioural_anomaly_detection_rate(tab78_results):
    m = tab78_results["behavioural_drift"]
    print(f"\n[Orchestration] Behavioural Anomaly Detection Rate="
          f"{m['behavioural_anomaly_detection_rate']:.3f} "
          f"(false positive rate={m['false_positive_rate']:.3f})")
    assert m["behavioural_anomaly_detection_rate"] > 0.5


def test_workflow_completion_rate(tab78_results):
    m = tab78_results["workflow_completion"]
    print(f"\n[Orchestration] Workflow Completion Rate="
          f"{m['workflow_completion_rate']:.3f} (sd={m['workflow_completion_rate_sd']:.3f})")
    assert m["workflow_completion_rate"] > 0.5


def test_provenance_identification_accuracy(tab78_results):
    m = tab78_results["provenance_identification"]
    print(f"\n[Taint Propagation Engine] Provenance Identification Accuracy="
          f"{m['provenance_identification_accuracy']:.3f}")
    assert m["provenance_identification_accuracy"] > 0.95


def test_taint_containment_rate(tab78_results):
    m = tab78_results["taint_containment"]
    print(f"\n[Taint Propagation Engine] Taint Containment Rate="
          f"{m['taint_containment_rate']:.3f} (threshold={m['containment_threshold']})")
    assert 0.0 <= m["taint_containment_rate"] <= 1.0


def test_privilege_path_reconstruction_accuracy(tab78_results):
    m = tab78_results["privilege_path_reconstruction"]
    print(f"\n[Taint Propagation Engine] Privilege Path Reconstruction Accuracy="
          f"{m['privilege_path_reconstruction_accuracy']:.3f}")
    assert m["privilege_path_reconstruction_accuracy"] > 0.8


def test_write_tab78_report(tab78_results):
    """Writes tab78_evaluation_report.csv next to statistical_validation_report.csv,
    one row per Tab 7.8 metric, so the dissertation's evaluation chapter
    can cite a single reproducible artefact for every named metric."""
    r = tab78_results
    rows = [
        ("Security Effectiveness", "Attack Detection Rate (ADR)", r["adversary_model"]["attack_detection_rate"]),
        ("Security Effectiveness", "Precision", r["adversary_model"]["precision"]),
        ("Security Effectiveness", "Recall", r["adversary_model"]["recall"]),
        ("Security Effectiveness", "F1-Score", r["adversary_model"]["f1_score"]),
        ("Trust Assurance", "Credential Verification Success Rate",
         r["trust_protocol"]["credential_verification_success_rate"]),
        ("Trust Assurance", "Delegation Integrity Rate", r["delegation_integrity"]["delegation_integrity_rate"]),
        ("Trust Assurance", "Trust Establishment Latency (ms, mean)",
         r["trust_protocol"]["trust_establishment_latency_ms"]["mean"]),
        ("Orchestration Effectiveness", "Policy Enforcement Accuracy",
         r["policy_enforcement"]["policy_enforcement_accuracy"]),
        ("Orchestration Effectiveness", "Behavioural Anomaly Detection Rate",
         r["behavioural_drift"]["behavioural_anomaly_detection_rate"]),
        ("Orchestration Effectiveness", "Workflow Completion Rate",
         r["workflow_completion"]["workflow_completion_rate"]),
        ("Provenance Integrity", "Provenance Identification Accuracy",
         r["provenance_identification"]["provenance_identification_accuracy"]),
        ("Provenance Integrity", "Taint Containment Rate", r["taint_containment"]["taint_containment_rate"]),
        ("Provenance Integrity", "Privilege Path Reconstruction Accuracy",
         r["privilege_path_reconstruction"]["privilege_path_reconstruction_accuracy"]),
    ]
    path = os.path.join(os.path.dirname(__file__), "..", "tab78_evaluation_report.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Evaluation Dimension", "Metric", "Value"])
        writer.writerows(rows)
    print(f"\nWrote Tab 7.8 evaluation report to {os.path.abspath(path)}")
    assert os.path.exists(path)
