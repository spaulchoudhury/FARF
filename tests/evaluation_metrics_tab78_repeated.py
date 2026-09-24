"""
Tab 7.8 metrics -- repeated-trial statistical rigor upgrade.

The functions in evaluation_metrics_tab78.py each already run a real,
seeded, parameterised batch of trials and return a single point-estimate
per metric (e.g. "F1-Score = 0.909 over 200 trials"). That's a genuine
number, not fabricated, but it's still ONE run -- it doesn't say how much
that number would move if you re-ran the same trial design with a
different random seed, which is exactly what `tests/stats_utils.py`
already reports for the FARS validation work (mean, SD, 95% CI across
n=30->400 repeated samples).

This module closes that gap the same way: wrap each `run_*_trials()`
call in an OUTER loop of N_REPEATS independent runs (different seed each
time, same n_trials per run), extract the metric(s) of interest from
each run, and feed the resulting list into
`stats_utils.descriptive_statistics()` for mean/SD/95% CI -- the same
function, the same statistical convention, already used for FARS.

All nine trial families here are cheap (each single run completes in
well under a second, including the ones that spin up a fresh
FederationBus + SQLite file per trial), so N_REPEATS=20 (the top of the
user-approved 10-20 range) is used throughout rather than trading it
down for speed.
"""
import csv
import os
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from federation_bus import FederationBus
from main import build_federation
from tests.evaluation_metrics_tab78 import (
    run_adversary_model_trials,
    run_behavioural_drift_detection_trials,
    run_delegation_integrity_trials,
    run_policy_enforcement_trials,
    run_privilege_path_reconstruction_trials,
    run_provenance_identification_trials,
    run_taint_containment_trials,
    run_trust_protocol_trials,
    run_workflow_completion_trials,
)
from tests.stats_utils import descriptive_statistics

N_REPEATS = 20


def _bus_factory():
    db_path = os.path.join(tempfile.gettempdir(), f"farf_tab78_repeated_{uuid.uuid4().hex}.db")
    bus = FederationBus(db_path=db_path, require_message_signatures=False)
    agents = build_federation(bus, n_orgs=3)
    return bus, agents


def repeated(metric_fn, extract: dict, n_trials: int, n_repeats: int = N_REPEATS,
             needs_bus_factory: bool = False) -> dict:
    """Runs metric_fn n_repeats times with seeds 0..n_repeats-1 (same
    n_trials each run), extracts one or more named scalars per run via
    the `extract` dict of {output_key: lambda result_dict: scalar}, and
    returns {output_key: descriptive_statistics(...)} for each.
    """
    samples = {key: [] for key in extract}
    for seed in range(n_repeats):
        if needs_bus_factory:
            result = metric_fn(_bus_factory, n_trials=n_trials, seed=seed)
        else:
            result = metric_fn(n_trials=n_trials, seed=seed)
        for key, fn in extract.items():
            samples[key].append(fn(result))
    return {key: descriptive_statistics(vals) for key, vals in samples.items()}


def run_all_repeated() -> dict:
    results = {}

    results["adversary_model"] = repeated(
        run_adversary_model_trials, n_trials=200,
        extract={
            "attack_detection_rate": lambda r: r["attack_detection_rate"],
            "precision": lambda r: r["precision"],
            "recall": lambda r: r["recall"],
            "f1_score": lambda r: r["f1_score"],
        })

    results["trust_protocol"] = repeated(
        run_trust_protocol_trials, n_trials=200,
        extract={
            "credential_verification_success_rate": lambda r: r["credential_verification_success_rate"],
            "trust_establishment_latency_ms_mean": lambda r: r["trust_establishment_latency_ms"]["mean"],
        })

    results["delegation_integrity"] = repeated(
        run_delegation_integrity_trials, n_trials=80, needs_bus_factory=True,
        extract={"delegation_integrity_rate": lambda r: r["delegation_integrity_rate"]})

    results["policy_enforcement"] = repeated(
        run_policy_enforcement_trials, n_trials=300,
        extract={"policy_enforcement_accuracy": lambda r: r["policy_enforcement_accuracy"]})

    results["behavioural_drift"] = repeated(
        run_behavioural_drift_detection_trials, n_trials=100,
        extract={
            "behavioural_anomaly_detection_rate": lambda r: r["behavioural_anomaly_detection_rate"],
            "false_positive_rate": lambda r: r["false_positive_rate"],
        })

    results["workflow_completion"] = repeated(
        run_workflow_completion_trials, n_trials=50, needs_bus_factory=True,
        extract={"workflow_completion_rate": lambda r: r["workflow_completion_rate"]})

    results["provenance_identification"] = repeated(
        run_provenance_identification_trials, n_trials=150,
        extract={"provenance_identification_accuracy": lambda r: r["provenance_identification_accuracy"]})

    results["taint_containment"] = repeated(
        run_taint_containment_trials, n_trials=50, needs_bus_factory=True,
        extract={"taint_containment_rate": lambda r: r["taint_containment_rate"]})

    results["privilege_path_reconstruction"] = repeated(
        run_privilege_path_reconstruction_trials, n_trials=150,
        extract={"privilege_path_reconstruction_accuracy": lambda r: r["privilege_path_reconstruction_accuracy"]})

    return results


def write_ci_report(results: dict, path: str) -> None:
    rows = [
        ("Security Effectiveness", "Attack Detection Rate (ADR)", "adversary_model", "attack_detection_rate", 200),
        ("Security Effectiveness", "Precision", "adversary_model", "precision", 200),
        ("Security Effectiveness", "Recall", "adversary_model", "recall", 200),
        ("Security Effectiveness", "F1-Score", "adversary_model", "f1_score", 200),
        ("Trust Assurance", "Credential Verification Success Rate", "trust_protocol",
         "credential_verification_success_rate", 200),
        ("Trust Assurance", "Trust Establishment Latency (ms, mean)", "trust_protocol",
         "trust_establishment_latency_ms_mean", 200),
        ("Trust Assurance", "Delegation Integrity Rate", "delegation_integrity",
         "delegation_integrity_rate", 80),
        ("Orchestration Effectiveness", "Policy Enforcement Accuracy", "policy_enforcement",
         "policy_enforcement_accuracy", 300),
        ("Orchestration Effectiveness", "Behavioural Anomaly Detection Rate", "behavioural_drift",
         "behavioural_anomaly_detection_rate", 100),
        ("Orchestration Effectiveness", "Behavioural False Positive Rate", "behavioural_drift",
         "false_positive_rate", 100),
        ("Orchestration Effectiveness", "Workflow Completion Rate", "workflow_completion",
         "workflow_completion_rate", 50),
        ("Provenance Integrity", "Provenance Identification Accuracy", "provenance_identification",
         "provenance_identification_accuracy", 150),
        ("Provenance Integrity", "Taint Containment Rate", "taint_containment",
         "taint_containment_rate", 50),
        ("Provenance Integrity", "Privilege Path Reconstruction Accuracy", "privilege_path_reconstruction",
         "privilege_path_reconstruction_accuracy", 150),
    ]
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Evaluation Dimension", "Metric", "N Repeats", "N Trials/Repeat",
                          "Mean", "SD", "95% CI Low", "95% CI High"])
        for dimension, metric_name, family, key, n_trials in rows:
            stats = results[family][key]
            writer.writerow([dimension, metric_name, N_REPEATS, n_trials,
                              round(stats["mean"], 4), round(stats["sd"], 4),
                              round(stats["ci_95"][0], 4), round(stats["ci_95"][1], 4)])


if __name__ == "__main__":
    r = run_all_repeated()
    out_path = os.path.join(os.path.dirname(__file__), "..", "tab78_evaluation_report_with_ci.csv")
    write_ci_report(r, out_path)
    print(f"Wrote {os.path.abspath(out_path)}")
    for family, metrics in r.items():
        print(f"\n=== {family} ===")
        for key, stats in metrics.items():
            print(f"  {key}: mean={stats['mean']:.4f} sd={stats['sd']:.4f} "
                  f"95% CI=({stats['ci_95'][0]:.4f}, {stats['ci_95'][1]:.4f})  n_repeats={stats['n']}")
