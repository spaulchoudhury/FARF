"""Aggregate cross-platform (execution-model) evidence into one citable summary.

The AWS<->GCP cross-cloud pilot now spans three execution models (ECS Fargate, Cloud Run, Lambda) plus
Docker Compose, each producing its own evidence files in its own format. This script pulls the figures
that matter for a "deployment portability" / "execution-model coverage" claim into one table, instead
of that claim resting on a reader trusting a chapter's prose to have transcribed five different evidence
files correctly. Read-only: never modifies evidence.

    python tools/cross_platform_summary.py --evidence-dir evidence_20260925 [--out summary.json]

Each source is OPTIONAL: a missing file produces a row saying so, not a crash, since not every pilot
session produces every artefact. This is a starting point, not a finished instrument -- the two entries
marked MANUAL below were compiled by hand from a chat transcript, not parsed from a file, because no
raw evidence file for them exists locally at the time this script was written. Replace them once you
have the corresponding raw file, or extend this script to parse whatever format that file turns out to
be in.
"""
import argparse
import glob
import json
import os
import statistics


def _load_lambda_cold_samples(evidence_dir):
    """cold_report_N.txt (CloudWatch REPORT lines) + cold_loop_N.json (handler output), N=1..5."""
    inits, billed = [], []
    for report_path in sorted(glob.glob(os.path.join(evidence_dir, "cold_report_*.txt"))):
        with open(report_path, encoding="utf-8") as fh:
            text = fh.read()
        for token, bucket in (("Init Duration:", inits), ("Billed Duration:", billed)):
            if token in text:
                bucket.append(float(text.split(token)[1].split("ms")[0].strip()))
    if not inits:
        return None
    return {"n": len(inits), "init_ms_mean": round(statistics.mean(inits), 2),
            "init_ms_sd": round(statistics.stdev(inits), 2) if len(inits) > 1 else None,
            "billed_ms_mean": round(statistics.mean(billed), 2) if billed else None}


def _load_wan_latency(evidence_dir):
    """Pull 'mean = X ms' lines out of any *load*.txt / *latency*.txt file in the evidence directory."""
    means = []
    for path in sorted(glob.glob(os.path.join(evidence_dir, "*latency*.txt")) +
                       glob.glob(os.path.join(evidence_dir, "*load*.txt"))):
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        if "mean = " in text and "Real WAN /send latency" in text:
            try:
                means.append(float(text.split("mean = ")[1].split("ms")[0].strip()))
            except (ValueError, IndexError):
                continue
    if not means:
        return None
    return {"n_captures": len(means), "mean_of_means_ms": round(statistics.mean(means), 2),
            "sd_of_means_ms": round(statistics.stdev(means), 2) if len(means) > 1 else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    report = {
        "execution_models_exercised": {
            "aws_ecs_fargate": "container orchestration, long-running task (Section 5.11.3)",
            "gcp_cloud_run": "managed serverless container (Section 5.11.2, 5.11.3)",
            "aws_lambda": "function-as-a-service, ephemeral per-environment (Section 5.11.4.6)",
        },
        "lambda_cold_start": _load_lambda_cold_samples(a.evidence_dir) or "no cold_report_*.txt found in evidence-dir",
        "wan_send_latency": _load_wan_latency(a.evidence_dir) or "no matching latency/load evidence file found",
        "quorum_witness_pairs_observed_live_MANUAL": [
            {"organisations": 4, "quorum_required": 3}, {"organisations": 7, "quorum_required": 5},
            {"organisations": 8, "quorum_required": 5}, {"organisations": 10, "quorum_required": 7},
            {"organisations": 11, "quorum_required": 7},
        ],
        "note": "Entries suffixed _MANUAL were compiled by hand, not parsed from a file in --evidence-dir; "
                "replace with a parser once a raw evidence file for that figure exists.",
    }
    text = json.dumps(report, indent=2)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)


if __name__ == "__main__":
    main()
