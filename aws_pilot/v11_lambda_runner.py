"""aws_pilot/v11_lambda_runner.py -- runs a v7.9.11 cloud scenario FROM AWS (Lambda, ap-south-1) against the GCP
Cloud Run bus, so the traffic really crosses the cloud boundary (AWS origin -> GCP bus).
Event:  {"scenario": "content_taint|gated_reinstatement|fars_loop|adaptive_attacker|personas|collusion", "url": "https://<bus>",
         "params": {...}}     e.g. {"n": 300} or {"cooling_off": 20}
Package: this file + pentest_cloud/v11_*.py + `requests`, handler = v11_lambda_runner.handler
Lambda limits: 15-min hard cap. gated_reinstatement with cooling_off 20 needs ~2.5 min; keep timeout >= 300 s.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_MODULES = {"content_taint": "v11_content_taint_cloud", "gated_reinstatement": "v11_gated_reinstatement_cloud",
            "fars_loop": "v11_fars_loop_cloud", "adaptive_attacker": "v11_adaptive_attacker_cloud",
            "personas": "v11_personas_cloud", "collusion": "v11_collusion_cloud"}


def handler(event, context=None):
    sc = event.get("scenario")
    if sc not in _MODULES:
        return {"statusCode": 400, "error": f"unknown scenario {sc!r}; choose from {sorted(_MODULES)}"}
    mod = importlib.import_module(_MODULES[sc])
    res = mod.run(event["url"], **event.get("params", {}))
    return {"statusCode": 200, "scenario": sc, "origin": "aws-lambda:" + os.environ.get("AWS_REGION", "?"),
            "ok": res.get("ok"), "summary": {k: v for k, v in res.items() if k not in ("lines", "partA")},
            "transcript": res.get("lines", [])}
