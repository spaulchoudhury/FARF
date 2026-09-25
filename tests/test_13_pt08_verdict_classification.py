"""PT-08 (cloud, v2) verdict classification, tested against a fake bus that replays scripted /send responses.

Guards two things at once:
  * exhausted bus state (org quarantined by the org-level volume window) is reported INCONCLUSIVE (exit 3),
    not VULNERABLE, because it is not a defence failure;
  * a REAL failure (the bus accepts a replay) must still be VULNERABLE (exit 1), so the relabel cannot hide one.
"""
import http.server
import json
import os
import subprocess
import sys
import threading

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "pentest_cloud", "pt08_session_hijack_cloud.py")

ALLOW = {"decision": "allow", "message_id": "m", "reason": "no_violation", "taint_level": 0.05}
NOSIG = {"decision": "block", "message_id": None, "reason": "missing_message_signature", "taint_level": 0.0}
REPLAYED = {"decision": "block", "message_id": None, "reason": "message_replayed", "taint_level": 0.0}
DRIFT = {"decision": "quarantine", "message_id": "m", "reason": "org_wide_behavioural_drift", "taint_level": 0.05}
UNADMITTED = {"decision": "block", "message_id": None, "reason": "unadmitted_identity", "taint_level": 0.0}


def _run_against(send_sequence):
    """Serve `send_sequence` (A legit, B unsigned, C first use, C replay) and return (exit code, stdout)."""
    calls = {"i": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _json(self, obj):
            raw = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self._json({"registered_orgs": ["PT08Org"]})

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if "send" in self.path:
                self._json(send_sequence[min(calls["i"], len(send_sequence) - 1)])
                calls["i"] += 1
            elif "sign" in self.path:
                self._json({"signature": "deadbeef"})
            else:
                self._json({"quorum_required": 5.0, "registered": "x", "valid": True, "reason": "ok",
                            "agent_id": "x", "registered_structurally": True})

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proc = subprocess.run([sys.executable, SCRIPT, "--url", f"http://127.0.0.1:{server.server_address[1]}"],
                              capture_output=True, text=True, timeout=60, check=False)
    finally:
        server.shutdown()
    return proc.returncode, proc.stdout


def test_healthy_run_is_not_vulnerable():
    code, out = _run_against([ALLOW, NOSIG, ALLOW, REPLAYED])
    assert code == 0 and "NOT VULNERABLE" in out


def test_exhausted_org_window_is_inconclusive_not_vulnerable():
    """The exact responses seen on Cloud Run on 24 Sep 2026 (4th PT-08 run on one bus revision)."""
    code, out = _run_against([ALLOW, NOSIG, DRIFT, UNADMITTED])
    assert code == 3 and "INCONCLUSIVE" in out and "NOT VULNERABLE" not in out


def test_a_real_replay_failure_is_still_vulnerable():
    code, out = _run_against([ALLOW, NOSIG, ALLOW, ALLOW])   # the bus ACCEPTS the replay
    assert code == 1 and out.count("VULNERABLE") >= 1 and "INCONCLUSIVE" not in out
