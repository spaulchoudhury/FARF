"""gcp_pilot/egress_load_test.py must survive transient network failures during its 1000-message loop
(reproduces the 24-25 Sep 2026 -Step load crash: a single ReadTimeout, thrown while 4 other jobs hammered the
same Cloud Run service concurrently, killed the whole script with an unhandled exception).

A flaky fake HTTP server is used because the bug is about NETWORK failure handling, not the bus's own logic:
`requests` must actually raise `requests.exceptions.RequestException` for the retry path to be exercised, which
a normal (non-flaky) test double cannot produce.
"""
import http.server
import json
import os
import socket
import subprocess
import sys
import threading

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "gcp_pilot", "egress_load_test.py")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _flaky_server(fail_every, hard_fail_message=None):
    """A /send that drops the connection on every `fail_every`-th call (simulating a timeout: the client gets
    no response at all), and always answers /register_org and /admit_agent. If hard_fail_message is set, /send
    always drops for messages whose 'trial' payload field equals that message number (used to make ONE specific
    message unrecoverable even after retries, so the loop must count it as an error and carry on)."""
    calls = {"send": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _json_ok(self, obj):
            raw = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            if self.path == "/send":
                calls["send"] += 1
                trial = json.loads(body).get("payload", {}).get("trial")
                always_fail = hard_fail_message is not None and trial == hard_fail_message
                if always_fail or (fail_every and calls["send"] % fail_every == 0):
                    self.connection.close()  # drop with no response: requests.exceptions.ConnectionError
                    return
                self._json_ok({"decision": "allow", "message_id": "m", "reason": "no_violation"})
            else:
                self._json_ok({"quorum_required": 5.0, "registered": "x"})

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _run(n_messages, server):
    proc = subprocess.run([sys.executable, SCRIPT, "--url", f"http://127.0.0.1:{server.server_address[1]}",
                           "--n-messages", str(n_messages)],
                          capture_output=True, text=True, timeout=60, check=False)
    server.shutdown()
    return proc


def test_recoverable_blips_do_not_crash_the_script():
    """Every 7th /send call drops once; the retry (up to 3 attempts) recovers it, so the run finishes clean."""
    server = _flaky_server(fail_every=7)
    proc = _run(30, server)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Done in" in proc.stdout and "0 errors" in proc.stdout


def test_a_message_that_fails_every_attempt_is_counted_not_fatal():
    """Message #5 always drops. The script must still finish and report exactly 1 error, not crash."""
    server = _flaky_server(fail_every=None, hard_fail_message=5)
    proc = _run(10, server)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Done in" in proc.stdout and "1 errors" in proc.stdout
    assert "message 5 failed after 3 attempts" in proc.stdout


def test_setup_failure_is_a_clear_message_not_a_raw_traceback():
    """If register_org itself never responds, fail fast with a readable message (not a bare stack trace)."""
    server = http.server.HTTPServer(("127.0.0.1", 0), type("Dead", (http.server.BaseHTTPRequestHandler,), {
        "do_POST": lambda self: self.connection.close(), "log_message": lambda *a: None}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proc = _run(1, server)
    assert proc.returncode != 0
    assert "FAIL (setup error): register_org" in (proc.stdout + proc.stderr)
    assert "Traceback (most recent call last)" not in proc.stdout


def test_healthy_run_is_unaffected():
    server = _flaky_server(fail_every=None)
    proc = _run(20, server)
    assert proc.returncode == 0 and "Done in" in proc.stdout and "0 errors" in proc.stdout
