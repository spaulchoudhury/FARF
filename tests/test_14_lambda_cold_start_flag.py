"""ADR-011 Lambda worker: cold-start detection.

A fresh import of the module models a fresh execution environment (module scope runs once per environment, in
Lambda's Init phase). The first invocation it serves is the cold one; every later one is warm. The previous
/proc/uptime < 5 s proxy never fired on real Lambda (uptime was 84 to 218 s on every first call)."""
import importlib.util
import json
import os

import pytest

WORKER = os.path.join(os.path.dirname(__file__), "..", "aws_pilot", "lambda_agent_worker.py")


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _fake_post(url, json=None, timeout=None):  # mirrors requests.post's signature
    if url.endswith("/register_org"):
        return _Resp({"quorum_required": 5.0, "registered": "x"})
    if url.endswith("/admit_agent"):
        return _Resp({"reason": "ok", "valid": True})
    return _Resp({"decision": "allow", "reason": "no_violation", "taint_level": 0.0, "message_id": "m"})


def _new_environment(monkeypatch, bus_url="https://bus.example"):
    """Import the worker afresh, as Lambda does when it creates an execution environment."""
    monkeypatch.setenv("FARF_BUS_URL", bus_url)
    spec = importlib.util.spec_from_file_location("lambda_agent_worker_env", WORKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod.requests, "post", _fake_post)
    return mod


def _invoke(mod):
    resp = mod.handler({}, None)
    assert resp["statusCode"] == 200
    return json.loads(resp["body"])


def test_first_invocation_is_cold_then_warm(monkeypatch):
    env = _new_environment(monkeypatch)
    first, second, third = _invoke(env), _invoke(env), _invoke(env)
    assert first["likely_cold_start"] is True and first["first_invocation_in_environment"] is True
    assert second["likely_cold_start"] is False and third["likely_cold_start"] is False
    assert first["send_result"]["decision"] == "allow"
    assert set(first["timings_ms"]) == {"register_org_ms", "admit_agent_ms", "send_ms", "total_wall_clock_ms"}


def test_a_new_environment_is_cold_again(monkeypatch):
    env_a = _new_environment(monkeypatch)
    _invoke(env_a)
    env_b = _new_environment(monkeypatch)
    assert _invoke(env_b)["likely_cold_start"] is True
    assert _invoke(env_a)["likely_cold_start"] is False


def test_a_failing_first_call_does_not_leave_the_environment_cold(monkeypatch):
    env = _new_environment(monkeypatch)

    def boom(*args, **kwargs):
        raise RuntimeError("bus unreachable")

    monkeypatch.setattr(env.requests, "post", boom)
    with pytest.raises(RuntimeError):
        env.handler({}, None)
    monkeypatch.setattr(env.requests, "post", _fake_post)
    assert _invoke(env)["likely_cold_start"] is False   # the failed call already consumed the cold start


def test_missing_bus_url_still_returns_500_and_consumes_the_flag(monkeypatch):
    monkeypatch.delenv("FARF_BUS_URL", raising=False)
    spec = importlib.util.spec_from_file_location("lambda_agent_worker_nobus", WORKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.handler({}, None)["statusCode"] == 500
    monkeypatch.setattr(mod, "BUS_URL", "https://bus.example")
    monkeypatch.setattr(mod.requests, "post", _fake_post)
    assert _invoke(mod)["likely_cold_start"] is False

