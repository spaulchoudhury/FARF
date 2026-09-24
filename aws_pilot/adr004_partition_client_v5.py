"""
aws_pilot/adr004_partition_client_v5.py
=========================================
v5 (2026-09-19) -- fixes two defects found by running v4 against the real
pentest_cloud/bus_service.py locally (see PRE_TEARDOWN_RUNBOOK_v3.md, Section A):

  1. ADMISSION EXPIRY. bus_service.py's /admit_agent hardcodes ttl_seconds=300,
     and FederationBus._is_admitted() rejects a sender once
     time.time() > issued_at + ttl. v4 admitted once at start; with
     60 iterations x 5s plus ~8s timeouts during the blackout (~358s total) the
     admission lapsed BEFORE the run ended, so the post-restore "recovery"
     segment would have read decision=block / reason=unadmitted_identity
     (HTTP 200, classified app_error) -- indistinguishable from "still
     partitioned" by eye. v5 re-admits every --readmit-every-seconds (default
     100s, well under 300s). Re-admission is idempotent (verified: it does not
     reset agent state or inflate the org count) and is attempted best-effort
     during the blackout (failure is logged, not fatal).

  2. LOG SHAPE FOR CLOUDWATCH. v4 printed the loop_complete summary as
     indented multi-line JSON, which CloudWatch splits into one event per
     line. v5 prints every event as ONE line of JSON, and adds t_epoch to each
     attempt so analyze_partition_log.py can correlate against operator-recorded
     revoke/restore timestamps (the RESTORE_NOW marker is NOT usable as a cue
     when this runs inside Fargate -- the log line may be delayed by the same
     blackout you are trying to end).

Everything else (fresh HTTPSConnection per attempt, ground-truth source port,
Connection: close, preflight gate, success == HTTP 200 + decision=allow) is v4
behaviour, unchanged.
"""
import argparse
import http.client
import json
import ssl
import sys
import time
from urllib.parse import urlsplit

import requests

ADMISSION_TTL_SECONDS = 300  # bus_service.py /admit_agent hardcode


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def emit(out_f, obj):
    line = json.dumps(obj)
    print(line, flush=True)
    out_f.write(line + "\n")
    out_f.flush()


def send_once(host, port, path, payload_json, timeout_s, use_tls=True):
    """Open one fresh connection (HTTPS by default; HTTP only for local
    sanity-testing against a plain-HTTP mock server), send one POST,
    return a result dict. Always closes the connection explicitly
    before returning."""
    if use_tls:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout_s,
                                            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout_s)
    source_port = None
    t0 = time.perf_counter()
    try:
        conn.connect()
        sockname = conn.sock.getsockname()  # ground truth: real socket, post-connect
        source_port = sockname[1]
        body = payload_json.encode("utf-8")
        headers = {"Content-Type": "application/json", "Connection": "close"}
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        t1 = time.perf_counter()
        result = {
            "outcome": "success",
            "source_port": source_port,
            "http_status": resp.status,
            "latency_ms": round((t1 - t0) * 1000.0, 2),
        }
        try:
            j = json.loads(resp_body.decode("utf-8", errors="replace"))
            result["decision"] = j.get("decision")
            result["reason"] = j.get("reason")
        except (ValueError, TypeError, AttributeError):
            pass
        if not (resp.status == 200 and result.get("decision") == "allow"):
            result["outcome"] = "app_error"
        if resp.status >= 400:
            # Capture (truncated) body so an app-level failure (e.g. an
            # unhandled exception / stack trace) is distinguishable from
            # a plain non-2xx with no useful detail, without re-running.
            try:
                body_text = resp_body.decode("utf-8", errors="replace")
            except (UnicodeError, AttributeError):
                body_text = repr(resp_body)
            result["resp_body_snippet"] = body_text[:500]
        return result
    except TimeoutError:
        t1 = time.perf_counter()
        return {"outcome": "timeout", "source_port": source_port,
                "latency_ms": round((t1 - t0) * 1000.0, 2)}
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError,
            BrokenPipeError, OSError) as e:
        t1 = time.perf_counter()
        return {"outcome": "connection_error", "source_port": source_port,
                "latency_ms": round((t1 - t0) * 1000.0, 2), "detail": str(e)}
    except Exception as e:  # noqa: BLE001 -- last-resort diagnostic capture for unexpected network failures
        t1 = time.perf_counter()
        return {"outcome": "other_error", "source_port": source_port,
                "latency_ms": round((t1 - t0) * 1000.0, 2),
                "detail": f"{type(e).__name__}: {e}"}
    finally:
        try:
            conn.close()
        except OSError:
            pass



def admit_agents(base, args, timeout_s, include_orgs=True):
    """Idempotent. Returns (ok, detail). Never raises."""
    try:
        if include_orgs:
            for org in sorted({args.from_org, args.to_org}):
                r = requests.post(f"{base}/register_org", json={"org": org}, timeout=timeout_s)
                if r.status_code != 200:
                    return False, f"register_org {org}: HTTP {r.status_code}"
        for agent, org, role in [(args.from_agent, args.from_org, "executor"),
                                 (args.to_agent, args.to_org, "advisor")]:
            r = requests.post(f"{base}/admit_agent",
                              json={"agent_id": agent, "org": org, "role": role,
                                    "base_privilege": 0.1}, timeout=timeout_s)
            if r.status_code != 200:
                return False, f"admit_agent {agent}: HTTP {r.status_code} {r.text[:80]}"
        return True, "ok"
    except requests.RequestException as e:
        return False, f"{type(e).__name__}: {str(e)[:120]}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="Base Cloud Run URL")
    p.add_argument("--path", default="/send")
    p.add_argument("--iterations", type=int, default=40)
    p.add_argument("--interval-seconds", type=float, default=5.0)
    p.add_argument("--timeout-seconds", type=float, default=8.0)
    p.add_argument("--readmit-every-seconds", type=float, default=100.0,
                   help="Re-admit both agents this often (must be < 300, the bus's hardcoded TTL)")
    p.add_argument("--revoke-at-iteration", type=int, default=None,
                   help="Informational marker only (see module docstring)")
    p.add_argument("--restore-at-iteration", type=int, default=None,
                   help="Informational marker only (see module docstring)")
    p.add_argument("--from-agent", default="PilotOrgA-executor")
    p.add_argument("--from-org", default="PilotOrgA")
    p.add_argument("--to-agent", default="PilotOrgB-advisor")
    p.add_argument("--to-org", default="PilotOrgB")
    p.add_argument("--out", default="partition_v5_log.jsonl")
    p.add_argument("--no-setup", action="store_true", help="skip org/agent registration")
    args = p.parse_args()

    if args.readmit_every_seconds >= ADMISSION_TTL_SECONDS:
        print(f"ERROR: --readmit-every-seconds must be < {ADMISSION_TTL_SECONDS}", file=sys.stderr)
        sys.exit(2)

    parts = urlsplit(args.url)
    host = parts.hostname
    use_tls = (parts.scheme == "https")
    port = parts.port or (443 if use_tls else 80)
    base = f"{'https' if use_tls else 'http'}://{host}" + (f":{parts.port}" if parts.port else "")

    payload = json.dumps({
        "from_agent": args.from_agent, "from_org": args.from_org,
        "to_agent": args.to_agent, "to_org": args.to_org,
        "action_type": "adr017_partition_probe_v5",
        "payload": {"probe": True}, "taint_delta": 0.0,
    })

    with open(args.out, "w", encoding="utf-8") as out_f:
        est = args.iterations * (args.interval_seconds) + 60
        emit(out_f, {"event": "run_start", "timestamp": utc_now(), "t_epoch": round(time.time(), 3),
                     "url": args.url, "iterations": args.iterations,
                     "interval_seconds": args.interval_seconds,
                     "timeout_seconds": args.timeout_seconds,
                     "readmit_every_seconds": args.readmit_every_seconds,
                     "estimated_min_duration_s": est})

        last_admit = None
        if not args.no_setup:
            ok, detail = admit_agents(base, args, 15)
            emit(out_f, {"event": "setup", "timestamp": utc_now(), "ok": ok, "detail": detail})
            if not ok:
                emit(out_f, {"event": "SETUP_FAILED", "timestamp": utc_now()})
                sys.exit(3)
            last_admit = time.time()

        pre = send_once(host, port, args.path, payload, args.timeout_seconds, use_tls=use_tls)
        emit(out_f, {"event": "PREFLIGHT", "timestamp": utc_now(), "t_epoch": round(time.time(), 3), **pre})
        if pre.get("outcome") != "success":
            emit(out_f, {"event": "PREFLIGHT_FAILED", "timestamp": utc_now(),
                         "detail": "baseline is not HTTP 200 + decision=allow; loop not started "
                                   "(a partition test on a broken baseline proves nothing)"})
            sys.exit(3)

        outcomes = {"success": 0, "app_error": 0, "timeout": 0, "connection_error": 0, "other_error": 0}
        decision_tally, reason_tally, http_status_tally = {}, {}, {}
        source_ports_seen = set()
        readmit_ok = readmit_fail = 0

        for i in range(args.iterations):
            if args.revoke_at_iteration is not None and i == args.revoke_at_iteration:
                emit(out_f, {"event": "REVOKE_NOW_MARKER", "iteration": i, "timestamp": utc_now(),
                             "t_epoch": round(time.time(), 3),
                             "note": "informational only; operator revokes on a wall-clock schedule"})
            if args.restore_at_iteration is not None and i == args.restore_at_iteration:
                emit(out_f, {"event": "RESTORE_NOW_MARKER", "iteration": i, "timestamp": utc_now(),
                             "t_epoch": round(time.time(), 3),
                             "note": "informational only; operator restores on a wall-clock schedule"})

            if (not args.no_setup and last_admit is not None
                    and time.time() - last_admit >= args.readmit_every_seconds):
                ok, detail = admit_agents(base, args, 3, include_orgs=False)
                if ok:
                    last_admit = time.time()
                    readmit_ok += 1
                else:
                    readmit_fail += 1
                emit(out_f, {"event": "readmit", "iteration": i, "timestamp": utc_now(),
                             "ok": ok, "detail": detail})

            result = send_once(host, port, args.path, payload, args.timeout_seconds, use_tls=use_tls)
            outcomes[result["outcome"]] += 1
            if result.get("source_port"):
                source_ports_seen.add(result["source_port"])
            if result.get("decision") is not None:
                decision_tally[result["decision"]] = decision_tally.get(result["decision"], 0) + 1
            if result.get("reason") and result.get("decision") != "allow":
                reason_tally[result["reason"]] = reason_tally.get(result["reason"], 0) + 1
            if result.get("http_status") is not None:
                k = str(result["http_status"])
                http_status_tally[k] = http_status_tally.get(k, 0) + 1

            emit(out_f, {"event": "send_attempt", "iteration": i, "timestamp": utc_now(),
                         "t_epoch": round(time.time(), 3), **result})
            time.sleep(args.interval_seconds)

        emit(out_f, {"event": "loop_complete", "timestamp": utc_now(), "iterations": args.iterations,
                     "outcomes": outcomes, "unique_source_ports_used": len(source_ports_seen),
                     "http_status_tally": http_status_tally, "decision_tally": decision_tally,
                     "non_allow_reason_tally": reason_tally,
                     "readmit_ok": readmit_ok, "readmit_fail": readmit_fail})
    


if __name__ == "__main__":
    main()
