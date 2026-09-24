"""
aws_pilot/analyze_partition_log.py
===================================
Reads a partition-client JSONL log (local file, or lines pasted/exported from
CloudWatch -- any line prefix before the first '{' is ignored) and classifies
every send_attempt as baseline / transition / partition / recovery using the
operator-recorded UTC revoke and restore times, NOT iteration numbers (iteration
spacing stretches during a blackout because each timed-out attempt burns the
full timeout).

Verdicts (printed last, also as the exit code):
  0  PARTITION OBSERVED AND RECOVERED   (clean baseline, >=90% fail in partition, recovers)
  10 INVALID BASELINE                    (baseline not clean -> nothing else is interpretable)
  11 NO EFFECT                           (baseline clean, zero failures during revoke window)
  12 PARTIAL / LAG                       (some, not >=90%, failures -- see first-failure delay)
  13 PARTITION OBSERVED, NO RECOVERY     (fails during window but not clean after restore)
  2  usage / parse error

Usage:
  python analyze_partition_log.py --log partition_v5_log.jsonl \
      --revoke-utc 2026-09-20T10:05:12Z --restore-utc 2026-09-20T10:06:42Z
"""
import argparse
import calendar
import json
import sys
import time
from collections import Counter


def parse_utc(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def load(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            i = line.find("{")
            if i < 0:
                continue
            try:
                rows.append(json.loads(line[i:]))
            except json.JSONDecodeError:
                continue
    return rows


def is_ok(r):
    return (r.get("outcome") == "success" and r.get("http_status") == 200
            and r.get("decision") == "allow")


def is_net_fail(r):
    return r.get("outcome") in ("timeout", "connection_error")


def describe(rs):
    c = Counter()
    for r in rs:
        key = r.get("outcome")
        if key in ("success", "app_error"):
            key = f"{key}/HTTP{r.get('http_status')}/{r.get('decision')}:{r.get('reason')}"
        c[key] += 1
    return dict(c)


def lat_stats(rs):
    """mean / p50 / p95 of latency_ms over CLEAN successes (fresh TCP+TLS connection each attempt)."""
    v = sorted(r["latency_ms"] for r in rs if is_ok(r) and r.get("latency_ms") is not None)
    if not v:
        return "n/a"
    def pct(p):
        return v[min(len(v) - 1, max(0, round(p * len(v) + 0.5) - 1))]
    return (f"n={len(v)} mean={sum(v)/len(v):.1f} ms p50={pct(0.50):.1f} ms p95={pct(0.95):.1f} ms "
            f"min={v[0]:.1f} max={v[-1]:.1f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--revoke-utc", required=True)
    ap.add_argument("--restore-utc", required=True)
    ap.add_argument("--settle-seconds", type=float, default=10.0,
                    help="grace after revoke/restore treated as 'transition' (rule propagation)")
    a = ap.parse_args()

    t_rev, t_res = parse_utc(a.revoke_utc), parse_utc(a.restore_utc)
    if t_res <= t_rev:
        print("restore must be after revoke", file=sys.stderr)
        sys.exit(2)

    rows = [r for r in load(a.log) if r.get("event") == "send_attempt"]
    if not rows:
        print("no send_attempt lines parsed", file=sys.stderr)
        sys.exit(2)

    def t_of(r):
        return r.get("t_epoch") or parse_utc(r["timestamp"])

    base, trans, part, trans_r, rec = [], [], [], [], []
    for r in rows:
        t = t_of(r)
        if t < t_rev:
            base.append(r)
        elif t < t_rev + a.settle_seconds:
            trans.append(r)
        elif t < t_res:
            part.append(r)
        elif t < t_res + a.settle_seconds:
            trans_r.append(r)
        else:
            rec.append(r)

    print(f"attempts: total={len(rows)} baseline={len(base)} transition={len(trans)} "
          f"partition={len(part)} restore-transition={len(trans_r)} recovery={len(rec)}")
    ports = {r.get("source_port") for r in rows if r.get("source_port")}
    print(f"unique source ports: {len(ports)} of {len([r for r in rows if r.get('source_port')])} "
          f"attempts that connected (fresh-connection check)")
    for name, rs in [("baseline", base), ("transition", trans), ("partition", part),
                     ("restore-transition", trans_r), ("recovery", rec)]:
        print(f"  {name:18s} {describe(rs)}")

    print(f"\nlatency, clean baseline attempts (client inside AWS -> Cloud Run, includes TCP+TLS setup): {lat_stats(base)}")
    print(f"latency, clean recovery attempts: {lat_stats(rec)}")

    # ---- baseline gate
    base_ok = sum(is_ok(r) for r in base)
    if len(base) < 5 or base_ok / len(base) < 0.9:
        print(f"\nVERDICT: INVALID BASELINE ({base_ok}/{len(base)} clean HTTP200+allow before revoke). "
              f"Fix the app layer first; the network layer cannot be read from this run.")
        sys.exit(10)

    # ---- partition
    considered = part if part else trans
    fails = [r for r in considered if is_net_fail(r)]
    frac = len(fails) / len(considered) if considered else 0.0
    if len(considered) < 5:
        print(f"\nWARNING: only {len(considered)} attempt(s) fell inside the partition window "
              f"(each timed-out attempt costs timeout+interval, ~13s). Treat the verdict as weak; "
              f"lengthen the revoke window (>=120s) and re-run before citing it.")
    first_fail = min((t_of(r) for r in rows if t_of(r) >= t_rev and is_net_fail(r)), default=None)
    print(f"\npartition window: {len(fails)}/{len(considered)} attempts failed at network level "
          f"({frac:.0%}); first failure "
          + (f"{first_fail - t_rev:.1f}s after revoke" if first_fail else "never"))

    if not fails:
        print("VERDICT: NO EFFECT -- clean baseline, but zero network failures while the rules were "
              "revoked. Check: (1) client really runs INSIDE the task whose SG you edited "
              "(compare Cloud Run request-log source IP with the task's public IP); (2) every egress "
              "rule shape was revoked (-1 AND tcp/443, IPv4 AND ::/0); (3) describe-security-groups "
              "during the window shows no matching rule; (4) the SG is attached to the task ENI.")
        sys.exit(11)
    if frac < 0.9:
        print("VERDICT: PARTIAL / LAG -- some failures but not >=90%. Suggests rule-propagation delay, "
              "a second egress path, or the revoke landing late; compare first-failure delay with "
              "the restore time.")
        sys.exit(12)

    # ---- recovery
    rec_ok = sum(is_ok(r) for r in rec)
    first_ok_after = min((t_of(r) for r in rows if t_of(r) >= t_res and is_ok(r)), default=None)
    print(f"recovery: {rec_ok}/{len(rec)} clean; first clean success "
          + (f"{first_ok_after - t_res:.1f}s after restore" if first_ok_after else "never"))
    if not rec or rec_ok / len(rec) < 0.9:
        bad = Counter(r.get("reason") for r in rec if not is_ok(r))
        print(f"VERDICT: PARTITION OBSERVED, NO CLEAN RECOVERY (non-ok reasons after restore: {dict(bad)}). "
              f"'unadmitted_identity' here means the 300s admission TTL lapsed (use v5 re-admit).")
        sys.exit(13)

    print("VERDICT: PARTITION OBSERVED AND RECOVERED -- clean baseline, "
          f"{frac:.0%} network failures during the revoke window, clean recovery.")
    sys.exit(0)


if __name__ == "__main__":
    main()
