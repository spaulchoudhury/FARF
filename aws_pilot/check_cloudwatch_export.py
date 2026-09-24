"""
aws_pilot/check_cloudwatch_export.py
====================================
Completeness check of a CloudWatch export (`aws logs filter-log-events --output json`) for the
partition client: per log stream, which loop iterations 0..N-1 are present and which are missing,
and whether the client's own loop_complete line accounts for them.

Purpose: run 2 of the partition test lacked iteration 12 in the exported text although the
client's loop_complete line counted 5 connection errors. This tells you whether the line is absent
from CloudWatch itself (delivery gap during the blackout) or was lost by the export.
"""
import json
import sys


def main():
    if len(sys.argv) < 2:
        print("usage: check_cloudwatch_export.py export.json")
        sys.exit(2)
    try:
        with open(sys.argv[1], encoding="utf-8-sig") as f:
            ev = json.load(f).get("events", [])
    except (OSError, ValueError, TypeError):
        print(f"failed to parse CloudWatch export: {sys.argv[1]}")
        sys.exit(2)
    streams = {}
    for e in ev:
        streams.setdefault(e.get("logStreamName", "?"), []).append(e)
    for name, es in sorted(streams.items()):
        its, start, done = set(), None, None
        for e in es:
            m = e["message"].strip()
            if not m.startswith("{"):
                continue
            try:
                j = json.loads(m)
            except (ValueError, TypeError):
                continue
            if j.get("event") == "send_attempt":
                its.add(j["iteration"])
            elif j.get("event") == "run_start":
                start = j
            elif j.get("event") == "loop_complete":
                done = j
        if start is None:
            print(f"stream {name}: {len(es)} events, not a partition-client stream")
            continue
        n = start["iterations"]
        missing = sorted(set(range(n)) - its)
        counted = sum(done["outcomes"].values()) if done else None
        print(f"stream {name}: {len(es)} events; send_attempt lines {len(its)}/{n}; missing iterations {missing}; "
              f"client's own outcome counters total {counted}")
        if missing and done:
            print(f"   -> {len(missing)} attempt(s) are counted by the client but absent from CloudWatch "
                  f"(log-delivery gap), not an export artefact." if counted == n else "   -> counters also short; investigate.")


if __name__ == "__main__":
    main()
