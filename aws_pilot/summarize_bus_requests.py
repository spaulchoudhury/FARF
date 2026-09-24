"""
aws_pilot/summarize_bus_requests.py
===================================
SERVER-SIDE corroboration of the partition runs, from Cloud Run's own request log.

The partition client's log says "these attempts failed". The bus's log says "these requests
arrived, from this source address, at these times". If the security-group revoke really cut the
path, the source address that was talking before the revoke must go completely silent between
the revoke and the restore, and resume just after. That gap is independent evidence because it is
written by Google's side, not by the client.

Input : JSON array from `gcloud logging read ... --format json` (request logs carry httpRequest).
Windows: CSV lines  name,start,end,revoke,restore   (UTC, e.g. 2026-09-20T19:02:40Z)
Output: per window, for each source address: request count, first/last, and the LARGEST silence
        with its start/end, plus whether that silence covers [revoke, restore].
Addresses are masked on screen (a.b.c.x); the --out file keeps them unmasked (keep it private).
"""
import argparse
import calendar
import itertools
import json
import re
import sys
import time


def to_epoch(s):
    s = re.sub(r"(\.\d{6})\d*", r"\1", s.replace("Z", ""))
    main, _, frac = s.partition(".")
    return calendar.timegm(time.strptime(main, "%Y-%m-%dT%H:%M:%S")) + (float("0." + frac) if frac else 0.0)


def utc(e):
    return time.strftime("%H:%M:%S", time.gmtime(e))


def mask(ip):
    p = ip.split(".")
    return ".".join(p[:3] + ["x"]) if len(p) == 4 else ip[:9] + "..."


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--windows", default=None, help="file with lines name,start,end,revoke,restore")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    try:
        with open(a.log, encoding="utf-8-sig") as f:
            entries = json.load(f)
    except (OSError, ValueError) as e:
        print(f"cannot read {a.log}: {e}")
        sys.exit(2)
    reqs = []
    for e in entries:
        h = e.get("httpRequest")
        if not h or not h.get("remoteIp"):
            continue
        path = h.get("requestUrl", "")
        reqs.append({"t": to_epoch(e["timestamp"]), "ip": h["remoteIp"], "status": h.get("status"),
                     "path": re.sub(r"^https?://[^/]+", "", path)})
    reqs.sort(key=lambda r: r["t"])
    lines = [f"request-log entries with a source address: {len(reqs)}"]
    total = {}
    for r in reqs:
        total[r["ip"]] = total.get(r["ip"], 0) + 1
    lines.append("all source addresses in the export: " + ", ".join(f"{mask(k)} ({v})" for k, v in sorted(total.items(), key=lambda kv: -kv[1])))
    full = list(lines)

    wins = []
    if a.windows:
        with open(a.windows, encoding="utf-8-sig") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    n, s, e, rv, rs = [x.strip() for x in ln.split(",")]
                    wins.append((n, to_epoch(s), to_epoch(e), to_epoch(rv), to_epoch(rs)))
    for name, s, e, rv, rs in wins:
        inw = [r for r in reqs if s - 5 <= r["t"] <= e + 5]
        block = [f"\n--- window {name}: {utc(s)}-{utc(e)} UTC, revoke {utc(rv)}, restore {utc(rs)} ---"]
        byip = {}
        for r in inw:
            byip.setdefault(r["ip"], []).append(r["t"])
        if not byip:
            block.append("  no requests in this window")
        for ip, ts in sorted(byip.items(), key=lambda kv: -len(kv[1])):
            if len(ts) < 5:
                block.append(f"  {mask(ip)}: {len(ts)} request(s) (too few to characterise)")
                continue
            gap, g0, g1 = 0, 0, 0
            for x, y in itertools.pairwise(ts):
                if y - x > gap:
                    gap, g0, g1 = y - x, x, y
            covers = g0 <= rv + 2 and g1 >= rs - 2
            block.append(f"  {mask(ip)}: {len(ts)} requests {utc(ts[0])}-{utc(ts[-1])}; largest silence {gap:.0f} s "
                         f"({utc(g0)} to {utc(g1)}); silence covers revoke..restore: {'YES' if covers else 'no'}")
        lines += block
        full += block
    print("\n".join(lines))
    if a.out:
        # unmasked copy for the private archive
        raw = []
        for name, s, e, rv, rs in wins:
            byip = {}
            for r in reqs:
                if s - 5 <= r["t"] <= e + 5:
                    byip.setdefault(r["ip"], []).append(r["t"])
            raw.append(f"--- {name} ---")
            for ip, ts in byip.items():
                raw.append(f"{ip}: {len(ts)} requests, first {utc(ts[0])}, last {utc(ts[-1])}")
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("\n".join(full + [""] + raw) + "\n")


if __name__ == "__main__":
    main()
