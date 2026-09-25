"""Teach pentest_cloud/pt08_session_hijack_cloud.py to report INCONCLUSIVE (not VULNERABLE) when the legitimate
message is quarantined by the org-level volume window.

Why: the bus quarantines an organisation once the last 40 messages sum to more than 0.35 taint
(SlidingWindowVolumeDetector, PT-04 fix). PT-08 sends 2 legitimate messages of 0.05 per run, so the 4th run
against one bus revision trips it. That is exhausted bus state, not a defence failure, but the v2 script only
recognised two other stale-state signatures and fell through to a false "VULNERABLE".
Exit code 3 (INCONCLUSIVE) is still a non-pass: the runner still stops. Only the label changes.

    python tools/patch_pt08_verdict.py --check
    python tools/patch_pt08_verdict.py
"""
import argparse
import sys

FILE = "pentest_cloud/pt08_session_hijack_cloud.py"
OLD = '''    stale_state_suspected = (
        legit.get("reason") == "agent_already_quarantined"
        or first_use.get("reason") == "message_replayed"
    )'''
NEW = '''    stale_state_suspected = (
        legit.get("reason") == "agent_already_quarantined"
        or first_use.get("reason") == "message_replayed"
        # Org-level volume window (window=40, cap=0.35, PT-04 fix): 8 legitimate 0.05-taint messages quarantine the
        # org, and this script sends 2 per run, so the 4th run on one bus revision trips it. Exhausted bus state,
        # not a defence failure. Use `farf_run.ps1 -Step warm` for a fresh revision.
        or "org_wide_behavioural_drift" in (legit.get("reason"), first_use.get("reason"))
    )'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    with open(FILE, "rb") as fh:
        raw = fh.read()
    crlf = b"\r\n" in raw
    text = raw.decode("utf-8").replace("\r\n", "\n")
    # Detect "already applied" by the functional line only, not the surrounding comment: someone applying this
    # by hand (the fallback instructions given alongside this script) is very likely to word the comment
    # differently, and that must still count as done, not as "file differs, refusing to touch it".
    FUNCTIONAL_LINE = 'or "org_wide_behavioural_drift" in (legit.get("reason"), first_use.get("reason"))'
    if NEW in text or FUNCTIONAL_LINE in text:
        print("DONE    already applied")
        return 0
    if text.count(OLD) != 1:
        print(f"** NOT FOUND ** {FILE}: verdict block differs from the reviewed version; nothing changed")
        return 1
    print("APPLY   " + FILE)
    if not a.check:
        out = text.replace(OLD, NEW)
        with open(FILE, "wb") as fh:
            fh.write((out.replace("\n", "\r\n") if crlf else out).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())